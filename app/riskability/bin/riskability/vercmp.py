"""Per-ecosystem version comparators.

A single "compare two version strings" function is the classic way to get
vulnerability matching wrong. ``3.0.13-0ubuntu3.4`` is not ``3.0.14``; ``1.10``
is not older than ``1.9``; ``1.0.0~rc1`` is older than ``1.0.0`` but
``1.0.0-rc1`` is newer than ``1.0.0`` under RPM's caret/tilde rules. Each
ecosystem gets its own comparator here, and the matcher refuses to guess when it
has no comparator for a package type.

Every comparator returns -1, 0 or 1 and never raises on malformed input: an
unparseable version compares as equal-to-nothing and the caller degrades the
finding to "uncertain" rather than inventing a verdict.

Pure standard library on purpose. This runs inside Splunk's bundled Python,
where third-party packages are not guaranteed to exist and vendoring anything
native complicates AppInspect.
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional, Sequence, Tuple

__all__ = [
    "compare",
    "parses",
    "comparator_for",
    "UnknownEcosystem",
    "dpkg_compare",
    "rpm_compare",
    "rpm_compare_version_only",
    "apk_compare",
    "semver_compare",
    "pep440_compare",
    "maven_compare",
    "go_compare",
    "windows_compare",
    "generic_compare",
]


class UnknownEcosystem(Exception):
    """Raised when no comparator is registered for a package type."""


def _cmp(a, b) -> int:
    return (a > b) - (a < b)


# ---------------------------------------------------------------------------
# Debian / Ubuntu
# ---------------------------------------------------------------------------

_DPKG_RE = re.compile(r"^(?:(\d+):)?([^:]*?)(?:-([^-:]*))?$")


def _dpkg_order(ch: str) -> int:
    """Debian's per-character collation order, matching dpkg's ``order()``.

    Tilde sorts before everything, including the end of string. A **digit
    orders as 0**, the same as end-of-string -- that is not an oversight in
    dpkg, it is what makes a version terminate before a letter run: ``1.0``
    sorts below ``1.0a`` but *above* ``unknown``. Letters order as their own
    code point, and anything else as its code point plus 256, so punctuation
    sorts after letters.

    Getting the digit case wrong is invisible in most corpora, because it only
    shows up when a letter is compared against a digit at the same position --
    exactly what happens when a component reports a non-numeric version such as
    ``UNKNOWN`` and it is compared against a real one.
    """
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if ch.isdigit():
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _dpkg_compare_part(a: str, b: str) -> int:
    """Compare one upstream-version or revision component."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        # Non-digit run, compared by Debian collation order.
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < la else "")
            bc = _dpkg_order(b[j] if j < lb else "")
            if ac != bc:
                return _cmp(ac, bc)
            i += 1 if i < la else 0
            j += 1 if j < lb else 0
            if i >= la and j >= lb:
                break
        # Digit run, compared numerically. Leading zeros are insignificant.
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if first_diff == 0:
                first_diff = _cmp(a[i], b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(v: str) -> Tuple[int, str, str]:
    v = (v or "").strip()
    epoch = 0
    rest = v
    if ":" in v:
        head, _, tail = v.partition(":")
        if head.isdigit():
            epoch = int(head)
            rest = tail
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """Compare two Debian/Ubuntu package versions (``[epoch:]upstream[-revision]``)."""
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return _cmp(ea, eb)
    r = _dpkg_compare_part(ua, ub)
    if r:
        return r
    return _dpkg_compare_part(ra, rb)


# ---------------------------------------------------------------------------
# RPM (RHEL, SUSE, Amazon, Rocky, Alma)
# ---------------------------------------------------------------------------

_RPM_SEG = re.compile(r"([a-zA-Z]+|[0-9]+|~|\^)")


def _rpm_segments(v: str) -> List[str]:
    return _RPM_SEG.findall(v or "")


def rpm_compare_label(a: str, b: str) -> int:
    """rpmvercmp() over a single version or release label."""
    sa, sb = _rpm_segments(a), _rpm_segments(b)
    i = 0
    while i < len(sa) and i < len(sb):
        x, y = sa[i], sb[i]
        # Tilde sorts before everything, including the empty string.
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            i += 1
            continue
        # Caret sorts after everything except a longer real segment.
        if x == "^" or y == "^":
            if x != y:
                return -1 if x == "^" else 1
            i += 1
            continue
        x_num, y_num = x[0].isdigit(), y[0].isdigit()
        if x_num != y_num:
            # A numeric segment always outranks an alphabetic one.
            return 1 if x_num else -1
        if x_num:
            xs, ys = x.lstrip("0") or "0", y.lstrip("0") or "0"
            if len(xs) != len(ys):
                return _cmp(len(xs), len(ys))
            if xs != ys:
                return _cmp(xs, ys)
        else:
            if x != y:
                return _cmp(x, y)
        i += 1
    if len(sa) == len(sb):
        return 0
    # Whichever still has segments is newer, unless that segment is a tilde.
    rest = sa[i:] if len(sa) > len(sb) else sb[i:]
    longer_is_a = len(sa) > len(sb)
    if rest and rest[0] == "~":
        return -1 if longer_is_a else 1
    if rest and rest[0] == "^":
        return 1 if longer_is_a else -1
    return 1 if longer_is_a else -1


def _rpm_split(v: str) -> Tuple[int, str, str]:
    v = (v or "").strip()
    epoch = 0
    rest = v
    if ":" in v:
        head, _, tail = v.partition(":")
        if head.strip().isdigit():
            epoch = int(head.strip())
            rest = tail
    version, sep, release = rest.partition("-")
    if not sep:
        version, release = rest, ""
    return epoch, version, release


def rpm_compare(a: str, b: str) -> int:
    """Compare two RPM EVRs (``[epoch:]version[-release]``).

    Matches ``rpm.vercmp`` exactly, including that a missing release sorts below
    any present one: ``1.0`` < ``1.0-1``. Do not "helpfully" treat an absent
    release as equal — an advisory that names a bare upstream version is a
    different problem, solved by :func:`rpm_compare_version_only` at the
    matching layer where the caller knows which side is the advisory.
    """
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return _cmp(ea, eb)
    r = rpm_compare_label(va, vb)
    if r:
        return r
    return rpm_compare_label(ra, rb)


def rpm_compare_version_only(a: str, b: str) -> int:
    """Compare RPM epoch and version, ignoring the release.

    For the case where an advisory gives an upstream version with no release and
    comparing releases would be meaningless rather than merely imprecise.
    """
    ea, va, _ = _rpm_split(a)
    eb, vb, _ = _rpm_split(b)
    if ea != eb:
        return _cmp(ea, eb)
    return rpm_compare_label(va, vb)


# ---------------------------------------------------------------------------
# Alpine apk
# ---------------------------------------------------------------------------

# Ordered weakest to strongest. Anything before the empty suffix is a
# pre-release; anything after it is a post-release.
_APK_SUFFIX_ORDER = {
    "alpha": -4,
    "beta": -3,
    "pre": -2,
    "rc": -1,
    "": 0,
    "cvs": 1,
    "svn": 2,
    "git": 3,
    "hg": 4,
    "p": 5,
}

_APK_RE = re.compile(
    r"^(?P<numbers>\d+(?:\.\d+)*)"
    r"(?P<letter>[a-z]?)"
    r"(?P<suffixes>(?:_[a-z]+\d*)*)"
    r"(?:-r(?P<rev>\d+))?$"
)


def _apk_parse(v: str):
    m = _APK_RE.match((v or "").strip())
    if not m:
        return None
    numbers = [int(x) for x in m.group("numbers").split(".")]
    letter = m.group("letter") or ""
    suffixes = []
    for suf in re.findall(r"_([a-z]+)(\d*)", m.group("suffixes") or ""):
        name, num = suf
        suffixes.append((_APK_SUFFIX_ORDER.get(name, 0), int(num or 0)))
    rev = int(m.group("rev") or 0)
    return numbers, letter, suffixes, rev


def apk_compare(a: str, b: str) -> int:
    """Compare two Alpine apk versions (``1.2.3a_rc1-r4``)."""
    pa, pb = _apk_parse(a), _apk_parse(b)
    if pa is None or pb is None:
        return generic_compare(a, b)
    na, la, sa, ra = pa
    nb, lb, sb, rb = pb
    for x, y in zip(na, nb):
        if x != y:
            return _cmp(x, y)
    if len(na) != len(nb):
        return _cmp(len(na), len(nb))
    if la != lb:
        return _cmp(la, lb)
    # Compare suffix chains position by position; a missing suffix is "release".
    for i in range(max(len(sa), len(sb))):
        x = sa[i] if i < len(sa) else (0, 0)
        y = sb[i] if i < len(sb) else (0, 0)
        if x != y:
            return _cmp(x, y)
    return _cmp(ra, rb)


# ---------------------------------------------------------------------------
# SemVer (npm, crates, most language ecosystems)
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]?([0-9A-Za-z.-]+?))?(?:\+([0-9A-Za-z.-]+))?$"
)


def _semver_prerelease_cmp(a: str, b: str) -> int:
    # Absent prerelease outranks any present one.
    if not a and not b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    pa, pb = a.split("."), b.split(".")
    for x, y in zip(pa, pb):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            r = _cmp(int(x), int(y))
        elif xn != yn:
            # Numeric identifiers always have lower precedence than alphanumeric.
            r = -1 if xn else 1
        else:
            r = _cmp(x, y)
        if r:
            return r
    return _cmp(len(pa), len(pb))


def semver_compare(a: str, b: str) -> int:
    """Compare two SemVer 2.0 versions. Build metadata is ignored, per spec."""
    ma, mb = _SEMVER_RE.match((a or "").strip()), _SEMVER_RE.match((b or "").strip())
    if not ma or not mb:
        return generic_compare(a, b)
    for i in (1, 2, 3):
        x = int(ma.group(i) or 0)
        y = int(mb.group(i) or 0)
        if x != y:
            return _cmp(x, y)
    return _semver_prerelease_cmp(ma.group(4) or "", mb.group(4) or "")


# ---------------------------------------------------------------------------
# PEP 440 (PyPI)
# ---------------------------------------------------------------------------

_PEP440_RE = re.compile(
    r"^\s*v?"
    r"(?:(?P<epoch>\d+)!)?"
    r"(?P<release>\d+(?:\.\d+)*)"
    r"(?P<pre>[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?"
    r"(?P<post>[-_.]?(?:post|rev|r)[-_.]?\d*|-\d+)?"
    r"(?P<dev>[-_.]?dev[-_.]?\d*)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?"
    r"\s*$",
    re.IGNORECASE,
)

_PRE_NORM = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}


def _pep440_parse(v: str):
    m = _PEP440_RE.match(v or "")
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    release = tuple(int(x) for x in m.group("release").split("."))

    pre = m.group("pre")
    if pre:
        pm = re.match(r"[-_.]?([a-z]+)[-_.]?(\d*)", pre, re.IGNORECASE)
        label = _PRE_NORM.get(pm.group(1).lower(), pm.group(1).lower())
        pre_key = (label, int(pm.group(2) or 0))
    else:
        pre_key = None

    post = m.group("post")
    if post:
        pm = re.match(r"[-_.]?(?:post|rev|r)?[-_.]?(\d*)", post, re.IGNORECASE)
        post_key = int(pm.group(1) or 0)
    else:
        post_key = None

    dev = m.group("dev")
    if dev:
        pm = re.match(r"[-_.]?dev[-_.]?(\d*)", dev, re.IGNORECASE)
        dev_key = int(pm.group(1) or 0)
    else:
        dev_key = None

    return epoch, release, pre_key, post_key, dev_key


def pep440_compare(a: str, b: str) -> int:
    """Compare two PEP 440 versions. Local versions are ignored for matching."""
    pa, pb = _pep440_parse(a), _pep440_parse(b)
    if pa is None or pb is None:
        return generic_compare(a, b)
    ea, ra, prea, posta, deva = pa
    eb, rb, preb, postb, devb = pb
    if ea != eb:
        return _cmp(ea, eb)
    # Pad the shorter release tuple with zeros: 1.0 == 1.0.0.
    n = max(len(ra), len(rb))
    ra_p = ra + (0,) * (n - len(ra))
    rb_p = rb + (0,) * (n - len(rb))
    if ra_p != rb_p:
        return _cmp(ra_p, rb_p)

    # Ordering within one release: .devN < preN < release < .postN
    def rank(pre, post, dev):
        if pre is None and post is None and dev is not None:
            return (0, (), 0, dev)          # dev release
        if pre is not None:
            return (1, pre, 0, dev if dev is not None else 1 << 30)
        if post is not None:
            return (3, (), post, dev if dev is not None else 1 << 30)
        return (2, (), 0, dev if dev is not None else 1 << 30)

    return _cmp(rank(prea, posta, deva), rank(preb, postb, devb))


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

_MAVEN_QUALIFIERS = {
    "alpha": 0, "a": 0,
    "beta": 1, "b": 1,
    "milestone": 2, "m": 2,
    "rc": 3, "cr": 3,
    "snapshot": 4,
    "": 5, "ga": 5, "final": 5, "release": 5,
    "sp": 6,
}


def _maven_tokens(v: str):
    v = (v or "").strip().lower()
    v = re.sub(r"([0-9])([a-z])", r"\1-\2", v)
    v = re.sub(r"([a-z])([0-9])", r"\1-\2", v)
    parts = re.split(r"[-_.]+", v)
    out = []
    for p in parts:
        if not p:
            continue
        out.append(int(p) if p.isdigit() else p)
    return out


_MAVEN_NULL_RANK = _MAVEN_QUALIFIERS[""]


def _maven_trim(tokens: list) -> list:
    """Drop trailing null tokens so 1.0, 1.0.0 and 1.0-ga are one version.

    Maven's ComparableVersion normalises by removing trailing "null" items: a
    zero, or a qualifier that means "the plain release" (ga, final, release).
    Without this, 1.0-ga sorts above 1.0 and every GA artifact looks newer than
    itself.
    """
    out = list(tokens)
    while out:
        last = out[-1]
        if isinstance(last, int):
            if last != 0:
                break
        elif _MAVEN_QUALIFIERS.get(last, 7) != _MAVEN_NULL_RANK:
            break
        out.pop()
    return out


def maven_compare(a: str, b: str) -> int:
    """Compare two Maven versions using ComparableVersion-like ordering."""
    ta, tb = _maven_trim(_maven_tokens(a)), _maven_trim(_maven_tokens(b))
    for i in range(max(len(ta), len(tb))):
        has_x, has_y = i < len(ta), i < len(tb)
        x = ta[i] if has_x else None
        y = tb[i] if has_y else None
        # An absent token is padded to match the kind of the token it faces:
        # zero against a number, the null qualifier against a qualifier.
        if x is None:
            x = 0 if isinstance(y, int) else ""
        if y is None:
            y = 0 if isinstance(x, int) else ""
        xi, yi = isinstance(x, int), isinstance(y, int)
        if xi and yi:
            if x != y:
                return _cmp(x, y)
        elif xi != yi:
            # A numeric token always outranks a qualifier: 1.0-alpha < 1.0.1.
            return 1 if xi else -1
        else:
            qa = _MAVEN_QUALIFIERS.get(x, 7)
            qb = _MAVEN_QUALIFIERS.get(y, 7)
            if qa != qb:
                return _cmp(qa, qb)
            if qa == 7 and x != y:
                # Two unknown qualifiers: fall back to lexical order.
                return _cmp(x, y)
    return 0


# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------

def _go_normalise(v: str) -> str:
    """Strip the Go toolchain prefix and build metadata.

    Syft reports the Go standard library's version as the toolchain string
    ``go1.26.6``, while advisories name it ``1.4.3``. Left alone, the ``go``
    prefix makes the SemVer parse fail, the generic fallback then orders
    ``go1.26.6`` *below* ``1.4.3``, and every host reports a decade of fixed
    stdlib CVEs. This is the single largest false-positive source seen on a
    real Go-heavy host.
    """
    v = (v or "").strip()
    v = v.replace("+incompatible", "")
    if v[:2].lower() == "go" and v[2:3].isdigit():
        v = v[2:]
    return v


def go_compare(a: str, b: str) -> int:
    """Compare two Go module or toolchain versions.

    Go module versions are SemVer with a leading ``v``; toolchain versions look
    like ``go1.26.6``. ``+incompatible`` is build metadata and is ignored, and
    pseudo-versions sort correctly under plain SemVer prerelease rules because
    their timestamp is the prerelease component.
    """
    return semver_compare(_go_normalise(a), _go_normalise(b))


# ---------------------------------------------------------------------------
# Windows (registry DisplayVersion, MSIX package versions)
# ---------------------------------------------------------------------------

_WINDOWS_RE = re.compile(r"^[vV]?(\d+(?:\.\d+)*)(.*)$")


def windows_compare(a: str, b: str) -> int:
    """Compare two Windows version strings.

    Windows has no version grammar: the value is whatever an installer wrote
    into the registry. In practice it is dotted-numeric with an optional "V"
    prefix that vendors apply inconsistently -- a real estate carried both
    ``V16.0`` and ``2.0.6`` for the same kind of product. Comparing those
    literally puts every V-prefixed version below every numeric one, because a
    letter sorts below a digit.

    Segments are compared numerically and the shorter is zero-padded, so
    ``3.12`` and ``3.12.0.0`` are equal. Anything left over after the numeric
    run is compared lexically, which is a guess -- but a Windows finding is
    already capped at low confidence because its identity comes from a
    generated CPE.
    """
    ma = _WINDOWS_RE.match((a or "").strip())
    mb = _WINDOWS_RE.match((b or "").strip())
    if not ma or not mb:
        return generic_compare(a, b)
    na = [int(x) for x in ma.group(1).split(".") if x.isdigit()]
    nb = [int(x) for x in mb.group(1).split(".") if x.isdigit()]
    for i in range(max(len(na), len(nb))):
        x = na[i] if i < len(na) else 0
        y = nb[i] if i < len(nb) else 0
        if x != y:
            return _cmp(x, y)
    return _cmp(ma.group(2).strip().lower(), mb.group(2).strip().lower())


# ---------------------------------------------------------------------------
# Generic fallback
# ---------------------------------------------------------------------------

_GENERIC_SEG = re.compile(r"(\d+|[a-zA-Z]+)")


def generic_compare(a: str, b: str) -> int:
    """Last-resort comparison for versions with no ecosystem rules.

    Splits into numeric and alphabetic runs and compares run by run. Callers
    must mark findings produced with this comparator as lower confidence: it is
    a heuristic, not an authority.
    """
    sa = _GENERIC_SEG.findall((a or "").strip())
    sb = _GENERIC_SEG.findall((b or "").strip())
    for i in range(max(len(sa), len(sb))):
        if i >= len(sa):
            return -1
        if i >= len(sb):
            return 1
        x, y = sa[i], sb[i]
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            r = _cmp(int(x), int(y))
        elif xn != yn:
            r = 1 if xn else -1
        else:
            r = _cmp(x, y)
        if r:
            return r
    return 0


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

# Keys are swinv/Syft package types, plus the OSV ecosystem names we normalise
# to during feed import.
_COMPARATORS = {
    "deb": dpkg_compare,
    "debian": dpkg_compare,
    "ubuntu": dpkg_compare,
    "rpm": rpm_compare,
    "redhat": rpm_compare,
    "rhel": rpm_compare,
    "suse": rpm_compare,
    "opensuse": rpm_compare,
    "amazon": rpm_compare,
    "rocky": rpm_compare,
    "alma": rpm_compare,
    "almalinux": rpm_compare,
    "apk": apk_compare,
    "alpine": apk_compare,
    "npm": semver_compare,
    "javascript": semver_compare,
    "crates.io": semver_compare,
    "rust-crate": semver_compare,
    "cargo": semver_compare,
    "nuget": semver_compare,
    "dotnet": semver_compare,
    "gem": semver_compare,
    "rubygems": semver_compare,
    "python": pep440_compare,
    "pypi": pep440_compare,
    "wheel": pep440_compare,
    "egg": pep440_compare,
    "java-archive": maven_compare,
    "maven": maven_compare,
    "jar": maven_compare,
    "go-module": go_compare,
    "go": go_compare,
    "golang": go_compare,
    "composer": semver_compare,
    "packagist": semver_compare,
    "hex": semver_compare,
    "pub": semver_compare,
    "conan": semver_compare,
    "swift": semver_compare,
    # Windows: no formal grammar, so a tolerant dotted-numeric comparison.
    "windows": windows_compare,
    "msix": windows_compare,
    "hotfix": windows_compare,
}

# Types that have a comparator but whose results should still be treated as
# heuristic, because the identifier itself is unreliable.
HEURISTIC_TYPES = {"binary", "unknown", "generic"}


# Whether a version string is actually parseable by its ecosystem's rules.
# A comparator that quietly falls back to generic_compare still returns an
# ordering, and that ordering is frequently wrong -- "go1.26.6" sorting below
# "1.4.3" is the worked example. The matcher uses this to tell a real
# comparison from a guess, and marks the guess as low confidence instead of
# reporting it as fact.
def _looks_like_a_version(v: str) -> bool:
    """Reject placeholders that dpkg/rpm would happily order anyway.

    Debian and RPM version syntax is permissive enough that "unknown" parses
    and sorts below every real version, so a component whose version could not
    be determined matches every advisory ever filed against that package. A
    real version contains at least one digit.
    """
    v = (v or "").strip()
    if not v or not any(ch.isdigit() for ch in v):
        return False
    return v.lower() not in {"unknown", "none", "null", "n/a", "-"}


_PARSE_CHECKS = {
    dpkg_compare: _looks_like_a_version,
    rpm_compare: _looks_like_a_version,
    apk_compare: lambda v: _apk_parse(v) is not None,
    semver_compare: lambda v: _SEMVER_RE.match((v or "").strip()) is not None,
    pep440_compare: lambda v: _pep440_parse(v) is not None,
    go_compare: lambda v: _SEMVER_RE.match(_go_normalise(v)) is not None,
    windows_compare: lambda v: _WINDOWS_RE.match((v or "").strip()) is not None,
    maven_compare: _looks_like_a_version,
    generic_compare: lambda v: False,
}


def parses(ecosystem: str, version: str) -> bool:
    """Can this ecosystem's rules actually parse this version string?

    False means any comparison involving it is a heuristic guess.
    """
    try:
        fn = comparator_for(ecosystem)
    except UnknownEcosystem:
        return False
    check = _PARSE_CHECKS.get(fn)
    if check is None:
        return True
    try:
        return bool(check(version))
    except Exception:
        return False


def comparator_for(ecosystem: str) -> Callable[[str, str], int]:
    """Return the comparator for a package type, or raise UnknownEcosystem."""
    key = (ecosystem or "").strip().lower()
    if key in _COMPARATORS:
        return _COMPARATORS[key]
    raise UnknownEcosystem(ecosystem)


def compare(ecosystem: str, a: str, b: str, strict: bool = False) -> int:
    """Compare two versions in the given ecosystem.

    With ``strict=False`` an unknown ecosystem falls back to ``generic_compare``
    so the caller still gets an ordering; the caller is responsible for marking
    that result as low confidence. With ``strict=True`` it raises instead.
    """
    try:
        fn = comparator_for(ecosystem)
    except UnknownEcosystem:
        if strict:
            raise
        fn = generic_compare
    try:
        return fn(a, b)
    except Exception:
        # A comparator must never take down a search over one bad version string.
        return generic_compare(a, b)
