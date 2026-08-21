"""Deciding whether an installed component is actually vulnerable.

The rule that matters most here is precedence. Ubuntu ships
``openssl 3.0.13-0ubuntu3.4`` with the fix for a CVE that upstream fixed in
3.0.14. NVD says "anything below 3.0.14 is vulnerable". Both statements are
true; only one of them is about this host. So a distro advisory always beats an
upstream ecosystem advisory, which always beats an NVD/CPE assertion, and an
explicit vendor "not affected" beats all of them.

Getting that order wrong is not a cosmetic defect: it produces a finding on
every patched package on every Debian-family host in the fleet, which is how
vulnerability tools get switched off.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional, Sequence

from . import feed as feedlib
from . import purl as purllib
from . import scope as scopelib
from . import vercmp


def prepare_component(component: dict) -> dict:
    """Resolve a raw inventory row into something safe to match against.

    Order matters and is the whole point of having one function for it:

    1. **PURL enrichment** recovers the source package and the package's own
       distro, both of which the flat inventory record drops.
    2. **The PURL's distro is applied** where the component is a host package,
       because it describes the package rather than the machine.
    3. **Scope resolution wins last**, because the root a package was physically
       found in is stronger evidence than a qualifier.

       Syft is well behaved here on its own: measured over a real host, all 804
       components living wholly inside a nested root carried *no* ``distro=``
       qualifier at all, which is the honest answer. The qualifier goes wrong
       only where one component's evidence spans two roots -- Syft then merges a
       nested package with host evidence and the surviving qualifier describes
       the host. That was 3 components out of 14,349, so this ordering is a
       cheap guard against a rare case rather than a fix for a widespread one.

       The ordering earns its place for the common case instead: a nested
       component inherits the host's ``os_id``/``os_version_id`` from the flat
       inventory row regardless of what its PURL says, because every row repeats
       host identity. Scope resolution is what replaces that with the root's own
       release, or with nothing when none can be derived.
    """
    enriched = purllib.enrich(component)

    if enriched.get("purl_distro"):
        enriched["os_id"] = enriched["purl_distro"]
        if enriched.get("purl_distro_release"):
            enriched["os_version_id"] = enriched["purl_distro_release"]

    return scopelib.apply_scope(enriched)

# Higher wins. A finding from a lower authority is dropped when a higher
# authority has already spoken about the same (component, advisory).
AUTHORITY_DISTRO = 30
AUTHORITY_ECOSYSTEM = 20
AUTHORITY_NVD = 10
AUTHORITY_HEURISTIC = 0

AUTHORITY_NAMES = {
    AUTHORITY_DISTRO: "distro",
    AUTHORITY_ECOSYSTEM: "ecosystem",
    AUTHORITY_NVD: "nvd",
    AUTHORITY_HEURISTIC: "heuristic",
}

# Package types whose version is a distribution version, not an upstream one.
# For these, an upstream range is never sufficient evidence on its own.
DISTRO_TYPES = {"deb", "rpm", "apk"}

# Paths that mean a *language* package was installed by the distribution rather
# than by pip/npm/gem. Debian puts distro-managed Python in dist-packages and
# leaves site-packages to pip; RPM distros use site-packages under /usr/lib,
# with /usr/local reserved for locally installed software.
_DISTRO_MANAGED_MARKERS = (
    "/dist-packages/",
    "/usr/share/nodejs/",
    "/usr/lib/node_modules/",
    "/usr/share/gems/",
    "/usr/lib/ruby/gems/",
)
_DISTRO_MANAGED_PREFIXES = (
    "/usr/lib/python",
    "/usr/lib64/python",
)


def distro_managed_language_package(component: dict) -> bool:
    """Is this language package owned by the distribution's package manager?

    The same installation is legitimately reported twice by an SBOM scanner --
    once as a deb from the dpkg database, once as a PyPI package from its
    egg-info. Assessed as an upstream PyPI package, Ubuntu's ESM-patched
    ``cryptography 2.1.4`` is thirty-seven releases behind the upstream fix and
    looks catastrophic; assessed as the deb it is, it is patched.

    So the same backport rule that protects deb/rpm/apk has to protect a
    language package that the distribution installed, and the install path is
    what distinguishes the two cases.
    """
    path = primary_path(component)
    if not path:
        return False
    if any(m in path for m in _DISTRO_MANAGED_MARKERS):
        return True
    if any(path.startswith(p) for p in _DISTRO_MANAGED_PREFIXES) and \
            "/site-packages/" in path:
        return True
    return False


def authority_for(range_row: dict) -> int:
    """How much this row's claim is worth for the package it names."""
    if range_row.get("distro"):
        return AUTHORITY_DISTRO
    source = (range_row.get("feed_source") or "").lower()
    if source.startswith("nvd") or (range_row.get("range_type") or "") == "CPE":
        return AUTHORITY_NVD
    return AUTHORITY_ECOSYSTEM


def _distro_matches(component: dict, row: dict) -> bool:
    """Is this distro advisory about the release the host is actually running?

    An Ubuntu 22.04 advisory says nothing about a 24.04 host. Applying it
    anyway is the second-biggest source of false positives after ignoring
    backports entirely.
    """
    row_distro = (row.get("distro") or "").lower()
    if not row_distro:
        return True
    comp_distro = (component.get("os_id") or "").lower()
    if not comp_distro:
        # No OS identity on the component: we cannot confirm the advisory
        # applies. Treat as non-matching rather than assuming.
        return False
    # OSV writes "red hat" where os-release says "rhel"; accept known aliases.
    aliases = {
        "rhel": {"rhel", "red hat", "redhat", "centos"},
        "red hat": {"rhel", "red hat", "redhat", "centos"},
        "rocky": {"rocky", "rocky linux"},
        "almalinux": {"almalinux", "alma"},
        "opensuse-leap": {"suse", "opensuse", "opensuse-leap"},
        "sles": {"suse", "sles"},
        "amzn": {"amazon linux", "amzn"},
    }
    comp_set = aliases.get(comp_distro, {comp_distro})
    row_set = aliases.get(row_distro, {row_distro})
    if not (comp_set & row_set):
        return False

    # A variant names a separate product line (Ubuntu Pro, FIPS, Realtime),
    # not the ordinary distribution. Applying those advisories to a plain host
    # reports package sets it does not have.
    variant = (row.get("distro_variant") or "").strip().lower()
    if variant and not _variant_applies(component, variant):
        return False

    row_release = _normalise_release(row.get("distro_release"))
    if not row_release:
        return True
    comp_release = _normalise_release(component.get("os_version_id"))
    if not comp_release:
        return False
    if comp_release == row_release:
        return True

    # Only Red Hat-family advisories are legitimately keyed on the major
    # version. Debian-family releases are dotted minor versions in their own
    # right, so a major-only fallback there matches 24.04 against 24.10 and
    # 25.04 against 25.10 -- different releases with different package sets.
    if (component.get("type") or "").lower() != "rpm":
        return False
    return comp_release.split(".")[0] == row_release.split(".")[0]


# Markers that show an installed package really does come from a given Ubuntu
# product line. An ESM package is stamped "+esm"; FIPS builds say so.
_VARIANT_EVIDENCE = {
    "pro": ("esm",),
    "fips": ("fips",),
    "fips-updates": ("fips",),
    "fips-preview": ("fips",),
    "realtime": ("realtime",),
}


def _variant_applies(component: dict, variant: str) -> bool:
    """Does this component actually belong to the advisory's product line?

    Ubuntu Pro/ESM advisories cover releases past standard support, so they are
    the *only* source for an 18.04 or 20.04 host and must not be discarded
    wholesale. The version string is the evidence: ESM packages carry "+esm",
    FIPS builds carry "fips". Where the marker is absent, the advisory is about
    a product the host is not running.
    """
    version = (component.get("version") or "").lower()
    tokens = [t for t in variant.split(":") if t]
    for token in tokens:
        markers = _VARIANT_EVIDENCE.get(token)
        if markers is None:
            # An unrecognised product line (Nvidia BlueField and similar):
            # nothing in the inventory identifies it, so do not assume it.
            return False
        if not any(m in version for m in markers):
            return False
    return bool(tokens)


def _normalise_release(release: Optional[str]) -> str:
    """Put a distro release string into one form before comparing.

    Feeds and hosts disagree on spelling: OSV publishes Alpine releases as
    ``v3.20`` while ``/etc/os-release`` reports ``3.20``. Comparing those two
    literally makes every Alpine advisory miss its own hosts, which looks
    exactly like "no vulnerabilities found".
    """
    r = (release or "").strip().lower()
    if r.startswith("v") and r[1:2].isdigit():
        r = r[1:]
    return r


def _in_range(ecosystem: str, installed: str, row: dict) -> Optional[bool]:
    """Is ``installed`` inside this affected range?

    Returns True, False, or None when the range carries no usable bound, in
    which case the caller must not claim anything.
    """
    introduced = (row.get("introduced") or "").strip()
    fixed = (row.get("fixed") or "").strip()
    last_affected = (row.get("last_affected") or "").strip()
    # NVD expresses lower bounds both inclusively and exclusively; OSV only
    # ever does the former, so this is CPE-specific.
    introduced_excl = (row.get("introduced_excluding") or "").strip()

    if not (introduced or fixed or last_affected or introduced_excl):
        return None

    cmp_fn = lambda a, b: vercmp.compare(ecosystem, a, b)  # noqa: E731

    if introduced_excl and cmp_fn(installed, introduced_excl) <= 0:
        return False
    if introduced and cmp_fn(installed, introduced) < 0:
        return False
    if fixed:
        # Half-open interval: [introduced, fixed). Installing the fixed version
        # is the whole point, so it must not match.
        return cmp_fn(installed, fixed) < 0
    if last_affected:
        return cmp_fn(installed, last_affected) <= 0
    # Only an "introduced" bound: affected from here on.
    return True


def cpe_candidate_keys(component: dict) -> List[str]:
    """The (vendor, product) keys this component might be advised under in NVD.

    swinv generates several candidate CPEs per Windows component, permuting how
    the vendor string might be normalised ("Igor Pavlov" -> igor, igor_pavlov)
    and whether the version and architecture are part of the product name. They
    are guesses, and are treated as such: any finding they produce is capped at
    low confidence, because the *identity* is inferred even when the version
    comparison is exact.
    """
    cpes = component.get("cpes") or ()
    if isinstance(cpes, str):
        cpes = [cpes]
    keys = []
    for c in cpes:
        k = feedlib.cpe_key(c)
        if k and k not in keys:
            keys.append(k)
    return keys


def _candidate_names(component: dict) -> List[str]:
    """Every package name this component might be advised under.

    Debian and RPM advisories are keyed on the SOURCE package, while an
    inventory reports the BINARY package: ``libssl3`` is advised as ``openssl``.
    swinv does not currently emit the source package, so when it is absent the
    only candidate is the binary name and source-keyed advisories are missed.
    That gap is reported as reduced coverage rather than silently tolerated.
    """
    names = []
    for key in ("source_package", "name"):
        v = (component.get(key) or "").strip().lower()
        if v and v not in names:
            names.append(v)
    return names


def primary_path(component: dict) -> str:
    """The install path this finding is about.

    swinv sorts and unions locations, so the first entry is stable across runs
    for a given install. Including it in a finding's identity is what makes it
    possible to say "the copy of lodash under /srv/app was upgraded" rather
    than collapsing every copy on the host into one row.
    """
    path = component.get("path")
    if path:
        return path if isinstance(path, str) else str(path)
    locations = component.get("locations") or ()
    if isinstance(locations, str):
        return locations
    return locations[0] if locations else ""


def finding_key(component: dict, vulnerability_id: str) -> str:
    """A stable identity for one finding, across scans.

    Deliberately excludes the installed version. The point of a finding's
    identity is to survive the package being upgraded, because that is exactly
    the transition worth reporting: same key, higher version, no longer
    matching means *mitigated*. Including the version would make every upgrade
    look like one finding vanishing and an unrelated one appearing.

    ``vulnerability_id`` is the CVE where one exists, not the advisory id, for
    the same reason: which advisory happens to win the authority contest can
    change between runs as feeds are added, and the identity of "this package
    is exposed to this CVE" must not change with it.
    """
    parts = [
        (component.get("hostname") or "").lower(),
        component.get("scope_id") or "",
        (component.get("type") or "").lower(),
        (component.get("name") or "").lower(),
        primary_path(component),
        vulnerability_id,
    ]
    return hashlib.sha1("\x1f".join(parts).encode("utf-8")).hexdigest()[:20]


def match_component(
    component: dict,
    ranges: Sequence[dict],
    notaffected: Sequence[dict] = (),
) -> List[dict]:
    """Match one installed component against its candidate ranges.

    ``ranges`` and ``notaffected`` must already be narrowed to rows whose
    (ecosystem, package) matches the component; this function applies release
    scoping, version comparison and precedence, not candidate selection.
    """
    ecosystem = (component.get("type") or "").strip().lower()
    installed = (component.get("version") or "").strip()
    if not installed:
        return []

    # Advisory ids the vendor has explicitly cleared for this package/release.
    cleared = set()
    for row in notaffected:
        if _distro_matches(component, row):
            cleared.add(row.get("advisory_id"))

    try:
        vercmp.comparator_for(ecosystem)
        have_comparator = True
    except vercmp.UnknownEcosystem:
        have_comparator = False
    installed_parses = vercmp.parses(ecosystem, installed)

    best: Dict[str, dict] = {}

    for row in ranges:
        advisory_id = row.get("advisory_id") or ""
        if not advisory_id:
            continue

        authority = authority_for(row)

        if authority == AUTHORITY_DISTRO and not _distro_matches(component, row):
            continue

        # An upstream range cannot settle a distro package: the distro version
        # string is not comparable to the upstream one, and a backport keeps the
        # upstream number unchanged. Record it as informational only.
        #
        # This covers both a native distro package and a language package the
        # distribution installed -- the latter is reported by its upstream
        # version, so it looks like a plain PyPI/npm package until you notice
        # where it lives on disk.
        upstream_claim_about_distro_pkg = (
            (ecosystem in DISTRO_TYPES or distro_managed_language_package(component))
            and authority < AUTHORITY_DISTRO
        )

        verdict = _in_range(ecosystem, installed, row)
        if verdict is None or verdict is False:
            continue

        if advisory_id in cleared:
            continue

        # Did the ecosystem's own rules actually parse both sides, or did the
        # comparator quietly fall back to the generic heuristic? A guess that
        # is reported as fact is worse than no finding at all.
        bounds = [b for b in (row.get("introduced"), row.get("fixed"),
                              row.get("last_affected")) if b and b != "0"]
        compared_properly = (
            installed_parses and all(vercmp.parses(ecosystem, b) for b in bounds)
        )

        # Only a row we reached through the CPE pseudo-ecosystem represents an
        # inferred identity. A deb matched by its real package name against an
        # NVD range is not that case, even though the range came from NVD --
        # there the backport caveat below is the accurate and more specific
        # explanation, so it must be tested first.
        is_cpe_identity = row.get("ecosystem") == feedlib.CPE_ECOSYSTEM

        confidence = "high"
        reason = ""
        if upstream_claim_about_distro_pkg:
            confidence = "informational"
            reason = (
                "upstream range for a package the distribution installed and "
                "maintains; the vendor may have backported the fix without "
                "changing the upstream version. Check the matching "
                + (ecosystem if ecosystem in DISTRO_TYPES else "distro")
                + " package instead."
            )
        elif is_cpe_identity:
            # The version comparison may be exact, but the component was tied to
            # this advisory through a CPE generated from a display name. That
            # identity is a guess, so the finding is a lead to verify rather
            # than a fact to report.
            confidence = "low"
            reason = ("matched through a generated CPE rather than a package "
                      "record, so the product identity is inferred")
        elif not have_comparator:
            confidence = "low"
            reason = f"no version comparator for ecosystem {ecosystem!r}"
        elif not compared_properly:
            confidence = "low"
            reason = (
                f"version strings are not valid {ecosystem} versions, so the "
                f"comparison fell back to a heuristic"
            )
        elif ecosystem in vercmp.HEURISTIC_TYPES:
            confidence = "low"
            reason = "component identity is inferred from a binary, not a package record"

        vulnerability_id = row.get("cve_id") or advisory_id
        finding = {
            "finding_key": finding_key(component, vulnerability_id),
            "path": primary_path(component),
            "advisory_id": advisory_id,
            "cve_id": row.get("cve_id") or advisory_id,
            "package": component.get("name"),
            "ecosystem": ecosystem,
            "installed_version": installed,
            "fixed_version": row.get("fixed") or "",
            "introduced_version": row.get("introduced") or "",
            "last_affected": row.get("last_affected") or "",
            "match_authority": AUTHORITY_NAMES[authority],
            "match_method": "distro-advisory" if authority == AUTHORITY_DISTRO
                            else ("cpe" if authority == AUTHORITY_NVD else "purl"),
            "distro": row.get("distro") or "",
            "distro_release": row.get("distro_release") or "",
            "feed_source": row.get("feed_source") or "",
            "confidence": confidence,
            "confidence_reason": reason,
            "_authority_rank": authority,
        }

        # Collapse to one finding per vulnerability, not per advisory record.
        # OSV routinely carries several advisories describing the same CVE -- a
        # GHSA record and a PYSEC record for one PyPI flaw, for instance -- and
        # a distro will publish its own alongside them. They are one thing to
        # fix, so they are one finding; reporting three is how a fleet appears
        # to have three times the vulnerabilities it has.
        dedup_key = vulnerability_id

        prev = best.get(dedup_key)
        if prev is None or authority > prev["_authority_rank"]:
            if prev is not None:
                # Preserve the losing advisory's id so the evidence trail is
                # not lost when a higher authority wins.
                finding["also_reported_as"] = sorted(
                    set(prev.get("also_reported_as", []))
                    | {prev["advisory_id"]}
                    - {finding["advisory_id"]}
                )
            best[dedup_key] = finding
        elif prev["advisory_id"] != advisory_id:
            prev["also_reported_as"] = sorted(
                set(prev.get("also_reported_as", [])) | {advisory_id}
            )

    out = []
    for finding in best.values():
        finding.pop("_authority_rank", None)
        out.append(finding)
    out.sort(key=lambda f: (f["cve_id"], f["package"]))
    return out


def suppressed(finding: dict, component: dict, suppressions: Iterable[dict], now: float) -> bool:
    """Has an operator accepted this risk, and is that acceptance still valid?"""
    for s in suppressions:
        if s.get("advisory_id") not in ("", None, finding["advisory_id"]):
            continue
        if s.get("package") not in ("", None, finding["package"]):
            continue
        host = s.get("hostname")
        if host not in ("", None, component.get("hostname")):
            continue
        expires = s.get("expires_at")
        if expires:
            try:
                if float(expires) < now:
                    continue
            except (TypeError, ValueError):
                pass
        return True
    return False
