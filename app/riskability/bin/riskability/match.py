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

from typing import Dict, Iterable, List, Optional, Sequence

from . import vercmp

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

    row_release = (row.get("distro_release") or "").strip()
    if not row_release:
        return True
    comp_release = (component.get("os_version_id") or "").strip()
    if not comp_release:
        return False
    if comp_release == row_release:
        return True
    # Red Hat-family advisories are often keyed on the major version only.
    return comp_release.split(".")[0] == row_release.split(".")[0]


def _in_range(ecosystem: str, installed: str, row: dict) -> Optional[bool]:
    """Is ``installed`` inside this affected range?

    Returns True, False, or None when the range carries no usable bound, in
    which case the caller must not claim anything.
    """
    introduced = (row.get("introduced") or "").strip()
    fixed = (row.get("fixed") or "").strip()
    last_affected = (row.get("last_affected") or "").strip()

    if not (introduced or fixed or last_affected):
        return None

    cmp_fn = lambda a, b: vercmp.compare(ecosystem, a, b)  # noqa: E731

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
        upstream_claim_about_distro_pkg = (
            ecosystem in DISTRO_TYPES and authority < AUTHORITY_DISTRO
        )

        verdict = _in_range(ecosystem, installed, row)
        if verdict is None or verdict is False:
            continue

        if advisory_id in cleared:
            continue

        confidence = "high"
        reason = ""
        if upstream_claim_about_distro_pkg:
            confidence = "informational"
            reason = (
                "upstream range for a distribution package; the vendor may have "
                "backported the fix without changing the upstream version"
            )
        elif not have_comparator:
            confidence = "low"
            reason = f"no version comparator for ecosystem {ecosystem!r}"
        elif ecosystem in vercmp.HEURISTIC_TYPES:
            confidence = "low"
            reason = "component identity is inferred from a binary, not a package record"

        finding = {
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

        # Keep only the highest-authority claim per advisory. A distro "fixed in
        # 3.0.13-0ubuntu3.4" must silence the upstream "< 3.0.14".
        prev = best.get(advisory_id)
        if prev is None or authority > prev["_authority_rank"]:
            best[advisory_id] = finding

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
