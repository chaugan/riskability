#!/usr/bin/env python3
"""Matcher behaviour tests, centred on the cases that produce false positives.

Run:  python3 tools/test_match.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app" / "riskability" / "bin"))

from riskability import match  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}" + (f" :: {detail}" if detail else ""))
        FAILURES.append(name)


UBUNTU_OPENSSL = {
    "hostname": "web-01",
    "name": "openssl",
    "version": "3.0.13-0ubuntu3.4",
    "type": "deb",
    "os_id": "ubuntu",
    "os_version_id": "24.04",
    "purl": "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04",
}

# What NVD says: everything below upstream 3.0.14 is vulnerable.
UPSTREAM_RANGE = {
    "advisory_id": "CVE-2024-9999",
    "cve_id": "CVE-2024-9999",
    "ecosystem": "deb",
    "package": "openssl",
    "introduced": "",
    "fixed": "3.0.14",
    "feed_source": "nvd",
    "range_type": "CPE",
}

# What Ubuntu says: fixed in this exact package version.
UBUNTU_FIXED_RANGE = {
    "advisory_id": "CVE-2024-9999",
    "cve_id": "CVE-2024-9999",
    "ecosystem": "deb",
    "package": "openssl",
    "introduced": "",
    "fixed": "3.0.13-0ubuntu3.4",
    "distro": "ubuntu",
    "distro_release": "24.04",
    "feed_source": "osv",
}


def main() -> int:
    print("backport precedence")

    # The flagship case. The host IS patched. A distro advisory saying "fixed in
    # 3.0.13-0ubuntu3.4" must win over NVD's "< 3.0.14" and produce no finding.
    findings = match.match_component(UBUNTU_OPENSSL, [UPSTREAM_RANGE, UBUNTU_FIXED_RANGE])
    check(
        "patched Ubuntu openssl produces no high-confidence finding",
        not [f for f in findings if f["confidence"] == "high"],
        f"got {findings}",
    )

    # With only the NVD claim available, we must not assert vulnerability on a
    # distro package -- but we must not silently hide it either.
    findings = match.match_component(UBUNTU_OPENSSL, [UPSTREAM_RANGE])
    check(
        "NVD-only claim about a deb is downgraded, not asserted",
        len(findings) == 1 and findings[0]["confidence"] == "informational",
        f"got {findings}",
    )

    # An unpatched host must still be caught.
    unpatched = dict(UBUNTU_OPENSSL, version="3.0.13-0ubuntu3.1")
    findings = match.match_component(unpatched, [UBUNTU_FIXED_RANGE])
    check(
        "unpatched Ubuntu openssl IS reported",
        len(findings) == 1 and findings[0]["confidence"] == "high",
        f"got {findings}",
    )

    print("release scoping")

    # A 22.04 advisory says nothing about a 24.04 host.
    other_release = dict(UBUNTU_FIXED_RANGE, distro_release="22.04", fixed="3.0.2-0ubuntu1.15")
    findings = match.match_component(UBUNTU_OPENSSL, [other_release])
    check(
        "advisory for a different Ubuntu release is not applied",
        not findings,
        f"got {findings}",
    )

    # Red Hat advisories are keyed on the major version.
    rhel_host = {
        "hostname": "rh-01", "name": "openssl", "version": "1:3.0.7-27.el9",
        "type": "rpm", "os_id": "rhel", "os_version_id": "9.4",
    }
    rhel_range = {
        "advisory_id": "CVE-2024-1111", "cve_id": "CVE-2024-1111",
        "ecosystem": "rpm", "package": "openssl",
        "fixed": "1:3.0.7-28.el9", "distro": "red hat", "distro_release": "9",
        "feed_source": "osv",
    }
    findings = match.match_component(rhel_host, [rhel_range])
    check(
        "RHEL major-version advisory applies to a 9.4 host",
        len(findings) == 1 and findings[0]["confidence"] == "high",
        f"got {findings}",
    )

    print("vendor not-affected")

    notaffected = [{
        "advisory_id": "CVE-2024-9999", "ecosystem": "deb", "package": "openssl",
        "distro": "ubuntu", "distro_release": "24.04", "status": "not-affected",
    }]
    findings = match.match_component(unpatched, [UBUNTU_FIXED_RANGE], notaffected)
    check(
        "vendor 'not affected' suppresses an otherwise-matching range",
        not findings,
        f"got {findings}",
    )

    print("range semantics")

    npm_comp = {"hostname": "h", "name": "lodash", "version": "4.17.20", "type": "npm"}
    npm_range = {
        "advisory_id": "GHSA-x", "cve_id": "CVE-2021-23337", "ecosystem": "npm",
        "package": "lodash", "introduced": "0", "fixed": "4.17.21",
        "feed_source": "osv",
    }
    findings = match.match_component(npm_comp, [npm_range])
    check("npm below fixed version is reported", len(findings) == 1, f"got {findings}")

    fixed_comp = dict(npm_comp, version="4.17.21")
    findings = match.match_component(fixed_comp, [npm_range])
    check("installing exactly the fixed version clears it", not findings, f"got {findings}")

    below_introduced = dict(npm_comp, version="3.0.0")
    r = dict(npm_range, introduced="4.0.0")
    findings = match.match_component(below_introduced, [r])
    check("version below 'introduced' is not affected", not findings, f"got {findings}")

    last_affected = {
        "advisory_id": "OSV-y", "cve_id": "CVE-2020-1", "ecosystem": "npm",
        "package": "lodash", "introduced": "", "fixed": "", "last_affected": "4.17.20",
        "feed_source": "osv",
    }
    findings = match.match_component(npm_comp, [last_affected])
    check("last_affected is inclusive", len(findings) == 1, f"got {findings}")
    findings = match.match_component(fixed_comp, [last_affected])
    check("version above last_affected is clear", not findings, f"got {findings}")

    print("degradation, not invention")

    empty_range = {
        "advisory_id": "OSV-z", "cve_id": "CVE-2020-2", "ecosystem": "npm",
        "package": "lodash", "introduced": "", "fixed": "", "last_affected": "",
        "feed_source": "osv",
    }
    findings = match.match_component(npm_comp, [empty_range])
    check("a range with no bounds yields no finding", not findings, f"got {findings}")

    no_version = dict(npm_comp, version="")
    findings = match.match_component(no_version, [npm_range])
    check("a component with no version yields no finding", not findings, f"got {findings}")

    binary_comp = {
        "hostname": "h", "name": "some-vendor-tool", "version": "1.2.3", "type": "binary",
    }
    binary_range = {
        "advisory_id": "CVE-2024-2222", "cve_id": "CVE-2024-2222", "ecosystem": "binary",
        "package": "some-vendor-tool", "introduced": "", "fixed": "1.2.4",
        "feed_source": "nvd", "range_type": "CPE",
    }
    findings = match.match_component(binary_comp, [binary_range])
    check(
        "a CPE hit on an unmanaged binary is low confidence, not high",
        len(findings) == 1 and findings[0]["confidence"] == "low",
        f"got {findings}",
    )

    print("source-package keying")

    # Debian advises the binary libssl3 under its source package, openssl.
    libssl = {
        "hostname": "d-01", "name": "libssl3", "source_package": "openssl",
        "version": "3.0.11-1~deb12u2", "type": "deb",
        "os_id": "debian", "os_version_id": "12",
    }
    check(
        "source package is offered as a candidate name",
        match._candidate_names(libssl) == ["openssl", "libssl3"],
        f"got {match._candidate_names(libssl)}",
    )
    check(
        "without a source package only the binary name is available",
        match._candidate_names({"name": "libssl3"}) == ["libssl3"],
    )


    print("feed/host spelling mismatches")

    alpine_host = {
        "hostname": "a-01", "name": "apache2", "version": "2.4.54-r0",
        "type": "apk", "os_id": "alpine", "os_version_id": "3.20",
    }
    alpine_range = {
        "advisory_id": "ALPINE-CVE-2006-20001", "cve_id": "CVE-2006-20001",
        "ecosystem": "apk", "package": "apache2", "fixed": "2.4.55-r0",
        "distro": "alpine", "distro_release": "v3.20", "feed_source": "osv:Alpine",
    }
    findings = match.match_component(alpine_host, [alpine_range])
    check(
        "OSV 'v3.20' matches a host reporting '3.20'",
        len(findings) == 1 and findings[0]["confidence"] == "high",
        f"got {findings}",
    )

    patched_alpine = dict(alpine_host, version="2.4.55-r0")
    findings = match.match_component(patched_alpine, [alpine_range])
    check("patched Alpine package is clear", not findings, f"got {findings}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("all matcher tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
