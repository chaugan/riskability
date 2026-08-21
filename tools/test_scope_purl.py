#!/usr/bin/env python3
"""Regression tests for defects found against real swinv inventory.

Every case here comes from an actual host scan, not from imagination. They are
the ones that produced wrong answers before being fixed, so they are the ones
most worth keeping honest.

Run:  python3 tools/test_scope_purl.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app" / "riskability" / "bin"))

from riskability import match, purl, scope, vercmp  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}" + (f" :: {detail}" if detail else ""))
        FAILURES.append(name)


def main() -> int:
    print("PURL source-package recovery")

    p = purl.parse(
        "pkg:deb/ubuntu/libssl3t64@3.5.5-1ubuntu3.3?arch=amd64"
        "&distro=ubuntu-26.04&upstream=openssl"
    )
    check("libssl3t64 resolves to source package openssl",
          p.get("source_package") == "openssl", f"got {p.get('source_package')!r}")
    check("distro qualifier splits into name and release",
          (p.get("distro"), p.get("distro_release")) == ("ubuntu", "26.04"),
          f"got {p.get('distro')!r}/{p.get('distro_release')!r}")

    # deb versions contain percent-encoded '+' that a naive split mangles.
    p = purl.parse("pkg:deb/debian/bash@5.2.15-2%2Bb7?arch=amd64&distro=debian-12")
    check("percent-encoded version decodes to 5.2.15-2+b7",
          p.get("version") == "5.2.15-2+b7", f"got {p.get('version')!r}")

    p = purl.parse("pkg:golang/golang.org/x/crypto@v0.23.0")
    check("multi-segment Go namespace is preserved",
          p.get("namespace") == "golang.org/x" and p.get("name") == "crypto",
          f"got {p.get('namespace')!r}/{p.get('name')!r}")

    p = purl.parse("pkg:npm/%40types/node@20.1.0")
    check("scoped npm namespace decodes to @types",
          p.get("namespace") == "@types", f"got {p.get('namespace')!r}")

    check("a non-PURL string yields nothing rather than garbage",
          purl.parse("not a purl") == {} and purl.parse("") == {})

    print("root/scope classification")

    for path, want_kind, want_release in [
        ("/usr/share/doc/libssl3t64/copyright", scope.SCOPE_HOST, ""),
        ("/var/lib/dpkg/status", scope.SCOPE_HOST, ""),
        ("/snap/core18/2999/usr/share/snappy/dpkg.yaml", scope.SCOPE_SNAP, "18.04"),
        ("/snap/core20/2866/usr/share/snappy/dpkg.yaml", scope.SCOPE_SNAP, "20.04"),
        ("/snap/gnome-3-28-1804/198/usr/share/doc/x", scope.SCOPE_SNAP, "18.04"),
        ("/var/lib/docker/overlay2/a/diff/var/lib/dpkg/status", scope.SCOPE_CONTAINER, ""),
        ("/opt/src/testdata/rootfs/var/lib/dpkg/status", scope.SCOPE_NESTED, ""),
    ]:
        kind, _, release = scope.classify(path)
        check(f"{path[:46]:<46} -> {want_kind}",
              kind == want_kind and release == want_release,
              f"got {kind}/{release!r}")

    print("host identity is not applied to other roots")

    # Real case: a Debian 12 openssl inside an unpacked rootfs on an Ubuntu
    # host. Syft normally omits distro= for nested roots, but where one
    # component's evidence spans two roots the merge leaves the HOST's
    # qualifier attached to a foreign package, which would match it against
    # Ubuntu advisories. Rare (3 of 14,349 on the measured host) but wrong.
    nested = {
        "name": "openssl", "version": "3.0.11-1~deb12u2", "type": "deb",
        "purl": "pkg:deb/ubuntu/openssl@3.0.11-1~deb12u2?arch=amd64&distro=ubuntu-26.04",
        "locations": ["/opt/code/swinv/testdata/rootfs/var/lib/dpkg/status"],
        "os_id": "ubuntu", "os_version_id": "26.04",
    }
    prepared = match.prepare_component(nested)
    check("a nested root does not inherit the host's distro",
          prepared["os_id"] == "" and prepared["os_version_id"] == "",
          f"got {prepared['os_id']!r}/{prepared['os_version_id']!r}")

    ubuntu_advisory = {
        "advisory_id": "CVE-2025-15467", "cve_id": "CVE-2025-15467",
        "ecosystem": "deb", "package": "openssl", "fixed": "3.5.5-1ubuntu1",
        "distro": "ubuntu", "distro_release": "26.04", "feed_source": "osv:Ubuntu",
    }
    check("an Ubuntu advisory does not match a Debian package in a nested root",
          not match.match_component(prepared, [ubuntu_advisory]),
          f"got {match.match_component(prepared, [ubuntu_advisory])}")

    # A base snap keeps its own release, so it can still be matched correctly.
    snap_pkg = {
        "name": "openssl", "version": "1.1.1-1ubuntu2.1~18.04.23+esm7", "type": "deb",
        "locations": ["/snap/core18/2999/usr/share/snappy/dpkg.yaml"],
        "os_id": "ubuntu", "os_version_id": "26.04",
    }
    prepared_snap = match.prepare_component(snap_pkg)
    check("a core18 snap is treated as Ubuntu 18.04, not the host's 26.04",
          prepared_snap["os_id"] == "ubuntu" and prepared_snap["os_version_id"] == "18.04",
          f"got {prepared_snap['os_id']!r}/{prepared_snap['os_version_id']!r}")
    check("the snap root is labelled for the operator",
          prepared_snap["scope"] == scope.SCOPE_SNAP
          and prepared_snap["scope_id"] == "snap:core18")

    # A host package must keep working.
    host_pkg = {
        "name": "libssl3t64", "version": "3.5.5-1ubuntu3.3", "type": "deb",
        "purl": "pkg:deb/ubuntu/libssl3t64@3.5.5-1ubuntu3.3?arch=amd64"
                "&distro=ubuntu-26.04&upstream=openssl",
        "locations": ["/usr/share/doc/libssl3t64/copyright"],
        "os_id": "ubuntu", "os_version_id": "26.04",
    }
    prepared_host = match.prepare_component(host_pkg)
    check("a host package keeps its distro and gains its source package",
          prepared_host["os_id"] == "ubuntu"
          and prepared_host["os_version_id"] == "26.04"
          and prepared_host["source_package"] == "openssl")
    check("the source package is offered as a match candidate",
          "openssl" in match._candidate_names(prepared_host))

    print("Go toolchain versions")

    check("go1.26.6 is newer than 1.4.3, not older",
          vercmp.go_compare("go1.26.6", "1.4.3") > 0)
    check("go1.25.0 is older than 1.25.6",
          vercmp.go_compare("go1.25.0", "1.25.6") < 0)
    stdlib = {"name": "stdlib", "version": "go1.26.6", "type": "go-module"}
    ancient = {
        "advisory_id": "CVE-2015-5739", "cve_id": "CVE-2015-5739",
        "ecosystem": "go-module", "package": "stdlib", "fixed": "1.4.3",
        "feed_source": "osv:Go",
    }
    check("a modern Go toolchain is not flagged for a 2015 stdlib CVE",
          not match.match_component(stdlib, [ancient]),
          f"got {match.match_component(stdlib, [ancient])}")

    print("placeholder versions")

    for bad in ("unknown", "UNKNOWN", "", "none", "n/a"):
        check(f"deb version {bad!r} is not treated as comparable",
              not vercmp.parses("deb", bad))
    check("a real deb version still parses", vercmp.parses("deb", "1:2.17.1-1ubuntu0.3"))

    unknown_git = {
        "name": "git", "version": "unknown", "type": "deb",
        "os_id": "ubuntu", "os_version_id": "18.04",
    }
    git_adv = {
        "advisory_id": "CVE-2018-17456", "cve_id": "CVE-2018-17456",
        "ecosystem": "deb", "package": "git", "fixed": "1:2.17.1-1ubuntu0.3",
        "distro": "ubuntu", "distro_release": "18.04", "feed_source": "osv:Ubuntu",
    }
    found = match.match_component(unknown_git, [git_adv])
    check("a component with an unknown version is never high confidence",
          all(f["confidence"] != "high" for f in found), f"got {found}")


    print("OSV Ubuntu release and product-line parsing")

    from riskability import feed as feedlib
    for eco, want in [
        ("Ubuntu:24.04:LTS", ("deb", "ubuntu", "24.04", "")),
        ("Ubuntu:Pro:18.04:LTS", ("deb", "ubuntu", "18.04", "pro")),
        ("Ubuntu:Pro:FIPS-updates:20.04:LTS", ("deb", "ubuntu", "20.04", "pro:fips-updates")),
        ("Ubuntu:25.10", ("deb", "ubuntu", "25.10", "")),
        ("Debian:12", ("deb", "debian", "12", "")),
        ("Alpine:v3.20", ("apk", "alpine", "3.20", "")),
        ("npm", ("npm", "", "", "")),
    ]:
        got = feedlib.split_osv_ecosystem(eco)
        check(f"{eco} parses to {want}", got == want, f"got {got}")

    # A 24.04 host must not match a 24.10 advisory just because both start "24".
    host_2404 = {"name": "curl", "version": "8.5.0-2ubuntu10", "type": "deb",
                 "os_id": "ubuntu", "os_version_id": "24.04"}
    adv_2410 = {"advisory_id": "CVE-X", "cve_id": "CVE-X", "ecosystem": "deb",
                "package": "curl", "fixed": "8.9.1-2", "distro": "ubuntu",
                "distro_release": "24.10", "feed_source": "osv:Ubuntu"}
    check("Ubuntu 24.04 host is not matched by a 24.10 advisory",
          not match.match_component(host_2404, [adv_2410]),
          f"got {match.match_component(host_2404, [adv_2410])}")

    adv_2404 = dict(adv_2410, distro_release="24.04")
    check("Ubuntu 24.04 host IS matched by a 24.04 advisory",
          len(match.match_component(host_2404, [adv_2404])) == 1)

    # RHEL advisories legitimately key on the major version.
    rhel = {"name": "openssl", "version": "1:3.0.7-27.el9", "type": "rpm",
            "os_id": "rhel", "os_version_id": "9.4"}
    rhel_adv = {"advisory_id": "CVE-Y", "cve_id": "CVE-Y", "ecosystem": "rpm",
                "package": "openssl", "fixed": "1:3.0.7-28.el9", "distro": "red hat",
                "distro_release": "9", "feed_source": "osv:Red Hat"}
    check("RHEL 9.4 host is still matched by a major-version 9 advisory",
          len(match.match_component(rhel, [rhel_adv])) == 1)

    print("Ubuntu product lines")

    pro_adv = {"advisory_id": "CVE-Z", "cve_id": "CVE-Z", "ecosystem": "deb",
               "package": "openssl", "fixed": "1.1.1f-1ubuntu2.24+esm5",
               "distro": "ubuntu", "distro_release": "20.04",
               "distro_variant": "pro", "feed_source": "osv:Ubuntu"}
    plain_2004 = {"name": "openssl", "version": "1.1.1f-1ubuntu2.20", "type": "deb",
                  "os_id": "ubuntu", "os_version_id": "20.04"}
    esm_2004 = {"name": "openssl", "version": "1.1.1f-1ubuntu2.24+esm3", "type": "deb",
                "os_id": "ubuntu", "os_version_id": "20.04"}
    check("a Pro/ESM advisory does not apply to a non-ESM package",
          not match.match_component(plain_2004, [pro_adv]),
          f"got {match.match_component(plain_2004, [pro_adv])}")
    check("a Pro/ESM advisory DOES apply to a +esm package",
          len(match.match_component(esm_2004, [pro_adv])) == 1,
          f"got {match.match_component(esm_2004, [pro_adv])}")

    fips_adv = dict(pro_adv, distro_variant="pro:fips-updates")
    check("a FIPS advisory does not apply to an ordinary ESM package",
          not match.match_component(esm_2004, [fips_adv]))

    unknown_variant = dict(pro_adv, distro_variant="nvidia-bluefield")
    check("an unrecognised product line is never assumed to apply",
          not match.match_component(esm_2004, [unknown_variant]))


    print("MITRE ATT&CK mapping")

    from riskability import feed as feedlib2
    # MITRE writes technique names containing colons; stopping at the first one
    # truncates them and makes distinct techniques collide under one label.
    csv_text = ("'ID,Name,Taxonomy Mappings\n"
                "1,Test,\"TAXONOMY NAME:ATTACK:ENTRY ID:1574.010:ENTRY NAME:"
                "Hijack Execution Flow: ServicesFile Permissions Weakness::\"\n")
    parsed = feedlib2.parse_capec_attack(csv_text)
    check("an ATT&CK entry name containing a colon is not truncated",
          parsed.get("1", [{}])[0].get("name")
          == "Hijack Execution Flow: ServicesFile Permissions Weakness",
          f"got {parsed}")
    check("the technique id gains its T prefix",
          parsed.get("1", [{}])[0].get("technique") == "T1574.010")

    # Several taxonomies share the field; only ATT&CK entries are wanted.
    multi = ("'ID,Name,Taxonomy Mappings\n"
             "2,Test,\"TAXONOMY NAME:WASC:ENTRY ID:07:ENTRY NAME:Buffer Overflow::::"
             "TAXONOMY NAME:ATTACK:ENTRY ID:1027:ENTRY NAME:Obfuscated Files or Information::\"\n")
    parsed = feedlib2.parse_capec_attack(multi)
    got = parsed.get("2", [])
    check("non-ATT&CK taxonomies are ignored",
          len(got) == 1 and got[0]["technique"] == "T1027"
          and got[0]["name"] == "Obfuscated Files or Information",
          f"got {got}")

    # The CWE -> ATT&CK join keeps the CAPEC that justified it.
    rows = feedlib2.build_attack_rows({"CWE-20": ["2"]}, parsed)
    check("the justifying CAPEC is carried through",
          rows and rows[0]["via_capec"] == ["2"] and rows[0]["cwe"] == "CWE-20",
          f"got {rows}")


    # MITRE's own CAPEC records disagree about technique names; one technique
    # must still render as one row.
    inconsistent = {
        "1": [{"technique": "T1552.004", "name": "Unsecure Credentials: Private Keys"}],
        "2": [{"technique": "T1552.004", "name": "Unsecured Credentials: Private Keys"}],
        "3": [{"technique": "T1552.004", "name": "Unsecured Credentials: Private Keys"}],
        "4": [{"technique": "T1036.006", "name": "Masquerading:Space after Filename"}],
        "5": [{"technique": "T1036.006", "name": "Masquerading: Space after Filename"}],
    }
    rows = feedlib2.build_attack_rows({"CWE-1": list(inconsistent)}, inconsistent)
    names = {r["technique"]: r["technique_name"] for r in rows}
    check("a typo'd variant loses to the majority spelling",
          names.get("T1552.004") == "Unsecured Credentials: Private Keys",
          f"got {names.get('T1552.004')!r}")
    check("colon spacing is normalised so variants collapse",
          names.get("T1036.006") == "Masquerading: Space after Filename",
          f"got {names.get('T1036.006')!r}")
    check("one technique yields exactly one row per CWE",
          len(rows) == 2, f"got {len(rows)}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("all scope/purl regression tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
