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
    # host. Syft stamps the HOST's distro onto it, which would match it against
    # Ubuntu advisories.
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

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("all scope/purl regression tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
