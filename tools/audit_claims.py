#!/usr/bin/env python3
"""Recompute every quantitative claim made in the README and the portal page.

Written after a claim about swinv's handling of nested roots turned out to be a
generalisation from a single example. The point is that anything asserted in
user-facing documentation should be reproducible by running one command, rather
than remembered from a terminal scrollback.

Run:  python3 tools/audit_claims.py
"""

from __future__ import annotations

import collections
import json
import pathlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app" / "riskability" / "bin"))

from riskability import feed as feedlib   # noqa: E402
from riskability import match as matchlib  # noqa: E402
from riskability import purl as purllib    # noqa: E402
from riskability import scope as scopelib  # noqa: E402
from riskability import vercmp             # noqa: E402

# The checked-in fixtures, not absolute paths on one developer's machine.
# A script whose job is to let a reader verify the README's numbers is worth
# nothing if only one person can run it, and it pointed at two files outside
# the repository -- which is also how it came to report "0 of 501 Windows
# components carry a CPE" long after the collector had started emitting them:
# it was still reading the scan from before that changed.
LINUX = ROOT / "testdata" / "ndjson" / "linux-host-01.ndjson"
WINDOWS = ROOT / "testdata" / "ndjson" / "windows-host-01.ndjson"
BUNDLE = ROOT / "testdata" / "feeds" / "riskability-feed-full.tar.gz"

results = []


def claim(name, value, note=""):
    results.append((name, value, note))
    print(f"  {name:<52} {value}")
    if note:
        print(f"  {'':<52} {note}")


def load(path):
    """Read a swinv scan, whether it is a JSON document or an NDJSON stream.

    Returns the same shape either way, so callers keep using ["components"].
    A component record is the one carrying no record_type: heartbeats, exposure
    rows and container rows share the stream and are not components.
    """
    text = pathlib.Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") and "\n{" not in stripped[:4096]:
        return json.loads(text)
    components = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if not record.get("record_type"):
            components.append(record)
    return {"components": components}


def main() -> int:
    print("\n== comparators ==")
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "test_vercmp_differential.py")],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "pairs match" in line:
            claim(line.split(":")[0] + " pairs vs reference", line.split(":")[1].strip())

    print("\n== inventory ==")
    lin = load(LINUX)
    win = load(WINDOWS)
    lc, wc = lin["components"], win["components"]
    claim("linux components", len(lc))
    claim("windows components", len(wc))
    claim("total indexed from both hosts", len(lc) + len(wc))

    types = collections.Counter(c.get("type") for c in lc)
    claim("linux kernel modules", types["linux-kernel-module"])
    claim("kernel modules as share of host", f"{types['linux-kernel-module']*100/len(lc):.1f}%")

    win_purl = sum(1 for c in wc if c.get("purl"))
    win_cpe = sum(1 for c in wc if c.get("cpes"))
    claim("windows components with a purl", f"{win_purl} of {len(wc)}")
    claim("windows components with cpes", f"{win_cpe} of {len(wc)}")

    print("\n== filesystem roots ==")
    by_root = collections.Counter()
    mixed = 0
    nested_with_distro = 0
    nested_total = 0
    mixed_with_host_distro = 0
    for c in lc:
        locs = c.get("locations") or []
        if not locs:
            by_root["(no locations)"] += 1
            continue
        roots = {scopelib.classify(l)[1] or "host" for l in locs}
        if len(roots) > 1:
            mixed += 1
            p = purllib.parse(c.get("purl") or "")
            if p.get("qualifier_distro") == "ubuntu-26.04" and "host" in roots:
                mixed_with_host_distro += 1
            continue
        root = next(iter(roots))
        by_root[root] += 1
        if root != "host":
            nested_total += 1
            if purllib.parse(c.get("purl") or "").get("qualifier_distro"):
                nested_with_distro += 1
    nonhost = sum(n for r, n in by_root.items() if r not in ("host", "(no locations)"))
    claim("components wholly in a non-host root", nonhost)
    claim("  as share of host", f"{nonhost*100/len(lc):.1f}%")
    claim("  of those, carrying any distro= qualifier", nested_with_distro,
          "0 means swinv correctly omits it -- NOT a mislabelling bug")
    claim("components whose locations span >1 root", mixed)
    claim("  of those, carrying the host distro= AND a host path", mixed_with_host_distro)
    claim("distinct openssl deb components on the host",
          sum(1 for c in lc if c.get("name") == "openssl" and c.get("type") == "deb"))

    print("\n== placeholder versions ==")
    unknown = [c for c in lc if str(c.get("version", "")).lower() in ("unknown", "")]
    claim("components with UNKNOWN/empty version", len(unknown))
    ut = collections.Counter(c.get("type") for c in unknown)
    claim("  of which kernel modules", ut["linux-kernel-module"])
    claim("  of which matchable ecosystems",
          sum(n for t, n in ut.items() if t != "linux-kernel-module"))
    claim("dpkg: 'unknown' < '1:2.17.1-1ubuntu0.3'",
          vercmp.dpkg_compare("unknown", "1:2.17.1-1ubuntu0.3") < 0)
    claim("dpkg: 'unknown' < '2.0'", vercmp.dpkg_compare("unknown", "2.0") < 0,
          "False -- it sorts ABOVE a digit-leading version")

    if not BUNDLE.exists():
        print(f"\n(bundle {BUNDLE} missing; skipping feed claims)")
        return 0

    print("\n== feed bundle ==")
    manifest = feedlib.read_manifest(str(BUNDLE))
    size = os.path.getsize(BUNDLE)
    claim("bundle size", f"{size/1024/1024:.1f} MB")
    claim("advisories", f"{manifest['counts']['advisories']:,}")
    claim("affected ranges", f"{manifest['counts']['ranges']:,}")
    claim("sources", ", ".join(s["name"] for s in manifest["sources"]))

    print("\n== source-package recovery (deb coverage) ==")
    ranges = collections.defaultdict(list)
    for row in feedlib.iter_member(str(BUNDLE), feedlib.RANGES_NAME):
        ranges[(row["ecosystem"], row["package"])].append(row)

    def deb_coverage(use_source_package: bool) -> int:
        n = 0
        for c in lc:
            if c.get("type") != "deb":
                continue
            comp = matchlib.prepare_component(c) if use_source_package else dict(c)
            if not use_source_package:
                comp.pop("source_package", None)
            names = [comp.get("name", "").lower()]
            if use_source_package and comp.get("source_package"):
                names.insert(0, comp["source_package"].lower())
            if any(ranges.get(("deb", nm)) for nm in names if nm):
                n += 1
        return n

    before, after = deb_coverage(False), deb_coverage(True)
    claim("deb components matched by binary name only", before)
    claim("deb components matched using the source package", after)
    claim("  improvement", f"{after/before:.2f}x" if before else "n/a")

    print("\n== one CVE, several advisories ==")
    per_cve = collections.Counter()
    for (eco, pkg), rows in ranges.items():
        seen = collections.defaultdict(set)
        for r in rows:
            if r.get("cve_id", "").startswith("CVE-"):
                seen[r["cve_id"]].add(r["advisory_id"])
        for cve, advs in seen.items():
            if len(advs) > 1:
                per_cve[len(advs)] += 1
    total_multi = sum(per_cve.values())
    claim("(package, CVE) pairs described by >1 advisory", f"{total_multi:,}")
    if per_cve:
        claim("  worst multiplicity", max(per_cve))

    print("\n== Go toolchain false positives (the pre-fix behaviour) ==")
    stdlib = [c for c in lc if c.get("name") == "stdlib" and c.get("type") == "go-module"]
    claim("stdlib components on the host", len(stdlib))
    bad = 0
    for c in stdlib:
        for row in ranges.get(("go-module", "stdlib"), ()):
            fixed = row.get("fixed") or ""
            if not fixed:
                continue
            correct = vercmp.go_compare(c["version"], fixed) < 0
            legacy = vercmp.generic_compare(c["version"], fixed) < 0
            if legacy and not correct:
                bad += 1
    claim("stdlib findings the old comparator invented", bad,
          "each was reported at high confidence before the fix")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
