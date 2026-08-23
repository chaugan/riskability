#!/usr/bin/env bash
#
# Build the self-contained feed builder that the app offers for download.
#
# The admin page used to offer build-feed.sh / build-feed.ps1 on their own,
# which was useless: both are wrappers around a riskability-feed tool that a
# person downloading from Splunkbase has no way to obtain. Every download
# failed with "riskability-feed not found".
#
# This produces one archive that works on its own, needing nothing but Python 3:
#
#   riskability-feedbuilder.zip
#     riskability-feed.pyz   a zipapp holding the feed-building code
#     build-feed.sh          convenience wrapper (Linux/macOS)
#     build-feed.ps1         convenience wrapper (Windows)
#     README.txt
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATIC="$ROOT/app/riskability/appserver/static/scripts"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# --- the zipapp ------------------------------------------------------------
APPDIR="$STAGE/pyz"
mkdir -p "$APPDIR/riskability"

# Only the modules the builder needs, and all of them are pure standard
# library, so the zipapp has no install step and no dependencies.
for m in __init__ feed build; do
  src="$ROOT/app/riskability/bin/riskability/$m.py"
  if [ -f "$src" ]; then cp "$src" "$APPDIR/riskability/$m.py"; fi
done
[ -f "$APPDIR/riskability/__init__.py" ] || : > "$APPDIR/riskability/__init__.py"

cat > "$APPDIR/__main__.py" <<'PYEOF'
"""riskability-feed - build an offline vulnerability bundle.

Run this on a machine with internet access, then carry the resulting file to
your air-gapped Splunk search head and import it on the Riskability
"Feed administration" page.

    python3 riskability-feed.pyz sources
    python3 riskability-feed.pyz build --out feed.tar.gz --ecosystem Ubuntu --kev --epss

Needs nothing but Python 3.8+. The app itself never reaches the network; this
is the piece that does, deliberately kept separate.
"""
import argparse
import sys

from riskability import build as buildlib


def cmd_sources(args):
    print("OSV ecosystem archives (https://osv.dev)\n")
    for eco, desc in buildlib.ECOSYSTEMS.items():
        size = ""
        if args.check:
            n = buildlib.head_size(buildlib.osv_url(eco))
            size = "unknown" if n is None else f"{n/1048576:.1f} MB"
        print(f"  {eco:<14} {size:>10}  {desc}")
    print("\nOther sources\n")
    print("  --nvd YEARS    NVD CPE ranges and CWE. Required for Windows estates,")
    print("                 which have no PURL. e.g. --nvd 2015-2026 or --nvd all")
    print("  --mitre        MITRE CWE -> CAPEC -> ATT&CK mapping")
    print("  --kev          CISA known-exploited catalogue")
    print("  --epss         FIRST exploitation-probability scores")
    print("")
    print("  --kev-file PATH   use a downloaded copy instead of fetching. CISA serves")
    print("                    KEV behind a CDN that refuses many datacentre ranges, so")
    print("                    this is often the only way to get it onto a build host.")
    print("  --epss-file PATH  same, for the EPSS csv or csv.gz")
    print("\nHosts contacted: " + ", ".join(buildlib.NETWORK_HOSTS))
    if not args.check:
        print("\n(pass --check to query live sizes)")
    return 0


def cmd_build(args):
    if not (args.ecosystem or args.nvd or args.mitre or args.kev or args.epss
            or args.kev_file or args.epss_file):
        print("error: choose at least one source (see 'sources')", file=sys.stderr)
        return 2
    try:
        manifest = buildlib.build_bundle(
            args.out,
            ecosystems=args.ecosystem or [],
            nvd=args.nvd, mitre=args.mitre, kev=args.kev, epss=args.epss,
            kev_file=args.kev_file, epss_file=args.epss_file,
            version=args.version,
            log=lambda m: print(m, file=sys.stderr),
        )
    except buildlib.BuildError as exc:
        print(f"\nbuild failed: {exc}", file=sys.stderr)
        return 1
    counts = manifest.get("counts", {})
    print(f"\nwrote {args.out}", file=sys.stderr)
    print(f"  size       {manifest.get('size_bytes', 0)/1048576:.1f} MB", file=sys.stderr)
    print(f"  advisories {counts.get('advisories', 0):,}", file=sys.stderr)
    print(f"  ranges     {counts.get('ranges', 0):,}", file=sys.stderr)
    print(f"  attack     {counts.get('attack', 0):,}", file=sys.stderr)
    print(f"  sha256     {manifest.get('sha256', '')}", file=sys.stderr)
    for w in manifest.get("warnings", []):
        print(f"  INCOMPLETE {w}", file=sys.stderr)
    print("\nImport it on the Riskability > Feed administration page.", file=sys.stderr)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="riskability-feed", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sources", help="list what can be fetched")
    s.add_argument("--check", action="store_true", help="query live sizes")
    s.set_defaults(func=cmd_sources)

    b = sub.add_parser("build", help="download feeds and write a bundle")
    b.add_argument("--out", required=True)
    b.add_argument("--ecosystem", action="append", help="repeatable")
    b.add_argument("--nvd", metavar="YEARS", default="")
    b.add_argument("--mitre", action="store_true")
    b.add_argument("--kev", action="store_true")
    b.add_argument("--epss", action="store_true")
    # CISA serves KEV behind a CDN that refuses whole datacentre ranges, so a
    # build host can be well connected and still never fetch it. Download it on
    # a workstation and pass the file.
    b.add_argument("--kev-file", dest="kev_file", default="", metavar="PATH",
                   help="use a downloaded known_exploited_vulnerabilities.json "
                        "instead of fetching it")
    b.add_argument("--epss-file", dest="epss_file", default="", metavar="PATH",
                   help="use a downloaded EPSS csv or csv.gz instead of fetching it")
    b.add_argument("--version", default="")
    b.set_defaults(func=cmd_build)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
PYEOF

python3 -m zipapp "$APPDIR" -o "$STAGE/riskability-feed.pyz" -p "/usr/bin/env python3"
chmod +x "$STAGE/riskability-feed.pyz"

# --- wrappers and readme ---------------------------------------------------
# The wrappers live here rather than under appserver/static, so the only thing
# the app can serve is the complete archive. They used to sit in static beside
# the zip, which meant a stale page -- or a stale browser cache -- could still
# hand someone a lone build-feed.ps1 that fails with "riskability-feed not
# found". A file that cannot work on its own should not be downloadable.
SRC="$ROOT/tools/feedbuilder"
cp "$SRC/build-feed.sh" "$STAGE/build-feed.sh"
cp "$SRC/build-feed.ps1" "$STAGE/build-feed.ps1"
chmod +x "$STAGE/build-feed.sh"

cat > "$STAGE/README.txt" <<'TXTEOF'
Riskability feed builder
========================

Builds an offline vulnerability bundle for the Riskability Splunk app.

Run this on a machine WITH internet access, then copy the resulting
.tar.gz to your Splunk search head and import it on the
Riskability > Feed administration page.

Requires Python 3.8 or later. Nothing else, and nothing to install.

PROFILES
--------
The two wrappers take the same three profiles, but spell them differently:
a positional flag on the shell script, a named parameter in PowerShell.

  Profile      Linux / macOS                 Windows
  ---------    ---------------------------   ---------------------------------
  Linux        ./build-feed.sh               .\build-feed.ps1 -FeedProfile Linux
  Windows      ./build-feed.sh --windows     .\build-feed.ps1
  Everything   ./build-feed.sh --everything  .\build-feed.ps1 -FeedProfile Everything

  Add the CVE encyclopaedia's source to any profile:

               ./build-feed.sh --with-cve-list
               .\build-feed.ps1 -WithCveList

  Linux        Ubuntu, Debian, Alpine, npm, PyPI, Go, Maven, plus CISA KEV,
               FIRST EPSS and the MITRE CWE -> ATT&CK mapping.
  Windows      All of the above plus NVD CPE data for 2015-2026. This is the
               default for the PowerShell script.
  Everything   Every distribution and ecosystem, and all NVD years. Much
               larger and much slower.

PowerShell also takes -OutDir <path> to choose where the bundle is written.

Or drive it directly:

  python3 riskability-feed.pyz sources
  python3 riskability-feed.pyz build --out feed.tar.gz \
      --ecosystem Ubuntu --ecosystem npm --kev --epss --mitre

Windows estates additionally need --nvd (e.g. --nvd 2015-2026): Windows
software is not installed by a package manager, so it carries no PURL and
only NVD's CPE data can assess it.

Outbound HTTPS is needed to:
  storage.googleapis.com  nvd.nist.gov  cwe.mitre.org
  capec.mitre.org         www.cisa.gov  epss.empiricalsecurity.com
TXTEOF

# Built with Python rather than zip(1), which is not installed everywhere, and
# with the executable bits set explicitly: a .pyz or .sh that unpacks
# non-executable is a confusing first experience on Linux and macOS.
python3 - "$STAGE" "$STATIC/riskability-feedbuilder.zip" <<'ZIPEOF'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
executable = {"riskability-feed.pyz", "build-feed.sh"}
os.makedirs(os.path.dirname(out), exist_ok=True)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for name in ("riskability-feed.pyz", "build-feed.sh", "build-feed.ps1", "README.txt"):
        path = os.path.join(stage, name)
        info = zipfile.ZipInfo.from_file(path, name)
        info.compress_type = zipfile.ZIP_DEFLATED
        mode = 0o755 if name in executable else 0o644
        info.external_attr = (mode << 16) | 0o100000
        with open(path, "rb") as fh:
            z.writestr(info, fh.read())
ZIPEOF

echo "  built $STATIC/riskability-feedbuilder.zip ($(du -h "$STATIC/riskability-feedbuilder.zip" | cut -f1))"
