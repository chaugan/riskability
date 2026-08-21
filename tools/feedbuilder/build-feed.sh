#!/usr/bin/env bash
#
# Riskability -- build an offline vulnerability feed bundle (Linux / macOS).
#
# Run this on a machine WITH internet access, then carry the resulting file to
# your Splunk search head and import it on the Riskability "Feed administration"
# page.
#
#   ./build-feed.sh                     # sensible default for a Linux fleet
#   ./build-feed.sh --windows           # add NVD CPE data for Windows estates
#   ./build-feed.sh --everything        # every distro, every ecosystem, all NVD
#
# Requires: Python 3.8+. Everything else ships in the same archive as this
# script -- keep the files together after unzipping.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The builder ships beside this script as a Python zipapp, so the download
# works on its own. An earlier version looked for a separately-installed
# "riskability-feed" that nobody downloading from Splunkbase could obtain.
PYZ="${RISKABILITY_FEED:-$HERE/riskability-feed.pyz}"
if [ ! -f "$PYZ" ]; then
  echo "error: riskability-feed.pyz not found next to this script." >&2
  echo "Download riskability-feedbuilder.zip from the Riskability app's" >&2
  echo "Feed administration page and unpack it, keeping the files together." >&2
  exit 1
fi

PY=""
for cand in python3 python py; do
  if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
done
if [ -z "$PY" ]; then
  echo "error: Python 3.8+ is required and was not found on PATH." >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%d)"
OUT="riskability-feed-${STAMP}.tar.gz"

# The distributions and ecosystems your fleet actually runs. Trim this list:
# every entry is a download, and a feed you do not need is only bulk to carry.
ARGS=(
  --ecosystem Ubuntu
  --ecosystem Debian
  --ecosystem Alpine
  --ecosystem npm
  --ecosystem PyPI
  --ecosystem Go
  --ecosystem Maven
  --kev
  --epss
  --mitre
)

case "${1:-}" in
  --windows)
    # Windows software is not installed by a package manager, so it has no
    # PURL. NVD's CPE data is the only thing that can assess it.
    ARGS+=(--nvd 2015-2026)
    ;;
  --everything)
    ARGS+=(
      --ecosystem "Red Hat" --ecosystem "Rocky Linux" --ecosystem AlmaLinux
      --ecosystem SUSE --ecosystem openSUSE --ecosystem NuGet
      --ecosystem RubyGems --ecosystem "crates.io" --ecosystem Packagist
      --nvd all
    )
    ;;
  --help|-h)
    awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
    exit 0
    ;;
esac

echo "Building $OUT ..."
"$PY" "$PYZ" build --out "$OUT" --version "$STAMP" "${ARGS[@]}"
echo
echo "Done. Copy $OUT to the search head and import it on the"
echo "Riskability > Feed administration page."
