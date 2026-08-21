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
# Requires: python3 (3.8+) and the riskability-feed tool from the repo, which
# must sit next to this script or on your PATH. Nothing else is installed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEED="${RISKABILITY_FEED:-}"
for cand in "$HERE/riskability-feed" "$HERE/../tools/riskability-feed" "$(command -v riskability-feed 2>/dev/null || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then FEED="$cand"; break; fi
done
if [ -z "$FEED" ]; then
  echo "error: riskability-feed not found." >&2
  echo "Put it next to this script, or set RISKABILITY_FEED=/path/to/riskability-feed" >&2
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
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

echo "Building $OUT ..."
"$FEED" build --out "$OUT" --version "$STAMP" "${ARGS[@]}"
echo
echo "Done. Copy $OUT to the search head and import it on the"
echo "Riskability > Feed administration page."
