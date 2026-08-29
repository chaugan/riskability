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
#
# NVD data (--windows, --everything) comes from a daily regeneration of the bulk
# feeds NIST retired, topped up from the NIST API with whatever changed since
# that regeneration ran. A full fetch takes about a minute and needs no API key.
#
#   --nvd-source api      use NIST directly and nothing else. Authoritative,
#                         but the API serves 2000 CVEs a request and takes
#                         about 20 seconds over each one, so expect an hour or
#                         more. Set NVD_API_KEY to soften the rate limiting:
#                         https://nvd.nist.gov/developers/request-an-api-key
#   --nvd-source mirror   the regenerated feeds only, skipping the top-up
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
  # Support lifecycles. Small, and the only source that answers "is anyone
  # still fixing this at all", which no advisory ever states.
  --lifecycle
)

# A loop rather than a single case, so the profile and the modifiers can be
# combined: --windows --with-cve-list is a reasonable thing to ask for.
while [ $# -gt 0 ]; do
  case "$1" in
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
        # The CVE Program catalogue, which is what gives the CVE encyclopaedia a
        # description and a product name. Only in this profile: it is about
        # 600 MB to fetch and roughly 120 MB in the bundle, which is a real
        # decision on an air gap rather than a default to inherit.
        --cve-list
      )
      ;;
    --with-cve-list)
      # Any profile plus the encyclopaedia's source. Kept as its own flag so a
      # Linux or Windows build can have it without taking every ecosystem too.
      ARGS+=(--cve-list)
      ;;
    --nvd-source)
      shift
      ARGS+=(--nvd-source "${1:?--nvd-source needs auto, mirror or api}")
      ;;
    --help|-h)
      awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "error: unknown option $1. Try --help." >&2
      exit 2
      ;;
  esac
  shift
done

# The default path does not need a key, so only say something when the operator
# has asked for the API-only source, where the rate limit genuinely bites.
if [ -z "${NVD_API_KEY:-}" ]; then
  for a in "${ARGS[@]}"; do
    if [ "$a" = "api" ]; then
      echo "note: --nvd-source api with no NVD_API_KEY is rate limited to 5" >&2
      echo "      requests per 30 seconds. This will take well over an hour." >&2
      echo "      A free key from https://nvd.nist.gov/developers/request-an-api-key" >&2
      echo "      helps, though the API is slow regardless." >&2
      break
    fi
  done
fi

echo "Building $OUT ..."
"$PY" "$PYZ" build --out "$OUT" --version "$STAMP" "${ARGS[@]}"
echo
echo "Done. Copy $OUT to the search head and import it on the"
echo "Riskability > Feed administration page."
