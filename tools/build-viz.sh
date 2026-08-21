#!/usr/bin/env bash
#
# Build the ECharts visualization bundle, and bump the app build number
# whenever its contents change.
#
# Splunk serves app static assets with "Cache-Control: public, max-age=31536000"
# -- one year -- under a URL that embeds the app's build number:
#
#   /static/@<splunk_build>-<app_build>/app/riskability/visualizations/...
#
# So the build number is not decoration: it IS the cache key. Ship a new
# visualization.js without bumping it and every browser that has ever loaded
# the old one keeps it for a year. That is not a development annoyance, it is
# an upgrade defect -- a Splunkbase user installing a new version would run the
# previous bundle against new dashboards and see "Unknown chart type", which is
# exactly what happened here.
#
# Bumping by hand is the kind of step that gets forgotten, so it is done here,
# automatically, and only when the built artefact actually changes.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VIZ="$ROOT/app/riskability/appserver/static/visualizations/riskability_chart"
APPCONF="$ROOT/app/riskability/default/app.conf"

[ -d "$VIZ/node_modules" ] || { echo "installing viz dependencies"; ( cd "$VIZ" && npm ci --silent --no-audit --no-fund ); }

before=""
[ -f "$VIZ/visualization.js" ] && before=$(sha256sum "$VIZ/visualization.js" | cut -d' ' -f1)

( cd "$VIZ" && npx webpack --mode production >/dev/null 2>&1 )

after=$(sha256sum "$VIZ/visualization.js" | cut -d' ' -f1)

if [ "$before" = "$after" ]; then
  echo "  visualization.js unchanged (build $(awk -F'= *' '/^build/{print $2; exit}' "$APPCONF"))"
  exit 0
fi

current=$(awk -F'= *' '/^build/{print $2; exit}' "$APPCONF")
next=$((current + 1))
# Portable in-place edit: sed -i differs between GNU and BSD.
tmp=$(mktemp)
awk -v n="$next" '/^build = /{print "build = " n; next} {print}' "$APPCONF" > "$tmp"
mv "$tmp" "$APPCONF"
echo "  visualization.js changed; app build $current -> $next (cache key)"
