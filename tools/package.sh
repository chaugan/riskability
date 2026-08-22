#!/usr/bin/env bash
#
# Build the installable Splunk packages (.spl) from the source tree.
#
# Everything the app needs at runtime must be inside these archives. A fix that
# only exists because someone edited a file on a dev container is not a fix --
# it is a difference between what was tested and what a Splunkbase user
# installs. The verification pass below exists to catch exactly that.
#
#   tools/package.sh            build into dist/
#   tools/package.sh --verify   build, then check each package is complete
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST="$ROOT/dist"
VERSION=$(awk -F'= *' '/^version/{print $2; exit}' "$ROOT/app/riskability/default/app.conf")
APPS=(riskability TA-riskability TA-riskability-indexes)

# Rebuild the downloadable feed builder first, so the archive in the package is
# always built from the tree being packaged. It shipped stale once already --
# as two wrapper scripts around a tool that was never in the package at all.
"$ROOT/tools/make-feedbuilder.sh"

# Rebuilds the ECharts bundle and bumps the app build if it changed. The build
# number is the cache key for a year-long Cache-Control, so this must happen
# before the version is read below.
"$ROOT/tools/build-viz.sh"

rm -rf "$DIST"
mkdir -p "$DIST"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

for app in "${APPS[@]}"; do
  src="$ROOT/app/$app"
  [ -d "$src" ] || { echo "missing $src" >&2; exit 1; }
  cp -r "$src" "$STAGE/$app"

  # Splunk forbids local/ and local.meta in a distributed package: they are the
  # user's layer, and shipping them silently overwrites their customisations on
  # upgrade.
  rm -rf "$STAGE/$app/local" "$STAGE/$app/metadata/local.meta"
  # node_modules is 93MB of build-time dependencies. visualization.js is the
  # artefact that ships; the sources it was built from stay in the repo, and
  # THIRD-PARTY.md records the pinned versions so the bundle is reproducible.
  find "$STAGE/$app" -name 'node_modules' -type d -prune -exec rm -rf {} + 2>/dev/null || true

  # Build artefacts. AppInspect fails a package containing bytecode.
  find "$STAGE/$app" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "$STAGE/$app" \( -name '*.pyc' -o -name '.DS_Store' -o -name '*.swp' \) -delete 2>/dev/null || true

  # A modular input script that is not executable is never introspected, and
  # Splunk says nothing about why the input does not appear.
  if [ -f "$STAGE/$app/bin/riskability_feedworker.py" ]; then
    chmod +x "$STAGE/$app/bin/riskability_feedworker.py"
  fi

  tar -C "$STAGE" -czf "$DIST/${app}-${VERSION}.spl" "$app"
  printf '  %-26s %s\n' "$app" "$(du -h "$DIST/${app}-${VERSION}.spl" | cut -f1)"
done

echo
echo "packages in $DIST"

[ "${1:-}" = "--verify" ] || exit 0

echo
echo "verifying package contents"
fail=0

# List each archive ONCE into a file, then grep the file.
#
# Not a micro-optimisation: "tar -tzf x | grep -q pattern" under
# "set -o pipefail" reports failure whenever grep matches early, because grep
# exits and tar dies of SIGPIPE. Entries near the end of the archive appear to
# pass and everything else appears to be missing -- a verification script that
# lies is worse than no verification script.
LISTS="$STAGE/lists"
mkdir -p "$LISTS"
for app in "${APPS[@]}"; do
  tar -tzf "$DIST/${app}-${VERSION}.spl" > "$LISTS/$app.txt"
done

need() {  # need <package> <path-inside> <why>
  if grep -qxF "$2" "$LISTS/$1.txt"; then
    printf '  ok    %-52s\n' "$1: $2"
  else
    printf '  MISS  %-52s %s\n' "$1: $2" "$3"; fail=1
  fi
}
forbid() {
  if grep -qF "$2" "$LISTS/$1.txt"; then
    printf '  BAD   %-52s %s\n' "$1: contains $2" "$3"; fail=1
  else
    printf '  ok    %-52s\n' "$1: no $2"
  fi
}

# The search-head app: everything the dashboards and matcher need at runtime.
need riskability "riskability/default/app.conf"                    "app identity"
need riskability "riskability/default/collections.conf"            "KV Store collections and their indexes"
need riskability "riskability/default/transforms.conf"             "lookup definitions"
need riskability "riskability/default/macros.conf"                 "search macros"
need riskability "riskability/default/props.conf"                  "search-time extraction"
need riskability "riskability/default/commands.conf"               "custom search commands"
need riskability "riskability/default/restmap.conf"                "admin REST endpoint"
need riskability "riskability/default/web.conf"                    "exposes the endpoint to Splunk Web"
need riskability "riskability/default/inputs.conf"                 "the feed worker input"
need riskability "riskability/default/savedsearches.conf"          "scheduled searches"
need riskability "riskability/default/data/ui/views/riskability_exceptions.xml" "the risk-exception register"
need riskability "riskability/README/inputs.conf.spec"             "without it the modular input is never introspected"
need riskability "riskability/metadata/default.meta"               "permissions"
need riskability "riskability/bin/riskability_feedworker.py"       "performs imports"
need riskability "riskability/bin/riskability_match.py"            "the matcher"
need riskability "riskability/bin/riskability_feed_rest.py"        "admin endpoint"
need riskability "riskability/bin/riskability/build.py"            "feed fetching"
need riskability "riskability/bin/riskability/vercmp.py"           "version comparators"
need riskability "riskability/bin/splunklib/binding.py"            "vendored SDK"
need riskability "riskability/bin/splunk_sdk-3.0.0.dist-info/METADATA" "vendored SDK version lookup"
need riskability "riskability/appserver/static/riskability_admin.js"  "admin page"
need riskability "riskability/appserver/static/riskability_exceptions.js" "the accept-risk dialog"
need riskability "riskability/appserver/static/riskability_exceptions.css" "styles the dialog"
need riskability "riskability/bin/riskability_exceptions_rest.py"    "the only writer of the exception register"
need riskability "riskability/default/authorize.conf"                "defines riskability_accept_risk"
need riskability "riskability/appserver/static/scripts/riskability-feedbuilder.zip" \
     "the self-contained feed builder the admin page offers"
need riskability "riskability/default/visualizations.conf"                "declares the custom visualization"
need riskability "riskability/appserver/static/visualizations/riskability_chart/visualization.js" \
     "the built ECharts bundle; without it every chart panel is blank"
need riskability "riskability/appserver/static/visualizations/riskability_chart/visualization.css" \
     "sizes the chart element; ECharts draws nothing at 0x0"
need riskability "riskability/appserver/static/visualizations/riskability_chart/formatter.html" \
     "panel options"
need riskability "riskability/appserver/static/visualizations/riskability_chart/ECHARTS-LICENSE.txt" \
     "Splunkbase vetting requires vendored licences"
need riskability "riskability/appserver/static/visualizations/riskability_chart/THIRD-PARTY.md" \
     "identifies the bundled library and version"
need riskability "riskability/appserver/static/visualizations/riskability_grid/visualization.js" \
     "the Tabulator table bundle"
need riskability "riskability/appserver/static/visualizations/riskability_grid/visualization.css" \
     "Tabulator's theme plus our palette; without it the grid is unstyled"
need riskability "riskability/appserver/static/visualizations/riskability_grid/formatter.html" \
     "panel options"
need riskability "riskability/appserver/static/visualizations/riskability_grid/TABULATOR-LICENSE.txt" \
     "Splunkbase vetting requires vendored licences"
need riskability "riskability/appserver/static/visualizations/riskability_grid/THIRD-PARTY.md" \
     "identifies the bundled library and version"
forbid riskability "node_modules" "build-time dependencies must not ship"

need TA-riskability "TA-riskability/default/inputs.conf"  "the file input"
need TA-riskability "TA-riskability/default/props.conf"   "index-time parsing"
forbid TA-riskability "indexes.conf" "a forwarder must not receive index definitions"

need TA-riskability-indexes "TA-riskability-indexes/default/indexes.conf" "index definitions"

for app in "${APPS[@]}"; do
  forbid "$app" "/local/"     "local/ is the user's layer and must not be shipped"
  forbid "$app" "__pycache__" "bytecode fails AppInspect"
done

# The modular input's mode must survive packaging.
mode=$(tar -tvzf "$DIST/riskability-${VERSION}.spl" 2>/dev/null | awk '/riskability_feedworker\.py$/{print $1}')
case "$mode" in
  *x*) printf '  ok    %-52s\n' "riskability: feedworker is executable ($mode)" ;;
  *)   printf '  BAD   %-52s %s\n' "riskability: feedworker not executable ($mode)" \
         "Splunk will never introspect it"; fail=1 ;;
esac

# The feed builder must be usable straight out of the package: a download that
# needs a separately-obtained tool is what this archive exists to replace.
fb="$STAGE/fb"
mkdir -p "$fb"
if tar -C "$fb" -xzf "$DIST/riskability-${VERSION}.spl" \
     riskability/appserver/static/scripts/riskability-feedbuilder.zip 2>/dev/null; then
  if python3 - "$fb/riskability/appserver/static/scripts/riskability-feedbuilder.zip" "$fb" <<'PYEOF'
import os, subprocess, sys, zipfile
src, dest = sys.argv[1], os.path.join(sys.argv[2], "unpacked")
with zipfile.ZipFile(src) as z:
    names = set(z.namelist())
    for info in z.infolist():
        z.extract(info, dest)
        os.chmod(os.path.join(dest, info.filename), info.external_attr >> 16)
missing = {"riskability-feed.pyz", "build-feed.sh", "build-feed.ps1"} - names
if missing:
    print("missing from the archive: " + ", ".join(sorted(missing)))
    sys.exit(1)
# Runs it the way a user would, which is the only check that would have caught
# the original "riskability-feed not found" failure.
r = subprocess.run([sys.executable, os.path.join(dest, "riskability-feed.pyz"), "sources"],
                   capture_output=True, text=True)
if r.returncode != 0:
    print("the builder does not run: " + (r.stderr.strip().splitlines() or [""])[-1])
    sys.exit(1)
PYEOF
  then
    printf '  ok    %-52s\n' "riskability: feed builder runs standalone"
  else
    printf '  BAD   %-52s %s\n' "riskability: feed builder is not usable" \
      "the download would fail for every user"; fail=1
  fi
else
  printf '  BAD   %-52s\n' "riskability: feed builder archive missing"; fail=1
fi

echo
if [ "$fail" -eq 0 ]; then echo "all packages complete"; else echo "PACKAGE INCOMPLETE"; exit 1; fi
