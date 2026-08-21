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
need riskability "riskability/appserver/static/scripts/build-feed.sh" "offered as a download"
need riskability "riskability/appserver/static/scripts/build-feed.ps1" "offered as a download"

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

echo
if [ "$fail" -eq 0 ]; then echo "all packages complete"; else echo "PACKAGE INCOMPLETE"; exit 1; fi
