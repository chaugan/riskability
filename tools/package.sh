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
  # Anything git does not track has no business in a shipped package. The app
  # directory is copied wholesale, so a gitignored directory sitting in a
  # developer's tree rides along silently: app/riskability/vectors/ - 1.8 MB of
  # lance index belonging to an unrelated tool - was inside every .spl built
  # here. Nobody would have found it by reading the repository, because it is
  # not in the repository.
  rm -rf "$STAGE/$app/vectors"


  # Ship the licence inside every package. Splunkbase vets intellectual
  # property, and an installed app that points at a licence living only in a
  # git repository is asking a reviewer - and later an auditor - to take the
  # terms on trust. Copied at package time rather than committed three times,
  # so there is one licence file in the tree and it cannot drift.
  cp "$ROOT/LICENSE" "$STAGE/$app/LICENSE"

  # The vendored SDK carries an optional AI subpackage this app never imports.
  # It needs Python 3.10 syntax, so it does not even parse on the interpreter
  # Splunk runs, and shipping twenty files that cannot be compiled invites a
  # question from every scanner that walks the package. Stripped here rather
  # than from the vendored source, which stays complete for the next upgrade.
  rm -rf "$STAGE/$app/bin/splunklib/ai"

  # Build artefacts. AppInspect fails a package containing bytecode.
  find "$STAGE/$app" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "$STAGE/$app" \( -name '*.pyc' -o -name '.DS_Store' -o -name '*.swp' \) -delete 2>/dev/null || true

  # A modular input script that is not executable is never introspected, and
  # Splunk says nothing about why the input does not appear.
  # Splunkbase: "files that indicate they are executable must actually be
  # executable". Every entry point here carries a shebang, so the exec bit has
  # to match or the submission is rejected on a technicality. Enforced at
  # package time rather than trusted to the checkout, because a tree cloned
  # with a umask that drops the bit would ship a package that fails review.
  for f in "$STAGE/$app"/bin/*.py; do
    [ -f "$f" ] || continue
    head -1 "$f" | grep -q '^#!' && chmod +x "$f"
  done

  tar -C "$STAGE" -czf "$DIST/${app}-${VERSION}.spl" "$app"
  # Splunkbase accepts .spl, .tar.gz and .tgz - they are the same gzipped tar -
  # but its upload page asks for a .tar.gz, and Splunk Web's "install app from
  # file" expects .spl. Ship both names for the one archive rather than making
  # somebody rename a file and wonder whether it is still the tested artefact.
  cp "$DIST/${app}-${VERSION}.spl" "$DIST/${app}-${VERSION}.tar.gz"
  printf '  %-26s %s  (.spl and .tar.gz)\n' "$app" "$(du -h "$DIST/${app}-${VERSION}.spl" | cut -f1)"
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
# Every dashboard must actually parse, and every conf file the app declares a
# search command for must exist.
#
# Splunk does not validate either at install time. A malformed view renders as a
# broken page for the one dashboard affected and nothing anywhere says why, and
# the trap that produced it twice here is subtle: a double hyphen is ILLEGAL
# inside an XML comment, so writing a perfectly ordinary "-- like this" aside
# into a comment silently breaks the whole file. A dangling commands.conf
# filename is worse -- it is a hard Splunkbase certification rejection, and the
# submission is refused before a human looks at it.
structure() {
  local root="$1"
  python3 - "$root" <<'PYEOF' || fail=1
import glob, os, sys, xml.dom.minidom
import configparser
root = sys.argv[1]
bad = False
for f in sorted(glob.glob(os.path.join(root, "default", "data", "ui", "**", "*.xml"), recursive=True)):
    try:
        xml.dom.minidom.parse(f)
        print(f"  ok    xml parses: {os.path.relpath(f, root)}")
    except Exception as exc:
        print(f"  BAD   xml is malformed: {os.path.relpath(f, root)}: {exc}")
        bad = True
cmds = os.path.join(root, "default", "commands.conf")
if os.path.exists(cmds):
    cp = configparser.ConfigParser(strict=False)
    cp.read(cmds)
    for stanza in cp.sections():
        fn = cp.get(stanza, "filename", fallback="")
        if fn and not os.path.exists(os.path.join(root, "bin", fn)):
            print(f"  BAD   commands.conf [{stanza}] names bin/{fn}, which does not exist")
            bad = True
        elif fn:
            print(f"  ok    command [{stanza}] -> bin/{fn}")
sys.exit(1 if bad else 0)
PYEOF
}

forbid() {
  if grep -qF "$2" "$LISTS/$1.txt"; then
    printf '  BAD   %-52s %s\n' "$1: contains $2" "$3"; fail=1
  else
    printf '  ok    %-52s\n' "$1: no $2"
  fi
}

# Splunk's runtime parser tolerates a continuation line that lost its trailing
# backslash; the Splunkbase Packaging Toolkit refuses the whole submission over
# it. Checked here so the answer arrives now rather than after an upload.
if ! python3 "$ROOT/tools/conf_lint.py" > "$STAGE/conflint.txt" 2>&1; then
  grep '  BAD' "$STAGE/conflint.txt" || cat "$STAGE/conflint.txt"
  fail=1
else
  printf '  ok    %-52s\n' "every conf parses under strict rules"
fi

# The wrappers and the tool they invoke must agree on flags. They are separate
# argument parsers in separate files, and a flag added to one and not the other
# fails only on a user's machine, with "unrecognized arguments".
if ! python3 "$ROOT/tools/check_feedbuilder_flags.py"; then fail=1; fi

# The search-head app: everything the dashboards and matcher need at runtime.
structure "$ROOT/app/riskability"

need riskability "riskability/static/appIcon.png"                  "36px app icon; Splunk Web shows a placeholder without it"
need riskability "riskability/static/appIcon_2x.png"               "72px app icon for high-DPI displays"
need riskability "riskability/default/app.conf"                    "app identity"
need riskability "riskability/default/collections.conf"            "KV Store collections and their indexes"
need riskability "riskability/default/transforms.conf"             "lookup definitions"
need riskability "riskability/default/macros.conf"                 "search macros"
need riskability "riskability/default/props.conf"                  "search-time extraction"
need riskability "riskability/default/commands.conf"               "custom search commands"
need riskability "riskability/default/restmap.conf"                "admin REST endpoint"
need riskability "riskability/default/web.conf"                    "exposes the endpoint to Splunk Web"
need riskability "riskability/default/inputs.conf"                 "the feed worker input"
need riskability "riskability/default/indexes.conf"                "the four indexes; without them a single instance installs to empty dashboards"
need riskability "riskability/default/savedsearches.conf"          "scheduled searches"
need riskability "riskability/default/data/ui/views/riskability_exceptions.xml" "the risk-exception register"
need riskability "riskability/default/data/ui/views/riskability_start.xml" "the landing page, and the app's default view"
need riskability "riskability/appserver/static/riskability_start.css"      "styles the landing page"
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
need riskability "riskability/appserver/static/visualizations/riskability_chart/preview.png" \
     "the picker icon; Splunkbase rejects a visualization stanza without one"
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
need riskability "riskability/appserver/static/visualizations/riskability_grid/preview.png" \
     "the picker icon; Splunkbase rejects a visualization stanza without one"
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
  forbid "$app" "vectors/" "untracked developer data must not ship"
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

# The Splunkbase Packaging Toolkit is the thing that actually accepts or refuses
# the upload, and Splunk ships it at /opt/splunk/bin/slim. Running it here turns
# "the submission was rejected" into a build failure. Skipped LOUDLY when the
# dev container is down: a check that silently does nothing is worse than one
# that is absent.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx riskability-splunk; then
  for app in "${APPS[@]}"; do
    docker cp "$DIST/${app}-${VERSION}.tar.gz" riskability-splunk:/tmp/ >/dev/null 2>&1
    out=$(docker exec -u splunk riskability-splunk /opt/splunk/bin/slim validate \
          "/tmp/${app}-${VERSION}.tar.gz" 2>&1 | grep -viE 'syntaxwarning|if self\.' || true)
    if printf '%s' "$out" | grep -q 'ERROR'; then
      printf '%s\n' "$out" | grep 'ERROR'
      printf '  BAD   %-52s\n' "$app: slim validate reported errors"; fail=1
    else
      n=$(printf '%s' "$out" | grep -c 'WARNING' || true)
      printf '  ok    %-52s (%s warnings)\n' "$app: slim validate passed" "$n"
    fi
  done
else
  echo "  SKIP  slim validate: riskability-splunk is not running"
fi

echo
if [ "$fail" -eq 0 ]; then echo "all packages complete"; else echo "PACKAGE INCOMPLETE"; exit 1; fi
