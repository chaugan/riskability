#!/usr/bin/env bash
# Build a demo instance from nothing, in the order a user would.
#
# Separate from test_fresh_install.sh on purpose. That script proves the app
# installs and matches correctly, and its fixtures are component-only because
# that is all matching needs. This one exists to produce an instance that looks
# like a real deployment - which means scans that also carry exposure, container
# and heartbeat records, and a feed built with every source including the ATT&CK
# tactic mapping. Screenshots taken from anything less show honest but empty
# pages: with no exposure records every finding is correctly reported as "not
# assessed", and with no tactics the ATT&CK matrix is correctly blank.
#
# Nothing is layered on top of anything. Torn down first, every time.
set -uo pipefail
# RK_ROOT lets this run from a copy outside the tree - handy when you want the
# running script to be immutable so editing the original cannot corrupt a live
# run. Without it, $0 resolves against wherever the copy lives and every
# sibling path silently misses.
cd "${RK_ROOT:-$(dirname "$0")/..}"
source docker/.env
# Feed bundles are gitignored - they are hundreds of megabytes and rebuilt from
# upstream, not checked in - so this cannot ship with one. Build it first:
#
#   tools/riskability-feed build --out testdata/feeds/riskability-demo.tar.gz \
#       --ecosystem Ubuntu --ecosystem Debian --ecosystem Alpine \
#       --ecosystem npm --ecosystem PyPI --ecosystem Go \
#       --nvd --kev --epss --mitre
#
# --mitre and --nvd are not optional here. Without the tactic mapping the ATT&CK
# matrix is correctly blank, and without NVD no Windows component matches at
# all, because Windows software carries CPEs rather than a purl.
BUNDLE="${RK_BUNDLE:-testdata/feeds/riskability-feed-20260822-full.tar.gz}"
if [ ! -f "$BUNDLE" ]; then
  echo "no feed bundle at $BUNDLE" >&2
  echo "build one first, or point RK_BUNDLE at an existing bundle. See the" >&2
  echo "comment at the top of this script for the command." >&2
  exit 1
fi
die_unless() { [ "$1" = 1 ] && return 0
  printf '\nFAILED: %s\n' "$2" >&2
  printf 'the instance is half-built; nothing downstream would be trustworthy.\n' >&2
  exit 1; }
say() { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
spl() { docker exec -i -u splunk riskability-splunk /opt/splunk/bin/splunk "$@" \
          -auth "admin:$SPLUNK_PASSWORD" 2>/dev/null; }

say "teardown: containers and volumes"
( cd docker && docker compose down -v --remove-orphans >/dev/null 2>&1 )

say "build the packages a user installs"
./tools/package.sh --verify >/dev/null 2>&1 || { echo "package build FAILED"; exit 1; }

say "start splunk and the forwarder"
# Runtime staging, gitignored: this only ever removes scans a previous run
# generated. The canonical scans live in testdata/scans/ and are never
# touched. mkdir because a fresh clone has no such directory and the
# compose bind mount would otherwise have Docker create it as root.
mkdir -p docker/uf/swinv-data
rm -f docker/uf/swinv-data/*.ndjson docker/uf/swinv-data/*.partial
( cd docker && docker compose up -d >/dev/null 2>&1 )
ready=0
for i in $(seq 1 60); do
  curl -sk -u "admin:$SPLUNK_PASSWORD" "https://127.0.0.1:8089/services/server/info?output_mode=json" \
    2>/dev/null | grep -q kvStoreStatus && { ready=1; break; }
  sleep 10
done
die_unless "$ready" "splunk never became responsive on 8089"
ready=0
for i in $(seq 1 60); do
  docker logs riskability-uf 2>&1 | grep -q "Ansible playbook complete" && { ready=1; break; }
  sleep 10
done
die_unless "$ready" "the forwarder never finished provisioning"

say "install the three packages"
for f in dist/*.spl; do
  docker cp "$f" riskability-splunk:/tmp/ >/dev/null
  spl install app "/tmp/$(basename "$f")" >/dev/null
done
# "splunk restart" stops cleanly but its start half waits on the licence prompt
# and never completes non-interactively, leaving splunkd down for good - the same
# trap deploy-dev.sh documents. Stop and start explicitly with the acceptance
# flags. No -i either: docker exec -i drains stdin, which is what lets the
# prompt hang in the first place.
docker exec -u splunk riskability-splunk /opt/splunk/bin/splunk stop >/dev/null 2>&1 || true
docker exec -u splunk riskability-splunk /opt/splunk/bin/splunk start \
  --accept-license --answer-yes --no-prompt >/dev/null 2>&1 || true
ready=0
for i in $(seq 1 60); do
  curl -sk -u "admin:$SPLUNK_PASSWORD" "https://127.0.0.1:8089/services/server/info?output_mode=json" \
    2>/dev/null | grep -q kvStoreStatus && { ready=1; break; }
  sleep 10
done
die_unless "$ready" "splunk did not come back after installing the packages"
./tools/deploy-uf.sh >/dev/null 2>&1
docker exec -u splunk riskability-uf /opt/splunkforwarder/bin/splunk start \
  --accept-license --answer-yes --no-prompt >/dev/null 2>&1 || true

say "import the feed: $(basename "$BUNDLE")"
docker exec -u splunk riskability-splunk mkdir -p /opt/splunk/var/run/riskability/incoming
docker cp "$BUNDLE" "riskability-splunk:/opt/splunk/var/run/riskability/incoming/" >/dev/null
docker exec -u root riskability-splunk chown splunk:splunk \
  "/opt/splunk/var/run/riskability/incoming/$(basename "$BUNDLE")"
curl -sk -u "admin:$SPLUNK_PASSWORD" -X POST \
  "https://127.0.0.1:8089/servicesNS/nobody/riskability/riskability/feed" \
  -H 'Content-Type: application/json' \
  -d "{\"action\":\"import\",\"filename\":\"$(basename "$BUNDLE")\"}" >/dev/null
for i in $(seq 1 80); do
  st=$(curl -sk -u "admin:$SPLUNK_PASSWORD" \
    "https://127.0.0.1:8089/servicesNS/nobody/riskability/storage/collections/data/riskability_feedstate/import_status?output_mode=json" \
    2>/dev/null | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('state',''))
except Exception: print('')" 2>/dev/null)
  case "$st" in done) echo "  import done"; break;; failed) echo "  import FAILED"; exit 1;; esac
  [ "$i" -eq 80 ] && { echo "  import did not finish in 20 minutes"; exit 1; }
  sleep 15
done

say "ingest both hosts, full scans with exposure and container records"
NOW=$(date +%s)
# Read the working tree, not git HEAD: reading HEAD silently ignores any local
# change to the fixtures, so a scan you just edited would not be the one tested.
for f in testdata/scans/linux-host-01.ndjson testdata/scans/windows-host-01.ndjson; do
  [ -f "$f" ] || die_unless 0 "missing scan fixture $f"
done
cp testdata/scans/linux-host-01.ndjson /tmp/rk-lin.ndjson
cp testdata/scans/windows-host-01.ndjson /tmp/rk-win.ndjson
python3 tools/stage_scan.py /tmp/rk-lin.ndjson \
  "docker/uf/swinv-data/linux-host-01-$(date -u -d @$NOW +%Y%m%dT%H%M%S).000Z.ndjson" --at "$NOW" >/dev/null
python3 tools/stage_scan.py /tmp/rk-win.ndjson \
  "docker/uf/swinv-data/windows-host-01-$(date -u -d @$((NOW+2)) +%Y%m%dT%H%M%S).000Z.ndjson" --at "$((NOW+2))" >/dev/null
for i in $(seq 1 40); do
  n=$(spl search 'index=* sourcetype=riskability:swinv record_type=exposure earliest=0 latest=+1h | stats count' \
      -app riskability -maxout 0 2>/dev/null | tail -1 | tr -d ' ')
  case "$n" in ''|*[!0-9]*) n=0;; esac
  [ "$n" -ge 220 ] && { echo "  exposure records: $n"; break; }
  sleep 20
done

say "run the pipeline until the open count settles"
prev=-1
for cycle in 1 2 3 4 5; do
  bash tools/pipeline_cycle.sh >/dev/null 2>&1 || die_unless 0 "a pipeline cycle failed to run"
  n=$(spl search '| inputlookup riskability_findings_state_lookup where status="open" | stats count' \
      -app riskability -maxout 0 2>/dev/null | tail -1 | tr -d ' ')
  case "$n" in ''|*[!0-9]*) die_unless 0 "could not read the open count from the state collection";; esac
  echo "  cycle $cycle: $n open"
  [ "$n" = "$prev" ] && [ "$n" != "0" ] && { echo "  settled after $cycle cycles"; break; }
  prev=$n
done
die_unless "$([ "$n" != "0" ] && echo 1 || echo 0)" \
  "the pipeline settled on zero open findings; the matcher index holds findings the fold never took up"

say "coherence"
spl search '| inputlookup riskability_findings_state_lookup where status="open" | stats count AS state_open' -app riskability -maxout 0 2>/dev/null | tail -1
spl search '| inputlookup riskability_openstate_host_lookup | stats sum(findings) AS rollup_open' -app riskability -maxout 0 2>/dev/null | tail -1
spl search '| inputlookup riskability_ranges_lookup | stats dc(gen) AS live_generations' -app riskability -maxout 0 2>/dev/null | tail -1
spl search 'index=* sourcetype=riskability:swinv NOT record_type=* earliest=0 latest=+1h | stats dc(_time) AS scans BY hostname' -app riskability -maxout 0 2>/dev/null | tail -3
say "done"
