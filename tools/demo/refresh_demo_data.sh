#!/usr/bin/env bash
# Refresh the simulated client and firewall data on the dev instance, in one go.
#
#   tools/demo/refresh_demo_data.sh [--dry-run] [--keep-old] [--cycles N] [--no-pipeline]
#
# What it loads, all stamped relative to "now":
#   - the real hosts' captured scans (fnaskZenbook, fnaskthinserver,
#     linux-host-01, windows-host-01), re-stamped as three scans each at
#     6 days, 3 days and 0 days ago
#   - the 11-host demo fleet (exposure + heartbeat) at 6, 4, 2 and 0 days ago,
#     and its seeded findings in the KV store
#   - six days of demo firewall traffic, ending now
# then runs the pipeline so findings, address claims and network grades are
# rebuilt from it. The CVE feed is not touched.
#
# This is the 12 Oct 2026 refresh, scripted, with the two fixes that refresh
# needed after the fact built in:
#   - riskability_hostaddr is backed up and cleared before the pipeline runs.
#     Left alone, it remembers the previous load's sightings, the gap between
#     those and this load exceeds the identity grace period, and every flow
#     resolves "stale".
#   - the demo fleet's newest scan is stamped now rather than two hours ago,
#     so no firewall edge is newer than the last scan that saw its host.
#
# Loads with "splunk add oneshot" straight into riskability-splunk, using the
# index, sourcetype and host the forwarder would have used. The forwarder
# (riskability-uf) has had no outputs.conf since 4 Sep 2026 and forwards
# nothing, so its watch directory is deliberately not used.
#
# Previous simulated events from the last 31 days are deleted first (--keep-old
# skips that). The address snapshot looks back 30 days and measures the gaps
# between sightings, so stacking a new load on an older one a fortnight back
# leaves a gap the identity guard refuses.
#
# --dry-run generates the files and prints what would be loaded, and changes
# nothing in Splunk.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
source docker/.env

DRY=0; KEEP_OLD=0; CYCLES=1; PIPELINE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1;;
    --keep-old) KEEP_OLD=1;;
    --cycles) CYCLES="$2"; shift;;
    --no-pipeline) PIPELINE=0;;
    -h|--help) sed -n '2,40p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
  shift
done

SPLUNK=riskability-splunk
API=https://127.0.0.1:8089
NS=$API/servicesNS/nobody/riskability
KV=$NS/storage/collections/data
AUTH="admin:$SPLUNK_PASSWORD"
# Private to this user, not /var/tmp: the backup is the estate's host and
# address list, and a predictable name in a shared directory can be read by
# anyone on the box or pre-planted as a symlink that the write follows.
BACKUPS=${RK_BACKUP_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/riskability/refresh-backups}

# The real hosts' captured scans. The first three live in the forwarder's
# staging dir, which is gitignored and which build_demo_instance.sh empties,
# so the check below fails loudly if they are gone.
SCANS=(
  docker/uf/swinv-data/fnaskZenbook-20260828T200000.ndjson
  docker/uf/swinv-data/fnaskthinserver-20260828T093000.ndjson
  docker/uf/swinv-data/linux-host-01-20260826T145150.ndjson
  testdata/ndjson/windows-host-01.ndjson
)
SCAN_DAYS=(6 3 0)

say()  { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }
rest() { curl -sk -u "$AUTH" "$@"; }
# A search, CSV out. $2 is earliest_time.
q() {
  rest "$API/servicesNS/admin/riskability/search/jobs/export" -d output_mode=csv \
    -d earliest_time="${2:-0}" -d latest_time=+1d --data-urlencode "search=$1"
}
# The single number a "| stats count" style search returns, or empty.
# "|| true": head closing the pipe early must not trip set -e/pipefail.
qnum() { { q "$1" "${2:-0}" | tail -n +2 | head -1 | tr -d '"\r '; } || true; }

# --- preflight -----------------------------------------------------------------
say "preflight"
for f in "${SCANS[@]}"; do [ -f "$f" ] || die "missing scan $f"; done
if [ "$DRY" = 0 ]; then
  docker ps --format '{{.Names}}' | grep -qx "$SPLUNK" || die "$SPLUNK is not running"
  rest "$API/services/server/info?output_mode=json" | grep -q kvStoreStatus \
    || die "splunkd does not answer on 8089"
  # Splunk refuses to search below 5 GB free, and this stages ~200 MB.
  free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
  [ "$free_gb" -ge 8 ] || die "only ${free_gb} GB free on /; splunk stops searching below 5 GB"
  # Search has to work before anything is loaded: data indexed into an
  # instance that cannot run the pipeline is half a refresh. The probe must
  # read an index. An expired license still lets "| makeresults" run, and
  # still lets data be indexed, so only a search over an index proves the
  # pipeline can run.
  # oneshot, not export: export answers a refused search with an empty 200,
  # while oneshot returns the FATAL message that says why.
  probe=$(rest "$API/services/search/jobs" -d exec_mode=oneshot -d output_mode=json -d earliest_time=0 \
            --data-urlencode 'search=| tstats count WHERE index=riskability_meta | eval rk_probe="ok"')
  if ! printf '%s' "$probe" | grep -Eq '"rk_probe": *"ok"'; then
    if printf '%s' "$probe" | grep -qi licen; then
      die "Splunk refuses to search: the license has expired or is in violation.
Install a valid license (Settings > Licensing) and run this again. Nothing was loaded."
    fi
    die "a trivial search failed: $(printf '%s' "$probe" | head -c 300)"
  fi
  echo "  splunk up, search works, ${free_gb} GB free"
fi

# --- generate --------------------------------------------------------------------
NOW=$(( $(date +%s) - 60 ))
RUN=rk-refresh-$NOW
WORK=$(mktemp -d "${TMPDIR:-/tmp}/$RUN.XXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/load"
say "generate, anchored at $(date -u -d @$NOW '+%F %T') UTC"

for src in "${SCANS[@]}"; do
  h=$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    l=l.strip()
    if l:
        r=json.loads(l)
        if r.get("hostname"): print(r["hostname"]); break' "$src")
  [ -n "$h" ] || die "no hostname in $src"
  for d in "${SCAN_DAYS[@]}"; do
    t=$(( NOW - d * 86400 ))
    out="$WORK/load/scan-$h-$(date -u -d @$t +%Y%m%dT%H%M%S).ndjson"
    n=$(python3 tools/stage_scan.py "$src" "$out" --at "$t")
    printf '  %-18s -%sd  %6s records\n' "$h" "$d" "$n"
  done
done
# --end is two hours ahead because the generator stamps its scans at end-2h;
# this puts the fleet's newest scan at now, after the newest firewall event.
python3 tools/demo/make_demo_fleet.py --end $(( NOW + 7200 )) > "$WORK/load/demo-fleet.json"
python3 tools/demo/make_demo_fleet.py --end $(( NOW + 7200 )) --findings > "$WORK/demo-findings.ndjson"
python3 tools/demo/make_firewall_events.py --days 6 --end "$NOW" > "$WORK/load/firewall.json"

EXPECT=$(cat "$WORK"/load/* | grep -c .)
HOSTS=$(cat "$WORK"/load/scan-* "$WORK/load/demo-fleet.json" | python3 -c 'import json,sys
hs=set()
for l in sys.stdin:
    l=l.strip()
    if l:
        h=json.loads(l).get("hostname")
        if h: hs.add(h)
print(" ".join(sorted(hs)))')
echo "  $EXPECT events to load for $(wc -w <<<"$HOSTS") hosts: $HOSTS"

if [ "$DRY" = 1 ]; then
  say "dry run: generated in $WORK, nothing loaded"
  ls -la "$WORK/load" "$WORK/demo-findings.ndjson"
  trap - EXIT
  echo "  (left in place for inspection; remove with: rm -rf $WORK)"
  exit 0
fi

# --- clear what the last load left behind -------------------------------------
if [ "$KEEP_OLD" = 0 ]; then
  say "delete previous simulated events from the last 31 days"
  inlist=$(printf '"%s",' $HOSTS); inlist=${inlist%,}
  n=$(qnum "search (index=riskability_inventory OR index=riskability_meta) sourcetype=riskability:swinv hostname IN ($inlist) | delete | stats sum(deleted) AS n | fillnull value=0 n" -31d)
  case "$n" in ''|*[!0-9]*) die "deleting the previous scan events failed (got '$n')";; esac
  echo "  scan events deleted: $n"
  n=$(qnum "search index=riskability_demo_firewall sourcetype=demo:firewall | delete | stats sum(deleted) AS n | fillnull value=0 n" 0)
  case "$n" in ''|*[!0-9]*) die "deleting the previous firewall events failed (got '$n')";; esac
  echo "  firewall events deleted: $n"
fi

say "back up and clear the address claims (riskability_hostaddr)"
( umask 077; mkdir -p "$BACKUPS" ) || die "could not create $BACKUPS"
[ -d "$BACKUPS" ] && [ ! -L "$BACKUPS" ] && [ -O "$BACKUPS" ] \
  || die "$BACKUPS is not a directory this user owns (or is a symlink); not writing the backup there"
chmod 700 "$BACKUPS"
bk="$BACKUPS/hostaddr-$NOW.json"
# noclobber: refuse a file (or a planted symlink) already at that name.
( umask 077; set -o noclobber; rest "$KV/riskability_hostaddr?limit=0&output_mode=json" > "$bk" ) \
  || die "could not write the backup to $bk; not clearing riskability_hostaddr"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert isinstance(d,list); print("  %d rows saved to %s" % (len(d), sys.argv[1]))' "$bk" \
  || die "could not back up riskability_hostaddr; not clearing it"
code=$(rest -X DELETE "$KV/riskability_hostaddr" -o /dev/null -w '%{http_code}')
[ "$code" = 200 ] || die "clearing riskability_hostaddr answered HTTP $code"

say "replace the demo findings in the KV store"
rest -X DELETE -G "$KV/riskability_findings_state" --data-urlencode 'query={"demo":"true"}' -o /dev/null
python3 -c 'import json,sys; print(json.dumps([json.loads(l) for l in open(sys.argv[1]) if l.strip()]))' \
  "$WORK/demo-findings.ndjson" > "$WORK/demo-findings-batch.json"
saved=$(rest -X POST -H 'Content-Type: application/json' --data-binary @"$WORK/demo-findings-batch.json" \
          "$KV/riskability_findings_state/batch_save" \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else d)')
echo "  demo findings saved: $saved"

# --- load ------------------------------------------------------------------------
say "load into $SPLUNK"
CDIR=/tmp/$RUN
docker exec -u root "$SPLUNK" mkdir -p "$CDIR"
docker cp "$WORK/load/." "$SPLUNK:$CDIR/" >/dev/null
docker exec -u root "$SPLUNK" chown -R splunk:splunk "$CDIR"
oneshot() {  # file index sourcetype [host]
  local extra=(); [ -n "${4:-}" ] && extra=(-host "$4")
  docker exec -u splunk "$SPLUNK" /opt/splunk/bin/splunk add oneshot "$CDIR/$1" \
    -index "$2" -sourcetype "$3" "${extra[@]}" -auth "$AUTH" 2>&1 | grep -v '^WARNING' | tail -1 || true
}
for f in "$WORK"/load/scan-*; do
  oneshot "$(basename "$f")" riskability_inventory riskability:swinv riskability-uf
done
oneshot demo-fleet.json riskability_meta riskability:swinv
oneshot firewall.json riskability_demo_firewall demo:firewall

say "wait for all $EXPECT events to be indexed"
got=0
for i in $(seq 1 90); do
  got=$(qnum "| tstats count WHERE (index=riskability_inventory OR index=riskability_meta OR index=riskability_demo_firewall) source=\"$CDIR/*\"")
  case "$got" in ''|*[!0-9]*) got=0;; esac
  [ "$got" -ge "$EXPECT" ] && break
  [ $(( i % 4 )) = 0 ] && echo "  $got / $EXPECT"
  sleep 10
done
[ "$got" -ge "$EXPECT" ] || die "only $got of $EXPECT events indexed after 15 minutes; files left in $SPLUNK:$CDIR"
echo "  $got indexed"
docker exec -u root "$SPLUNK" rm -rf "$CDIR"

# --- pipeline --------------------------------------------------------------------
if [ "$PIPELINE" = 1 ]; then
  for c in $(seq 1 "$CYCLES"); do
    say "pipeline cycle $c of $CYCLES (takes a while)"
    bash tools/pipeline_cycle.sh | grep -v ' DONE$' || true
  done
fi

# --- report ----------------------------------------------------------------------
say "result"
echo "  events per index and day (last 7 days):"
q '| tstats count WHERE (index=riskability_inventory OR index=riskability_meta OR index=riskability_demo_firewall) BY index _time span=1d | eval day=strftime(_time,"%F") | table index day count' -7d \
  | tail -n +2 | sed 's/^/    /'
echo "  open findings:"
q '| inputlookup riskability_findings_state_lookup where status="open" | stats count AS open, dc(hostname) AS hosts, max(last_seen) AS newest | eval newest=strftime(newest,"%F %T")' \
  | sed 's/^/    /'
echo "  network grades:"
q '| inputlookup riskability_netevidence_lookup | stats count BY observed_grade, identity_state' | sed 's/^/    /'
say "done. hostaddr backup: $bk"
