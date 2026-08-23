#!/usr/bin/env bash
#
# End-to-end fresh-install test: nothing, to a working app, to repeated loads.
#
# What this proves, and why each piece of it is here:
#
#   * The app works when INSTALLED FROM THE PACKAGE. tools/deploy-dev.sh copies
#     a source tree into a container, which is a development shortcut and tests
#     the tree rather than the archive. Every defect this harness has any chance
#     of catching -- a file left out of the package, a mode bit lost in the tar,
#     a collection that never gets created -- is invisible to that path by
#     construction. So this installs dist/*.spl the way an operator does.
#
#   * It works from NOTHING. The containers and their volumes are destroyed
#     first. A test that runs against an instance somebody has already been
#     working in cannot tell "the app creates this" from "this was already
#     there", and the things a fresh instance lacks -- receiving on 9997, the
#     indexes, every KV Store collection -- are exactly the things that make a
#     new install report a clean fleet when it is simply blind.
#
#   * It SHIPS NO VULNERABILITY DATA. The operator supplies all of it. That is
#     asserted twice: nothing feed-shaped inside the packages, and every KV
#     collection empty after install and before an import.
#
#   * It works in EITHER ORDER. Importing a feed and pointing a forwarder at an
#     inventory are two separate jobs, often two different people, and nothing
#     decides which happens first. So both orders are run as separate scenarios,
#     from separate fresh installs, with the SAME host data -- and the test is
#     that they converge on the same answer. The dangerous order is data first:
#     a host seen before any feed existed has already been checkpointed, and if
#     the import does not bring it back for matching it stays clean-looking
#     until something else changes its software, which on a stable server can be
#     months and reads on every dashboard as good news.
#
#   * Loading data REPEATEDLY keeps working. One scan producing findings is the
#     easy half. The half that goes wrong is the second host, the same file
#     arriving twice, and a newer scan superseding an older one, because each of
#     those is a chance to double-count, to lose a host, or to leave findings
#     from a scan that no longer exists asserting that software is installed
#     when it is not.
#
# The pipeline is driven the way the scheduler drives it: the shipped saved
# searches, dispatched through the same REST endpoint, in cron order. Order is
# load-bearing -- close is gated on evidence written by the acknowledgement,
# which is gated on the fold-in, which needs the matcher's output -- so the
# order is read out of the shipped savedsearches.conf rather than hardcoded.
#
# One cycle of that pipeline does not necessarily produce every finding.
# Indexing the matcher's output is asynchronous, and a fold-in that runs before
# the events are searchable folds nothing, which withholds the acknowledgement,
# which withholds closing. So the harness runs the pipeline until the
# open-finding count stops changing and reports HOW MANY cycles that took. That
# number is the headline result: it says how long after an install the app tells
# the truth.
#
# Assertions do not abort the run. One run is meant to give a full picture, so a
# failed assertion is recorded and the next stage still runs; only a failure
# that makes later stages meaningless (no Splunk, no app) stops the harness, and
# even then the summary is printed.
#
#   tools/test_fresh_install.sh
#
# Environment overrides:
#   RK_FEED_BUNDLE   feed bundle to import (default testdata/feeds/riskability-feed-combined.tar.gz)
#   RK_MAX_CYCLES    convergence bound per stage (default 10)
#   RK_SKIP_BUILD    1 to reuse dist/*.spl instead of rebuilding

# Deliberately not "set -e". Every stage has to run.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE="$ROOT/docker/docker-compose.yml"
SPLUNK=riskability-splunk
UF=riskability-uf
SWINV="$ROOT/docker/uf/swinv-data"

# testdata/feeds/riskability-feed-combined.tar.gz, not riskability-feed-full.tar.gz.
# "full" is full of OSV, which is Linux and language ecosystems only. Windows
# software carries no purl and is matched purely on its CPEs, so against that
# bundle the Windows host in stage 6 would report zero findings -- and the stage
# would be measuring the feed's coverage while appearing to measure the app.
# The combined bundle carries the same OSV ecosystems plus nvd, which is what
# gives both hosts something to match. Stage 5 asserts that rather than assuming
# it, so pointing RK_FEED_BUNDLE at an OSV-only bundle fails with the reason
# instead of quietly halving the test.
FEED_BUNDLE=${RK_FEED_BUNDLE:-$ROOT/testdata/feeds/riskability-feed-combined.tar.gz}
MAX_CYCLES=${RK_MAX_CYCLES:-10}

# shellcheck source=/dev/null
source "$ROOT/docker/.env"
: "${SPLUNK_PASSWORD:?docker/.env must define SPLUNK_PASSWORD}"

RUNDIR=$(mktemp -d -t riskability-fresh-XXXXXX)
RESULTS="$RUNDIR/results.tsv"
: > "$RESULTS"

HOST_A=linux-host-01
HOST_B=windows-host-01

# Filled in as stages run, so the summary can quote them even after a failure.
declare -A CYCLES=()
declare -a PIPELINE=()

START_EPOCH=$SECONDS
FAILURES=0
ASSERTIONS=0

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

say() {
  printf '[%s +%04ds] %s\n' "$(date -u +%H:%M:%S)" "$((SECONDS - START_EPOCH))" "$*"
}

stage() {
  echo
  echo "============================================================================"
  printf '  STAGE %s\n' "$*"
  echo "============================================================================"
}

# record <stage> <assertion> <expected> <actual> <PASS|FAIL>
record() {
  ASSERTIONS=$((ASSERTIONS + 1))
  [ "$5" = "FAIL" ] && FAILURES=$((FAILURES + 1))
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$RESULTS"
  printf '  %-4s %s\n       expected: %s\n       actual:   %s\n' "$5" "$2" "$3" "$4"
}

assert_eq() {   # <stage> <assertion> <expected> <actual>
  local r=FAIL; [ "$3" = "$4" ] && r=PASS
  record "$1" "$2" "$3" "$4" "$r"
  [ "$r" = PASS ]
}

# Numeric comparisons take the operator as a word so the assertion line reads as
# the claim being made rather than as an expression to decode.
assert_num() { # <stage> <assertion> <op> <bound> <actual>
  local r=FAIL
  case "$5" in ''|*[!0-9-]*) record "$1" "$2" "$3 $4" "$5 (not a number)" FAIL; return 1;; esac
  if [ "$5" -"$3" "$4" ]; then r=PASS; fi
  record "$1" "$2" "$3 $4" "$5" "$r"
  [ "$r" = PASS ]
}

fatal() {
  say "FATAL: $*"
  record "${CURRENT_STAGE:-?}" "$*" "the run continues" "the run cannot continue" FAIL
  summary
  exit 1
}

summary() {
  echo
  echo "============================================================================"
  echo "  SUMMARY"
  echo "============================================================================"
  {
    printf 'STAGE\tASSERTION\tEXPECTED\tACTUAL\tRESULT\n'
    cat "$RESULTS"
  } | awk -F'\t' '
    { for (i = 1; i <= NF; i++) { l = length($i); if (l > w[i]) w[i] = l }
      n++; for (i = 1; i <= NF; i++) row[n, i] = $i; cols = NF }
    END {
      for (r = 1; r <= n; r++) {
        line = ""
        for (i = 1; i <= cols; i++)
          line = line sprintf("%-*s  ", w[i], row[r, i])
        sub(/ +$/, "", line)
        print "  " line
        if (r == 1) { sep = ""; for (i = 1; i <= cols; i++) { for (j = 0; j < w[i] + 2; j++) sep = sep "-" } print "  " sep }
      }
    }'
  echo
  echo "  convergence cycles (pipeline runs needed before the open-finding count settled)"
  local k
  if [ "${#CYCLES[@]}" -gt 0 ]; then
    for k in "${!CYCLES[@]}"; do printf '    %-32s %s\n' "$k" "${CYCLES[$k]}"; done | sort
  else
    echo "    none reached"
  fi
  echo
  printf '  %d assertions, %d failed, %d minutes elapsed\n' \
    "$ASSERTIONS" "$FAILURES" "$(((SECONDS - START_EPOCH) / 60))"
  echo "  full log artefacts in $RUNDIR"
  if [ "$FAILURES" -eq 0 ]; then echo "  RESULT: PASS"; else echo "  RESULT: FAIL"; fi
}

# ---------------------------------------------------------------------------
# Talking to the instance
# ---------------------------------------------------------------------------

# curl runs INSIDE the container rather than against the published port: the
# harness must work whether or not 8089 is reachable from this host, and the
# published ports are bound to 127.0.0.1 in a compose file that is free to
# change them.
#
# Every exec is wrapped in "timeout" and given /dev/null for stdin. Both are
# scars. docker exec inherits whatever the process inside does, and a call that
# never returns takes the harness with it -- this script hung for eleven minutes
# on a "splunk status" that spun at 100% CPU inside a container that was
# otherwise perfectly healthy. And "docker exec -i" reads the stdin it is
# given, so inside a "while read ... done < file" loop the first call drains the
# rest of the file: every pipeline cycle ran one search out of twenty-eight,
# reported success, and settled at zero findings.
rest() { # rest GET|POST <path> [curl args...]
  local method=$1 path=$2; shift 2
  timeout 960 docker exec -u splunk "$SPLUNK" curl -sS -k --max-time 900 \
    -u "admin:$SPLUNK_PASSWORD" -X "$method" \
    "https://localhost:8089${path}" "$@" < /dev/null
}

json() { python3 -c 'import sys,json;
d=json.load(sys.stdin)
for k in sys.argv[1:]:
    if d is None: break
    d = d[int(k)] if isinstance(d, list) else d.get(k)
print("" if d is None else d)' "$@" 2>/dev/null; }

# How many entries a Splunk REST reply carries. Counting is not the same as
# grepping the body for the name: a 404 from splunkd is itself JSON and can
# quote the endpoint that was asked for, so a grep reports a missing input as
# present.
entry_count() { python3 -c 'import sys,json
try: print(len(json.load(sys.stdin).get("entry") or []))
except Exception: print(0)' 2>/dev/null; }

# How many rows a KV Store collection holds, capped: this is asked of
# collections that must be EMPTY, so one row is all the evidence needed and
# counting three million is not.
kv_rows() { # kv_rows <collection> [limit]
  rest GET "/servicesNS/nobody/riskability/storage/collections/data/$1?limit=${2:-1}&output_mode=json" \
    | python3 -c 'import sys,json
try: print(len(json.load(sys.stdin)))
except Exception: print(-1)' 2>/dev/null
}

spl() { # spl <search> [extra CLI args...]
  local query=$1; shift
  timeout 1800 docker exec -u splunk "$SPLUNK" /opt/splunk/bin/splunk search "$query" \
    -app riskability -maxout 0 -output csv -auth "admin:$SPLUNK_PASSWORD" "$@" \
    < /dev/null 2>/dev/null
}

# A single number out of a "| stats count" search. Returns the literal string
# "ERR" on failure rather than 0: a search that could not run and a fleet with
# no findings look identical otherwise, and one of those is a passing test.
spl_number() {
  local out rc
  out=$(spl "$@"); rc=$?
  [ $rc -ne 0 ] && { echo ERR; return 1; }
  out=$(printf '%s\n' "$out" | tr -d '\r' | grep -E '^[0-9]+$' | tail -1)
  [ -z "$out" ] && { echo ERR; return 1; }
  echo "$out"
}

open_findings() { # [hostname]
  if [ $# -eq 1 ]; then
    spl_number "$(printf '| inputlookup riskability_findings_state_lookup where status="open" AND hostname="%s" | stats count' "$1")"
  else
    spl_number '| inputlookup riskability_findings_state_lookup where status="open" | stats count'
  fi
}

# How many hosts the app currently considers due for re-matching.
#
# Called with an explicit "search" prefix, not a leading pipe. The macro expands
# to a search TERM, so "| `riskability_dirty_hosts`" parses as a pipe into a
# bare field expression and fails; the app's own call site inside
# riskability_dirty_inventory writes "[search `riskability_dirty_hosts` ...]"
# for the same reason.
#
# The time range is given explicitly because the macro's computed-digest branch
# inherits the caller's, and a default range that happens not to cover the
# newest scan reports an empty fleet rather than an error.
dirty_hosts() {
  spl_number 'search `riskability_dirty_hosts` | stats count' \
    -earliest_time -24h -latest_time +1h
}

hosts_reporting() {
  spl_number '| `riskability_hosts_seen` | stats count'
}

# ---------------------------------------------------------------------------
# Waiting
# ---------------------------------------------------------------------------

# wait_for <seconds> <label> <shell condition...>
wait_for() {
  local limit=$1 label=$2; shift 2
  local deadline=$((SECONDS + limit))
  while [ $SECONDS -lt $deadline ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 5
  done
  say "timed out after ${limit}s waiting for $label"
  return 1
}

# The output is captured and THEN matched, never piped into "grep -q".
# Under "set -o pipefail" grep exits the moment it matches, the writer upstream
# dies of SIGPIPE, and the pipeline reports failure -- so the check says "no"
# precisely when the answer is yes. The same trap is documented in
# tools/package.sh, where it made a verification script lie.
cli_status() { # cli_status <container> <splunk home>
  local out
  out=$(timeout 60 docker exec -u splunk "$1" "$2/bin/splunk" status 2>/dev/null) || return 1
  grep -q "splunkd is running" <<<"$out"
}

splunkd_up() { cli_status "$SPLUNK" /opt/splunk; }

# The CLI is called ONCE per readiness gate, never in a poll loop. What hung
# this harness was "splunk status" spinning at 100% CPU while the container was
# still starting, and "timeout" does not help as much as it looks: it kills the
# docker exec on this side and leaves the process spinning inside, so a five
# second poll interval accumulates spinning copies inside a two-CPU container.
# So the loop waits on something inert and the CLI answers once, afterwards.
uf_running() {
  local i
  for i in 1 2 3; do cli_status "$UF" /opt/splunkforwarder && return 0; done
  return 1
}

# The forwarder image disables its management port, so there is no REST to poll
# on that side. The pid file is the cheapest fact that means the same thing.
uf_splunkd_started() {
  timeout 60 docker exec -u splunk "$UF" \
    sh -c 'test -s /opt/splunkforwarder/var/run/splunk/splunkd.pid' < /dev/null
}

kvstore_ready() {
  local s
  s=$(rest GET "/services/kvstore/status?output_mode=json" 2>/dev/null \
      | json entry 0 content current status)
  [ "$s" = ready ]
}

# Readiness is decided on the management port, not on the CLI. splunkd
# answering REST is the same fact and cannot spin; the CLI is asserted
# separately, once, where a hang costs one timeout rather than the run.
splunk_ready() {
  [ -n "$(rest GET '/services/server/info?output_mode=json' 2>/dev/null | json entry 0 content version)" ] \
    && kvstore_ready
}

uf_provisioned() {
  timeout 60 docker logs "$UF" > "$RUNDIR/uf.log" 2>&1
  grep -q "Ansible playbook complete" "$RUNDIR/uf.log"
}

# ---------------------------------------------------------------------------
# Driving the scheduler's searches
# ---------------------------------------------------------------------------

urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

dispatch_saved() { # <saved search name>
  local name=$1 enc sid state started
  enc=$(urlenc "$name")
  started=$SECONDS
  sid=$(rest POST "/servicesNS/nobody/riskability/saved/searches/$enc/dispatch?output_mode=json" \
          -d trigger_actions=1 | json sid)
  if [ -z "$sid" ]; then
    say "    dispatch REFUSED: $name"
    return 1
  fi
  local deadline=$((SECONDS + 1800))
  while [ $SECONDS -lt $deadline ]; do
    state=$(rest GET "/services/search/jobs/$(urlenc "$sid")?output_mode=json" \
            | json entry 0 content dispatchState)
    case "$state" in
      DONE) printf '    %-62s %4ds\n' "$name" "$((SECONDS - started))"; return 0 ;;
      FAILED) say "    FAILED: $name"; return 1 ;;
      "") say "    LOST: $name (job vanished)"; return 1 ;;
    esac
    sleep 3
  done
  say "    TIMEOUT: $name"
  return 1
}

# The scheduler has eight minutes between the matcher at :17 and the fold-in at
# :25; dispatched back to back there is none, and "collect" writes through a
# spool file that the indexer picks up asynchronously. Folding before those
# events are searchable folds nothing, withholds the acknowledgement, and
# withholds closing -- so this waits for the findings index to stop growing
# rather than pretending the gap in the cron schedule is incidental.
settle_index() {
  local prev=-1 now stable=0 deadline=$((SECONDS + 180))
  while [ $SECONDS -lt $deadline ]; do
    now=$(spl_number '| tstats count where index=riskability_findings')
    case "$now" in ERR) now=0 ;; esac
    if [ "$now" = "$prev" ]; then
      stable=$((stable + 1))
      [ "$stable" -ge 2 ] && return 0
    else
      stable=0
    fi
    prev=$now
    sleep 5
  done
  return 0
}

# CYCLE_FAILURES is what makes "the pipeline survived an empty feed" an
# assertion rather than an impression. A saved search that errors still leaves
# the finding count where it was, so counting findings alone cannot tell a
# pipeline that ran cleanly from one that fell over.
#
# The list is read into an array ONCE rather than looped over with a redirect;
# see the note on stdin above rest().
CYCLE_FAILURES=0
run_cycle() {
  local name n=0
  CYCLE_FAILURES=0
  for name in "${PIPELINE[@]}"; do
    n=$((n + 1))
    dispatch_saved "$name" || CYCLE_FAILURES=$((CYCLE_FAILURES + 1))
    # Only the matcher needs settling; everything after it reads what it wrote.
    case "$name" in *"materialise findings") settle_index ;; esac
  done
  say "  cycle complete ($n of ${#PIPELINE[@]} searches, $CYCLE_FAILURES failed)"
}

# Run the pipeline until the open-finding count stops moving, and say how long
# that took.
#
# Convergence at zero is NOT convergence: an install where nothing ever matched
# has a count that never changes either, and reporting that as settled is the
# exact failure mode this app exists to avoid. Two consecutive zeroes end the
# loop anyway, and are reported as "stuck at zero" -- because nothing is being
# produced, so the remaining cycles would only cost time and say the same thing.
converge() { # <stage> <label> [max cycles]
  local st=$1 label=$2 max=${3:-$MAX_CYCLES}
  local prev=-1 count cycles=0 settled=0 stuck=0
  while [ "$cycles" -lt "$max" ]; do
    cycles=$((cycles + 1))
    say "pipeline cycle $cycles of at most $max ($label)"
    run_cycle
    count=$(open_findings)
    say "  open findings after cycle $cycles: $count"
    if [ "$count" = "$prev" ] && [ "$count" != ERR ]; then
      if [ "$count" -gt 0 ]; then settled=1; else stuck=1; fi
      break
    fi
    prev=$count
  done
  local verdict
  if [ "$settled" = 1 ]; then verdict=$cycles
  elif [ "$stuck" = 1 ]; then verdict="$cycles (STUCK AT ZERO)"
  else verdict="$cycles (NOT SETTLED)"; fi
  CYCLES["$label"]=$verdict
  echo
  say "### CONVERGENCE: $label -- $cycles pipeline cycles, $count open findings ($verdict) ###"
  echo
  assert_eq "$st" "open-finding count converges within $max pipeline cycles" \
    "settled" "$([ "$settled" = 1 ] && echo settled || echo "$verdict")"
}

# ---------------------------------------------------------------------------
# Loading a scan
# ---------------------------------------------------------------------------

# Copies a fixture into the forwarder's watch directory under a fresh scan-style
# filename, waits for every line to be searchable, and returns the filename.
#
# The wait is on the count of events from that exact source. Anything looser --
# a fixed sleep, or a count over the whole index -- passes while the forwarder
# is still streaming, and the stage that follows then measures a partial scan.
LAST_STAGED=""
stage_scan() { # <stage> <fixture> <host> [reuse-file]
  local st=$1 fixture=$2 host=$3 reuse=${4:-}
  local stamp name expected actual
  stamp=$(date -u +%Y%m%dT%H%M%S.000Z)
  name="${host}-${stamp}.ndjson"
  if [ -n "$reuse" ]; then
    # Byte-identical on purpose: the duplicate-load stage is about the same
    # scan arriving under a new name, so it must be a copy, not a re-render.
    cp "$SWINV/$reuse" "$SWINV/$name"
    expected=$(wc -l < "$SWINV/$name" | tr -d ' ')
  else
    expected=$("$ROOT/tools/stage_scan.py" "$fixture" "$SWINV/$name")
  fi
  LAST_STAGED=$name
  say "staged $name ($expected records) for $host"

  local q; q=$(printf '| tstats count where index=riskability_inventory source="/var/lib/swinv/%s"' "$name")
  local deadline=$((SECONDS + 900)) last=-1
  while [ $SECONDS -lt $deadline ]; do
    actual=$(spl_number "$q"); case "$actual" in ERR) actual=0 ;; esac
    [ "$actual" -ge "$expected" ] && break
    [ "$actual" != "$last" ] && say "  indexed $actual of $expected"
    last=$actual
    sleep 10
  done
  assert_eq "$st" "every record of $name reaches the inventory index" "$expected" "$actual"
}

# The six components run2 upgrades past the versions run1 reported, counted in
# whatever the app currently considers this host's newest scan. Six before the
# rescan and zero after is the whole claim: a non-zero count afterwards means the
# superseded scan is still speaking, and every finding derived from it is a
# statement about software that is no longer installed. Name AND version
# together, because "3.12" and "5.3.1" are ordinary version strings that other
# packages on this host legitimately carry.
SUPERSEDED='(name="lodash" AND version="4.17.23") OR (name="lodash.template" AND version="4.17.23") OR (name="next" AND version="16.2.2") OR (name="golang.org/x/crypto" AND version="v0.23.0") OR (name="pyyaml" AND version="3.12") OR (name="pyyaml" AND version="5.3.1")'
superseded_components() {
  spl_number "$(printf 'index=riskability_inventory sourcetype=riskability:swinv hostname="%s" NOT record_type=* earliest=-24h latest=+1h | eventstats max(_time) AS rk_newest BY hostname | where _time >= rk_newest | search %s | stats count' "$HOST_A" "$SUPERSEDED")"
}

# ---------------------------------------------------------------------------
# Provisioning, run once per scenario
# ---------------------------------------------------------------------------
#
# The two ordering scenarios each need an instance that has never held a feed,
# so these three run twice. Every assertion carries the stage that called them,
# which is what keeps the summary table readable: "the app installs cleanly" is
# a different claim the second time, on a different instance.

do_teardown() { # <stage>
  local st=$1
  say "removing containers and volumes"
  timeout 600 docker compose -f "$COMPOSE" down -v --remove-orphans >/dev/null 2>&1
  # Belt and braces: a container left behind by an earlier compose project name
  # would otherwise survive and the whole test would run against it.
  timeout 300 docker rm -f "$SPLUNK" "$UF" >/dev/null 2>&1
  timeout 300 docker volume rm -f docker_splunk-etc docker_splunk-var >/dev/null 2>&1

  local c v
  c=$(docker ps -a --filter "name=^riskability-" --format '{{.Names}}' | wc -l | tr -d ' ')
  assert_num "$st" "no riskability container survives" eq 0 "$c"
  v=$(docker volume ls --format '{{.Name}}' | grep -c 'splunk-etc\|splunk-var')
  assert_num "$st" "no Splunk etc/var volume survives" eq 0 "$v"

  # The watch directory is a bind mount, so it outlives the containers. Leaving
  # a scan in it would have the forwarder ingest a host before the stage that
  # is supposed to introduce it.
  #
  # Note for whoever runs this next: docker/uf/swinv-data is tracked, and the
  # scans checked in there are deleted by this line. That is deliberate -- the
  # directory has to start empty -- but it does leave the working tree dirty.
  # "git checkout docker/uf/swinv-data" puts them back afterwards.
  rm -f "$SWINV"/*.ndjson "$SWINV"/*.partial
  local f; f=$(ls "$SWINV" 2>/dev/null | wc -l | tr -d ' ')
  assert_num "$st" "the forwarder's watch directory is empty" eq 0 "$f"
}

do_bringup() { # <stage>
  local st=$1
  timeout 900 docker compose -f "$COMPOSE" up -d >/dev/null 2>&1 \
    || fatal "docker compose up failed"

  say "waiting for splunkd, its management port and the KV Store"
  wait_for 900 "Splunk to be ready" splunk_ready
  assert_eq "$st" "splunkd is running and answering on 8089" \
    "running" "$(splunkd_up && echo running || echo down)"
  assert_eq "$st" "the KV Store reports ready" "ready" \
    "$(rest GET '/services/kvstore/status?output_mode=json' | json entry 0 content current status)"
  [ "$(rest GET '/services/server/info?output_mode=json' | json entry 0 content version)" ] \
    || fatal "Splunk never came up"

  # The forwarder's healthcheck goes green while ansible is still provisioning
  # it, and deploying apps into a container that is about to have etc/apps
  # rewritten by /sbin/updateetc.sh loses them silently.
  say "waiting for the forwarder's ansible run to finish"
  wait_for 900 "the forwarder to provision" uf_provisioned
  assert_eq "$st" "the forwarder's ansible playbook completed" "complete" \
    "$(uf_provisioned && echo complete || echo "still provisioning")"
  wait_for 300 "the forwarder's splunkd" uf_splunkd_started
  assert_eq "$st" "the forwarder's splunkd is running" "running" \
    "$(uf_running && echo running || echo down)"
}

do_install() { # <stage>
  local st=$1 pkg base

  for pkg in "$ROOT"/dist/*.spl; do
    base=$(basename "$pkg")
    docker cp "$pkg" "$SPLUNK:/tmp/$base" >/dev/null || fatal "could not copy $base in"
    docker exec -u root "$SPLUNK" chown splunk:splunk "/tmp/$base"
    say "splunk install app $base"
    timeout 600 docker exec -u splunk "$SPLUNK" /opt/splunk/bin/splunk install app "/tmp/$base" \
      -auth "admin:$SPLUNK_PASSWORD" > "$RUNDIR/install-$base.log" 2>&1
    assert_eq "$st" "splunk install app $base succeeds" 0 "$?"
  done

  # Not app configuration, and deliberately not shipped: an app that opens a
  # listening port on someone's indexer has made a decision that is not its to
  # make. The README lists it as one of three deployment steps, and a fresh
  # install has it off -- so a harness that skipped it would test an app that
  # can never receive data.
  say "enabling receiving on 9997 (a deployment step, not app config)"
  timeout 300 docker exec -u splunk "$SPLUNK" /opt/splunk/bin/splunk enable listen 9997 \
    -auth "admin:$SPLUNK_PASSWORD" > "$RUNDIR/listen.log" 2>&1

  say "restarting Splunk so the new conf files, indexes and modular input load"
  timeout 600 docker exec -u splunk "$SPLUNK" /opt/splunk/bin/splunk stop >/dev/null 2>&1
  timeout 900 docker exec -u splunk "$SPLUNK" /opt/splunk/bin/splunk start \
    --accept-license --answer-yes --no-prompt > "$RUNDIR/restart.log" 2>&1
  wait_for 900 "Splunk to come back" splunk_ready || fatal "Splunk did not restart"

  local apps app
  apps=$(rest GET "/services/apps/local?count=0&output_mode=json" \
         | python3 -c 'import sys,json;print(" ".join(e["name"] for e in json.load(sys.stdin)["entry"]))')
  for app in riskability TA-riskability TA-riskability-indexes; do
    assert_eq "$st" "$app is installed" "present" \
      "$(grep -qw "$app" <<<"$apps" && echo present || echo missing)"
  done

  # Every collection the app declares must EXIST after installation, and every
  # one must be EMPTY. A missing collection is not an error anywhere -- a lookup
  # against one that is not there returns no rows, which on this app reads as
  # "no vulnerabilities" -- and a pre-populated one would mean the package is
  # shipping vulnerability data it has no licence to ship.
  local declared present missing=0 seeded=0 name rows total
  declared=$(grep -oP '^\[\K[^]]+' "$ROOT/app/riskability/default/collections.conf")
  total=$(wc -l <<<"$declared" | tr -d ' ')
  present=$(rest GET "/servicesNS/nobody/riskability/storage/collections/config?count=0&output_mode=json" \
            | python3 -c 'import sys,json;print("\n".join(e["name"] for e in json.load(sys.stdin)["entry"]))')
  while IFS= read -r name; do
    if grep -qxF "$name" <<<"$present"; then
      rows=$(kv_rows "$name")
      if [ "${rows:-0}" != 0 ]; then
        seeded=$((seeded + 1)); say "  NOT EMPTY on a fresh install: $name ($rows)"
      fi
    else
      missing=$((missing + 1)); say "  MISSING collection: $name"
    fi
  done <<< "$declared"
  assert_num "$st" "all $total collections in collections.conf exist" eq 0 "$missing"
  assert_num "$st" "every collection is empty before any import" eq 0 "$seeded"

  local idx
  for idx in riskability_inventory riskability_findings riskability_findings_archive riskability_audit; do
    assert_eq "$st" "index $idx exists" "1" \
      "$(rest GET "/services/data/indexes/$idx?output_mode=json" | entry_count)"
  done

  # If the feedworker lost its executable bit in the tar, splunkd never
  # introspects it and the input simply is not there -- with nothing in
  # splunkd.log to say why, and no feed import possible ever again.
  assert_num "$st" "the riskability_feedworker modular input is registered" ge 1 \
    "$(rest GET '/services/data/inputs/riskability_feedworker?output_mode=json' | entry_count)"

  local cooked
  cooked=$(rest GET '/services/data/inputs/tcp/cooked?output_mode=json')
  assert_eq "$st" "the indexer is receiving on 9997" "present" \
    "$(grep -q '9997' <<<"$cooked" && echo present || echo missing)"

  say "installing the forwarder-side apps"
  timeout 900 "$ROOT/tools/deploy-uf.sh" > "$RUNDIR/deploy-uf.log" 2>&1
  assert_eq "$st" "tools/deploy-uf.sh succeeds" 0 "$?"
  wait_for 300 "the forwarder to restart" uf_splunkd_started
  local fwd
  fwd=$(timeout 120 docker exec -u splunk "$UF" /opt/splunkforwarder/bin/splunk list forward-server \
          -auth "admin:$SPLUNK_PASSWORD" 2>/dev/null < /dev/null)
  assert_eq "$st" "the forwarder ships to the indexer" "active" \
    "$(grep -q 'riskability-splunk:9997' <<<"$fwd" && echo active || echo "not configured")"
}

# Stages the bundle and drives the import to completion through the same admin
# endpoint the Feed administration page uses. The endpoint only queues; the
# modular input does the work, because splunkd recycles the persistent-script
# process a long import would otherwise die inside.
do_import_feed() { # <stage>
  local st=$1 bundle; bundle=$(basename "$FEED_BUNDLE")
  [ -f "$FEED_BUNDLE" ] || fatal "no feed bundle at $FEED_BUNDLE"

  timeout 120 docker exec -u splunk "$SPLUNK" mkdir -p /opt/splunk/var/run/riskability/incoming
  say "staging $bundle ($(du -h "$FEED_BUNDLE" | cut -f1)) into the incoming directory"
  docker cp "$FEED_BUNDLE" "$SPLUNK:/opt/splunk/var/run/riskability/incoming/$bundle" >/dev/null
  docker exec -u root "$SPLUNK" chown splunk:splunk \
    "/opt/splunk/var/run/riskability/incoming/$bundle"

  local resp
  resp=$(rest POST "/services/riskability/feed?output_mode=json" \
          -H 'Content-Type: application/json' \
          --data "$(printf '{"action":"import","filename":"%s"}' "$bundle")")
  say "queued: $resp"
  assert_eq "$st" "the admin endpoint accepts the import" "queued" \
    "$(grep -q '"queued": true' <<<"$resp" && echo queued || echo "$resp")"

  local deadline=$((SECONDS + 5400)) state="" msg="" last=""
  while [ $SECONDS -lt $deadline ]; do
    resp=$(rest GET "/services/riskability/feed?output_mode=json")
    state=$(json status state <<<"$resp")
    msg=$(json status message <<<"$resp")
    [ "$state$msg" != "$last" ] && say "  import: ${state:-?} ${msg:-}"
    last="$state$msg"
    case "$state" in done|failed) break ;; esac
    sleep 15
  done
  assert_eq "$st" "the feed import completes" "done" "${state:-timed out}"

  resp=$(rest GET "/services/riskability/feed?output_mode=json")
  local gen adv rng consistent sources
  gen=$(json feed generation <<<"$resp")
  adv=$(json feed advisory_count <<<"$resp")
  rng=$(json feed range_count <<<"$resp")
  consistent=$(json verify consistent <<<"$resp")
  assert_num "$st" "the feed state records a generation" ge 1 "${gen:-0}"

  # Named explicitly because its absence is invisible: an OSV-only feed matches
  # every Linux package and no Windows one, and the Windows host then looks
  # clean rather than unassessed.
  sources=$(python3 -c 'import sys,json;print(" ".join(s.get("name","") for s in (json.load(sys.stdin)["feed"].get("sources") or [])))' <<<"$resp" 2>/dev/null)
  say "feed sources: $sources"
  assert_eq "$st" "the bundle carries a CPE source, without which no Windows host can match" \
    "present" "$(grep -qw nvd <<<"$sources" && echo present || echo "absent: $sources")"

  # The endpoint verifies the live generation is actually readable, which is the
  # one failure a row count cannot see: a state row promising millions of
  # advisories that are no longer reachable looks exactly like a healthy feed.
  assert_eq "$st" "the admin endpoint verifies the live feed is readable" "True" \
    "${consistent:-absent from the reply}"

  # Non-empty read against the collections themselves, not just the counter the
  # importer wrote.
  assert_num "$st" "riskability_advisories is non-empty (state claims ${adv:-0})" ge 1 "$(kv_rows riskability_advisories)"
  assert_num "$st" "riskability_ranges is non-empty (state claims ${rng:-0})" ge 1 "$(kv_rows riskability_ranges)"
}

# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

B_ORDER_COUNT=""; A_ORDER_COUNT=""; B_AFTER_6=""; A_AFTER_7=""; FIRST_A_FILE=""

stage_build() {
  CURRENT_STAGE="0 build"
  stage "0  BUILD THE PACKAGES"
  if [ "${RK_SKIP_BUILD:-0}" = 1 ]; then
    say "RK_SKIP_BUILD=1, reusing dist/"
  else
    say "tools/package.sh --verify"
    "$ROOT/tools/package.sh" --verify > "$RUNDIR/package.log" 2>&1
    assert_eq "0 build" "tools/package.sh --verify succeeds" "0" "$?" \
      || say "see $RUNDIR/package.log"
  fi
  local n; n=$(ls "$ROOT"/dist/*.spl 2>/dev/null | wc -l | tr -d ' ')
  assert_num "0 build" "dist/ holds the three installable packages" eq 3 "$n"

  # No vulnerability data may ship inside a package. It is the operator's to
  # supply and not ours to redistribute, and a bundle that crept in would also
  # make every "fresh install" assertion below meaningless.
  #
  # riskability-feedbuilder.zip is exempt by name: it is the TOOL that builds a
  # bundle, which is exactly the thing that has to ship so the operator can
  # produce their own.
  local entries bad
  entries="$RUNDIR/package-entries.txt"
  : > "$entries"
  local pkg; for pkg in "$ROOT"/dist/*.spl; do tar -tzf "$pkg" >> "$entries"; done
  bad=$(grep -Ei '(^|/)(advisories|ranges|notaffected|attack|tactics)\.jsonl$|(^|/)manifest\.json$|\.tar\.gz$|(^|/)osv|(^|/)nvd' "$entries" \
        | grep -v 'riskability-feedbuilder\.zip' | tee "$RUNDIR/package-feedlike.txt" | wc -l)
  [ "${bad:-0}" != 0 ] && sed 's/^/  ships: /' "$RUNDIR/package-feedlike.txt"
  assert_num "0 build" "no feed archive or advisory data ships inside the packages" eq 0 "${bad:-0}"
}

stage_teardown() { CURRENT_STAGE="1 teardown"; stage "1  TEARDOWN"; do_teardown "1 teardown"; }
stage_bringup()  { CURRENT_STAGE="2 bring up"; stage "2  BRING UP SPLUNK AND THE FORWARDER"; do_bringup "2 bring up"; }
stage_install()  { CURRENT_STAGE="3 install";  stage "3  INSTALL THE APPS FROM dist/*.spl"; do_install "3 install"; }

# SCENARIO B: the forwarder is pointed at a host before the operator has
# imported anything. Nothing about this is exotic -- the add-on and the feed are
# two separate jobs, often done by two different people, and whoever wires up
# the forwarder first produces exactly this state.
#
# Two things have to be true here and they pull in opposite directions. The app
# must not invent a single finding, because with no feed there is no basis for
# one. And the pipeline must survive running against empty collections, because
# the searches that record this host as seen are the same ones that have to
# bring it back once a feed arrives.
#
# Then the feed lands, and the question the scenario exists to ask: does the
# host that was already on record come back for matching? The mechanism is the
# feed generation changing, so the assertion is made directly on the dirty-host
# evaluation rather than only on the end state -- "no findings appeared" has
# many causes and this pins which one.
stage_scenario_b() {
  CURRENT_STAGE="4 scenario B"
  stage "4  SCENARIO B: DATA FIRST, THEN THE FEED ($HOST_A)"

  local gen
  gen=$(rest GET "/services/riskability/feed?output_mode=json" | json feed generation)
  # Reported as words rather than as an empty string against an empty string,
  # so the summary row says what was checked instead of showing two blanks.
  assert_eq "4 scenario B" "a freshly installed app carries no feed at all" "no feed" \
    "$([ -z "$gen" ] && echo "no feed" || echo "generation $gen")"

  stage_scan "4 scenario B" "$ROOT/testdata/ndjson/linux-host-01.ndjson" "$HOST_A"

  say "running one pipeline cycle with no feed imported"
  run_cycle
  assert_num "4 scenario B" "no scheduled search fails against empty collections" eq 0 "$CYCLE_FAILURES"
  assert_eq "4 scenario B" "no finding is invented without a feed" "0" "$(open_findings)"
  # If the host is not on record, the import has nothing to bring back and the
  # rest of this scenario would be testing the wrong thing.
  assert_num "4 scenario B" "$HOST_A is on record as having reported" ge 1 \
    "$(spl_number "$(printf '| inputlookup riskability_hoststate_lookup | search hostname="%s" | stats count' "$HOST_A")")"

  do_import_feed "4 scenario B"

  # THE ASSERTION. Every host that has reported inventory must be due for
  # re-matching the instant a new feed generation exists: a feed the fleet has
  # never been matched against makes every verdict on every host provisional,
  # whatever their software did or did not do.
  local due reporting
  reporting=$(hosts_reporting)
  due=$(dirty_hosts)
  say "hosts reporting inventory: $reporting; hosts the app considers dirty: $due"
  assert_eq "4 scenario B" "importing a feed makes every reporting host due for re-matching" \
    "$reporting" "$due"

  converge "4 scenario B" "scenario B (data, then feed)" 4
  B_ORDER_COUNT=$(open_findings "$HOST_A")
  assert_num "4 scenario B" "$HOST_A, whose data arrived first, ends up assessed" gt 0 "$B_ORDER_COUNT"
}

# SCENARIO A: the same host data against the same feed, on an instance that has
# never seen either, with the feed imported first. This is the order everyone
# tests by hand, and it is here as the control: if the two scenarios disagree,
# the disagreement is the order and nothing else.
#
# It runs on a REBUILT instance rather than the one scenario B left behind,
# because "no feed has ever been imported here" is the precondition and it can
# only be had once per instance.
stage_scenario_a() {
  CURRENT_STAGE="5 scenario A"
  stage "5  SCENARIO A: FEED FIRST, THEN DATA ($HOST_A) -- ON A REBUILT INSTANCE"
  do_teardown "5 scenario A"
  do_bringup "5 scenario A"
  do_install "5 scenario A"
  do_import_feed "5 scenario A"

  stage_scan "5 scenario A" "$ROOT/testdata/ndjson/linux-host-01.ndjson" "$HOST_A"
  FIRST_A_FILE=$LAST_STAGED
  converge "5 scenario A" "scenario A (feed, then data)"

  A_ORDER_COUNT=$(open_findings "$HOST_A")
  assert_num "5 scenario A" "$HOST_A, arriving after the feed, is assessed" gt 0 "$A_ORDER_COUNT"
  assert_num "5 scenario A" "the matcher wrote a receipt for $HOST_A" ge 1 \
    "$(spl_number "$(printf 'index=riskability_findings sourcetype=riskability:findings record_type="match_receipt" hostname="%s" earliest=0 latest=+10y | stats count' "$HOST_A")")"
  assert_num "5 scenario A" "the six components run2 will upgrade are present now" eq 6 \
    "$(superseded_components)"

  # The verdict on the pair. Same package, same feed, same host, two install
  # orders: if these differ, one of the two orders is under-reporting risk, and
  # which one it is does not depend on anything an operator can see.
  assert_eq "5 scenario A" "both install orders converge on the same open-finding count" \
    "$A_ORDER_COUNT" "${B_ORDER_COUNT:-scenario B did not run}"
}

stage_second_host() {
  CURRENT_STAGE="6 second host"
  stage "6  LOAD A SECOND HOST ($HOST_B)"
  local before=$A_ORDER_COUNT
  stage_scan "6 second host" "$ROOT/testdata/ndjson/windows-host-01.ndjson" "$HOST_B"
  converge "6 second host" "stage 6 second host"

  B_AFTER_6=$(open_findings "$HOST_B")
  assert_num "6 second host" "$HOST_B now has open findings" gt 0 "$B_AFTER_6"
  # The first host was not re-scanned, so nothing about it may move. If it does,
  # a second host arriving is enough to disturb the first one's answer.
  assert_eq "6 second host" "$HOST_A's open findings are unchanged" \
    "$before" "$(open_findings "$HOST_A")"
  assert_eq "6 second host" "the fleet total is both hosts' findings" \
    "$((before + B_AFTER_6))" "$(open_findings)"
}

stage_duplicate() {
  CURRENT_STAGE="7 duplicate"
  stage "7  RE-LOAD THE SAME SCAN UNDER A NEW FILENAME"
  local before_a before_total raw_before raw_after
  before_a=$(open_findings "$HOST_A")
  before_total=$(open_findings)
  raw_before=$(spl_number "$(printf '| tstats count where index=riskability_inventory source="/var/lib/swinv/%s*"' "$HOST_A")")

  # crcSalt = <SOURCE> makes the add-on treat a new filename as a new file even
  # when the bytes are identical, which is what the fixture reproduces: the same
  # scan really is read and indexed twice. If it were skipped at the forwarder
  # the stage would pass without testing anything, so the raw count is asserted
  # to have grown before the finding count is asserted not to have.
  stage_scan "7 duplicate" "" "$HOST_A" "$FIRST_A_FILE"
  say "duplicate md5: $(md5sum "$SWINV/$FIRST_A_FILE" "$SWINV/$LAST_STAGED" | awk '{print $1}' | tr '\n' ' ')"
  raw_after=$(spl_number "$(printf '| tstats count where index=riskability_inventory source="/var/lib/swinv/%s*"' "$HOST_A")")
  assert_num "7 duplicate" "the duplicate really was re-indexed (raw events grew)" gt "$raw_before" "$raw_after"

  converge "7 duplicate" "stage 7 duplicate load"

  assert_eq "7 duplicate" "$HOST_A's open findings did not double" \
    "$before_a" "$(open_findings "$HOST_A")"
  assert_eq "7 duplicate" "the fleet total did not double" \
    "$before_total" "$(open_findings)"
  assert_eq "7 duplicate" "$HOST_B is untouched" "$B_AFTER_6" "$(open_findings "$HOST_B")"
  A_AFTER_7=$(open_findings "$HOST_A")
}

stage_later_scan() {
  CURRENT_STAGE="8 later scan"
  stage "8  LOAD A SECOND, LATER SCAN FOR $HOST_A"
  # The run2 fixture is the same host with six packages upgraded past their
  # fixed versions, so the honest expectation is that the count FALLS and that
  # the findings which fell are recorded as upgraded rather than merely gone.
  local before=$A_AFTER_7
  stage_scan "8 later scan" "$ROOT/testdata/ndjson/linux-host-01-run2.ndjson" "$HOST_A"
  converge "8 later scan" "stage 8 later scan"

  local after; after=$(open_findings "$HOST_A")
  assert_num "8 later scan" "$HOST_A's open findings fall after the patched scan" lt "$before" "$after"
  assert_num "8 later scan" "findings retired by the upgrade are recorded as upgraded" ge 1 \
    "$(spl_number "$(printf '| inputlookup riskability_findings_state_lookup | search hostname="%s" closure_reason="upgraded" | stats count' "$HOST_A")")"

  # Nothing from the superseded scan may still be asserting itself. A finding
  # older than the host's last acknowledged fold was not produced by the scan
  # that is now current, so an open one is a stale claim about software that
  # has been replaced.
  assert_eq "8 later scan" "no open finding for $HOST_A predates the current match" "0" \
    "$(spl_number "$(printf '| inputlookup riskability_findings_state_lookup where status="open" AND hostname="%s" | lookup riskability_matchstate_lookup hostname OUTPUT folded_run AS host_folded_run | where isnotnull(host_folded_run) AND last_match_run < tonumber(host_folded_run) - 300 | stats count' "$HOST_A")")"

  # The superseded scan's inventory must not linger either. run2 upgrades six
  # components past the versions run1 reported; if any of those old versions is
  # still part of what the app considers this host's current state, the earlier
  # scan is still speaking and every finding derived from it is a claim about
  # software that is not installed.
  assert_eq "8 later scan" "none of the six superseded components survives in $HOST_A's current inventory" "0" \
    "$(superseded_components)"

  assert_eq "8 later scan" "$HOST_B is untouched by $HOST_A's rescan" \
    "$B_AFTER_6" "$(open_findings "$HOST_B")"
}

# ---------------------------------------------------------------------------

main() {
  say "run artefacts: $RUNDIR"
  python3 "$ROOT/tools/pipeline_order.py" > "$RUNDIR/pipeline_order.txt" \
    || fatal "could not read the scheduled searches out of savedsearches.conf"
  mapfile -t PIPELINE < "$RUNDIR/pipeline_order.txt"
  [ "${#PIPELINE[@]}" -gt 0 ] || fatal "savedsearches.conf yielded no scheduled searches"
  say "${#PIPELINE[@]} scheduled searches, in cron order"

  stage_build
  stage_teardown
  stage_bringup
  stage_install
  stage_scenario_b
  stage_scenario_a
  stage_second_host
  stage_duplicate
  stage_later_scan

  stage "9  SUMMARY"
  summary
  [ "$FAILURES" -eq 0 ]
}

main "$@"
