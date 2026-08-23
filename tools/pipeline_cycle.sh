#!/usr/bin/env bash
# One pipeline cycle: dispatch every scheduled search in cron order, the way the
# scheduler would. Bounded waits throughout - no loop here can outlive the run.
set -u
cd /opt/code/riskability
source docker/.env
mapfile -t SEARCHES < <(python3 tools/pipeline_order.py)
echo "cycle: ${#SEARCHES[@]} searches"
for name in "${SEARCHES[@]}"; do
  enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$name")
  sid=$(curl -sk -u "admin:$SPLUNK_PASSWORD" -X POST \
        "https://127.0.0.1:8089/servicesNS/nobody/riskability/saved/searches/$enc/dispatch" \
        -d trigger_actions=1 2>/dev/null | grep -o '<sid>[^<]*' | sed 's/<sid>//')
  [ -z "$sid" ] && { printf '  %-56s DISPATCH-FAILED\n' "$name"; continue; }
  for i in $(seq 1 60); do
    st=$(curl -sk -u "admin:$SPLUNK_PASSWORD" \
         "https://127.0.0.1:8089/services/search/jobs/$sid?output_mode=json" 2>/dev/null \
         | python3 -c "import sys,json
try: print(json.load(sys.stdin)['entry'][0]['content']['dispatchState'])
except Exception: print('')" 2>/dev/null)
    case "$st" in DONE|FAILED) break;; esac
    sleep 5
  done
  printf '  %-56s %s\n' "$name" "${st:-TIMEOUT}"
done
