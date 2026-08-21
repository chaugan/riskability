#!/usr/bin/env bash
# Sync the app into the dev Splunk container and reload it.
# Uses docker cp rather than a bind mount so the container keeps Splunk's own
# file ownership, which Splunk is fussy about.
set -euo pipefail
CONTAINER=${CONTAINER:-riskability-splunk}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/docker/.env"

for app in riskability TA-riskability; do
  [ -d "$ROOT/app/$app" ] || continue
  docker exec -u splunk "$CONTAINER" rm -rf "/opt/splunk/etc/apps/$app"
  docker cp "$ROOT/app/$app" "$CONTAINER:/opt/splunk/etc/apps/$app"
  docker exec -u root "$CONTAINER" chown -R splunk:splunk "/opt/splunk/etc/apps/$app"
  # Bytecode caches are build artefacts; AppInspect flags them and they can
  # shadow edited sources across a re-deploy.
  docker exec -u splunk "$CONTAINER" sh -c "find /opt/splunk/etc/apps/$app -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true"
  echo "deployed $app"
done

if [ "${RESTART:-0}" = "1" ]; then
  docker exec -u splunk "$CONTAINER" /opt/splunk/bin/splunk restart -auth "admin:$SPLUNK_PASSWORD" >/dev/null
  echo "splunk restarted"
else
  docker exec -u splunk "$CONTAINER" /opt/splunk/bin/splunk reload auth -auth "admin:$SPLUNK_PASSWORD" >/dev/null 2>&1 || true
  echo "deployed (pass RESTART=1 for a full restart when conf files change)"
fi
