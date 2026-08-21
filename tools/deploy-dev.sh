#!/usr/bin/env bash
# Sync the app into the dev Splunk container and reload it.
# Uses docker cp rather than a bind mount so the container keeps Splunk's own
# file ownership, which Splunk is fussy about.
set -euo pipefail
CONTAINER=${CONTAINER:-riskability-splunk}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/docker/.env"

# The downloadable feed builder is a build artefact, not a checked-in file, so
# build it before syncing or the admin page offers a download that is missing.
"$ROOT/tools/make-feedbuilder.sh"
"$ROOT/tools/build-viz.sh"

for app in riskability TA-riskability TA-riskability-indexes; do
  [ -d "$ROOT/app/$app" ] || continue
  # Replace default/ and bin/ but never local/ or metadata/local.meta: Splunk
  # writes runtime state there (the is_configured flag, any UI edits), and an
  # upgrade that deletes it is exactly the upgrade that loses an operator's
  # customisations. Splunk's own precedence rules expect local/ to survive.
  docker exec -u splunk "$CONTAINER" sh -c "
    cd /opt/splunk/etc/apps/$app 2>/dev/null || exit 0
    find . -mindepth 1 -maxdepth 1 ! -name local ! -name metadata -exec rm -rf {} +
    [ -d metadata ] && find metadata -maxdepth 1 -type f ! -name local.meta -delete
    true"
  docker exec -u splunk "$CONTAINER" mkdir -p "/opt/splunk/etc/apps/$app"
  docker cp "$ROOT/app/$app/." "$CONTAINER:/opt/splunk/etc/apps/$app/"
  docker exec -u root "$CONTAINER" chown -R splunk:splunk "/opt/splunk/etc/apps/$app"
  # Splunk will not introspect a modular input script that is not executable,
  # and the failure is silent: the input simply never appears under
  # /services/data/inputs. docker cp preserves the source mode, so this only
  # guards against a checkout that lost the bit.
  docker exec -u splunk "$CONTAINER" sh -c "chmod +x /opt/splunk/etc/apps/$app/bin/*feedworker*.py 2>/dev/null || true"
  # Bytecode caches are build artefacts; AppInspect flags them and they can
  # shadow edited sources across a re-deploy.
  docker exec -u splunk "$CONTAINER" sh -c "find /opt/splunk/etc/apps/$app -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true"
  echo "deployed $app"
done

if [ "${RESTART:-0}" = "1" ]; then
  # "splunk restart" stops cleanly but its start half waits on a license
  # prompt and never completes non-interactively, leaving splunkd down. Stop
  # and start explicitly with the acceptance flags instead.
  docker exec -u splunk "$CONTAINER" /opt/splunk/bin/splunk stop >/dev/null 2>&1 || true
  docker exec -u splunk "$CONTAINER" /opt/splunk/bin/splunk start \
    --accept-license --answer-yes --no-prompt >/dev/null
  echo "splunk restarted"
else
  docker exec -u splunk "$CONTAINER" /opt/splunk/bin/splunk reload auth -auth "admin:$SPLUNK_PASSWORD" >/dev/null 2>&1 || true
  echo "deployed (pass RESTART=1 for a full restart when conf files change)"
fi
