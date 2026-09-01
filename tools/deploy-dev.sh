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

# All five packages the repository ships. riskability-config and
# TA-riskability-ai joined in 1.3.0; missing one from this list is how a
# developer ends up debugging a configuration app that exists in git but has
# never been installed anywhere.
for app in riskability riskability-config TA-riskability TA-riskability-indexes TA-riskability-ai; do
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
  # The dev portal reverse-proxies Splunk under a share prefix, and Splunk builds
# absolute asset URLs, so it has to be told to serve from that same prefix.
# The prefix belongs to a portal SHARE, which targets a registered service by
# name -- so the service has to keep the name the share was minted against.
# Renaming it leaves the share pointing at nothing.
# The setting lives in the etc volume: recreating the container drops it, and
# the only symptom is that the portal link breaks while localhost:8000 works
# perfectly -- which reads as the portal being at fault. Restored here so a
# rebuild does not silently take the environment away from whoever is using it.
#
# tools.proxy.on matters as much as the prefix. Without it Splunk answers every
# redirect with an absolute URL built from the Host header it was proxied with,
# so the first navigation throws the browser from the portal to
# http://127.0.0.1:8000/... -- which is unreachable for anybody not sitting on
# this machine. With it, Splunk honours X-Forwarded-Host and redirects back to
# the portal's own hostname.
#
# Register the service the way the portal's own guide says, once:
#   curl -X POST http://localhost:3300/api/services -H "Authorization: Bearer $TOKEN" \
#        -d '{"name":"riskability","target":"http://localhost:8000"}'
# Both default to empty, and the block below is skipped when they are. They
# describe one developer's reverse proxy, not anything about this app, and a
# share path is a working URL to somebody's instance - not a thing to ship in a
# public repository. Export them to use it:
#   RISKABILITY_SHARE_PREFIX=/share/xxxx RISKABILITY_PROXY_BASE=host:443 ./tools/deploy-dev.sh
SHARE_PREFIX="${RISKABILITY_SHARE_PREFIX:-}"
PROXY_BASE="${RISKABILITY_PROXY_BASE:-}"
if [ -n "$SHARE_PREFIX" ] && [ -n "$PROXY_BASE" ]; then
  docker exec -u splunk "$CONTAINER" sh -c \
    "grep -q 'root_endpoint = $SHARE_PREFIX' /opt/splunk/etc/system/local/web.conf 2>/dev/null || \
     printf '[settings]\nroot_endpoint = %s\ntools.proxy.on = True\ntools.proxy.base = %s\n' '$SHARE_PREFIX' '$PROXY_BASE' > /opt/splunk/etc/system/local/web.conf" \
    >/dev/null 2>&1 || true
fi

docker exec -u splunk "$CONTAINER" /opt/splunk/bin/splunk reload auth -auth "admin:$SPLUNK_PASSWORD" >/dev/null 2>&1 || true
  # Views are cached by splunkd and are NOT refreshed by "reload auth". Without
  # this the file on disk is the new one, the REST endpoint still serves the old
  # one, and the browser draws a dashboard you have already changed. It looks
  # exactly like a change that did not work, which is the most expensive way to
  # be wrong about a dashboard: measured a panel height twice against a version
  # that was no longer on disk.
  # Views AND saved searches are both cached by splunkd, and neither is
  # refreshed by "reload auth". The saved search case is the nastier of the two:
  # dispatching one over REST runs the definition splunkd has in memory, so a
  # pipeline test can pass or fail against a version of the search that is no
  # longer on disk. Cost an afternoon: a field added to a snapshot job kept
  # coming back empty because the job being run was the previous one.
  for app in riskability riskability-config TA-riskability TA-riskability-indexes TA-riskability-ai; do
    for endpoint in data/ui/views saved/searches admin/macros admin/transforms-lookup admin/collections-conf; do
      docker exec -u splunk "$CONTAINER" curl -sk -u "admin:$SPLUNK_PASSWORD" -X POST \
        "https://localhost:8089/servicesNS/nobody/$app/$endpoint/_reload" \
        >/dev/null 2>&1 || true
    done
  done
  echo "deployed (pass RESTART=1 for a full restart when conf files change)"
fi
