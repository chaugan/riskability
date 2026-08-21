#!/usr/bin/env bash
# Install the forwarder-side apps into the running Universal Forwarder.
#
# Copied in rather than bind-mounted: the splunk/universalforwarder image
# provisions itself with ansible, which runs /sbin/updateetc.sh and rewrites
# etc/apps. A read-only mount there makes provisioning fail and the container
# restart-loops with only "rc: 2" to show for it.
set -euo pipefail
UF=${UF:-riskability-uf}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

# The add-on exactly as an operator would receive it, plus a small config app
# that enables its input and points the forwarder at the indexer -- which is
# what a deployment server would push in a real estate.
for src in "$ROOT/app/TA-riskability:TA-riskability" \
           "$ROOT/docker/uf/outputs:riskability_forwarder_outputs"; do
  path=${src%%:*}; name=${src##*:}
  # As root: a previous copy may be owned by another user, and the splunk
  # account cannot remove it.
  docker exec -u root "$UF" rm -rf "/opt/splunkforwarder/etc/apps/$name"
  docker exec -u root "$UF" mkdir -p "/opt/splunkforwarder/etc/apps/$name"
  docker cp "$path/." "$UF:/opt/splunkforwarder/etc/apps/$name/"
  docker exec -u root "$UF" chown -R splunk:splunk "/opt/splunkforwarder/etc/apps/$name"
  echo "installed $name on the forwarder"
done

docker exec -u splunk "$UF" /opt/splunkforwarder/bin/splunk restart \
  --accept-license --answer-yes --no-prompt >/dev/null 2>&1 || true
echo "forwarder restarted"
