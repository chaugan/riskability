#!/usr/bin/env python
"""Alert action: tell the GPU box that a candidate queue is ready.

Splunk's role in the AI pipeline is the one the build spec gives it: it owns
the schedule, the queue and the audit trail. This script is the single point
where "the queue is built" becomes "go and analyse it".

How it fires
------------

The "Riskability AI - generate candidate queue" saved search runs on its
cron, writes the queue into the candidates index and fires this action
(``actions = riskability_ai_trigger`` in the saved search, counttype -1 so
it fires on every run). The action reads ``trigger_command`` from
riskability_ai.conf -- set by an admin on the Riskability Configuration page
-- substitutes ``$run_id$``, and runs it.

Typical commands:

    ssh -i /opt/splunk/etc/auth/ssh/gpu_key cve-admin@gpu-cve-01 \
        "sudo systemctl start cve-orchestrator@$run_id@.service"

    curl -sf -X POST https://gpu-cve-01:9443/run -H 'Authorization: Bearer ...' \
        -d '{"run_id": "$run_id$"}'

or nothing at all, when the GPU box polls Splunk for new queues itself and
the command field is left empty -- in which mode this script is a no-op, on
purpose, because a poller and a trigger both firing would run the same queue
twice.

Security notes, stated plainly:

* ``trigger_command`` is an arbitrary command executed as the Splunk service
  account. That is its entire job, and it is why writing it requires the
  ``riskability_ai_admin`` capability rather than being a general setting.
* The run_id is substituted from the alert payload, then the whole string is
  validated against a strict character allowlist before execution. The
  alert payload is data produced by the pipeline's own search, but a field
  value that carried a shell metacharacter must fail closed here rather than
  become part of a command line.
* Failures are logged, never silently swallowed: a trigger that did not fire
  is a run that never happened, and the run health search exists to notice
  exactly that.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

from riskability import ai_config  # noqa: E402

LOG_NAME = "riskability_ai_trigger"


def log(message: str):
    # splunkd ships a logging handler for $SPLUNK_HOME/var/log/splunk, which
    # is where an operator checking why a run never started will look first.
    import logging
    logger = logging.getLogger(LOG_NAME)
    if not logger.handlers:
        path = os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"),
                            "var", "log", "splunk", LOG_NAME + ".log")
        handler = logging.FileHandler(path)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    logger.info(message)


def load_payload() -> dict:
    raw = sys.stdin.read()
    try:
        return json.loads(raw)
    except Exception:
        log("payload was not valid JSON; ignoring")
        return {}


def read_settings(session_key: str, server_uri: str) -> dict:
    """The AI connection settings, read with the alert's own session.

    An alert action gets a session key scoped to the search owner. Reading
    through it keeps this script credential-free: no stored password, no
    passAuth file, nothing to leak, and if the session has expired the run
    is skipped loudly rather than half-done.
    """
    host = server_uri.replace("https://", "").replace("http://", "")
    service = client.connect(token=session_key, owner="nobody", app="riskability",
                             host=host.split(":")[0],
                             port=int(host.split(":")[1]) if ":" in host else 8089,
                             scheme="https")
    stanza = service.confs["riskability_ai"]["connection"]
    return dict(stanza.content)


def extract_run_id(payload: dict) -> str:
    """The run_id the queue search stamped on every row.

    From the alert's first result. A search that somehow produced no rows
    still fires under counttype -1, and there is then nothing to analyse, so
    the action records that and exits successfully -- a warning in the log is
    the correct severity for an empty queue.
    """
    result = payload.get("result") or {}
    return str(result.get("run_id") or "").strip()


# What may appear in a run_id after substitution: the search writes
# strftime output, the orchestrator's own examples use the same shape, and
# nothing legitimate needs anything else.
SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
# The command template itself: printable, no newlines. Anything a shell would
# read as "start a second command from injected input" on a line of its own is
# out. Pipe and redirect stay allowed -- the admin who can write this setting
# can write a shell script and point the setting at it, so refusing them buys
# nothing and breaks legitimate commands.
SAFE_COMMAND = re.compile(r"^[\x20-\x7e]{1,2000}$")


def build_command(template: str, run_id: str) -> str:
    command = template.replace("$run_id$", run_id)
    if not SAFE_COMMAND.match(command):
        raise ValueError("trigger command contains characters that are not allowed")
    return command


def main() -> int:
    payload = load_payload()
    session = payload.get("session_key") or ""
    server_uri = payload.get("server_uri") or ""
    if not session or not server_uri:
        log("no session in the alert payload; cannot read settings")
        return 0
    try:
        cfg = read_settings(session, server_uri)
    except Exception as exc:
        log("could not read riskability_ai.conf: %s" % exc)
        return 0

    if str(cfg.get("enabled", "0")).strip().lower() not in ("1", "true", "yes", "on"):
        log("AI analysis is switched off; doing nothing")
        return 0
    template = (cfg.get("trigger_command") or "").strip()
    if not template:
        # Poller mode: the GPU box watches the queue index itself. Nothing to
        # do here, and nothing to be alarmed about.
        log("no trigger command configured (GPU box is expected to poll); doing nothing")
        return 0

    run_id = extract_run_id(payload)
    if not run_id:
        log("the queue search produced no run_id (empty queue?); nothing to dispatch")
        return 0
    try:
        command = build_command(template, run_id)
    except ValueError as exc:
        log("run_id %r refused: %s" % (run_id, exc))
        return 1

    log("dispatching run_id=%s" % run_id)
    try:
        completed = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        log("trigger command for run_id=%s timed out after 120s" % run_id)
        return 1
    if completed.returncode != 0:
        log("trigger command for run_id=%s failed (rc=%s): %s"
            % (run_id, completed.returncode,
               (completed.stderr or completed.stdout or "")[:500]))
        return 1
    log("trigger command for run_id=%s completed" % run_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
