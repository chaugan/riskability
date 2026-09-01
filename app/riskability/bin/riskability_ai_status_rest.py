#!/usr/bin/env python
"""The user-facing half of the AI pipeline: one bit, one endpoint.

    GET /riskability/ai_status   ->  {"enabled": true|false}

This is the only AI endpoint a normal user can reach, on purpose. The AI page
in the main app asks it this one question to decide whether to exist -- and
when the answer is no, the page renders nothing at all, so an instance where
AI was never configured shows users exactly as much AI as it configured,
which is none. The capability is list_settings, the same gate the exceptions
endpoint gives its read path: effectively any signed-in user, because the
answer is already public the moment any dashboard with the page in its nav is
visible.

The bit is read from the riskability_aistate KV collection, NOT from the conf
file: conf reads over REST are admin-tier, and this endpoint exists for
precisely the users conf reads would exclude. Reading fails closed -- any
error answers false, which hides the page -- because a status check that
invents "on" would draw a dashboard over a pipeline that is not there.

This is a separate file from riskability_ai_rest.py for a reason splunkd
enforces, not a style choice: a persistent REST handler script may contain
exactly ONE class implementing PersistentServerConnectionApplication, and a
file with two fails to start with "More than one class implements
PersistentServerConnectionApplication". Found by deploying, not by reading.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

import splunklib.results as splunk_results  # noqa: E402

from splunklib import client  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

STATE_COLLECTION = "riskability_aistate"


def _reply(status: int, payload: dict) -> dict:
    return {
        "status": status,
        "payload": json.dumps(payload),
        "headers": {"Content-Type": "application/json"},
    }


def _first(value):
    """REST JSON hands multivalue fields back as lists; every consumer of a
    field here wants its first (usually only) value."""
    if isinstance(value, list):
        return value[0] if value else ""
    return value


def _ctx():
    return ssl._create_unverified_context()


def _run_search(splunkd_base: str, token: str, search: str,
                earliest: str = "0") -> list:
    """One oneshot search under the caller's session; rows as plain dicts.

    Raw REST, not splunklib jobs: on Splunk 9.4 both jobs.oneshot() and
    jobs.create()+results() through splunklib 3.0 came back empty while the
    identical search over raw REST returned rows (verified repeatedly). The
    session token authorizes exactly like the user's own browser would.

    Retries: this box intermittently returns an empty result set for a
    search that succeeds seconds later (post-boot search-peer warm-up, most
    likely). One empty answer triggers one backoff retry; a search that is
    genuinely empty returns empty twice in a row and stays honest.
    """
    fields = {"exec_mode": "oneshot", "output_mode": "json", "count": "0",
              "earliest_time": earliest, "search": search}
    data = urllib.parse.urlencode(fields).encode()
    rows, msgs = [], []
    for attempt in range(3):
        req = urllib.request.Request(
            splunkd_base + "/servicesNS/nobody/riskability/search/jobs",
            data=data, method="POST")
        req.add_header("Authorization", "Splunk " + token)
        with urllib.request.urlopen(req, context=_ctx(), timeout=240) as r:
            out = json.loads(r.read().decode())
        rows = out.get("results", []) if isinstance(out, dict) else []
        msgs = [str(m.get("text", ""))[:200] for m in out.get("messages", [])] \
            if isinstance(out, dict) else []
        if rows:
            break
        time.sleep(1.5 * (attempt + 1))
    return [{k: _first(v) for k, v in row.items()} for row in rows], msgs


def _overview(service, splunkd_base: str, token: str) -> dict:
    """Everything the AI overview page draws, computed server-side."""
    out = {}
    now = int(time.time())

    try:
        verdicts = list(service.kvstore["riskability_aiverdicts"].data.query(
            **{"query": json.dumps(
                {"priority_tier": {"$in": ["P0", "P1", "P2", "P3", "P4"]}})}))
        out["analyzed_cves"] = len({v.get("cve_id") for v in verdicts})
        out["failed_analyses"] = sum(1 for v in verdicts
                                     if v.get("analysis_source") == "fallback")
    except Exception as exc:
        out["analyzed_cves"] = 0
        out["overview_error"] = str(exc)

    try:
        rows, err = _run_search(splunkd_base, token,
            "search `riskability_ai_results_latest` | stats count AS findings, "
            "dc(asset_id) AS assets, count(eval(priority_tier==\"P0\")) AS p0, "
            "count(eval(priority_tier==\"P1\")) AS p1, max(analysed_at) AS latest_at")
        if err:
            out["overview_error"] = err
        if rows:
            row = rows[0]
            out["findings"] = int(row.get("findings") or 0)
            out["assets"] = int(row.get("assets") or 0)
            out["p0"] = int(row.get("p0") or 0)
            out["p1"] = int(row.get("p1") or 0)
            out["latest_at"] = int(row.get("latest_at") or 0)
    except Exception as exc:
        out["overview_error"] = str(exc)

    try:
        rows, run_err = _run_search(splunkd_base, token,
            "search `riskability_ai_results_latest` | sort 0 - priority_score "
            "| head 10 | table cve_id asset_id priority_tier priority_score "
            "confidence recommended_action exposure_zone epss kev severity "
            "rationale recommended_mitigations attck_techniques "
            "analysis_source analysed_at")
        if run_err:
            out["overview_error"] = run_err
        out["top"] = rows[:10]
    except Exception as exc:
        out["overview_error"] = str(exc)

    try:
        rows, run_err = _run_search(splunkd_base, token,
            "search `riskability_index_ai_candidates` | stats dc(cve_id) AS open_cves",
            "-7d")
        if run_err:
            out["overview_error"] = run_err
        if rows:
            out["open_cves"] = int(rows[0].get("open_cves") or 0)
    except Exception as exc:
        out["overview_error"] = str(exc)

    try:
        rows, run_err = _run_search(splunkd_base, token,
            "search `riskability_index_ai_prioritized` | stats count AS analyzed, "
            "dc(asset_id) AS assets, count(eval(priority_tier==\"P0\")) AS p0, "
            "max(_time) AS at BY run_id | sort 0 - at | head 5")
        if run_err:
            out["overview_error"] = run_err
        out["runs"] = rows[:5]
    except Exception as exc:
        out["overview_error"] = str(exc)

    out["generated_at"] = now
    return out


class AIStatusHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line=None, _command_arg=None):
        super().__init__()

    def handle(self, in_string):
        if isinstance(in_string, (bytes, bytearray)):
            in_string = in_string.decode("utf-8")
        try:
            request = json.loads(in_string)
        except Exception:
            return _reply(400, {"error": "request body was not valid JSON"})
        try:
            session_key = request.get("session", {}).get("authtoken")
            if not session_key:
                raise PermissionError("no session token")
            service = client.connect(
                token=session_key, owner="nobody", app="riskability",
                host=request.get("server", {}).get("hostname") or "localhost",
                port=request.get("server", {}).get("port") or 8089,
                scheme="https")
            enabled = False
            try:
                for row in service.kvstore[STATE_COLLECTION].data.query(
                        **{"query": json.dumps({"_key": "ai_enabled"})}):
                    enabled = str(row.get("enabled", "0")) in ("1", "true")
            except Exception:
                enabled = False
            reply = {"enabled": enabled}
            if enabled:
                # The page's data travels with the status on purpose: the
                # splunkd __raw proxy on this build 500s on proxied search
                # POSTs (splunkd substr fault), so browser-issued oneshot
                # searches are not survivable. GETs proxy fine. The searches
                # run here under the caller's own session and permissions.
                scheme = "https"
                host = request.get("server", {}).get("hostname") or "127.0.0.1"
                port = request.get("server", {}).get("port") or "8089"
                reply["overview"] = _overview(
                    service, f"{scheme}://{host}:{port}", session_key)
            return _reply(200, reply)
        except PermissionError as exc:
            return _reply(401, {"error": str(exc)})
        except Exception as exc:
            return _reply(500, {"error": str(exc)})
