#!/usr/bin/env python
"""The user-facing half of the AI pipeline: one bit + precomputed overview.

    GET /riskability/ai_status   ->  {"enabled": true|false, "overview": {...}}

This is the only AI endpoint a normal user can reach, on purpose. The AI
page in the main app asks it this one question to decide whether to exist
-- and when the answer is no, the page renders nothing at all, so an
instance where AI was never configured shows users exactly as much AI as
it configured, which is none. The capability is list_settings, the same
gate the exceptions endpoint gives its read path.

The overview data rides on the same GET, read entirely from the KV Store
(verdicts collection + summary row written by the expansion search). No
searches run on page load: the expansion search precomputes the summary
and this handler serves it instantly. This is a deliberate architecture
decision -- running SPL searches per page load was both slow (30+ s) and
unreliable on the target Splunk build (flaky empty results, proxied search
POSTs that 500). A KV read is O(1) and cannot fail emptily.

Separate file from riskability_ai_rest.py: splunkd allows exactly ONE
class implementing PersistentServerConnectionApplication per script file.
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

import splunklib.results as splunk_results  # noqa: E402

from splunklib import client  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

STATE_COLLECTION = "riskability_aistate"
VERDICTS_COLLECTION = "riskability_aiverdicts"


def _reply(status: int, payload: dict) -> dict:
    return {
        "status": status,
        "payload": json.dumps(payload),
        "headers": {"Content-Type": "application/json"},
    }


def _first(value):
    """KV store fields arrive as lists for multivalue; consumers want the value."""
    if isinstance(value, list):
        return value[0] if value else ""
    return value


def _overview_from_kv(service) -> dict:
    """Everything the AI overview page draws, read entirely from KV Store.

    Two collections:
    - riskability_aistate: the summary row (_key=overview) written by the
      expansion search's appendpipe (findings, p0, p1, assets, latest_at)
    - riskability_aiverdicts: the verdict cache (count = coverage; top rows
      sorted by score = the page's priority table)

    No searches. No index reads. This cannot be slow or flaky.
    """
    out = {"generated_at": int(time.time())}

    # -- summary row (written by expansion) -------------------------------
    try:
        rows = list(service.kvstore[STATE_COLLECTION].data.query(
            **{"query": json.dumps({"_key": "overview"})}))
        if rows:
            row = rows[0]
            for key in ("findings", "p0", "p1", "assets", "cves", "latest_at"):
                val = _first(row.get(key))
                out[key] = int(val) if val not in ("", None) else 0
            out["last_run_id"] = _first(row.get("run_id")) or ""
    except Exception:
        pass  # summary not written yet (first expansion hasn't completed)

    # -- coverage + top rows from the verdicts cache -----------------------
    try:
        verdicts = list(service.kvstore[VERDICTS_COLLECTION].data.query(
            **{"query": json.dumps(
                {"priority_tier": {"$in": ["P0", "P1", "P2", "P3", "P4"]}})}))
        out["analyzed_cves"] = len({v.get("cve_id") for v in verdicts})
        out["failed_analyses"] = sum(1 for v in verdicts
                                     if v.get("analysis_source") == "fallback")

        # top rows: sort verdicts by score, take the best 10 — these are
        # per-CVE verdicts (not per-finding), which is the right grain for
        # "what should I look at first" — the per-finding expansion lives
        # in the index for the detail drill-down.
        scored = []
        for v in verdicts:
            try:
                score = int(_first(v.get("priority_score")) or 0)
            except (ValueError, TypeError):
                score = 0
            scored.append((score, v))
        scored.sort(key=lambda pair: -pair[0])
        out["top"] = [
            {k: _first(v.get(k)) for k in (
                "cve_id", "priority_tier", "priority_score", "confidence",
                "rationale", "recommended_action", "recommended_mitigations",
                "attck_techniques", "exploitability_signal", "analysis_source",
                "analysed_at")}
            for _, v in scored[:10]
        ]
    except Exception:
        out["analyzed_cves"] = 0
        out["top"] = []

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
                reply["overview"] = _overview_from_kv(service)
            return _reply(200, reply)
        except PermissionError as exc:
            return _reply(401, {"error": str(exc)})
        except Exception as exc:
            return _reply(500, {"error": str(exc)})
