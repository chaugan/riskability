#!/usr/bin/env python
"""On-demand deep explanation for one CVE a person actually opened.

    POST /riskability/ai_explain  {"cve_id": "CVE-2024-3094"}

This is the only path in the app where a NON-ADMIN can cause the search head to
call the model endpoint, so the reasoning for that is written down here rather
than assumed.

Why it exists at all. The pipeline's scheduled pass answers a closed schema in
400 tokens, which is the right budget for ranking thousands of CVEs and the
wrong budget for the one an analyst has stopped on. The settings this replaces
(t3_max_tokens, t3_deep_threshold) promised a "deep reasoning" second tier for
every high scorer and were wired to nothing at all: they rendered as live
controls on the admin page while no code read them. A batch second pass was the
wrong answer anyway. The same model with three times the tokens re-rolls the
same dice more verbosely; it cannot add a schema field and it cannot override
the deterministic rules. What genuinely was missing is the case where a human
is looking at one row and wants the reasoning spelled out. That is this.

Why a person may trigger egress here, when nothing else lets them. Turning AI
analysis on is already the organisation's decision that this endpoint may
receive findings data, and it is guarded by riskability_ai_admin. What leaves
here is the same class of data the hourly pipeline already sends for the same
CVE, for one CVE, at a person's deliberate click. The capability is separate
anyway (riskability_ai_explain), so a site that wants the scheduled pipeline
without letting analysts drive the GPU simply does not grant it.

What this endpoint deliberately cannot do:

* It cannot change a priority. It never writes priority_tier, priority_score,
  confidence, recommended_action or any other field the dashboards rank on. It
  writes one field, "explanation", beside the verdict. A rendering of the
  reasoning must not be able to quietly re-rank the fleet.
* It cannot analyse a CVE the pipeline has not already analysed. No cached
  verdict, no explanation: this is not a way to make the scheduled budget,
  the candidate cap or the master switch irrelevant by clicking.
* It cannot run while AI analysis is switched off, and it re-reads that from
  the conf file rather than the mirrored KV row, because the conf is the
  authority and the row is a convenience for the page.
* It cannot be replayed for free. An explanation is cached with the verdict's
  signature, so a second click on an unchanged CVE costs no model call, and a
  hundred users opening the same row cost one.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from riskability import ai_config, ai_settings  # noqa: E402

VERDICTS_COLLECTION = "riskability_aiverdicts"

# The one place a longer answer is worth paying for. Not a setting: a knob here
# would be the T3 threshold again, a control whose effect nobody can see.
EXPLAIN_MAX_TOKENS = 1200

# A CVE id and nothing else. The value is interpolated into a KV query and
# rendered in a browser, and "it comes from our own dashboard" is not an
# argument that survives anyone typing a URL.
import re  # noqa: E402
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")

SYSTEM_PROMPT_EXPLAIN = """You are a vulnerability analyst writing for a colleague who has opened one
finding and wants to understand it.

Write prose, not JSON. Explain, in this order:
- what the vulnerability actually is, in two or three sentences
- what an attacker would need in order to exploit it here, given the evidence
- what the evidence provided does and does not establish
- what you would do about it, and what you would check first

Rules:
- Use only the evidence given. Never invent a version, a port, a host or a CVE
  detail that is not in the input.
- Where the evidence is silent, say so plainly rather than guessing. "The link
  records do not say whether this library is loaded" is a useful sentence.
- No preamble, no restating the question, no markdown headings."""


def _reply(status: int, payload: dict) -> dict:
    return {
        "status": status,
        "payload": json.dumps(payload),
        "headers": {"Content-Type": "application/json"},
    }


class AIExplainHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line=None, _command_arg=None):
        super().__init__()

    def handle(self, in_string):
        if isinstance(in_string, (bytes, bytearray)):
            in_string = in_string.decode("utf-8")
        try:
            request = json.loads(in_string)
        except Exception:
            return _reply(400, {"error": "request body was not valid JSON"})

        if str(request.get("method", "POST")).upper() != "POST":
            return _reply(405, {"error": "only POST is supported"})

        try:
            body = self._body(request)
            cve_id = str(body.get("cve_id") or "").strip().upper()
            if not CVE_RE.match(cve_id):
                return _reply(400, {"error": "cve_id must look like CVE-2024-3094"})

            service = self._service(request)
            cfg = ai_settings.load_config(service)
            if str(cfg.get("enabled", "0")).strip().lower() not in ("1", "true", "yes", "on"):
                return _reply(409, {"error": "AI analysis is switched off"})

            kv = service.kvstore[VERDICTS_COLLECTION].data
            rows = list(kv.query(**{"query": json.dumps({"cve_id": cve_id})}))
            if not rows:
                # Deliberate: no verdict, no explanation. Explaining a CVE the
                # pipeline has not reached would let a click bypass the budget
                # and the queue ordering that exist to bound model cost.
                return _reply(404, {"error": "no analysis for this CVE yet; it is "
                                             "still in the queue"})
            verdict = rows[0]

            cached = verdict.get("explanation")
            cached_sig = verdict.get("explanation_sig")
            if cached and cached_sig and cached_sig == verdict.get("sig"):
                return _reply(200, {"cve_id": cve_id, "explanation": cached,
                                    "cached": True})

            secret = ai_settings.read_secret(service)
            answer = ai_config.explain_finding(
                cfg["endpoint_url"], cfg["auth_type"], cfg["username"], secret,
                cfg["model"], cfg["verify_tls"] == "1", int(cfg["request_timeout"]),
                verdict, SYSTEM_PROMPT_EXPLAIN, EXPLAIN_MAX_TOKENS)
            if not answer.get("ok"):
                return _reply(502, {"error": answer.get("error", "the model "
                                                        "endpoint did not answer")})

            text = answer["text"]
            try:
                doc = dict(verdict)
                doc["explanation"] = text
                doc["explanation_sig"] = verdict.get("sig", "")
                doc = {k: v for k, v in doc.items()
                       if k == "_key" or not k.startswith("_")}
                kv.batch_save(doc)
            except Exception:
                # The explanation is worth returning even if it could not be
                # cached; the only cost of a failed write is the next reader
                # paying for it again.
                pass
            return _reply(200, {"cve_id": cve_id, "explanation": text,
                                "cached": False,
                                "latency_ms": answer.get("latency_ms", 0)})
        except PermissionError as exc:
            return _reply(401, {"error": str(exc)})
        except Exception as exc:
            return _reply(500, {"error": str(exc)})

    def _service(self, request):
        session_key = request.get("session", {}).get("authtoken")
        if not session_key:
            raise PermissionError("no session token")
        return client.connect(
            token=session_key, owner="nobody", app="riskability",
            host=request.get("server", {}).get("hostname") or "localhost",
            port=request.get("server", {}).get("port") or 8089,
            scheme="https")

    def _body(self, request) -> dict:
        raw = request.get("payload") or request.get("body") or "{}"
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
