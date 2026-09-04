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

Who may call it. Anyone holding riskability_ai_explain, which ships granted
to user, power, admin and sc_admin: this is the analyst-facing button. The
handler does its reading with the system token splunkd passes it (restmap
passSystemAuth), so the caller's own rights do not have to cover the stored
secret or the admin-write verdict cache. An earlier version read the secret
on the caller's session, which quietly limited the button to admins; a site
that wants it narrower removes the capability from a role in authorize.conf.

What this endpoint deliberately cannot do:

* It cannot change a priority. It re-reads the verdict immediately before
  writing and abandons the write if the signature moved, so a scheduled run
  that landed during the model call is never reverted. It adds two keys and
  preserves the rest of the document as it stood at that moment. An earlier
  version wrote back the copy it had read minutes earlier, which could and
  would restore a superseded tier onto the whole fleet.
* It cannot analyse a CVE the pipeline has not already analysed. No cached
  verdict, no explanation: this is not a way to make the scheduled budget,
  the candidate cap or the master switch irrelevant by clicking.
* It cannot run while AI analysis is switched off, and it re-reads that from
  the conf file rather than the mirrored KV row, because the conf is the
  authority and the row is a convenience for the page.
* It is shared. The answer is written with the system token (restmap
  passSystemAuth), so the reader who asked first pays the model call and
  every later reader of that CVE, admin or analyst, gets the stored answer.
  force=1 asks for a fresh answer and overwrites the stored one; it is
  honoured only when there is a stored answer to replace.
* It is not replayed for free WHEN the cache write succeeds. An explanation is
  stored against the verdict's signature, so a second click on an unchanged
  CVE costs no model call. When the write is denied the reply says
  "stored": false rather than looking identical to a success, because a
  permanent denial means every click is a fresh call and that should be
  visible rather than inferred.

What it still does NOT have, said plainly rather than discovered later: any
rate limit. A holder can call it once per analysed CVE with no per-user budget
and no cap on requests in flight, and the model server it shares with the
scheduled pipeline serves well under one request a second. That is acceptable
only while the capability is admin-tier. It must be fixed before the analyst
design above is built.
"""

from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from riskability import ai_config, ai_settings  # noqa: E402

VERDICTS_COLLECTION = "riskability_aiverdicts"

# The one place a longer answer is worth paying for. Not a setting: a knob here
# would be the T3 threshold again, a control whose effect nobody can see.
EXPLAIN_MAX_TOKENS = 1200

# Interactive, so it does not inherit the batch timeout. request_timeout is
# sized for the slowest card a site might run and can reach 600 seconds; a
# person waiting at a browser has given up long before that, and a handler
# blocked that long is a splunkd worker nobody can have back.
EXPLAIN_TIMEOUT = 60

# A CVE id and nothing else. The value is interpolated into a KV query and
# rendered in a browser, and "it comes from our own dashboard" is not an
# argument that survives anyone typing a URL.
import re  # noqa: E402
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")

SYSTEM_PROMPT_EXPLAIN = """You are a vulnerability analyst writing for a colleague who has opened one
finding and wants to understand it.

YOU HAVE NEVER HEARD OF THIS CVE. Assume it was published after your training
ended, because in six months that will be true of most of them. Do not recall
anything about it. Do not infer from the identifier. Everything you write must
come from the evidence block below.

Write for a person, not JSON. Use light markdown and nothing more: one bold
label line for each of the four parts below (for example **What the evidence
establishes**), short paragraphs under it, and a bulleted list where you are
listing checks or steps. No top-level headings, no tables, no code fences
unless quoting a command. The four parts, in this order:
- what the evidence establishes about the vulnerability. If a description is
  given, work from it. If none is given, say so, and read the CVSS vector
  instead: it states the attack vector, complexity, privileges required, user
  interaction and impact, and it is accurate for a vulnerability disclosed this
  morning. The CWE names the weakness class.
- what an attacker would need in order to exploit it HERE, given the measured
  evidence about this fleet
- what the evidence does NOT establish, explicitly
- what you would do, and what you would check first

Rules:
- Never state what the vulnerability is beyond what the description, the vector
  and the CWE support. A fluent invented sentence is worse than an admission.
- Where the evidence is silent, say so plainly. "The feed carries no
  description for this one, and the vector is absent, so what it does cannot be
  established from what we hold" is a genuinely useful sentence.
- Never invent a version, a port, a host, a CWE or a CVE detail.
- No preamble, no restating the question, no headings beyond the four bold
  labels."""


def _reply(status: int, payload: dict) -> dict:
    return {
        "status": status,
        "payload": json.dumps(payload),
        "headers": {"Content-Type": "application/json"},
    }


def _log(message: str) -> None:
    """One line per outbound call, in a file splunkd indexes into _internal.

    This is the only path where a person can make this app call out, and until
    now it left no record that egress had happened at all: splunkd's access log
    shows the REST hit, not the request to the model endpoint behind it. For an
    app whose thesis is that it makes no unintentional outbound calls, the
    intentional ones need to be countable and alertable.
    """
    try:
        splunk_home = os.environ.get("SPLUNK_HOME", "")
        if not os.path.isabs(splunk_home):
            return
        path = os.path.join(splunk_home, "var", "log", "splunk",
                            "riskability_ai_explain.log")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("%s riskability_ai_explain %s\n"
                         % (time.strftime("%Y-%m-%d %H:%M:%S"), message))
    except Exception:
        pass


class AIExplainHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line=None, _command_arg=None):
        super().__init__()

    def _log(self, message):
        _log(message)

    def handle(self, in_string):
        if isinstance(in_string, (bytes, bytearray)):
            in_string = in_string.decode("utf-8")
        try:
            request = json.loads(in_string)
        except Exception:
            return _reply(400, {"error": "request body was not valid JSON"})

        if str(request.get("method", "GET")).upper() != "POST":
            return _reply(405, {"error": "only POST is supported"})

        try:
            body = self._body(request)
            cve_id = str(body.get("cve_id") or "").strip().upper()
            if not CVE_RE.match(cve_id):
                return _reply(400, {"error": "cve_id must look like CVE-2024-3094"})

            # Everything the handler touches on the caller's behalf is read
            # with the system token splunkd passes (restmap passSystemAuth):
            # the connection settings, the stored secret and the verdict
            # cache. The caller's own session decides nothing here beyond
            # what splunkd already decided at the door, the capability on the
            # POST. That is what makes riskability_ai_explain grantable to a
            # plain user role: without it the secret read ran as the caller,
            # who cannot list storage passwords, and the call went out with
            # no credential.
            service = self._system_service(request)
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
            force = str(body.get("force") or "").strip().lower() in ("1", "true", "yes")
            if cached and cached_sig and cached_sig == verdict.get("sig") and not force:
                return _reply(200, {"cve_id": cve_id, "explanation": cached,
                                    "cached": True, "stored": True,
                                    "explained_at": verdict.get("explained_at")})
            # force=1 is a person asking for a fresh answer over a stored one.
            # It is honoured only when a stored one exists to replace, so it
            # cannot be used to make the cache pointless by always sending it.

            secret = ai_settings.read_secret(service)
            answer = ai_config.explain_finding(
                cfg["endpoint_url"], cfg["auth_type"], cfg["username"], secret,
                cfg["model"], cfg["verify_tls"] == "1",
                min(int(cfg["request_timeout"]), EXPLAIN_TIMEOUT),
                verdict, SYSTEM_PROMPT_EXPLAIN, EXPLAIN_MAX_TOKENS)
            if not answer.get("ok"):
                # The detail goes to the log, not to the browser. _http's prose
                # names the endpoint URL and its TLS posture on purpose, which
                # is right for an admin reading a test result and wrong for a
                # reply to whoever clicked a button on a dashboard.
                _log("endpoint call failed for %s: %s"
                     % (cve_id, answer.get("error", "unknown")))
                return _reply(502, {"error": "the model endpoint did not answer; "
                                             "an administrator can see why in "
                                             "riskability_ai_explain.log"})

            _log("explained %s in %sms" % (cve_id, answer.get("latency_ms", 0)))
            text = answer["text"]
            # Re-read before writing, and abandon the write if the verdict
            # moved. batch_save REPLACES a document by _key, and the model
            # call above can take minutes, so writing back the copy read
            # before it would revert whatever the scheduled pipeline decided
            # in between. That is not theoretical: a CVE that entered KEV and
            # was re-analysed to P0 mid-call would be restored to its old
            # tier, and the expansion search would then serve the old tier to
            # every host in the fleet.
            try:
                fresh = list(kv.query(**{"query": json.dumps({"cve_id": cve_id})}))
                current = fresh[0] if fresh else None
                if not current or not current.get("_key"):
                    raise RuntimeError("verdict disappeared while explaining")
                if current.get("sig") != verdict.get("sig"):
                    # Re-analysed under us. The explanation describes inputs
                    # that no longer apply, so it is returned to the person who
                    # asked and deliberately not cached for anyone else.
                    return _reply(200, {"cve_id": cve_id, "explanation": text,
                                        "cached": False, "stale": True,
                                        "latency_ms": answer.get("latency_ms", 0)})
                doc = {k: v for k, v in current.items()
                       if k == "_key" or not k.startswith("_")}
                doc["explanation"] = text
                doc["explanation_sig"] = current.get("sig") or ""
                doc["explained_at"] = int(time.time())
                # Written with the system token when splunkd passed one. The
                # collection is admin-write, so the caller's own session would
                # be refused for every analyst and the answer would never be
                # shared: the next reader would pay for the same model call.
                service.kvstore[VERDICTS_COLLECTION].data.batch_save(doc)
                cached_ok = True
            except Exception as exc:
                # Worth returning the answer anyway, but NOT worth pretending
                # it was stored. A permanent denial (the verdict collection is
                # writable by admins only) makes every click a fresh model
                # call, which is the opposite of the caching this endpoint
                # claims, so the reply says so rather than looking identical
                # to a successful write.
                self._log("explanation for %s could not be cached: %s"
                          % (cve_id, exc))
                cached_ok = False
            return _reply(200, {"cve_id": cve_id, "explanation": text,
                                "cached": False, "stored": cached_ok,
                                "explained_at": int(time.time()),
                                "latency_ms": answer.get("latency_ms", 0)})
        except PermissionError as exc:
            return _reply(401, {"error": str(exc)})
        except Exception as exc:
            _log("unhandled error: %s" % exc)
            return _reply(500, {"error": "the explanation could not be produced"})

    def _system_service(self, request):
        """System auth when splunkd passed it (restmap passSystemAuth), the
        caller otherwise, so a deployment without the flag degrades to the old
        admin-only behaviour rather than failing."""
        token = request.get("system_authtoken")
        if not token:
            return self._service(request)
        return client.connect(
            token=token, owner="nobody", app="riskability",
            host=request.get("server", {}).get("hostname") or "localhost",
            port=request.get("server", {}).get("port") or 8089,
            scheme="https")

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
