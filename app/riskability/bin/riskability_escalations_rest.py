#!/usr/bin/env python
"""Escalation rules: list them, and switch one on or off.

    GET  /riskability/escalations
    POST /riskability/escalations  {"rule": "<stanza>", "enabled": true|false}

Why this exists. A rule was enabled by editing riskability_escalations.conf
and re-running tools/build_escalation_macro.py, which compiles the enabled
set into the riskability_escalation_rules macro the evaluation search
expands. That is a build step, not an operation, and an operator who has
just read the replay and decided to switch a rule on should not need a shell
on the search head to do it.

Why it is still the compiled macro and not a lookup read at search time. The
compiled form is one place, reviewable, and identical on every search head
that shares the conf. That property is kept here by changing NOTHING about
where the enabled set lives: this handler flips the stanza's enabled key and
recompiles the macro, both through splunkd's conf API, which a search head
cluster replicates to every member. A single search head sees the same two
writes land locally. Nothing is written to a file by hand, and there is no
second copy of the enabled set for the members to disagree about.

The compiler is the same function the build script uses (escalate.to_spl),
so the macro this writes and the macro the repository ships are produced by
one piece of code. tools/test_escalations.py checks that the two agree.

Only the enabled flag can be changed here. The condition, the bump and the
description stay in the conf file, where a change is a diff somebody reviews:
a predicate typed into a web form and applied to every finding in the estate
is exactly the class of change this app makes deliberately slow.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from riskability import escalate  # noqa: E402

CONF = "riskability_escalations"
MACRO = "riskability_escalation_rules"


def _reply(status: int, payload: dict) -> dict:
    return {"status": status, "payload": json.dumps(payload),
            "headers": {"Content-Type": "application/json"}}


def conf_text_from_entities(entities) -> str:
    """Rebuild the conf as text so the one parser in escalate.py reads it.

    splunkd hands stanzas back as entities. The validator was written against
    the file, deliberately (see escalate.parse_conf), and rather than teach it
    a second input shape the entities are rendered back into the shape it
    already validates. Values with newlines are re-joined with the
    continuation the file would carry.
    """
    out = []
    for ent in entities:
        name = ent.name
        if name == "default":
            continue
        out.append("[%s]" % name)
        for key in escalate.RULE_KEYS:
            value = ent.content.get(key)
            if value is None:
                continue
            value = str(value).replace("\n", " \\\n")
            out.append("%s = %s" % (key, value))
        out.append("")
    return "\n".join(out)


def macro_definition(rules) -> str:
    """The enabled set as one line, the shape a conf API write wants."""
    return " ".join(line.strip() for line in escalate.to_spl(rules).split("\n")
                    if line.strip())


class EscalationsHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line=None, _command_arg=None):
        super().__init__()

    def handle(self, in_string):
        if isinstance(in_string, (bytes, bytearray)):
            in_string = in_string.decode("utf-8")
        try:
            request = json.loads(in_string)
        except Exception:
            return _reply(400, {"error": "request body was not valid JSON"})
        method = str(request.get("method", "GET")).upper()
        try:
            service = self._service(request)
            if method == "GET":
                return self._get(service)
            if method == "POST":
                return self._post(service, self._body(request))
            return _reply(405, {"error": "%s is not supported" % method})
        except PermissionError as exc:
            return _reply(401, {"error": str(exc)})
        except ValueError as exc:
            return _reply(400, {"error": str(exc)})
        except Exception as exc:
            return _reply(500, {"error": "escalation rules could not be read or "
                                         "written: %s" % exc})

    # -- reads -------------------------------------------------------------
    def _rules(self, service):
        entities = list(service.confs[CONF])
        rules, problems = escalate.load_rules(conf_text_from_entities(entities))
        return rules, problems

    def _get(self, service):
        rules, problems = self._rules(service)
        # The stanza text for rules the validator refused, so the page can show
        # what was written rather than only that it was refused.
        raw = {}
        for ent in service.confs[CONF]:
            if ent.name != "default":
                raw[ent.name] = {k: str(ent.content.get(k) or "")
                                 for k in escalate.RULE_KEYS}
        try:
            macro = service.confs["macros"][MACRO].content.get("definition", "")
        except Exception:
            macro = ""
        want = macro_definition(rules)
        return _reply(200, {
            "rules": [{"name": r.name, "description": r.description,
                       "when": r.when, "bump": r.bump, "enabled": bool(r.enabled),
                       "fields": sorted(r.fields)} for r in rules],
            "problems": [{"rule": p.rule, "kind": p.kind, "detail": p.reason,
                          "description": raw.get(p.rule, {}).get("description", ""),
                          "when": raw.get(p.rule, {}).get("when", ""),
                          "bump": raw.get(p.rule, {}).get("bump", "")}
                         for p in problems],
            # True when the compiled macro on this search head matches what
            # the rules say. False means somebody edited the conf without
            # recompiling, and the search is evaluating a stale set; the page
            # says so rather than showing an enabled flag that is not in force.
            "in_force": _normalise(macro) == _normalise(want),
        })

    # -- writes ------------------------------------------------------------
    def _post(self, service, body):
        name = str(body.get("rule") or "").strip()
        if not name or not escalate.RULE_NAME_RE.match(name):
            raise ValueError("rule must name a stanza in %s.conf" % CONF)
        enabled = str(body.get("enabled")).strip().lower() in ("1", "true", "yes", "on")

        rules, problems = self._rules(service)
        target = next((r for r in rules if r.name == name), None)
        if target is None:
            bad = next((p for p in problems if p.rule == name), None)
            if bad is not None:
                raise ValueError("%s cannot be switched on: %s" % (name, bad.reason))
            raise ValueError("no rule named %s" % name)
        if enabled and any(p.rule == name and p.kind == escalate.UNPRODUCED
                           for p in problems):
            raise ValueError("%s names a field nothing computes today, so it "
                             "would fire never; it stays off" % name)

        # 1. the stanza. A conf write through splunkd, so a cluster replicates it.
        service.confs[CONF][name].update(enabled="1" if enabled else "0")
        # 2. the compiled macro, from the same compiler the build script uses.
        rules, _ = self._rules(service)
        definition = macro_definition(rules)
        service.confs["macros"][MACRO].update(definition=definition)

        return _reply(200, {"rule": name, "enabled": enabled,
                            "enabled_rules": [r.name for r in rules if r.enabled],
                            "in_force": True})

    # -- plumbing ----------------------------------------------------------
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


def _normalise(text: str) -> str:
    return " ".join(str(text or "").replace("\\\n", " ").split())
