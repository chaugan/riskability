#!/usr/bin/env python
"""Firewall data source: read the settings, save them, test them.

    GET  /riskability/firewall
    POST /riskability/firewall  {"action": "set",  "config": {...}}
    POST /riskability/firewall  {"action": "test", "config": {...}}

Settings live in riskability_firewall.conf [settings], written through
splunkd's conf API so a search head cluster replicates them. On every save
the five riskability_fw_* macros are regenerated from the settings by
riskability.firewall and written the same way. That is the whole mechanism:
one source of truth a person edits, five derived definitions nobody edits,
and both halves reach every search head the same way.

"test" runs the generated edge reduction over the last day, bounded, and
returns how many edges it found and how new the newest is. It runs as the
caller and writes nothing, so an administrator can try a field mapping
before it becomes what the assess job reads.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client, results  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from riskability import firewall  # noqa: E402

CONF = "riskability_firewall"
STANZA = "settings"


def _reply(status: int, payload: dict) -> dict:
    return {"status": status, "payload": json.dumps(payload),
            "headers": {"Content-Type": "application/json"}}


class FirewallHandler(PersistentServerConnectionApplication):
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
                body = self._body(request)
                action = str(body.get("action") or "set")
                if action == "set":
                    return self._set(service, body.get("config") or {})
                if action == "test":
                    return self._test(service, body.get("config") or {})
                raise ValueError("unknown action %r" % action)
            return _reply(405, {"error": "%s is not supported" % method})
        except PermissionError as exc:
            return _reply(401, {"error": str(exc)})
        except (ValueError, firewall.SettingsError) as exc:
            return _reply(400, {"error": str(exc)})
        except Exception as exc:
            return _reply(500, {"error": "firewall settings could not be read or "
                                         "written: %s" % exc})

    # -- reads -------------------------------------------------------------
    def _read(self, service) -> dict:
        try:
            content = service.confs[CONF][STANZA].content
        except Exception:
            return firewall.defaults()
        # A key that is present with an empty value must arrive as "", not
        # be dropped: splunklib hands an empty conf value back as None, and a
        # reader that skipped None fell back to the default for action_field,
        # generated a macro with the action term in it, and reported the
        # freshly saved macro as out of step with settings it had just saved.
        raw = {k: ("" if content.get(k) is None else content.get(k))
               for k in firewall.FIELDS if k in content}
        try:
            return firewall.validate(raw)
        except firewall.SettingsError:
            # A hand-edited conf that no longer validates still has to be
            # shown, so the page can say what is wrong; the raw values are
            # returned over the defaults.
            out = firewall.defaults()
            out.update({k: str(v) for k, v in raw.items()})
            return out

    def _macro_state(self, service, settings) -> dict:
        """Whether each macro on this search head is what the settings generate."""
        want = firewall.macros(settings)
        state = {}
        for name, definition in want.items():
            try:
                have = service.confs["macros"][name].content.get("definition", "")
            except Exception:
                have = None
            state[name] = (_norm(have) == _norm(definition)) if have is not None else None
        return state

    def _get(self, service):
        settings = self._read(service)
        return _reply(200, {
            "config": settings,
            "configured": firewall.configured(settings),
            "macros": self._macro_state(service, settings),
            "defaults": firewall.defaults(),
        })

    # -- writes ------------------------------------------------------------
    def _set(self, service, config):
        clean = firewall.validate(config)
        service.confs[CONF][STANZA].update(**clean)
        for name, definition in firewall.macros(clean).items():
            service.confs["macros"][name].update(definition=definition)
        return _reply(200, {"config": clean, "configured": firewall.configured(clean),
                            "macros": self._macro_state(service, clean)})

    def _test(self, service, config):
        clean = firewall.validate(config)
        if not firewall.configured(clean):
            raise ValueError("name an index before testing")
        query = firewall.test_search(clean)
        job = service.jobs.create(query, earliest_time="-1d", latest_time="now",
                                  exec_mode="blocking", max_count=10)
        rows = []
        for item in results.JSONResultsReader(job.results(output_mode="json", count=10)):
            if isinstance(item, dict):
                rows.append(item)
        row = rows[0] if rows else {}
        edges = int(row.get("edges") or 0)
        return _reply(200, {
            "query": query,
            "edges": edges,
            "sources": int(row.get("sources") or 0),
            "destinations": int(row.get("destinations") or 0),
            "newest_edge": row.get("newest_edge"),
            "verdict": ("the source yields permitted edges" if edges
                        else "no edges in the last day: check the index, the "
                             "sourcetype, the action value and the field names"),
        })

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


def _norm(text) -> str:
    return " ".join(str(text or "").replace("\\\n", " ").split())
