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
import time

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
                if action == "preview":
                    return self._preview(service, body.get("config") or {},
                                         body.get("limit"))
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
        # The window is the feed's own staleness setting, not a fixed day. The
        # assess job calls the feed stale when its newest edge is older than
        # stale_days, so that is the window in which edges have to exist for
        # the pipeline to use them, and it is what a test should look at. A
        # fixed day reported "0 edges, check your field names" on a source
        # whose mapping was right and whose newest event was six days old.
        days = int(clean["stale_days"])
        row = self._run_one(service, query, "-%dd" % days, clean)
        edges = int(row.get("edges") or 0)
        out = {"query": query, "window_days": days, "edges": edges,
               "sources": int(row.get("sources") or 0),
               "destinations": int(row.get("destinations") or 0),
               "newest_edge": row.get("newest_edge")}
        if edges:
            out["verdict"] = "the source yields permitted edges within the last %d days" % days
            return _reply(200, out)
        # Nothing in the window. Before blaming the mapping, look further back:
        # if edges exist at all, the mapping is right and the DATA is old, which
        # is a different problem with a different fix.
        wide = self._run_one(service, query, "-90d", clean)
        older = int(wide.get("edges") or 0)
        out["edges_90d"] = older
        if older:
            newest = wide.get("newest_edge")
            out["newest_edge"] = newest
            try:
                age = (time.time() - float(newest)) / 86400.0
                age_text = "%.1f days old" % age
            except (TypeError, ValueError):
                age_text = "older than %d days" % days
            out["verdict"] = ("the mapping works: %d edges exist in the last 90 days, but the newest "
                              "is %s, outside the %d day staleness window. Either the source has "
                              "stopped receiving flows, or raise \"feed stale after\" if this feed "
                              "is expected to be that quiet. The field names are not the problem."
                              % (older, age_text, days))
        else:
            out["verdict"] = ("no permitted edges in the last 90 days. Check the index or model, "
                              "the sourcetype, the action value and the field names; Show top "
                              "100 edges will list what the reduction sees.")
        return _reply(200, out)

    def _run_one(self, service, query, earliest, clean) -> dict:
        try:
            job = service.jobs.create(query, earliest_time=earliest, latest_time="now",
                                      exec_mode="blocking", max_count=10)
            for item in results.JSONResultsReader(job.results(output_mode="json", count=10)):
                if isinstance(item, dict):
                    return item
        except Exception as exc:
            # splunkd refuses the search for a model that does not exist or is
            # not accelerated, and for an index that cannot be read. splunklib
            # raises that at whichever call first talks to the job, so both
            # are inside the guard. It is an answer about the settings, not a
            # server fault, so it is a 400 with the reason in plain words
            # rather than a 500 wrapping the raw HTTP body.
            raise ValueError(_search_refusal(exc, clean))
        return {}

    def _preview(self, service, config, limit):
        """Top edges over the last day, as the reduction produces them."""
        clean = firewall.validate(config)
        if not firewall.configured(clean):
            raise ValueError("name a source before previewing")
        try:
            n = max(1, min(int(limit or 100), 500))
        except (TypeError, ValueError):
            n = 100
        query = firewall.preview_search(clean, n)
        rows = []
        try:
            job = service.jobs.create(query, earliest_time="-%dd" % int(clean["stale_days"]),
                                      latest_time="now",
                                      exec_mode="blocking", max_count=n)
            for item in results.JSONResultsReader(job.results(output_mode="json", count=n)):
                if isinstance(item, dict):
                    rows.append({k: item.get(k) for k in
                                 ("src_ip", "dest_ip", "port", "protocol", "sessions",
                                  "first_seen", "last_seen")})
        except Exception as exc:
            raise ValueError(_search_refusal(exc, clean))
        return _reply(200, {"query": query, "limit": n, "rows": rows,
                            "returned": len(rows), "window_days": int(clean["stale_days"])})

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


def _search_refusal(exc, clean) -> str:
    text = str(exc)
    if "was not found" in text and "Data model" in text:
        return ("data model %s was not found on this search head. In accelerated "
                "mode the model must exist and be accelerated; the CIM add-on "
                "provides Network_Traffic" % clean.get("datamodel"))
    if "summariesonly" in text or "not accelerated" in text.lower():
        return ("data model %s is not accelerated, and tstats runs summaries-only "
                "here so that a firewall volume never falls back to a raw scan"
                % clean.get("datamodel"))
    import re as _re
    m = _re.search(r'"text":"([^"]{1,200})', text)
    return "the test search was refused: %s" % (m.group(1) if m else text[:200])


def _norm(text) -> str:
    return " ".join(str(text or "").replace("\\\n", " ").split())
