#!/usr/bin/env python
"""Admin REST endpoint for the AI analysis pipeline.

Routes (the admin route requires the ``riskability_ai_admin`` capability, see
restmap.conf and authorize.conf; the status route is readable by anyone who
can list settings):

    GET  /riskability/ai            current AI configuration + pipeline state
    POST /riskability/ai            {action: set | clear_password |
                                              test_connection |
                                              test_completion | test_bert}
    GET  /riskability/ai_status     {enabled: true|false} -- and nothing else

The admin route is deliberately a different capability from
``admin_all_objects``, which guards the feed endpoint. Configuring the GPU
analysis and importing vulnerability feeds are different duties: a site may
well want the person who owns the GPU box to own this page without owning the
feed, and the answer to "who can switch AI prioritisation on" should be
readable off one capability name rather than inferred from a superset.

Two properties the handlers rely on and the tests pin down:

* The secret never leaves the server. Storage passwords hold it; GET replies
  carry only ``password_set``; probes receive it in-process and their replies
  are prose written by ai_config, which never echoes credentials.
* The user-facing part of the app learns exactly one fact from
  ``/riskability/ai_status`` -- whether AI prioritisation is switched on. No
  URL, no model name, no endpoint existence hint, so an instance where an
  admin never configured AI gives a normal user nothing to observe at all.
"""

from __future__ import annotations

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from riskability import ai_config, ai_settings  # noqa: E402
from riskability.ai_settings import SECRET_REALM, SECRET_USER  # noqa: E402,F401

# The storage password is one entry, namespaced so nothing else in the
# instance can collide with it: realm "riskability", user "riskability_ai".
# Anyone who can list storage passwords can read it back in clear -- that is
# Splunk's own trust model for storage passwords, and list_storage_passwords
# is an admin-tier capability, not an analyst one.
SECRET_REALM = "riskability"
SECRET_USER = "riskability_ai"

# Saved searches the master switch owns. All four ship disabled: a scheduled
# search building a candidate queue for a model endpoint nobody configured
# would sit there running every hour for nothing, and worse, announce the
# pipeline's existence in the job system. The set action flips them together.
QUEUE_SEARCH = "Riskability AI - generate candidate queue"
HEALTH_SEARCH = "Riskability AI - results stopped arriving"
ANALYZE_SEARCH = "Riskability AI - analyze latest queue"
EXPAND_SEARCH = "Riskability AI - expand verdicts to findings"
MANAGED_SEARCHES = (QUEUE_SEARCH, HEALTH_SEARCH, ANALYZE_SEARCH, EXPAND_SEARCH)

# The one-bit mirror of the master switch that normal users can read (see
# collections.conf for why it is not the conf file). Every set action rewrites
# it, so the conf file and this row cannot disagree for longer than one save.
STATE_COLLECTION = "riskability_aistate"


def _reply(status: int, payload: dict) -> dict:
    return {
        "status": status,
        "payload": json.dumps(payload),
        "headers": {"Content-Type": "application/json"},
    }


class AIAdminHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line=None, _command_arg=None):
        super().__init__()

    # -- plumbing ----------------------------------------------------------

    def _service(self, meta: dict):
        session_key = meta.get("session", {}).get("authtoken")
        if not session_key:
            raise PermissionError("no session token")
        return client.connect(
            token=session_key,
            owner="nobody",
            app="riskability",
            host=meta.get("server", {}).get("hostname") or "localhost",
            port=meta.get("server", {}).get("port") or 8089,
            scheme="https",
        )

    def _read_secret(self, service) -> str:
        """The stored secret, or "" when none is set. Never logged."""
        return ai_settings.read_secret(service)

    def _password_set(self, service) -> bool:
        return ai_settings.password_set(service)

    def _write_secret(self, service, secret: str):
        """Rotate: delete then create. Storage passwords are updated by
        replacement, and a failed create after a successful delete must be
        visible here rather than silently leaving the pipeline keyless."""
        ai_settings.write_secret(service, secret)

    def _delete_secret(self, service):
        ai_settings.delete_secret(service)

    def _read_config(self, service) -> dict:
        """The [connection] stanza as strings, defaults filled from the
        schema so the page always renders a complete form. Unknown keys in a
        hand-edited conf are dropped rather than served."""
        return ai_settings.load_config(service)

    def _write_config(self, service, merged: dict):
        ai_settings.write_config(service, merged)

    def _search_states(self, service) -> dict:
        out = {}
        for name in MANAGED_SEARCHES:
            state = {"disabled": True}
            try:
                entity = service.confs["savedsearches"][name]
                state["disabled"] = str(entity.content.get("disabled", "1")) in ("1", "true")
            except Exception:
                pass
            out[name] = state
        return out

    def _set_searches(self, service, disabled: bool) -> str:
        """Flip every managed schedule, and say which ones would not move.

        Returns prose for the reminders list, or "" when all four followed.

        This used to swallow the failure entirely, and the comment claimed the
        page reported it. It did not, and the gap was invisible for as long as
        the searches shipped with no disabled key: a search nobody managed
        simply ran, so a silent failure and a success looked identical. Now
        that they ship disabled, the same silence has the opposite effect and
        is far worse. A switch-on that quietly fails to enable the analyse and
        expand searches leaves the queue search building a candidate queue
        every hour that nothing ever consumes: no verdicts, no prioritised
        rows, no error, and a page that says AI analysis is on. Found exactly
        that on the reference instance, where only two of the four searches
        had ever been written.
        """
        failed = []
        for name in MANAGED_SEARCHES:
            try:
                service.confs["savedsearches"][name].update(
                    disabled="1" if disabled else "0")
            except Exception as exc:
                failed.append("%s (%s)" % (name, exc))
        if not failed:
            return ""
        return ("These schedules could not be %s and the pipeline will not "
                "run correctly until they are: %s"
                % ("disabled" if disabled else "enabled", "; ".join(failed)))

    def _sync_macros(self, service, merged: dict) -> str:
        """Re-stamp the macros that mirror a saved setting, and say so when
        that fails.

        Two settings are edited here as conf fields and read elsewhere as
        macros, because a scheduled search can expand a macro and cannot read
        a conf file: the per-run budget, and the verdict cache salt. Every
        save re-stamps both from what was just saved, so there is one source
        of truth rather than a conf value and a macro drifting apart.

        This used to be written twice, once here and once in ai_settings, and
        only the ai_settings copy was ever called. Two implementations of a
        bridge whose whole purpose is to stop two copies of a number
        disagreeing is the joke telling itself, so the local copy is gone.

        A failure is RETURNED rather than raised or swallowed. Raising would
        report a save that did happen as a failure, since the settings are
        already written by the time this runs. Swallowing would leave the
        page showing one budget while the queue obeys another, which is the
        exact condition this bridge exists to prevent and the one nobody goes
        looking for.
        """
        try:
            ai_settings.sync_budget_macro(service, merged["candidate_cap"])
            ai_settings.sync_sig_salt_macro(service, merged["model"],
                                            merged.get("endpoint_fingerprint", ""))
        except Exception as exc:
            return (
                "The settings are saved, but the macros the scheduled "
                "searches read could not be re-stamped (%s). Until they are, "
                "the candidate queue keeps its previous size limit and the "
                "verdict cache keeps its previous salt, so a changed model "
                "will be answered from the old model's cached verdicts. Save "
                "again once splunkd accepts a configuration write." % exc)
        return ""

    def _mirror_enabled(self, service, enabled: bool):
        """Publish the switch to everything that reads it.

        Two stores, because two audiences read two different resources:

        * the riskability_aistate KV row, for /riskability/ai_status -- the one
          endpoint a normal user can reach;
        * the AI overview view's ACL, for Splunk's own navigation filtering.

        The second is what actually keeps the page out of the nav bar while AI
        is off: Splunk filters nav entries by view read permission server
        side, so the item never renders for a user at any point, not even for
        the instant before a script could hide it. When the switch moves, the
        ACL opens to everyone or closes back to admins.

        Delete-then-insert for the KV row, the same pattern the feed queue
        uses for its request row, because a KV Store update on a
        possibly-absent row is two questions where one write will do.
        """
        data = service.kvstore[STATE_COLLECTION].data
        try:
            data.delete(json.dumps({"_key": "ai_enabled"}))
        except Exception:
            pass
        data.insert(json.dumps({"_key": "ai_enabled",
                                "enabled": "1" if enabled else "0"}))
        # Splunk takes a comma-separated role list in one perms.read parameter.
        # The path is absolute (leading slash) on purpose: splunklib prefixes a
        # relative path with the connection's own namespace, which turned this
        # into /servicesNS/nobody/riskability/servicesNS/nobody/riskability/...
        # and a 404 that the save swallowed, so the page never opened to anyone.
        # The fields go as the request body, also on purpose: splunklib's post()
        # takes owner, app and sharing as ITS namespace arguments and drops them,
        # and splunkd then refuses the write for missing owner and sharing.
        service.post(
            "/servicesNS/nobody/riskability/data/ui/views/riskability_ai/acl",
            body={"perms.read": "*" if enabled else "admin,sc_admin",
                  "owner": "nobody", "sharing": "app"})

    # -- routes ------------------------------------------------------------

    def handle(self, in_string):
        if isinstance(in_string, (bytes, bytearray)):
            in_string = in_string.decode("utf-8")
        try:
            request = json.loads(in_string)
        except Exception:
            return _reply(400, {"error": "request body was not valid JSON"})
        method = (request.get("method") or "GET").upper()
        try:
            if method == "GET":
                return self._get(request)
            if method == "POST":
                return self._post(request)
            return _reply(405, {"error": f"{method} is not supported"})
        except PermissionError as exc:
            return _reply(401, {"error": str(exc)})
        except ValueError as exc:
            return _reply(400, {"error": str(exc)})
        except Exception as exc:
            return _reply(500, {
                "error": f"unexpected failure: {exc}",
                "traceback": traceback.format_exc(limit=6),
            })

    def _view_open(self, service):
        """True if the overview view is readable by everyone, False if by
        admins only, None if the ACL could not be read."""
        try:
            body = service.get("/servicesNS/nobody/riskability/data/ui/views/riskability_ai",
                               output_mode="json").body.read()
            perms = json.loads(body)["entry"][0]["acl"].get("perms") or {}
            return "*" in (perms.get("read") or [])
        except Exception:
            return None

    def _heal_mirror(self, service, current):
        """Re-assert the view ACL from the switch when the two disagree.

        The ACL is written when the switch is saved and at no other time, so
        a switch that was flipped before this mirror existed, or a search head
        whose local metadata was lost, leaves the page closed to everyone but
        admins while AI is on. Every admin visit to the settings page is a
        chance to notice and put it right; it costs one read when they agree.
        """
        enabled = str(current.get("enabled") or "0") == "1"
        state = self._view_open(service)
        if state is None or state == enabled:
            return
        try:
            self._mirror_enabled(service, enabled)
        except Exception:
            pass

    def _get(self, request):
        service = self._service(request)
        current = self._read_config(service)
        self._heal_mirror(service, current)
        # The test history is written to the same stanza by _note_test but is
        # not a setting, so load_config drops it with every other unknown key;
        # it is read here on its own, or the page said "never run" for ever.
        try:
            current["last_test"] = service.confs["riskability_ai"]["connection"].content.get("last_test") or ""
        except Exception:
            current["last_test"] = ""
        return _reply(200, {
            "config": current,
            "password_set": self._password_set(service),
            "searches": self._search_states(service),
            "presets": {name: {"label": preset["label"], "values": preset["values"]}
                        for name, preset in ai_config.PRESETS.items()},
            # What the pipeline expects to find on this instance, spelled out
            # so the GPU box's operator can copy the contract straight from
            # the page that configures the other half of it.
            "contract": {
                "candidates_index_macro": "riskability_index_ai_candidates",
                "prioritized_index_macro": "riskability_index_ai_prioritized",
                "alerts_index_macro": "riskability_index_ai_alerts",
                "candidate_sourcetype": "riskability:ai:candidate",
                "prioritized_sourcetype": "riskability:ai:prioritized",
                "alerts_sourcetype": "riskability:ai:alert",
            },
        })

    def _post(self, request):
        payload = request.get("payload")
        if not payload:
            raise ValueError("missing request payload")
        try:
            body = json.loads(payload)
        except Exception:
            raise ValueError("payload was not valid JSON")
        action = (body.get("action") or "").lower()
        if action == "set":
            return self._set(request, body)
        if action == "clear_password":
            return self._clear_password(request)
        if action == "test_connection":
            return self._test_connection(request)
        if action == "test_completion":
            return self._test_completion(request)
        if action == "test_bert":
            return self._test_bert(request)
        raise ValueError(f"unknown action {action!r}")

    # -- actions -----------------------------------------------------------

    def _effective(self, request, body) -> dict:
        """The merged settings a test action should use: what is saved, with
        anything the admin just typed overlaid. The Test buttons must test
        what the Save button would save, or they answer a question nobody
        asked -- the classic order is type URL, test, save, and a test that
        reads only stored settings reports the previous URL as unreachable."""
        current = self._read_config(self._service(request))
        updates = {k: v for k, v in (body.get("config") or {}).items()
                   if k in ai_config.FIELD_SPECS and k != "enabled"}
        try:
            return ai_config.validate_settings(updates, current)
        except ValueError as exc:
            raise ValueError("could not use those settings: %s" % exc)

    def _set(self, request, body):
        service = self._service(request)
        current = self._read_config(service)
        updates = {k: v for k, v in (body.get("config") or {}).items()}
        merged = ai_config.validate_settings(updates, current)
        self._write_config(service, merged)

        reminders = []
        password_message = ""
        # An empty password string means "leave the stored one alone"; only a
        # non-empty value rotates. There is no field on the page that shows
        # the secret, so the browser never has it to send back -- a form that
        # round-trips passwords trains everyone to put them in JavaScript.
        secret = str(body.get("password") or "")
        if secret:
            if len(secret) > 4096:
                raise ValueError("the secret is too long")
            self._write_secret(service, secret)
            password_message = "Secret stored in Splunk's encrypted password store."
        elif body.get("clear_password"):
            self._delete_secret(service)
            password_message = "Stored secret removed."

        # Derived, never accepted from the caller: whatever arrived in the
        # request body for this field is overwritten with what the endpoint
        # itself reports, so it cannot be spoofed into pinning a stale cache.
        # A probe failure leaves the previous value alone rather than blanking
        # it, because "we could not reach the server just now" is not evidence
        # that the server changed.
        try:
            probed = ai_config.endpoint_fingerprint(
                merged["endpoint_url"], merged["auth_type"], merged["username"],
                self._secret_for_test(request, body), merged["model"],
                merged["verify_tls"] == "1", int(merged["request_timeout"]))
            if probed:
                merged["endpoint_fingerprint"] = probed
                self._write_config(service, merged)
        except Exception:
            pass

        enabled = merged["enabled"] == "1"
        schedule_error = self._set_searches(service, disabled=not enabled)
        # Unconditionally, on the one path that can write these settings.
        # Not inside the "enabled" branch: an admin who lowers the budget
        # while AI is off, then switches it on later, must not get one run at
        # the old number. The test actions below never write settings, so
        # this is the only place the mirrors can fall behind.
        macro_error = self._sync_macros(service, merged)
        # Mirrored last: the user-facing bit flips only after the schedules
        # behind it have followed, so the page can never be visible while its
        # pipeline is still disabled, nor hidden while its schedules still run.
        mirror_error = ""
        try:
            self._mirror_enabled(service, enabled)
        except Exception as exc:
            mirror_error = (
                "The master switch could not be published (%s). The setting is "
                "saved; until it publishes, the AI page's visibility and the "
                "status endpoint may lag one save behind. Save once more once "
                "the KV Store and REST are reachable." % exc)
        if enabled:
            # The three scheduled searches do the whole job on this search
            # head, so the reminders describe the model SERVER's settings
            # rather than an orchestrator's environment. Saying otherwise
            # sent admins to configure a component this app does not have.
            reminders = [
                "The AI searches are now scheduled: the queue is built at "
                ":50, analysed at :52 and expanded onto findings at :55. "
                "Nothing leaves this instance except the analysis requests "
                "to the endpoint above.",
                "Concurrency is set to %s. It must match what the model "
                "server itself serves in parallel (OLLAMA_NUM_PARALLEL, or "
                "vLLM's batching); above that the requests queue inside the "
                "server. On the reference RTX 3060 one request answered in "
                "3,142 ms, while the median at concurrency 8 was 23,419 ms "
                "for about six per cent more throughput."
                % merged["t2_concurrency"],
                "Run 'Test analysis' once against this endpoint before "
                "trusting the first scheduled run.",
            ]
        else:
            reminders = [
                "AI prioritisation is switched off. The AI page is hidden "
                "from everyone, the queue search is disabled, and no data "
                "leaves this instance.",
            ]
        # Appended after the static text: a reminder list built above must
        # not silently overwrite a failure notice nobody would otherwise see,
        # which is exactly what an append-before-replace does.
        for problem in (schedule_error, macro_error, mirror_error):
            if problem:
                reminders.append(problem)
        return _reply(200, {
            "ok": True,
            "config": self._read_config(service),
            "password_set": self._password_set(service),
            "password_message": password_message,
            "searches": self._search_states(service),
            "reminders": reminders,
        })

    def _clear_password(self, request):
        service = self._service(request)
        self._delete_secret(service)
        return _reply(200, {"ok": True,
                            "password_set": self._password_set(service)})

    def _secret_for_test(self, request, body) -> str:
        """The secret a test action should use: the one just typed if the
        admin typed one (without saving it), else the stored one."""
        typed = str(body.get("password") or "")
        if typed:
            return typed
        return self._read_secret(self._service(request))

    def _test_connection(self, request):
        body = self._body(request)
        cfg = self._effective(request, body)
        result = ai_config.probe_models(
            cfg["endpoint_url"], cfg["auth_type"], cfg["username"],
            self._secret_for_test(request, body),
            cfg["verify_tls"] == "1", cfg["request_timeout"])
        self._note_test(request, "connection", result["ok"],
                        "HTTP 200 · %s ms · models: %s"
                        % (result["latency_ms"], ", ".join(result["models"][:5]) or "none listed"))
        result["hint"] = (
            "If the model name here differs from the configured one, either "
            "change the setting or serve the model under the configured name.")
        return _reply(200, result)

    def _test_completion(self, request):
        body = self._body(request)
        cfg = self._effective(request, body)
        result = ai_config.probe_completion(
            cfg["endpoint_url"], cfg["auth_type"], cfg["username"],
            self._secret_for_test(request, body), cfg["model"],
            cfg["verify_tls"] == "1", cfg["request_timeout"])
        if result.get("ok"):
            # The validated answer carries the model's own tier and score as
            # model_tier and model_score: the priority the app uses is computed
            # from measured facts, and the model's is recorded for calibration.
            # Reading the old names here raised KeyError on a test that had in
            # fact succeeded, reported as "unexpected failure: 'priority_tier'".
            res = result.get("result") or {}
            detail = "%s ms · model said tier %s, score %s" % (
                result["latency_ms"], res.get("model_tier", "?"), res.get("model_score", "?"))
        else:
            detail = result.get("validation_error") or "invalid output"
        self._note_test(request, "analysis", result.get("ok", False), detail)
        return _reply(200, result)

    def _test_bert(self, request):
        body = self._body(request)
        cfg = self._effective(request, body)
        if not cfg["bert_url"]:
            raise ValueError("no classifier URL is configured")
        result = ai_config.probe_bert(
            cfg["bert_url"], cfg["verify_tls"] == "1", cfg["request_timeout"])
        detail = ("classified: %s" % ", ".join(result.get("tactics", []))) \
            if result.get("ok") else result.get("error", "failed")
        self._note_test(request, "classifier", result.get("ok", False), detail)
        return _reply(200, result)

    # The body arrives on POST only; the test helpers read it from the
    # original request so they can be called in any order without re-parsing.
    def _body(self, request):
        payload = request.get("payload") or "{}"
        try:
            return json.loads(payload)
        except Exception:
            return {}

    def _note_test(self, request, kind, ok, detail):
        """Best-effort history. A test that could not even reach out still
        wants its failure remembered on the page; a failure to record that
        failure must not replace the original error."""
        try:
            service = self._service(request)
            conf = service.confs["riskability_ai"]
            stanza = conf["connection"]
            stanza.update(last_test=ai_config.summarize_test(kind, ok, detail))
        except Exception:
            pass
