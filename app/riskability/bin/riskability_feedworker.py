#!/usr/bin/env python
"""Modular input that performs feed imports and online fetches.

Why this exists rather than doing the work in the REST handler:

Importing a full bundle takes minutes. The first implementation ran it on a
background thread inside the persistent REST handler, which fails in a way that
is easy to miss -- splunkd owns that process's lifecycle and shuts down the
``PersistentScriptPool`` when it goes idle, taking the thread with it. Observed
directly: an import stopped at 804,000 of 3,323,891 rows with no error anywhere
except a "Connection closed by peer" on the status write, and the generation it
was building simply stopped growing.

A modular input is the mechanism Splunk provides for long-running work. splunkd
keeps it alive, restarts it if it dies, and runs it on the schedule in
inputs.conf. So the REST handler now only *records* a request, and this worker
picks it up and does the work.

Because imports are generation-tagged, a worker killed mid-import is harmless:
the live feed is untouched and the partial generation is cleaned up by the next
successful import.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402
from splunklib.modularinput import Scheme, Script  # noqa: E402

from riskability import build as buildlib  # noqa: E402
from riskability import feed as feedlib  # noqa: E402
from riskability import importer  # noqa: E402

REQUEST_KEY = "import_request"

# How long an in-flight operation may go without a progress write before it is
# assumed dead. Comfortably above the importer's progress interval.
ORPHAN_AFTER_SECONDS = 300
STATE_COLLECTION = "riskability_feedstate"
FINDINGS_STATE_COLLECTION = "riskability_findings_state"

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
INCOMING_DIR = os.path.join(SPLUNK_HOME, "var", "run", "riskability", "incoming")


def read_request(kvstore):
    try:
        rows = kvstore[STATE_COLLECTION].data.query(
            query=json.dumps({"_key": REQUEST_KEY}))
    except Exception:
        return None
    return rows[0] if rows else None


def write_request(kvstore, row) -> None:
    data = kvstore[STATE_COLLECTION].data
    try:
        data.delete(json.dumps({"_key": REQUEST_KEY}))
    except Exception:
        pass
    if row is not None:
        row["_key"] = REQUEST_KEY
        data.insert(json.dumps(row))


def clear_request(kvstore) -> None:
    write_request(kvstore, None)


class FeedWorker(Script):
    def get_scheme(self):
        scheme = Scheme("Riskability feed worker")
        scheme.description = (
            "Performs vulnerability feed imports and online fetches requested "
            "from the Riskability admin page. Long-running work cannot live in "
            "a REST handler, whose process splunkd recycles when idle.")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        # Deliberately no arguments. "interval" in particular must NOT be
        # declared: Splunk handles it internally and refuses to initialise a
        # modular input that defines it via introspection ("Endpoint argument
        # 'interval' is an internal argument ... should not be defined").
        return scheme

    def validate_input(self, definition):
        return

    def stream_events(self, inputs, ew):
        for name, item in inputs.inputs.items():
            try:
                self._run_once(name, item, ew)
            except Exception:
                ew.log("ERROR", "riskability feed worker failed: "
                                + traceback.format_exc(limit=6).replace("\n", " | "))

    def _run_once(self, name, item, ew):
        service = client.connect(
            token=self.service.token,
            owner="nobody",
            app="riskability",
            host=self.service.host,
            port=self.service.port,
            scheme=self.service.scheme,
        )
        kv = service.kvstore
        request = read_request(kv)

        # Self-heal an orphaned operation. A worker that is killed -- splunkd
        # restart, reboot, OOM -- leaves the status saying "importing" forever,
        # and the app then refuses every future request as "already running".
        # A live operation always has a request row, because the worker only
        # clears it after writing the final status. So an in-flight status with
        # no request row means the owner is gone.
        status = importer.import_status(kv) or {}
        in_flight = status.get("state") in ("importing", "cleaning", "fetching")
        try:
            quiet_for = int(time.time()) - int(status.get("updated_at") or 0)
        except (TypeError, ValueError):
            quiet_for = 0
        # A worker claims its request before starting and clears it only after
        # writing the final status, so a "running" request whose status has
        # gone quiet belongs to a worker that is no longer alive. The window is
        # generous relative to the progress interval, so a slow import is never
        # mistaken for a dead one.
        abandoned = (in_flight and request
                     and request.get("state") == "running"
                     and quiet_for > ORPHAN_AFTER_SECONDS)
        if (in_flight and not request) or abandoned:
            # An interruption after the atomic flip is not a failure: the feed
            # landed and only the old generation's cleanup was cut short. Saying
            # "the last import failed" above a feed showing 487,041 advisories
            # is worse than saying nothing, so compare what the operation was
            # building against what is now live before declaring anything.
            target = 0
            try:
                target = int(status.get("generation") or 0)
            except (TypeError, ValueError):
                pass
            live = importer.live_generation(kv)

            if target and live >= target:
                importer._write_status(
                    kv, state="done", generation=live,
                    error="",
                    message="completed; the previous feed's cleanup was "
                            "interrupted and will finish on the next import")
                ew.log("INFO", "riskability: operation had already completed "
                               "before the interruption; marked done")
                # The old generation is unreachable but still occupying space.
                for gen in range(0, live):
                    importer._delete_generation(kv, gen)
            else:
                importer._write_status(
                    kv, state="failed",
                    error="the worker running this operation was interrupted "
                          "(usually a Splunk restart). The live feed was not "
                          "affected; start the import again.")
                ew.log("WARN", "riskability: cleared an orphaned feed operation")
            clear_request(kv)
            return

        if not request or request.get("state") != "pending":
            # Nothing queued: use the tick to finish any cleanup a previous run
            # was interrupted during. A stale generation is not merely wasted
            # space -- the advisory enrichment lookup matches on cve_id without
            # a generation filter, so a leftover row can be returned in place of
            # the live one.
            if status.get("state") not in ("importing", "cleaning", "fetching"):
                self._sweep_stale_generations(kv, ew)
                self._reconcile_configured(service, kv, ew)
                self._expire_archived_findings(kv, ew)
            return

        action = request.get("action")
        user = request.get("requested_by") or ""

        # Claim it before starting, so a second worker tick cannot pick up the
        # same job while this one is running.
        request["state"] = "running"
        request["claimed_at"] = int(time.time())
        write_request(kv, dict(request))

        try:
            if action == "import":
                path = self._staged_path(request.get("filename", ""))
                ew.log("INFO", f"riskability: importing {os.path.basename(path)}")
                importer.import_bundle(path, kv, imported_by=user)

            elif action == "fetch":
                stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
                out = os.path.join(INCOMING_DIR,
                                   f"riskability-feed-online-{stamp}.tar.gz")
                os.makedirs(INCOMING_DIR, exist_ok=True)
                ew.log("INFO", "riskability: fetching feeds from upstream")

                def say(msg):
                    importer._write_status(kv, state="fetching", message=msg)

                buildlib.build_bundle(
                    out,
                    ecosystems=request.get("ecosystems") or [],
                    nvd=request.get("nvd") or "",
                    mitre=bool(request.get("mitre")),
                    kev=bool(request.get("kev")),
                    epss=bool(request.get("epss")),
                    version=f"online-{stamp}",
                    log=say,
                )
                importer.import_bundle(out, kv, imported_by=user)

            else:
                raise ValueError(f"unknown action {action!r}")

            self._mark_configured(service)
            ew.log("INFO", "riskability: feed operation complete")

        except Exception as exc:
            importer._write_status(kv, state="failed", error=str(exc))
            ew.log("ERROR", f"riskability: feed operation failed: {exc}")
        finally:
            clear_request(kv)

    def _reconcile_configured(self, service, kv, ew) -> None:
        """Keep Splunk's setup gate in step with whether a feed actually exists.

        app.conf ships is_configured=0 so a fresh install lands the admin on the
        feed page instead of on dashboards that can only show zeroes. Clearing
        that writes to local/app.conf -- which a reinstall or an upgrade
        replaces, leaving Splunk insisting the app "has not been fully
        configured yet" while the KV Store holds half a million advisories.

        The flag should describe the current state rather than remember a past
        event, so it is recomputed here: a feed present means configured.
        """
        if importer.live_generation(kv) <= 0:
            return
        try:
            app = service.apps["riskability"]
            if str(app.content.get("configured", "0")).lower() in ("1", "true"):
                return
        except Exception:
            return
        try:
            service.post("/servicesNS/nobody/riskability/apps/local/riskability",
                         configured=1)
            ew.log("INFO", "riskability: a feed is present; cleared the setup gate")
        except Exception:
            pass

    def _expire_archived_findings(self, kv, ew) -> None:
        """Delete state rows that have already been written to the archive.

        Deletion, not the decision to delete. A scheduled search decides what
        has aged out, writes it to the archive index and stamps the row; this
        only removes rows carrying that stamp. Splitting it that way means a
        failed archive leaves the row in place rather than losing it, which is
        the right direction for the failure to go.

        It is here rather than in SPL because removing rows from a KV Store
        collection with outputlookup means rewriting the whole collection --
        and while that rewrite is in flight, dashboards read a partial or empty
        result. On a vulnerability dashboard that renders as "no findings",
        which is the most dangerous wrong answer this app can give. A delete by
        query touches only the rows concerned and is invisible to readers.
        """
        try:
            data = kv[FINDINGS_STATE_COLLECTION].data
        except Exception:
            return
        # "$ne": null, not "$exists". Splunk's KV Store accepts only a subset of
        # MongoDB's query operators and rejects $exists outright with "The
        # provided query was invalid" -- and the worker swallowed that, so
        # nothing was ever deleted and nothing was ever logged. $gt: 0 is no
        # good either: SPL writes the timestamp as a string, so a numeric
        # comparison matches nothing.
        selector = json.dumps({"archived": {"$ne": None}})
        try:
            pending = data.query(query=selector, limit=1)
        except Exception as exc:
            ew.log("WARN", f"riskability: could not look for archived findings: {exc}")
            return
        if not pending:
            return
        try:
            data.delete(query=selector)
            ew.log("INFO", "riskability: removed archived findings from the "
                           "state collection")
        except Exception as exc:
            # Not fatal: the rows stay, the archive already has them, and the
            # next tick tries again. Better a collection that is briefly larger
            # than one that is briefly wrong.
            ew.log("WARN", f"riskability: could not expire archived findings: {exc}")

    def _sweep_stale_generations(self, kv, ew) -> None:
        live = importer.live_generation(kv)
        if live <= 0:
            return
        removed = []
        for gen in range(0, live):
            try:
                rows = kv[importer.COLLECTIONS["advisories"]].data.query(
                    query=json.dumps({"gen": gen}), limit=1)
            except Exception:
                continue
            if rows:
                importer._delete_generation(kv, gen)
                removed.append(gen)
        if removed:
            ew.log("INFO", "riskability: removed stale feed generation(s) "
                           + ",".join(str(g) for g in removed))

    def _staged_path(self, filename: str) -> str:
        name = os.path.basename(filename or "")
        full = os.path.realpath(os.path.join(INCOMING_DIR, name))
        root = os.path.realpath(INCOMING_DIR)
        if not name or not (full == root or full.startswith(root + os.sep)):
            raise ValueError(f"invalid staged filename {filename!r}")
        if not os.path.isfile(full):
            raise ValueError(f"no staged bundle named {name!r}")
        return full

    def _mark_configured(self, service):
        try:
            service.post("/servicesNS/nobody/riskability/apps/local/riskability",
                         configured=1)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(FeedWorker().run(sys.argv))
