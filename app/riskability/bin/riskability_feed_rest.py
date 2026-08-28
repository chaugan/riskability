#!/usr/bin/env python
"""Admin REST endpoint for the offline vulnerability feed.

Routes (all require ``admin_all_objects``):

    GET  /riskability/feed              current feed state + stageable files
    POST /riskability/feed {action:import, filename:...}
    POST /riskability/feed {action:upload, filename:..., data:<base64>}

Two ways in, because bundle size varies by two orders of magnitude:

* **Staged file** -- the operator copies the bundle to
  ``$SPLUNK_HOME/var/run/riskability/incoming/`` and imports it by name. This
  is the path for large bundles: nothing has to fit in memory or pass through
  Splunk Web's 500 MB ``max_upload_size``.
* **Direct upload** -- convenient for small bundles, but a persistent REST
  handler receives the whole payload as one string, so it is capped here
  rather than allowed to exhaust the search head's memory.

Filenames from the client are never joined to a path directly: only the
basename is used, and the result must still resolve inside the incoming
directory. This endpoint is a privileged file parser reachable over the
network, so it treats its input as hostile.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

# Splunk bundles this base class; the Splunk SDK dropped its own copy in 3.0,
# so importing it from splunklib would break on any modern install.
from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from riskability import build as buildlib  # noqa: E402
from riskability import feed as feedlib  # noqa: E402
from riskability import importer  # noqa: E402

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
INCOMING_DIR = os.path.join(SPLUNK_HOME, "var", "run", "riskability", "incoming")

# The four index names, held in macros so SPL picks them up by expansion and a
# site can use its own naming scheme without forking the app. Order is the
# order they appear on the setup page.
INDEX_MACROS = (
    ("riskability_index_inventory", "riskability_inventory",
     "Software inventory from swinv."),
    ("riskability_index_findings", "riskability_findings",
     "Findings the matcher produces, and its per-host receipts."),
    ("riskability_index_archive", "riskability_findings_archive",
     "Findings retired out of the live state collection."),
    ("riskability_index_audit", "riskability_audit",
     "Who accepted which risk, when, and what they said was in place instead."),
)


def _index_names(service) -> list:
    """What each index is currently called, and what it ships as."""
    out = []
    for name, shipped, blurb in INDEX_MACROS:
        current = shipped
        try:
            current = (service.confs["macros"][name].content.get("definition")
                       or shipped).strip() or shipped
        except Exception:
            pass
        out.append({"macro": name, "value": current, "default": shipped,
                    "description": blurb})
    return out

# An upload arrives base64-encoded in a JSON body, and a persistent REST
# handler holds that body in memory whole. That is why uploads are chunked:
# this bounds one request, not the bundle, so a 200 MB bundle costs the same
# memory as a 20 MB one.
#
# The old design capped the whole bundle instead and told the operator to stage
# large ones on disk. That advice is unusable on a search head cluster, where
# nobody has a shell on the member, which is precisely where a big bundle is
# most likely to be needed.
MAX_CHUNK_BYTES = 24 * 1024 * 1024

# Splunk Web's max_upload_size (500 MB by default) and splunkd's
# max_content_length (2 GB) both apply per request, so a chunk well under either
# never meets them. Nothing here needs those raised.

SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _is_clustered(service) -> bool:
    """Whether this search head is a member of a search head cluster.

    Only used to word an error message, so an unreachable endpoint or an older
    Splunk must not raise: not knowing is the same as not clustered here.
    """
    try:
        conf = service.confs["server"]["shclustering"]
        return (conf.content.get("disabled") or "1").strip() not in ("1", "true")
    except Exception:
        return False


def _safe_incoming_path(filename: str) -> str:
    """Resolve a client-supplied name inside the incoming directory, or fail.

    ``os.path.basename`` alone is not enough on its own to reason about; the
    realpath check below is what actually guarantees the result cannot escape,
    including via a symlink planted in the incoming directory.
    """
    name = os.path.basename(filename or "")
    if not name or not SAFE_NAME.match(name):
        raise ValueError(f"invalid filename: {filename!r}")
    if not name.endswith(".tar.gz"):
        raise ValueError("bundle filename must end in .tar.gz")
    os.makedirs(INCOMING_DIR, exist_ok=True)
    full = os.path.realpath(os.path.join(INCOMING_DIR, name))
    root = os.path.realpath(INCOMING_DIR)
    if not (full == root or full.startswith(root + os.sep)):
        raise ValueError("filename resolves outside the incoming directory")
    return full


def _reply(status: int, payload: dict) -> dict:
    return {
        "status": status,
        "payload": json.dumps(payload),
        "headers": {"Content-Type": "application/json"},
    }


class FeedAdminHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line=None, _command_arg=None):
        super().__init__()

    # -- helpers -----------------------------------------------------------

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

    def _set_indexes(self, service, body):
        """Point the app at differently-named indexes.

        Writes the macros to the app's local layer. It deliberately does not
        create the indexes or touch any forwarder: creating indexes on someone
        else's indexer tier is not an app's decision, and the forwarder is not
        reachable from here. Both are named in the reply so the operator is told
        what is still theirs to do, rather than finding out from an empty
        dashboard.
        """
        wanted = body.get("indexes") or {}
        shipped = {m: d for m, d, _ in INDEX_MACROS}
        changed, unknown = [], []
        for macro, value in wanted.items():
            if macro not in shipped:
                unknown.append(macro)
                continue
            value = str(value or "").strip()
            if not value:
                value = shipped[macro]
            # Splunk index names: letters, digits, underscore and hyphen, not
            # starting with an underscore (that namespace is Splunk's own).
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,255}$", value):
                raise ValueError(
                    f"{value!r} is not a usable index name. Splunk allows letters, "
                    "digits, underscores and hyphens, and a leading underscore is "
                    "reserved for Splunk's own indexes.")
            try:
                conf = service.confs["macros"]
                if macro in conf:
                    conf[macro].update(definition=value)
                else:
                    conf.create(macro, definition=value, iseval=0)
            except Exception as exc:
                raise ValueError(
                    f"could not write the {macro} macro: {exc}. The app directory "
                    "is probably not writable by the user splunkd runs as -- see "
                    "the README's install notes.")
            changed.append({"macro": macro, "value": value})
        if unknown:
            raise ValueError("unknown index setting(s): " + ", ".join(sorted(unknown)))
        return _reply(200, {
            "ok": True,
            "changed": changed,
            "indexes": _index_names(service),
            "reminder": [
                "Create these indexes on the indexers if they do not exist. "
                "TA-riskability-indexes creates the four default names only.",
                "Point the forwarder's inputs.conf at the same inventory index, "
                "or no data will arrive.",
                "Data already written to the previous indexes stays there.",
            ],
        })

    def _list_incoming(self):
        os.makedirs(INCOMING_DIR, exist_ok=True)
        out = []
        for name in sorted(os.listdir(INCOMING_DIR)):
            if not name.endswith(".tar.gz"):
                continue
            full = os.path.join(INCOMING_DIR, name)
            if not os.path.isfile(full):
                continue
            entry = {"filename": name, "size_bytes": os.path.getsize(full)}
            # Show what each staged file actually is, so an operator is not
            # importing a bundle identified only by its filename.
            try:
                m = feedlib.read_manifest(full)
                entry["manifest"] = {
                    "bundle_id": m.get("bundle_id"),
                    "bundle_version": m.get("bundle_version"),
                    "created_at": m.get("created_at"),
                    "counts": m.get("counts"),
                    "sources": [s.get("name") for s in m.get("sources", [])],
                }
            except Exception as exc:
                entry["error"] = str(exc)
            out.append(entry)
        return out

    # -- routes ------------------------------------------------------------

    def handle(self, in_string):
        # splunkd may hand this over as bytes or str depending on version.
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
        except feedlib.FeedError as exc:
            return _reply(400, {"error": f"bundle rejected: {exc}"})
        except importer.ImportError_ as exc:
            return _reply(500, {"error": str(exc)})
        except Exception as exc:
            return _reply(500, {
                "error": f"unexpected failure: {exc}",
                "traceback": traceback.format_exc(limit=6),
            })

    def _get(self, request):
        service = self._service(request)
        state = importer.current_state(service.kvstore)
        status = importer.import_status(service.kvstore)
        payload = {
            "feed": state,
            "status": status,
            "incoming": self._list_incoming(),
            "incoming_dir": INCOMING_DIR,
            "schema": feedlib.SCHEMA_VERSION,
            "indexes": _index_names(service),
        }
        # Only verify when nothing is mid-flight: during an import the counts
        # legitimately disagree, and counting millions of rows is not free.
        if not status or status.get("state") in ("done", "failed", None):
            try:
                payload["verify"] = importer.verify(service.kvstore)
            except Exception as exc:
                # Reported, not swallowed. A bare pass here hid a KeyError in
                # verify() for its whole life: the key was simply absent from
                # the reply, and the page only warns when it reads
                # consistent === false, so a check that never ran looked
                # exactly like a check that passed. consistent is None rather
                # than False - the check did not fail, it did not run, and the
                # page must not claim corruption it has not seen.
                payload["verify"] = {"consistent": None, "error": str(exc)}
        return _reply(200, payload)

    def _post(self, request):
        payload = request.get("payload")
        if not payload:
            raise ValueError("missing request payload")
        try:
            body = json.loads(payload)
        except Exception:
            raise ValueError("payload was not valid JSON")

        action = (body.get("action") or "").lower()
        if action == "upload":
            return self._upload(request, body)
        if action == "import":
            return self._import(request, body)
        if action == "delete":
            return self._delete(body)
        if action == "set_indexes":
            return self._set_indexes(self._service(request), body)
        if action == "online_check":
            return self._online_check()
        if action == "fetch":
            return self._fetch(request, body)
        raise ValueError(f"unknown action {action!r}")

    def _online_check(self):
        """Report which upstream hosts this search head can actually reach.

        Offered before the Fetch button is used so an air-gapped instance says
        so immediately, rather than starting a download that fails minutes in.
        """
        return _reply(200, {
            "ok": True,
            "reachable": buildlib.online(),
            "hosts": buildlib.NETWORK_HOSTS,
            "ecosystems": buildlib.ECOSYSTEMS,
        })

    def _fetch(self, request, body):
        """Download feeds directly and build a bundle on this search head.

        This is the one code path in the app that touches the network, and it
        runs only when an operator presses the button. Nothing here is
        scheduled, and nothing runs at install time.
        """
        service = self._service(request)
        user = request.get("session", {}).get("user") or ""

        self._refuse_if_busy(service)

        ecosystems = [e for e in (body.get("ecosystems") or []) if e in buildlib.ECOSYSTEMS]
        nvd = str(body.get("nvd") or "").strip()
        mitre = bool(body.get("mitre"))
        kev = bool(body.get("kev"))
        epss = bool(body.get("epss"))
        # The CVE Program catalogue. Accepted here so an instance that does have
        # outbound access can fetch it the same way it fetches everything else,
        # rather than the encyclopaedia's source being reachable only through
        # the offline builder.
        cve_list = bool(body.get("cve_list"))
        # Months of Microsoft update history. Bounded here rather than trusted:
        # this arrives from a browser, and each month is a separate download.
        try:
            windows_updates = int(body.get("windows_updates") or 0)
        except (TypeError, ValueError):
            windows_updates = 0
        windows_updates = max(0, min(windows_updates, 120))
        if not (ecosystems or nvd or mitre or kev or epss or cve_list
                or windows_updates):
            raise ValueError("select at least one source to fetch")

        self._queue(service, {
            "action": "fetch",
            "ecosystems": ecosystems,
            "nvd": nvd,
            "mitre": mitre,
            "kev": kev,
            "epss": epss,
            "cve_list": cve_list,
            "windows_updates": windows_updates,
            "requested_by": user,
            "requested_at": int(time.time()),
            "state": "pending",
        })
        importer._write_status(service.kvstore, state="queued",
                               message="waiting for the feed worker to start the download")
        return _reply(202, {"ok": True, "queued": True})

    def _upload(self, request, body):
        """Append one chunk of a bundle to its staging file.

        The client sends ``offset``, and the file is only published under its
        real name once ``final`` is set and the manifest parses. An offset of 0
        truncates, so a retried or abandoned upload restarts cleanly instead of
        appending to a corpse.

        A single-shot upload is just the case where offset is 0 and final is
        true, which is what an older client sends, so both still work.
        """
        path = _safe_incoming_path(body.get("filename", ""))
        data_b64 = body.get("data") or ""
        # Base64 inflates by 4/3; check before decoding so an oversized chunk is
        # refused rather than materialised.
        if len(data_b64) * 3 // 4 > MAX_CHUNK_BYTES:
            raise ValueError(
                f"chunk exceeds {MAX_CHUNK_BYTES // (1024*1024)} MB. This is a "
                f"per-request limit, not a bundle limit; send smaller chunks.")
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:
            raise ValueError("data was not valid base64")

        try:
            offset = int(body.get("offset") or 0)
        except (TypeError, ValueError):
            raise ValueError("offset must be an integer")
        if offset < 0:
            raise ValueError("offset must not be negative")
        final = bool(body.get("final", True))

        if offset == 0 and body.get("import_now"):
            # Checked before the bytes rather than after. Discovering at the end
            # of a 150 MB upload that an import was already running wastes the
            # whole transfer.
            self._refuse_if_busy(self._service(request))

        tmp = path + ".partial"
        if offset == 0:
            with open(tmp, "wb") as f:
                f.write(raw)
        else:
            # Refuse to write at an offset that does not continue the file we
            # have. Out-of-order or duplicated chunks would otherwise produce a
            # plausible-looking bundle that is quietly wrong.
            have = os.path.getsize(tmp) if os.path.exists(tmp) else 0
            if have != offset:
                raise ValueError(
                    f"chunk offset {offset} does not continue the staged file, "
                    f"which holds {have} bytes. Restart the upload.")
            with open(tmp, "ab") as f:
                f.write(raw)

        written = os.path.getsize(tmp)
        if not final:
            return _reply(200, {"ok": True, "received_bytes": written,
                                "filename": os.path.basename(path),
                                "final": False})

        # Validate before publishing the name, so a rejected bundle never
        # appears in the staged list as if it were importable.
        try:
            feedlib.read_manifest(tmp)
        except Exception:
            os.unlink(tmp)
            raise
        os.replace(tmp, path)

        # Import from here, in the request that finished the upload, because
        # this is the only moment we know which member holds the file. A second
        # request from the browser goes back through the load balancer and may
        # well arrive somewhere else, which is exactly how "no staged bundle
        # named ..." happens on a search head cluster.
        if body.get("import_now"):
            service = self._service(request)
            try:
                self._refuse_if_busy(service)
            except Exception as exc:
                # The bundle is staged and valid; only the import could not
                # start. Reporting this as a failed upload would be a lie, and
                # would send the operator to re-send bytes that already landed.
                return _reply(200, {
                    "ok": True, "filename": os.path.basename(path),
                    "size_bytes": written, "final": True, "queued": False,
                    "message": f"uploaded, but the import did not start: {exc}",
                })
            feedlib.read_manifest(path)
            user = request.get("session", {}).get("user") or ""
            self._queue(service, {
                "action": "import",
                "filename": os.path.basename(path),
                "requested_by": user,
                "requested_at": int(time.time()),
                "state": "pending",
            })
            importer._write_status(service.kvstore, state="queued",
                                   message="waiting for the feed worker",
                                   bundle_version=os.path.basename(path))
            return _reply(202, {"ok": True, "filename": os.path.basename(path),
                                "size_bytes": written, "final": True,
                                "queued": True})

        return _reply(200, {"ok": True, "filename": os.path.basename(path),
                            "size_bytes": written, "final": True})

    def _import(self, request, body):
        """Queue an import for the feed worker and return immediately.

        The work deliberately does not happen here. Importing a full bundle
        takes minutes, and splunkd recycles the persistent-script process this
        handler runs in when it goes idle -- an early version ran the import on
        a thread here and it died at 804,000 of 3,323,891 rows, silently. The
        riskability_feedworker modular input does the work instead; splunkd
        keeps that alive.
        """
        path = _safe_incoming_path(body.get("filename", ""))
        service = self._service(request)
        if not os.path.isfile(path):
            # On a search head cluster this is almost never a missing file. The
            # upload landed on whichever member the load balancer chose, and
            # this request reached a different one. Saying so is the difference
            # between a five minute fix and an afternoon.
            hint = ""
            if _is_clustered(service):
                hint = (" This member is "
                        f"{importer.member_id(service) or 'unidentified'} and it "
                        "is part of a search head cluster, where staged files "
                        "are local to the member that received them. Upload the "
                        "bundle again from this page: an upload now starts its "
                        "own import on the member that holds it.")
            raise ValueError(
                f"no staged bundle named {os.path.basename(path)!r}." + hint)
        user = request.get("session", {}).get("user") or ""

        self._refuse_if_busy(service)

        # Validate in the request, so a bad bundle is an immediate error to the
        # operator rather than a background failure they must go looking for.
        feedlib.read_manifest(path)

        self._queue(service, {
            "action": "import",
            "filename": os.path.basename(path),
            "requested_by": user,
            "requested_at": int(time.time()),
            "state": "pending",
        })
        importer._write_status(service.kvstore, state="queued",
                               message="waiting for the feed worker",
                               bundle_version=os.path.basename(path))
        return _reply(202, {"ok": True, "queued": True,
                            "filename": os.path.basename(path)})

    # -- queueing ----------------------------------------------------------

    # A feed operation that stops reporting for this long is treated as dead.
    # Generously above the worst observed gap between progress writes on a
    # 3.3M-row import, so a slow import is never mistaken for a stalled one.
    STALE_AFTER_SECONDS = 900

    def _refuse_if_busy(self, service):
        """Refuse a second concurrent operation -- but not because of a corpse.

        A worker can die without clearing its status: splunkd restarts, the
        machine reboots, the process is killed. Left alone, the stale row makes
        the app permanently refuse every future import with "already running",
        and the only fix is editing the KV Store by hand. So a status that has
        not been updated for a long time is declared failed and stepped over.
        """
        running = importer.import_status(service.kvstore) or {}
        state = running.get("state")
        if state not in ("queued", "importing", "cleaning", "fetching"):
            return

        try:
            age = int(time.time()) - int(running.get("updated_at") or 0)
        except (TypeError, ValueError):
            age = 0
        if age > self.STALE_AFTER_SECONDS:
            importer._write_status(
                service.kvstore, state="failed",
                error=(f"the previous {state} operation stopped reporting "
                       f"{age // 60} minutes ago and was assumed dead. The live "
                       f"feed was not affected."))
            try:
                service.kvstore["riskability_feedstate"].data.delete(
                    json.dumps({"_key": "import_request"}))
            except Exception:
                pass
            return

        raise ValueError(
            "a feed operation is already running or queued; wait for it to "
            "finish before starting another")

    def _queue(self, service, row):
        """Record a request for the feed worker to pick up on its next tick.

        Stamped with this member, because the row replicates across a search
        head cluster but the staged file it names does not. A worker elsewhere
        must leave the job alone rather than claim it and fail to find the file.
        """
        row.setdefault("owner", importer.member_id(service))
        data = service.kvstore["riskability_feedstate"].data
        try:
            data.delete(json.dumps({"_key": "import_request"}))
        except Exception:
            pass
        row["_key"] = "import_request"
        data.insert(json.dumps(row))

    def _mark_configured(self, service):
        """Clear Splunk's first-run setup gate once a feed actually exists.

        app.conf ships ``is_configured = 0`` so a fresh install lands the admin
        on this page instead of on dashboards that can only show zeroes. Nothing
        clears that flag on its own, though, so without this the setup screen
        keeps interrupting every navigation forever. Importing a feed is the
        one thing that makes the app useful, so it is what marks it configured.
        """
        try:
            service.post("/servicesNS/nobody/riskability/apps/local/riskability",
                         configured=1)
        except Exception:
            # Never fail an otherwise-successful import over a cosmetic flag.
            pass

    def _delete(self, body):
        path = _safe_incoming_path(body.get("filename", ""))
        if os.path.isfile(path):
            os.unlink(path)
        return _reply(200, {"ok": True})
