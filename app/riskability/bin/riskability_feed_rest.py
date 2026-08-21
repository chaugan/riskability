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
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

# Splunk bundles this base class; the Splunk SDK dropped its own copy in 3.0,
# so importing it from splunklib would break on any modern install.
from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from riskability import feed as feedlib  # noqa: E402
from riskability import importer  # noqa: E402

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
INCOMING_DIR = os.path.join(SPLUNK_HOME, "var", "run", "riskability", "incoming")

# A direct upload arrives base64-encoded in a JSON body and is held in memory
# whole. Anything larger belongs in the staged-file flow.
MAX_DIRECT_UPLOAD_BYTES = 64 * 1024 * 1024

SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


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
        return _reply(200, {
            "feed": state,
            "incoming": self._list_incoming(),
            "incoming_dir": INCOMING_DIR,
            "schema": feedlib.SCHEMA_VERSION,
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
        if action == "upload":
            return self._upload(request, body)
        if action == "import":
            return self._import(request, body)
        if action == "delete":
            return self._delete(body)
        raise ValueError(f"unknown action {action!r}")

    def _upload(self, request, body):
        path = _safe_incoming_path(body.get("filename", ""))
        data_b64 = body.get("data") or ""
        # Base64 inflates by 4/3; check before decoding so an oversized upload
        # is refused rather than materialised.
        if len(data_b64) * 3 // 4 > MAX_DIRECT_UPLOAD_BYTES:
            raise ValueError(
                f"upload exceeds {MAX_DIRECT_UPLOAD_BYTES // (1024*1024)} MB; "
                f"copy the bundle to {INCOMING_DIR} and use the import action instead"
            )
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:
            raise ValueError("data was not valid base64")

        tmp = path + ".partial"
        with open(tmp, "wb") as f:
            f.write(raw)
        # Validate before publishing the name, so a rejected bundle never
        # appears in the staged list as if it were importable.
        try:
            feedlib.read_manifest(tmp)
        except Exception:
            os.unlink(tmp)
            raise
        os.replace(tmp, path)
        return _reply(200, {"ok": True, "filename": os.path.basename(path),
                            "size_bytes": len(raw)})

    def _import(self, request, body):
        path = _safe_incoming_path(body.get("filename", ""))
        if not os.path.isfile(path):
            raise ValueError(f"no staged bundle named {os.path.basename(path)!r}")
        service = self._service(request)
        user = request.get("session", {}).get("user") or ""
        state = importer.import_bundle(path, service.kvstore, imported_by=user)
        return _reply(200, {"ok": True, "feed": state})

    def _delete(self, body):
        path = _safe_incoming_path(body.get("filename", ""))
        if os.path.isfile(path):
            os.unlink(path)
        return _reply(200, {"ok": True})
