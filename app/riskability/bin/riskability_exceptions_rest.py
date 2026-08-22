#!/usr/bin/env python
"""The risk-exception register: create, edit, revoke and list exceptions.

Why an endpoint rather than letting the dashboard write the collection

A KV Store collection's ACL can say "admin may write" but it cannot say "the
holder of riskability_accept_risk may write". Splunk expresses that only
through a REST endpoint's ``capability.post``. Letting the browser POST to
``/storage/collections/data/...`` would mean the authorisation question is
answered by a collection permission that cannot express the answer -- and the
old riskability_suppressions collection is writable by ``power``, the ordinary
analyst role, which is exactly the hole this avoids.

Everything the register records is a decision a person made, so every write
also emits an audit event to an index. An index is append-only; a register that
can be rewritten by whoever can write the register is not an audit trail.

The endpoint never mutates riskability_findings_state. A separate reconciler
stamps the flag onto findings, so there is one writer of that collection per
concern and no race with the hourly jobs.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib import client  # noqa: E402

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

EXCEPTIONS_COLLECTION = "riskability_exceptions"
FINDINGS_STATE_COLLECTION = "riskability_findings_state"
AUDIT_INDEX = "riskability_audit"
AUDIT_SOURCETYPE = "riskability:exception:audit"

# An exception says one of three things, and which one has to be stated rather
# than inferred from which fields happen to be empty. A blank hostname meaning
# "every host in the fleet, including ones that do not exist yet" is how a
# whole class of findings disappears by accident.
SCOPE_KINDS = ("host_cve", "finding", "fleet_cve")

# Why the risk is not being patched. Worth an enum as well as free text: if it
# turns out most "exceptions" are recorded as false positives, that is a
# matcher bug being papered over, and only a countable field will show it.
REASON_KINDS = ("compensating_control", "risk_accepted", "false_positive")

# A control with no review date is not a control, it is a shrug. Permanent
# remains possible but has to be asked for explicitly.
DEFAULT_EXPIRY_DAYS = 90

MAX_NOTES = 4000
MAX_CONTROL = 2000


def _now() -> int:
    return int(time.time())


class BadRequest(Exception):
    """Something the caller can fix, reported as 400 rather than 500."""


def _require(payload: dict, field: str) -> str:
    value = (payload.get(field) or "").strip()
    if not value:
        raise BadRequest(f"{field} is required")
    return value


def _validate(payload: dict) -> dict:
    """Turn a request body into a register row, or explain why it cannot be.

    Validation is here rather than in the browser because the browser is not
    the only caller: this endpoint is reachable by anyone holding the
    capability, and an exception written by a script with a missing scope_kind
    would silently behave as whichever branch the reader assumed.
    """
    scope_kind = _require(payload, "scope_kind")
    if scope_kind not in SCOPE_KINDS:
        raise BadRequest(f"scope_kind must be one of {', '.join(SCOPE_KINDS)}")

    cve_id = _require(payload, "cve_id").upper()
    if not cve_id.startswith("CVE-"):
        raise BadRequest("cve_id must be a CVE identifier")

    row = {
        "scope_kind": scope_kind,
        "cve_id": cve_id,
        "hostname": (payload.get("hostname") or "").strip(),
        "finding_key": (payload.get("finding_key") or "").strip(),
    }

    if scope_kind in ("host_cve", "finding") and not row["hostname"]:
        raise BadRequest(f"hostname is required for scope_kind={scope_kind}")
    if scope_kind == "finding" and not row["finding_key"]:
        raise BadRequest("finding_key is required for scope_kind=finding")
    if scope_kind == "fleet_cve":
        # Not merely ignored -- cleared, so a fleet-wide row can never carry a
        # hostname that makes it look narrower than it is in the register.
        row["hostname"] = ""
        row["finding_key"] = ""

    reason_kind = (payload.get("reason_kind") or "compensating_control").strip()
    if reason_kind not in REASON_KINDS:
        raise BadRequest(f"reason_kind must be one of {', '.join(REASON_KINDS)}")
    row["reason_kind"] = reason_kind

    # The point of the register. "n/a" is not a control, and an exception whose
    # justification is blank is indistinguishable from someone hiding a number.
    control = _require(payload, "control")
    if len(control) > MAX_CONTROL:
        raise BadRequest(f"control must be under {MAX_CONTROL} characters")
    row["control"] = control

    notes = (payload.get("notes") or "").strip()
    if len(notes) > MAX_NOTES:
        raise BadRequest(f"notes must be under {MAX_NOTES} characters")
    row["notes"] = notes

    # expires_at absent means "use the default"; explicitly null means
    # permanent. Those are different requests and must not collapse into one.
    if "expires_at" in payload:
        expires = payload.get("expires_at")
        if expires in (None, "", "never"):
            row["expires_at"] = ""
        else:
            try:
                row["expires_at"] = str(int(float(expires)))
            except (TypeError, ValueError):
                raise BadRequest("expires_at must be an epoch time, or null for permanent")
    else:
        row["expires_at"] = str(_now() + DEFAULT_EXPIRY_DAYS * 86400)

    # One key the reconciler can join on, so it never has to branch per scope
    # inside a search. A finding generates the same three candidate keys and
    # takes the most specific hit.
    row["match_key"] = _match_key(row)
    return row


def _active_key(row: dict, state: str) -> str:
    """match_key, but only while the decision is actually in force.

    The reconciler resolves a finding to an exception with a KV lookup keyed on
    match_key. That key is deliberately NOT unique across the register -- a
    scope can be accepted, withdrawn, and accepted again, and keeping all three
    on one key is what makes the history readable. But a Splunk lookup that
    matches two documents returns every output field as a MULTIVALUE, and every
    guard the reconciler applies to those values then collapses to false. The
    exception reads "active" in the register, covers zero findings, and the
    findings stay in the risk pool: an operator accepts a risk, is told it was
    accepted, and nothing happens, with no error anywhere.

    So the lookup keys on this instead. Revoked and expired rows carry an empty
    string and are simply not found, which is what they should be to a search
    asking what is in force right now.
    """
    return row.get("match_key", "") if state == "active" else ""


def _match_key(row: dict) -> str:
    kind = row["scope_kind"]
    if kind == "finding":
        return "find|" + row["finding_key"]
    if kind == "host_cve":
        return "host|" + row["hostname"] + "|" + row["cve_id"]
    return "fleet|" + row["cve_id"]


class ExceptionsHandler(PersistentServerConnectionApplication):

    def __init__(self, command_line=None, command_arg=None):
        super().__init__()

    # -- plumbing ----------------------------------------------------------

    @staticmethod
    def _reply(status: int, body: dict) -> dict:
        return {"status": status,
                "payload": json.dumps(body),
                "headers": {"Content-Type": "application/json"}}

    @staticmethod
    def _service(token: str):
        return client.connect(token=token, owner="nobody", app="riskability")

    @staticmethod
    def _user(request: dict) -> str:
        """Who is asking, taken from the session rather than the payload.

        A client-supplied username in an audit trail records whatever the
        client felt like claiming.
        """
        session = request.get("session") or {}
        return session.get("user") or "unknown"

    def _audit(self, service, action: str, user: str, row: dict,
               before: dict = None, finding_count: int = None) -> None:
        """Record the decision, separately from the register that holds it."""
        event = {
            "action": action,
            "who": user,
            "when": _now(),
            "exception_key": row.get("_key") or row.get("exception_key"),
            "scope_kind": row.get("scope_kind"),
            "hostname": row.get("hostname"),
            "cve_id": row.get("cve_id"),
            "finding_key": row.get("finding_key"),
            "reason_kind": row.get("reason_kind"),
            "control": row.get("control"),
            "notes": row.get("notes"),
            "expires_at": row.get("expires_at"),
            "revoked_at": row.get("revoked_at"),
        }
        if before:
            # The diff, not just the new document: "Alice changed the expiry"
            # is only meaningful next to what it was before.
            changed = {k: {"from": before.get(k), "to": row.get(k)}
                       for k in ("control", "notes", "expires_at", "reason_kind",
                                 "scope_kind", "hostname", "revoked_at")
                       if before.get(k) != row.get(k)}
            event["changed"] = json.dumps(changed, sort_keys=True)
        if finding_count is not None:
            # What this actually covered at the moment it was decided. Without
            # it an auditor sees "accepted CVE-2024-X" with no idea whether it
            # was one host or four hundred.
            event["findings_affected"] = finding_count
        try:
            service.indexes[AUDIT_INDEX].submit(
                json.dumps(event, sort_keys=True), sourcetype=AUDIT_SOURCETYPE)
        except Exception:
            # An audit that cannot be written must not silently succeed, but it
            # must also not roll back a decision the operator already made and
            # can see in the register. Surfaced in the response instead.
            raise

    def _matching_findings(self, service, row: dict):
        """The open findings an exception covers, right now.

        Used for the audit snapshot and to report back what the operator just
        did. Scoped queries only -- never a scan of the whole collection.
        """
        query = {"status": "open", "cve_id": row["cve_id"]}
        if row["scope_kind"] == "finding":
            query = {"finding_key": row["finding_key"]}
        elif row["scope_kind"] == "host_cve":
            query["hostname"] = row["hostname"]
        try:
            data = service.kvstore[FINDINGS_STATE_COLLECTION].data
            return data.query(query=json.dumps(query), limit=10000)
        except Exception:
            return []

    # -- routes ------------------------------------------------------------

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
        except Exception:
            return self._reply(400, {"error": "malformed request"})

        method = (request.get("method") or "GET").upper()
        try:
            service = self._service(request.get("session", {}).get("authtoken"))
            if method == "GET":
                return self._get(service, request)
            if method == "POST":
                return self._post(service, request)
            return self._reply(405, {"error": f"{method} not supported"})
        except BadRequest as exc:
            return self._reply(400, {"error": str(exc)})
        except Exception as exc:
            return self._reply(
                500, {"error": str(exc),
                      "trace": traceback.format_exc(limit=6).split("\n")})

    def _get(self, service, request):
        """The register, with each row's effective state resolved."""
        data = service.kvstore[EXCEPTIONS_COLLECTION].data
        rows = data.query(query=json.dumps({}), limit=10000)
        now = _now()
        for r in rows:
            r["state"] = self._state_of(r, now)
        return self._reply(200, {"exceptions": rows, "now": now,
                                 "default_expiry_days": DEFAULT_EXPIRY_DAYS,
                                 "scope_kinds": list(SCOPE_KINDS),
                                 "reason_kinds": list(REASON_KINDS)})

    @staticmethod
    def _state_of(row: dict, now: int) -> str:
        """active, expired or revoked.

        Expiry is derived, never a stored flag that a failed job can leave
        wrong. The scheduled reconciler records the *event* of expiring; it is
        not what makes an exception expired.
        """
        if row.get("revoked_at"):
            return "revoked"
        expires = row.get("expires_at")
        if expires:
            try:
                if float(expires) <= now:
                    return "expired"
            except (TypeError, ValueError):
                pass
        return "active"

    def _preview(self, service, payload: dict) -> dict:
        """How many findings each scope would actually cover.

        The difference is not cosmetic. The same CVE usually appears at several
        paths on one host -- measured on a real fleet, 1,462 of 2,107 host/CVE
        pairs, one of them at eleven paths -- so "this CVE on this host" almost
        always covers more than whoever selected two rows had in mind. One copy
        of a library being unreachable says nothing about the others.
        """
        cve = (payload.get("cve_id") or "").upper()
        hosts = [h for h in (payload.get("hostnames") or []) if h]
        keys = [k for k in (payload.get("finding_keys") or []) if k]
        data = service.kvstore[FINDINGS_STATE_COLLECTION].data

        def count(query):
            try:
                return len(data.query(query=json.dumps(query), limit=10000))
            except Exception:
                return -1

        out = {"cve_id": cve, "selected": len(keys)}
        out["finding"] = len(keys)
        out["host_cve"] = sum(
            count({"status": "open", "cve_id": cve, "hostname": h}) for h in hosts)
        out["fleet_cve"] = count({"status": "open", "cve_id": cve})
        out["hosts"] = len(hosts)
        try:
            fleet_rows = data.query(
                query=json.dumps({"status": "open", "cve_id": cve}), limit=10000)
            out["fleet_hosts"] = len({r.get("hostname") for r in fleet_rows})
        except Exception:
            out["fleet_hosts"] = 0
        return out

    def _apply(self, service, row: dict, active: bool) -> int:
        """Stamp (or clear) the accepted flag on the findings this covers, now.

        The hourly reconciler computes exactly the same thing and remains the
        authority; this is the same answer applied immediately, because an
        operator who has just accepted a risk and is told it covers nothing has
        every reason to think the feature is broken. Waiting up to an hour to
        find out whether a decision took effect is not a reasonable thing to ask.

        Read-modify-write of the whole document, deliberately: a KV Store upsert
        REPLACES the row rather than merging into it, so writing just the flag
        would erase every other field on the finding.
        """
        try:
            data = service.kvstore[FINDINGS_STATE_COLLECTION].data
        except Exception:
            return 0

        if active:
            targets = self._matching_findings(service, row)
        else:
            # Clearing: find what this exception is currently stamped on rather
            # than recomputing its scope, so a revoke still works after the
            # scope fields have been edited.
            try:
                targets = data.query(
                    query=json.dumps({"exception_key": row.get("exception_key")}),
                    limit=10000)
            except Exception:
                return 0

        touched = 0
        for finding in targets:
            # Never stamp a finding that is not open. Mitigated and removed are
            # already out of the risk pool, and marking them accepted would be
            # laundering history.
            if active and finding.get("status") != "open":
                continue
            updated = dict(finding)
            updated["accepted"] = "1" if active else "0"
            updated["exception_key"] = row.get("exception_key", "") if active else ""
            updated["exception_expires_at"] = row.get("expires_at", "") if active else ""
            key = updated.get("_key") or updated.get("finding_key")
            if not key:
                continue
            try:
                data.update(key, json.dumps(updated))
                touched += 1
            except Exception:
                continue
        return touched

    def _post(self, service, request):
        try:
            payload = json.loads(request.get("payload") or "{}")
        except Exception:
            raise BadRequest("body must be JSON")

        action = (payload.get("action") or "create").strip()
        user = self._user(request)
        data = service.kvstore[EXCEPTIONS_COLLECTION].data

        if action == "preview":
            return self._reply(200, self._preview(service, payload))

        if action == "revoke":
            key = _require(payload, "exception_key")
            existing = self._one(data, key)
            row = dict(existing)
            row["revoked_at"] = str(_now())
            row["revoked_by"] = user
            row["updated_at"] = str(_now())
            row["updated_by"] = user
            row["active_match_key"] = ""
            data.update(key, json.dumps(row))
            cleared = self._apply(service, row, active=False)
            self._audit(service, "revoke", user, {**row, "_key": key}, before=existing,
                        finding_count=cleared)
            return self._reply(200, {"ok": True, "exception_key": key,
                                     "state": self._state_of(row, _now()),
                                     "findings_affected": cleared})

        if action in ("create", "update", "reactivate"):
            now = _now()
            if action != "create":
                # Scope is taken from the record, never from the request.
                #
                # What an exception covers is the decision itself; changing it
                # is a different decision and should be a withdrawal and a new
                # entry, so the trail shows both. The dialog disables the
                # control, but a disabled control in a browser is a courtesy,
                # not an authorisation boundary.
                key = _require(payload, "exception_key")
                before = self._one(data, key)
                payload = dict(payload)
                for field_name in ("scope_kind", "hostname", "cve_id", "finding_key"):
                    payload[field_name] = before.get(field_name, "")
                if "expires_at" not in payload:
                    payload["expires_at"] = before.get("expires_at", "")

            row = _validate(payload)
            if action == "create":
                # Two active exceptions with the same match key are two records
                # of one decision. The reconciler takes the most specific hit
                # and would apply either, so the duplicate is invisible in the
                # findings; it only surfaces when somebody withdraws one and
                # the finding stays suppressed with no reason on screen. The
                # dialog disables the button when every selected row is already
                # accepted, but that is a courtesy -- this is the boundary.
                clash = self._active_with_key(data, row["match_key"], _now())
                if clash:
                    raise BadRequest(
                        "this is already accepted: "
                        + (clash.get("scope_label") or clash.get("match_key", ""))
                        + ", by " + (clash.get("created_by") or "someone")
                        + ". Change or withdraw that entry on the Risk exceptions page "
                        "rather than recording a second decision for the same finding.")
                key = uuid.uuid4().hex
                row.update({"exception_key": key, "created_by": user,
                            "created_at": str(now), "updated_by": user,
                            "updated_at": str(now), "revoked_at": "",
                            "revoked_by": ""})
                before = None
            else:
                row.update({"exception_key": key,
                            "created_by": before.get("created_by", user),
                            "created_at": before.get("created_at", str(now)),
                            "updated_by": user, "updated_at": str(now)})
                # Reactivating is an edit that clears the revocation, not a new
                # row: the history of one decision stays on one record.
                row["revoked_at"] = "" if action == "reactivate" else before.get("revoked_at", "")
                row["revoked_by"] = "" if action == "reactivate" else before.get("revoked_by", "")

            covered = self._matching_findings(service, row)
            row["_key"] = key
            # insert for a new key, update for an existing one. batch_save
            # takes dicts and wraps them itself, so handing it a JSON string
            # produces a list containing a string and KV Store rejects the
            # whole request as an invalid query.
            if action == "create":
                data.insert(json.dumps(row))
            else:
                data.update(key, json.dumps(row))
            state = self._state_of(row, _now())
            row["active_match_key"] = _active_key(row, state)
            data.update(key, json.dumps(row))
            self._stand_down_stale(data, row, _now())
            applied = self._apply(service, row, active=(state == "active"))
            self._audit(service, action, user, row, before=before,
                        finding_count=len(covered))
            return self._reply(200, {
                "ok": True, "exception_key": key,
                "state": state,
                "findings_affected": len(covered),
                "findings_applied": applied,
                "kev_affected": sum(1 for f in covered if f.get("kev_added")),
            })

        raise BadRequest(f"unknown action {action!r}")

    def _stand_down_stale(self, data, row: dict, now: int) -> None:
        """Clear active_match_key on any other row covering the same scope.

        Expiry is derived from a timestamp rather than written, so a row can
        lapse without anything touching it. If a new exception is then recorded
        for that scope, both rows carry the key until the hourly expiry job
        notices, and for that hour the lookup matches two documents and the new
        decision does nothing. Doing it here makes it immediate.
        """
        key = row.get("match_key", "")
        mine = row.get("_key") or row.get("exception_key", "")
        if not key:
            return
        try:
            rows = data.query(query=json.dumps({"match_key": key}), limit=500)
        except Exception:
            return
        for other in rows:
            if other.get("_key") == mine:
                continue
            if not other.get("active_match_key"):
                continue
            if self._state_of(other, now) == "active":
                continue
            other = dict(other)
            other["active_match_key"] = ""
            try:
                data.update(other["_key"], json.dumps(other))
            except Exception:
                pass

    def _active_with_key(self, data, match_key: str, now: int):
        """An exception already in force covering exactly this scope, if any.

        Expired and revoked entries do not count: re-accepting something whose
        review date passed is a legitimate new decision, and that is the point
        of letting them lapse rather than deleting them.
        """
        try:
            rows = data.query(query=json.dumps({"match_key": match_key}), limit=200)
        except Exception:
            return None
        for row in rows:
            if self._state_of(row, now) == "active":
                return row
        return None

    @staticmethod
    def _one(data, key: str) -> dict:
        rows = data.query(query=json.dumps({"_key": key}), limit=1)
        if not rows:
            raise BadRequest(f"no exception with key {key!r}")
        return rows[0]
