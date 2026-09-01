"""Loaders for the AI pipeline configuration and its stored secret.

Splunklib-dependent (that is the point — the awkward parts are talking to
splunkd), and shared by two callers with different privileges:

* ``riskability_ai_rest.py`` — the admin endpoint, writing on behalf of a
  user holding ``riskability_ai_admin``;
* ``riskabilityaianalyze.py`` — the search command, reading on behalf of
  whoever dispatched the analysis search.

One implementation of "how to read the conf" and "how to read the secret"
means the two callers cannot drift. Field names are validated against
``ai_config.FIELD_SPECS``; see the warning there about why a conf key must
never be named ``url`` (splunklib collides on it).
"""

from __future__ import annotations

from . import ai_config

SECRET_REALM = "riskability"
SECRET_USER = "riskability_ai"


def load_config(service) -> dict:
    """The [connection] stanza with schema defaults filled in. Unknown keys
    in a hand-edited conf are dropped rather than served."""
    try:
        stanza = service.confs["riskability_ai"]["connection"]
        current = dict(stanza.content)
    except Exception:
        current = {}
    return {key: current.get(key, spec["default"])
            for key, spec in ai_config.FIELD_SPECS.items()}


def write_config(service, merged: dict) -> None:
    conf = service.confs["riskability_ai"]
    try:
        stanza = conf["connection"]
    except KeyError:
        conf.create("connection", **merged)
        return
    stanza.update(**merged)


def find_secret_entry(service):
    for entry in service.storage_passwords:
        if (entry.content.get("realm") == SECRET_REALM
                and entry.content.get("username") == SECRET_USER):
            return entry
    return None


def password_set(service) -> bool:
    return find_secret_entry(service) is not None


def read_secret(service) -> str:
    entry = find_secret_entry(service)
    if entry is None:
        return ""
    return entry.content.get("clear_password") or ""


def write_secret(service, secret: str) -> None:
    """Rotate: delete then create, so a failed create is visible rather than
    quietly leaving the pipeline keyless."""
    delete_secret(service)
    service.storage_passwords.create(secret, SECRET_USER, realm=SECRET_REALM)


def delete_secret(service) -> None:
    try:
        service.storage_passwords.delete(SECRET_USER, realm=SECRET_REALM)
    except Exception:
        pass


def sync_budget_macro(service, candidate_cap) -> None:
    """Re-stamp the budget macro from the settings field. The searches
    expand the macro; the admin page edits the field; this is the bridge
    that keeps a single source of truth."""
    service.confs["macros"]["riskability_ai_candidate_cap"].update(
        definition=str(int(candidate_cap)))
