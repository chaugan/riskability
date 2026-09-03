"""Firewall data source settings, and the macros generated from them.

The network evidence pipeline reads two macros a site has to point at its own
data: riskability_fw_edges, the permitted flows reduced to unique edges, and
riskability_fw_entry_points, where an attacker plausibly starts. Three more
hold freshness numbers. All five ship resolving to nothing, and until now a
site wired them by editing macros.conf, which is a build step on a single
search head and a deployment on a cluster.

This module is the whole of the logic that turns a small set of settings a
person can type into the SPL those macros need. It is deliberately free of
Splunk imports so it can be tested on any machine: validate() refuses what
cannot work, and macros() returns the five definitions. The REST handler is
the only thing that touches splunkd, and it writes the settings to
riskability_firewall.conf and the generated definitions to macros.conf through
the conf API, which a search head cluster replicates.

Why generated SPL rather than a free SPL box. A site's firewall index is a
handful of fields under names that vary by vendor; the reduction from raw log
lines to unique permitted edges is the same for all of them. Asking for the
index, the sourcetype and the five field names gives the app enough to write
a correct reduction, and takes away the ability to paste a search that
returns three columns named wrongly and produces a page full of "unknown"
that reads as a fact about the network. A site that genuinely needs its own
SPL can still edit the macro; the settings record shows when that has
happened, because the macro no longer matches what the settings generate.
"""

from __future__ import annotations

import ipaddress
import re

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

FIELDS = {
    # "index" reads raw events and reduces them; "datamodel" runs tstats over an
    # accelerated data model, which is how a site with a real firewall volume
    # does this: the reduction is already summarised on the indexers and a
    # search that took minutes takes seconds. The fields below are grouped by
    # which mode reads them; the page shows one group at a time.
    "mode":         {"default": "index", "kind": "enum",   "max": 16,
                     "values": ("index", "datamodel")},
    "index":        {"default": "",      "kind": "name",   "max": 128},
    "sourcetype":   {"default": "",      "kind": "text",   "max": 128},
    "extra_filter": {"default": "",      "kind": "filter", "max": 500},
    "src_field":    {"default": "src_ip",   "kind": "field", "max": 64},
    "dest_field":   {"default": "dest_ip",  "kind": "field", "max": 64},
    "port_field":   {"default": "dest_port", "kind": "field", "max": 64},
    "proto_field":  {"default": "transport", "kind": "field", "max": 64},
    "action_field": {"default": "action", "kind": "field", "max": 64},
    "action_allowed": {"default": "allowed", "kind": "text", "max": 128},
    # Data model mode. The CIM Network_Traffic model is the default and its
    # field names are the defaults below; a site with its own model names it
    # and the fields under it. Fields are written as the model exposes them,
    # so "All_Traffic.src" not "src".
    "datamodel":    {"default": "Network_Traffic", "kind": "name", "max": 128},
    "dm_object":    {"default": "All_Traffic", "kind": "name", "max": 128},
    "dm_src_field": {"default": "All_Traffic.src", "kind": "dmfield", "max": 96},
    "dm_dest_field": {"default": "All_Traffic.dest", "kind": "dmfield", "max": 96},
    "dm_port_field": {"default": "All_Traffic.dest_port", "kind": "dmfield", "max": 96},
    "dm_proto_field": {"default": "All_Traffic.transport", "kind": "dmfield", "max": 96},
    "dm_action_field": {"default": "All_Traffic.action", "kind": "dmfield", "max": 96},
    "dm_where":     {"default": "",      "kind": "filter", "max": 500},
    "entry_points": {"default": "",      "kind": "entries", "max": 8000},
    "fresh_days":   {"default": "7",     "kind": "days",   "max": 5},
    "stale_days":   {"default": "2",     "kind": "days",   "max": 5},
    "identity_grace_days": {"default": "7", "kind": "days", "max": 5},
}

PRESSURES = ("constant", "occasional")

_NAME_RE = re.compile(r"^[A-Za-z0-9_\-*]{1,128}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:\-{}]{0,63}$")
# A data model field: Object.field, dotted, nothing that could close a quote
# or open a subsearch.
_DMFIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
# What a filter may contain: field=value terms, quoted values, AND/OR/NOT,
# parentheses. No pipes, no subsearch brackets, no backticks: a filter is a
# where-clause, not a search.
_FILTER_FORBIDDEN = re.compile(r"[|`\[\]]")


class SettingsError(ValueError):
    pass


def defaults() -> dict:
    return {k: v["default"] for k, v in FIELDS.items()}


def validate(raw: dict) -> dict:
    """Return clean settings or raise SettingsError naming the first fault."""
    clean = defaults()
    for key, spec in FIELDS.items():
        if key not in raw or raw[key] is None:
            continue
        value = str(raw[key]).strip()
        if len(value) > spec["max"]:
            raise SettingsError("%s is longer than %d characters" % (key, spec["max"]))
        kind = spec["kind"]
        if kind == "enum" and value not in spec["values"]:
            raise SettingsError("%s must be one of %s" % (key, ", ".join(spec["values"])))
        if kind == "dmfield" and value and not _DMFIELD_RE.match(value):
            raise SettingsError("%s must be a data model field such as All_Traffic.src" % key)
        if kind == "name" and value and not _NAME_RE.match(value):
            raise SettingsError("%s must be an index name (letters, digits, _ - *)" % key)
        if kind == "field" and value and not _FIELD_RE.match(value):
            raise SettingsError("%s must be a field name" % key)
        if kind == "filter" and _FILTER_FORBIDDEN.search(value):
            raise SettingsError("extra_filter may not contain |, backticks or brackets: "
                                "it is a filter, not a search")
        if kind == "days":
            if not value.isdigit() or not 1 <= int(value) <= 3650:
                raise SettingsError("%s must be a whole number of days from 1 to 3650" % key)
        if kind == "text" and ('"' in value or "\n" in value):
            raise SettingsError("%s may not contain quotes or line breaks" % key)
        clean[key] = value
    if int(clean["stale_days"]) > int(clean["fresh_days"]):
        raise SettingsError("stale_days cannot exceed fresh_days: an edge is fresh "
                            "before it is stale")
    # Stored in the shape a person typed it, normalised: one entry per line,
    # "cidr | name | pressure" with spaces, the CIDR canonical, the pressure
    # filled in, and a name left blank when none was given rather than the
    # CIDR copied into it. The first version packed the line as
    # cidr|cidr|occasional and handed that back to the form, which read as
    # the app having rewritten what the administrator typed.
    clean["entry_points"] = "\n".join(
        "%s | %s | %s" % (cidr, name, pressure)
        for cidr, name, pressure in parse_entries(clean["entry_points"], keep_blank_name=True))
    return clean


def parse_entries(text: str, keep_blank_name: bool = False) -> list:
    """Entry points, one per line as  cidr | name | pressure.

    A bare address is accepted and becomes /32 or /128. The pressure is
    "constant" (the internet: unsolicited traffic arrives continuously, so an
    absence of flow means something) or "occasional" (a jump network: silence
    means nobody used it). It defaults to occasional, which is the weaker
    claim; nothing here should default to the one that licenses "not
    observed".
    """
    out = []
    for n, line in enumerate(str(text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        cidr = parts[0]
        name = parts[1] if len(parts) > 1 and parts[1] else ("" if keep_blank_name else cidr)
        pressure = (parts[2] if len(parts) > 2 and parts[2] else "occasional").lower()
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise SettingsError("entry point line %d: %r is not an address or CIDR" % (n, cidr))
        if pressure not in PRESSURES:
            raise SettingsError("entry point line %d: pressure must be constant or "
                                "occasional, not %r" % (n, pressure))
        if "|" in name or '"' in name or len(name) > 80:
            raise SettingsError("entry point line %d: the name may not contain | or "
                                "quotes and must be under 80 characters" % n)
        out.append((str(net), name, pressure))
    return out


def configured(settings: dict) -> bool:
    """Whether the edges source is set at all. Entry points and days alone do
    not make a configuration: with no edges every row is unknown regardless.
    In data model mode the model name is what has to be present; the default
    names the CIM model, so a site that picks the mode is configured."""
    if settings.get("mode") == "datamodel":
        return bool(settings.get("datamodel")) and bool(settings.get("dm_object"))
    return bool(settings.get("index"))


# ---------------------------------------------------------------------------
# Macros
# ---------------------------------------------------------------------------

def _q(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def edges_definition(s: dict) -> str:
    """The permitted-edge reduction for this site's firewall index.

    Field contract downstream (riskability_fw_entry_join and the assess job):
    src_ip, dest_ip, port, protocol, sessions, edge_first_seen, edge_last_seen.
    Only permitted flows are edges. A denied flow proves a rule exists, not a
    path, and counting it would be the false attack path this page exists to
    refuse. The action filter is applied only when an action field is named.
    """
    if not configured(s):
        return ('makeresults | eval src_ip = "", dest_ip = "", port = 0, protocol = "", '
                'sessions = 0, edge_first_seen = 0, edge_last_seen = 0 | where 1=0')
    if s.get("mode") == "datamodel":
        return _dm_edges(s)
    terms = ["index=%s" % s["index"]]
    if s.get("sourcetype"):
        terms.append("sourcetype=%s" % _q(s["sourcetype"]))
    if s.get("action_field") and s.get("action_allowed"):
        terms.append("%s=%s" % (s["action_field"], _q(s["action_allowed"])))
    if s.get("extra_filter"):
        terms.append("(%s)" % s["extra_filter"])
    return (
        "search " + " ".join(terms)
        + " | eval src_ip = lower('%s'), dest_ip = lower('%s'), port = tonumber('%s'), "
          "protocol = lower(coalesce('%s', \"tcp\"))"
          % (s["src_field"], s["dest_field"], s["port_field"], s["proto_field"])
        + " | where isnotnull(src_ip) AND isnotnull(dest_ip) AND isnotnull(port)"
        + " | stats count AS sessions, min(_time) AS edge_first_seen, max(_time) AS edge_last_seen"
          " BY src_ip, dest_ip, port, protocol"
        + " | fields src_ip, dest_ip, port, protocol, sessions, edge_first_seen, edge_last_seen"
    )


def _dm_edges(s: dict) -> str:
    """tstats over an accelerated model, to the same field contract.

    summariesonly=true, on purpose. A tstats that falls back to raw events
    when the acceleration is behind returns the right answer slowly, and on a
    firewall index "slowly" is the difference between an hourly job that
    finishes and one that runs into the next hour. A site whose acceleration
    lags sees fewer edges, which grades more rows unknown, which is the safe
    direction; the newest_edge the test reports is how they would notice.

    Only permitted flows are edges, so the action is a where clause on the
    model's action field, the CIM value for which is "allowed".
    """
    model = "%s.%s" % (s["datamodel"], s["dm_object"])
    fields = (s["dm_src_field"], s["dm_dest_field"], s["dm_port_field"], s["dm_proto_field"])
    where = []
    if s.get("dm_action_field") and s.get("action_allowed"):
        where.append("%s=%s" % (s["dm_action_field"], _q(s["action_allowed"])))
    if s.get("dm_where"):
        where.append("(%s)" % s["dm_where"])
    return (
        "tstats summariesonly=true count AS sessions, min(_time) AS edge_first_seen, "
        "max(_time) AS edge_last_seen FROM datamodel=%s%s BY %s"
        % (model, (" WHERE " + " ".join(where)) if where else "", ", ".join(fields))
        + " | rename %s AS src_ip, %s AS dest_ip, %s AS port, %s AS protocol" % fields
        + " | eval src_ip = lower(src_ip), dest_ip = lower(dest_ip), port = tonumber(port),"
          " protocol = lower(coalesce(protocol, \"tcp\"))"
        + " | where isnotnull(src_ip) AND isnotnull(dest_ip) AND isnotnull(port)"
        + " | stats sum(sessions) AS sessions, min(edge_first_seen) AS edge_first_seen,"
          " max(edge_last_seen) AS edge_last_seen BY src_ip, dest_ip, port, protocol"
        + " | fields src_ip, dest_ip, port, protocol, sessions, edge_first_seen, edge_last_seen"
    )


def entry_points_definition(s: dict) -> str:
    """One row per entry point, built without mvappend.

    mvappend() with a single argument is a hard error in Splunk ("the
    arguments to the mvappend function are invalid"), so a site that declared
    exactly one entry point, which is the common case (the internet), got a
    macro that failed to parse, and with it the entry point dropdown, the
    assess job and the routes page. Caught by a user, not by the test, which
    had two entries. Each entry is now its own makeresults row and the rows
    are appended, which is valid for one entry and for fifty.
    """
    entries = parse_entries(s.get("entry_points", ""))
    if not entries:
        return ('makeresults | eval entry_cidr = "", entry_name = "", '
                'entry_scan_pressure = "" | where 1=0')
    def row(e):
        return ('makeresults | eval entry_cidr = %s, entry_name = %s, entry_scan_pressure = %s'
                % (_q(e[0]), _q(e[1]), _q(e[2])))
    first, rest = entries[0], entries[1:]
    spl = row(first)
    for e in rest:
        spl += " | append [| %s]" % row(e)
    return spl + " | fields entry_cidr, entry_name, entry_scan_pressure"


def macros(s: dict) -> dict:
    """Macro name -> definition, for everything the settings decide."""
    return {
        "riskability_fw_edges": edges_definition(s),
        "riskability_fw_entry_points": entry_points_definition(s),
        "riskability_fw_fresh_days": str(int(s["fresh_days"])),
        "riskability_fw_stale_days": str(int(s["stale_days"])),
        "riskability_fw_identity_grace_days": str(int(s["identity_grace_days"])),
    }


def preview_search(s: dict, limit: int = 100) -> str:
    """The top edges the reduction yields, for a person to read before saving.

    The count the test reports says whether the mapping works; the rows say
    whether it maps the RIGHT things, which a count cannot: a port field that
    actually holds the source port produces a plausible count and a useless
    graph. Sorted by sessions so the busiest edges, the ones most likely to
    matter, come first.
    """
    return ("| " + edges_definition(s)
            + " | sort %d - sessions" % int(limit)
            + " | eval first_seen = strftime(edge_first_seen, \"%Y-%m-%d %H:%M\"),"
              " last_seen = strftime(edge_last_seen, \"%Y-%m-%d %H:%M\")"
            + " | table src_ip, dest_ip, port, protocol, sessions, first_seen, last_seen")


def test_search(s: dict) -> str:
    """A bounded search a person can run to see whether the source yields edges."""
    return "| " + edges_definition(s) \
        + " | stats count AS edges, dc(src_ip) AS sources, dc(dest_ip) AS destinations, " \
          "max(edge_last_seen) AS newest_edge"
