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
    "index":        {"default": "",      "kind": "name",   "max": 128},
    "sourcetype":   {"default": "",      "kind": "text",   "max": 128},
    "extra_filter": {"default": "",      "kind": "filter", "max": 500},
    "src_field":    {"default": "src_ip",   "kind": "field", "max": 64},
    "dest_field":   {"default": "dest_ip",  "kind": "field", "max": 64},
    "port_field":   {"default": "dest_port", "kind": "field", "max": 64},
    "proto_field":  {"default": "transport", "kind": "field", "max": 64},
    "action_field": {"default": "action", "kind": "field", "max": 64},
    "action_allowed": {"default": "allowed", "kind": "text", "max": 128},
    "entry_points": {"default": "",      "kind": "entries", "max": 8000},
    "fresh_days":   {"default": "7",     "kind": "days",   "max": 5},
    "stale_days":   {"default": "2",     "kind": "days",   "max": 5},
    "identity_grace_days": {"default": "7", "kind": "days", "max": 5},
}

PRESSURES = ("constant", "occasional")

_NAME_RE = re.compile(r"^[A-Za-z0-9_\-*]{1,128}$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:\-{}]{0,63}$")
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
    clean["entry_points"] = "\n".join(
        "%s|%s|%s" % e for e in parse_entries(clean["entry_points"]))
    return clean


def parse_entries(text: str) -> list:
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
        name = parts[1] if len(parts) > 1 and parts[1] else cidr
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
    not make a configuration: with no edges every row is unknown regardless."""
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


def entry_points_definition(s: dict) -> str:
    entries = parse_entries(s.get("entry_points", ""))
    if not entries:
        return ('makeresults | eval entry_cidr = "", entry_name = "", '
                'entry_scan_pressure = "" | where 1=0')
    packed = ", ".join(_q("%s|%s|%s" % e) for e in entries)
    return (
        "makeresults | eval rk_e = mvappend(%s) | mvexpand rk_e"
        " | eval entry_cidr = mvindex(split(rk_e, \"|\"), 0),"
        " entry_name = mvindex(split(rk_e, \"|\"), 1),"
        " entry_scan_pressure = mvindex(split(rk_e, \"|\"), 2)"
        " | fields entry_cidr, entry_name, entry_scan_pressure" % packed
    )


def macros(s: dict) -> dict:
    """Macro name -> definition, for everything the settings decide."""
    return {
        "riskability_fw_edges": edges_definition(s),
        "riskability_fw_entry_points": entry_points_definition(s),
        "riskability_fw_fresh_days": str(int(s["fresh_days"])),
        "riskability_fw_stale_days": str(int(s["stale_days"])),
        "riskability_fw_identity_grace_days": str(int(s["identity_grace_days"])),
    }


def test_search(s: dict) -> str:
    """A bounded search a person can run to see whether the source yields edges."""
    return "| " + edges_definition(s).replace("search ", "search ", 1) \
        + " | stats count AS edges, dc(src_ip) AS sources, dc(dest_ip) AS destinations, " \
          "max(edge_last_seen) AS newest_edge"
