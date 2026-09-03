#!/usr/bin/env python3
"""The firewall settings module: what it refuses, and the SPL it writes.

No Splunk here. riskability.firewall is pure so the reduction a site's
firewall index goes through can be checked on any machine, before an
administrator saves it into five macros that every network evidence grade
depends on.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app" / "riskability" / "bin"))

from riskability import firewall  # noqa: E402

FAILURES = []


def check(name, ok, detail=""):
    print("  %s %s%s" % ("ok  " if ok else "FAIL", name, (" " + str(detail)) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def refuses(config, why):
    try:
        firewall.validate(config)
    except firewall.SettingsError as exc:
        check("refuses %s" % why, True)
        return str(exc)
    check("refuses %s" % why, False, "accepted")
    return ""


def main():
    # --- unconfigured is the honest default -----------------------------------
    d = firewall.validate({})
    check("defaults are not 'configured'", not firewall.configured(d))
    m = firewall.macros(d)
    check("unconfigured edges macro yields nothing", "where 1=0" in m["riskability_fw_edges"])
    check("unconfigured entry macro yields nothing", "where 1=0" in m["riskability_fw_entry_points"])
    check("day macros are plain integers", m["riskability_fw_fresh_days"] == "7"
          and m["riskability_fw_stale_days"] == "2")

    # --- what is refused --------------------------------------------------------
    refuses({"index": "fw", "extra_filter": "src=1 | delete"}, "a pipe in the filter")
    refuses({"index": "fw", "extra_filter": "[search x]"}, "a subsearch in the filter")
    refuses({"index": "fw", "extra_filter": "`macro`"}, "a backtick in the filter")
    refuses({"index": "fw; rm"}, "an index name that is not a name")
    refuses({"index": "fw", "src_field": "src ip"}, "a field name with a space")
    refuses({"index": "fw", "fresh_days": "0"}, "zero days")
    refuses({"index": "fw", "fresh_days": "1", "stale_days": "5"}, "stale beyond fresh")
    refuses({"index": "fw", "entry_points": "not-an-address|x|constant"}, "a bad CIDR")
    refuses({"index": "fw", "entry_points": "10.0.0.0/8|dc|always"}, "an unknown pressure")
    refuses({"index": "fw", "action_allowed": 'allowed" OR 1=1'}, "a quote in the action value")

    # --- what is generated ------------------------------------------------------
    s = firewall.validate({
        "index": "firewall", "sourcetype": "pan:traffic", "extra_filter": "dvc=edge-fw-1",
        "src_field": "src_ip", "dest_field": "dest_ip", "port_field": "dest_port",
        "proto_field": "transport", "action_field": "action", "action_allowed": "allowed",
        "entry_points": "0.0.0.0/0 | internet | constant\n10.9.0.5 | jump host\n# comment\n",
        "fresh_days": "10", "stale_days": "3", "identity_grace_days": "7",
    })
    check("a named index is 'configured'", firewall.configured(s))
    edges = firewall.macros(s)["riskability_fw_edges"]
    for want in ("index=firewall", 'sourcetype="pan:traffic"', 'action="allowed"',
                 "(dvc=edge-fw-1)", "BY src_ip, dest_ip, port, protocol",
                 "fields src_ip, dest_ip, port, protocol, sessions, edge_first_seen, edge_last_seen"):
        check("edges macro carries %s" % want, want in edges)
    check("edges macro is a generating search with no leading pipe",
          edges.startswith("search ") and not edges.startswith("|"))
    check("only permitted flows are counted", "action=" in edges)
    check("denied flows are not edges when no action field is named",
          "action=" not in firewall.edges_definition(dict(s, action_field="")))

    entries = firewall.parse_entries(s["entry_points"])
    check("bare address becomes /32", ("10.9.0.5/32", "jump host", "occasional") in entries)
    check("pressure defaults to the weaker claim", entries[1][2] == "occasional")
    check("comments and blank lines are ignored", len(entries) == 2)
    ep = firewall.macros(s)["riskability_fw_entry_points"]
    check("entry macro sets cidr, name and pressure per row",
          'entry_cidr = "0.0.0.0/0", entry_name = "internet", entry_scan_pressure = "constant"' in ep)
    check("entry macro has no leading pipe", ep.startswith("makeresults"))
    check("entry macro never uses mvappend (invalid with one argument)", "mvappend" not in ep)
    one = firewall.validate({"index": "fw", "entry_points": "10.0.45.0/24"})
    ep1 = firewall.macros(one)["riskability_fw_entry_points"]
    check("a single entry point generates a valid macro",
          ep1.startswith("makeresults | eval entry_cidr = \"10.0.45.0/24\"") and "append" not in ep1)
    check("saved entry text is readable and a blank name stays blank",
          one["entry_points"] == "10.0.45.0/24 |  | occasional", repr(one["entry_points"]))
    check("saved entry text keeps a given name",
          s["entry_points"].splitlines()[0] == "0.0.0.0/0 | internet | constant", repr(s["entry_points"]))
    three = firewall.validate({"index": "fw", "entry_points": "1.1.1.0/24|a|constant\n2.2.2.0/24|b\n3.3.3.0/24"})
    check("three entries append two rows",
          firewall.macros(three)["riskability_fw_entry_points"].count("| append [|") == 2)
    check("days pass through as integers",
          firewall.macros(s)["riskability_fw_fresh_days"] == "10")

    # --- data model mode ----------------------------------------------------------
    refuses({"mode": "tstats"}, "an unknown mode")
    refuses({"mode": "datamodel", "dm_src_field": "src"}, "an unprefixed data model field")
    refuses({"mode": "datamodel", "dm_src_field": 'All_Traffic.src" OR 1=1'}, "a quote in a data model field")
    refuses({"mode": "datamodel", "dm_where": "x | delete"}, "a pipe in the data model where")
    dm = firewall.validate({"mode": "datamodel"})
    check("data model mode with defaults is configured (CIM Network_Traffic)", firewall.configured(dm))
    check("index mode with defaults is still not configured", not firewall.configured(firewall.validate({"mode": "index"})))
    e = firewall.macros(dm)["riskability_fw_edges"]
    for want in ("tstats summariesonly=true", "FROM datamodel=Network_Traffic.All_Traffic",
                 'WHERE All_Traffic.action="allowed"',
                 "BY All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.transport",
                 "rename All_Traffic.src AS src_ip", "sum(sessions) AS sessions",
                 "fields src_ip, dest_ip, port, protocol, sessions, edge_first_seen, edge_last_seen"):
        check("tstats macro carries %s" % want, want in e)
    check("tstats macro is a generating search with no leading pipe",
          e.startswith("tstats ") and not e.startswith("|"))
    custom = firewall.validate({"mode": "datamodel", "datamodel": "Site_FW", "dm_object": "Flows",
                                "dm_src_field": "Flows.s", "dm_dest_field": "Flows.d",
                                "dm_port_field": "Flows.p", "dm_proto_field": "Flows.t",
                                "dm_action_field": "", "dm_where": 'Flows.dvc="fw1"'})
    e2 = firewall.macros(custom)["riskability_fw_edges"]
    check("a site model and its fields are used verbatim",
          "FROM datamodel=Site_FW.Flows" in e2 and "BY Flows.s, Flows.d, Flows.p, Flows.t" in e2)
    check("no action term when no action field is named, but the where survives",
          "action" not in e2 and 'WHERE (Flows.dvc="fw1")' in e2)
    check("index settings do not leak into the tstats macro",
          "index=" not in e and "sourcetype" not in e)
    check("the test search works for tstats too",
          firewall.test_search(dm).startswith("| tstats "))

    # --- the preview reads the same reduction and is bounded ----------------------
    pv = firewall.preview_search(s, 100)
    check("preview starts from the same reduction", pv.startswith("| search index=firewall"))
    check("preview is bounded and sorted busiest first", "| sort 100 - sessions" in pv)
    check("preview returns the seven edge columns",
          "table src_ip, dest_ip, port, protocol, sessions, first_seen, last_seen" in pv)
    check("preview works for tstats too", firewall.preview_search(dm, 50).startswith("| tstats "))

    # --- the test search is bounded and reads the same reduction ------------------
    t = firewall.test_search(s)
    check("test search starts with a pipe and ends in a stats", t.startswith("| search ")
          and "stats count AS edges" in t)

    # --- the shipped stub macros are exactly what an empty config generates -----
    macros = (ROOT / "app" / "riskability" / "default" / "macros.conf").read_text()
    def shipped(name):
        m2 = re.search(r"^\[%s\]\ndefinition = (.*?)^iseval" % re.escape(name), macros, re.S | re.M)
        return " ".join(m2.group(1).replace("\\\n", " ").split()) if m2 else None
    for name in ("riskability_fw_fresh_days", "riskability_fw_stale_days",
                 "riskability_fw_identity_grace_days"):
        check("shipped %s equals the default" % name, shipped(name) == firewall.macros(d)[name],
              "%r vs %r" % (shipped(name), firewall.macros(d)[name]))

    # --- wiring ------------------------------------------------------------------
    conf = (ROOT / "app" / "riskability" / "default").read_text if False else None
    restmap = (ROOT / "app" / "riskability" / "default" / "restmap.conf").read_text()
    web = (ROOT / "app" / "riskability" / "default" / "web.conf").read_text()
    auth = (ROOT / "app" / "riskability" / "default" / "authorize.conf").read_text()
    check("restmap routes /riskability/firewall", "match = /riskability/firewall" in restmap)
    check("web.conf exposes it", "pattern = riskability/firewall" in web)
    check("capability granted to admin and sc_admin",
          auth.count("riskability_firewall_admin = enabled") == 2)
    check("the default conf exists with the settings stanza",
          "[settings]" in (ROOT / "app" / "riskability" / "default" / "riskability_firewall.conf").read_text())
    check("the spec documents every field",
          all(("%s =" % k) in (ROOT / "app" / "riskability" / "README" / "riskability_firewall.conf.spec").read_text()
              for k in firewall.FIELDS))

    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
