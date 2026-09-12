#!/usr/bin/env python3
"""The Executive summary page: the two traps it is built around, and parity.

An executive page is the most dangerous place in this app to show a wrong
number, because the reader cannot check it. Two mechanical traps produce wrong
numbers silently in Simple XML, and both have bitten this app before:

  1. stats over an empty input returns NO row when it carries only aggregates,
     so a done handler never fires and the page prints the token's own name.
     Every dashboard-level search here must end its aggregation with a count.
  2. A token an html panel reads must be set in EVERY branch of the done
     handler that owns it; a branch that forgets one leaves "$x_open$" on the
     sheet. A depends= on a div inside an html panel does nothing at all.

The third check is parity: the tile queries must be the sibling pages' own
definitions, read from the same roll-ups, or a figure here can disagree with
the page it links to.

No Splunk here; this reads the shipped XML.
"""
import os
import re
import sys
# The file parsed is the app's own shipped view, not input from anyone else, so
# the standard parser is fine here; defusedxml is not available on an
# air-gapped search head and this tool must run where the app runs.
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app", "riskability")
VIEW = os.path.join(APP, "default", "data", "ui", "views", "riskability_executive.xml")

FAILURES = []


def check(name, ok, detail=""):
    print("  %s %s%s" % ("ok  " if ok else "FAIL", name, (" " + str(detail)) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def main():
    raw = open(VIEW, encoding="utf-8").read()
    tree = ET.parse(VIEW)
    root = tree.getroot()

    print("Trap 1: every state search ends its aggregation with a count")
    for s in root.findall("search"):
        sid = s.get("id", "?")
        q = " ".join((s.findtext("query") or "").split())
        # the last stats in the pipeline is the one that decides whether a row
        # comes back at all, so that is the one that must carry a plain count.
        # An earlier stats ... BY is fine: it feeds rows into the final count.
        # Subsearches in brackets are appendcols feeders: the main row exists
        # whether or not they return one, so only the main pipeline is judged.
        main = re.sub(r"\[[^\[\]]*\]", "", q)
        found = re.findall(r"\|\s*stats\s+(.*?)(?=\||$)", main)
        last = found[-1] if found else ""
        has_count = re.search(r"(^|,\s*)count\s+AS\s+\w+", last) is not None
        check("%s: final stats carries count" % sid, has_count, last[:80])

    print("\nTrap 2: every token the page reads is set in every branch that owns it")
    # tokens set per search, per branch
    owners = {}
    for s in root.findall("search") + root.findall(".//search"):
        sid = s.get("id", "?")
        done = s.find("done")
        if done is None:
            continue
        branches = done.findall("condition")
        check("%s: every child of its done block is a condition" % sid,
              len(list(done)) == len(branches))
        per_branch = [set(t.get("token") for t in b.findall("set")) | set(t.get("token") for t in b.findall("unset"))
                      for b in branches]
        for tok in set().union(*per_branch) if per_branch else set():
            owners.setdefault(tok, []).append((sid, [tok in pb for pb in per_branch]))
    # tokens referenced in html panels and option/title text
    referenced = set(re.findall(r"\$([a-zA-Z_][a-zA-Z0-9_]*)\$", raw))
    referenced -= {"result", "click", "row", "form"}  # syntax, not page tokens
    referenced = {t for t in referenced if not t.startswith(("result.", "row.", "click."))}
    for tok in sorted(referenced):
        if tok in owners:
            ok = all(all(flags) for _, flags in owners[tok])
            check("$%s$ is set in every branch of %s" % (tok, ", ".join(sid for sid, _ in owners[tok])), ok)
        else:
            check("$%s$ is owned by some done handler" % tok, False, "referenced but never set")
    check("no depends= on an element inside an html panel",
          not re.search(r"<html>(?:(?!</html>).)*?<(?:div|span|p)[^>]*\bdepends=", raw, re.S))

    print("\nParity: the tiles are the sibling pages' own definitions")
    ov = open(os.path.join(APP, "default", "data", "ui", "views", "riskability_overview.xml"), encoding="utf-8").read()
    st = open(os.path.join(APP, "default", "data", "ui", "views", "riskability_start.xml"), encoding="utf-8").read()
    q = " ".join(raw.split())
    check("open findings and accepted come from riskability_openstate_host_lookup, as Fleet overview",
          "inputlookup riskability_openstate_host_lookup | stats count AS hosts_open, sum(findings) AS open_findings, sum(accepted) AS accepted" in q
          and "inputlookup riskability_openstate_host_lookup | stats sum(findings) AS n" in " ".join(ov.split()))
    check("known-exploited present is Fleet overview's KEV table filter",
          'inputlookup riskability_openstate_cve_lookup | where isnotnull(kev_added) AND kev_added!=""' in q
          and "stats count AS kev_cves, sum(overdue) AS kev_overdue" in q
          and 'where isnotnull(kev_added) AND kev_added!=""' in " ".join(ov.split()))
    check("tile 1 is a card, not a single value whose under-label clips",
          "<single>" not in raw)
    check("reachable-and-exploited is Exposure's rk_kev_reach, at conf=* and every host",
          'riskability_reachability_for("*", "*")' in q and "rk_kev_reach = if(reach_rank &gt;= 2 AND is_kev = 1, 1, 0)" in q)
    check("the roll-up age search is Fleet overview's, verbatim",
          "rolled_mins = if(isnull(rolled), 99999, round((now() - rolled) / 60))" in q
          and "rolled_mins = if(isnull(rolled), 99999, round((now() - rolled) / 60))" in " ".join(ov.split()))
    check("hosts gone quiet is Start here's fleetstate, verbatim",
          "eval is_late = if(tonumber(learned) = 1 AND tonumber(late) = 1, 1, 0)" in q
          and "eval is_late = if(tonumber(learned) = 1 AND tonumber(late) = 1, 1, 0)" in " ".join(st.split()))
    check("no composite score, gauge or percentage-only headline",
          not re.search(r"risk score|gauge|health %|score\s*=", q, re.I))
    check("the movement window is the 30 days closed findings are retained for",
          q.count('relative_time(now(), "-30d@d")') >= 2 and "-90d" not in q)

    print("\nPrint")
    js = open(os.path.join(APP, "appserver", "static", "riskability_executive.js"), encoding="utf-8").read()
    viz = open(os.path.join(APP, "appserver", "static", "visualizations", "riskability_chart", "src",
                            "visualization_source.js"), encoding="utf-8").read()
    css = open(os.path.join(APP, "appserver", "static", "riskability_executive.css"), encoding="utf-8").read()
    check("A4 landscape is fixed by the stylesheet", re.search(r"@page\s*\{[^}]*size:\s*A4 landscape", css) is not None)
    check("the script builds three sheets and the stylesheet breaks only between them",
          "buildSheets" in js and "unbuildSheets" in js
          and ".rk-sheet { break-after: page; page-break-after: always; }" in css
          and "break-before" not in css.split("@media print", 1)[1])
    check("rows are sized against the paper, not in pixels",
          re.search(r"#rk_exec_tiles \.rk-exec-card \{ min-height: \d+vh", css) is not None
          and "--rk-print-h: " in css)
    check("the print stand-in is vector SVG first, a canvas copy second",
          "renderToSVGString" in viz and "renderToCanvas" in viz and "SVGRenderer" in viz)
    check("the sheet is not left at Splunk's 960 px print width", "body { width: auto !important; }" in css.split("@media print", 1)[1])
    check("the closing line prints in normal flow, since Safari has no margin boxes and Chromium misplaces fixed elements",
          "position: fixed" not in css.split("@media print", 1)[1] and "@bottom-left" not in js
          and 'class="rk-exec-foot"' in raw.split('id="rk_exec_note"', 1)[1])

    check("notes print even when Panel notes is off",
          "body.rk-help-off .rk-status:not(.rk-bad) { display: block !important; }" in css)
    check("the print control never prints", ".rk-exec-print-bar" in css.split("@media print", 1)[1])
    check("the visualization re-renders light and swaps a synchronous PNG in for print",
          "if (printMode) { return LIGHT; }" in viz and "getDataURL(" in viz
          and "addEventListener('beforeprint'" in viz)
    check("the button prints through the browser and nothing else", "window.print()" in js and "jsPDF" not in js)
    nav = open(os.path.join(APP, "default", "data", "ui", "nav", "default.xml"), encoding="utf-8").read()
    check("the page is in the navigation, right after Fleet overview",
          '<view name="riskability_overview"/>\n  <view name="riskability_executive"/>' in nav)

    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
