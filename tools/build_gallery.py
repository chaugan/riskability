#!/usr/bin/env python3
"""Rebuild docs/index.html, the screenshot gallery GitHub Pages serves.

    python3 tools/build_gallery.py

Lists every PNG under docs/screenshots with a caption from the table below,
or its file name when it has none, so a new capture is never silently
missing from the gallery. Dates come from git. No dependencies.
"""
import html, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = "docs/screenshots"

CAPTIONS = {
 "ai-prioritization":      ("AI prioritization", "The sea of CVEs banded by exploit likelihood, the few lifted above the waterline, and the paged, sortable, filterable work queue with the model's reasoning beside each row."),
 "ai-explain-rendered":    ("Explain in depth, rendered", "A saved explanation opened from its green button: headings, paragraphs and lists built from the model's markdown, with Re-run beside it."),
 "network-evidence":       ("Network evidence", "With a firewall source wired: ten ports confirmed observed from a declared entry point, one graded not observed on a covered host, the rest unknown, and the coverage state that gates every grade. Every table sorts and filters by column."),
 "netevidence-grades":     ("Network evidence, grades", "The grade donut with the coverage grid beside it. No green anywhere, because none of these grades means safe; not observed is the app's one negative claim and it is licensed only where a constant pressure entry point is declared."),
 "routes":                 ("Routes", "The jumps a permitted flow has been seen to make, laid out by hop: entry point, the host reached, its port, the software listening, the findings open in it. Each host to host jump carries the port and session count; a red edge lands on software with a known exploited or high EPSS finding open."),
 "routes-host-filter":     ("Routes, one host", "Filtered to one host: only the chains through it, at the hops the unfiltered graph gives them. A host reached both directly and through two others sits in both columns."),
 "routes-drilldown":       ("Routes, drill-down", "Clicking a point on the route opens the findings behind it on the same page, with tier, score, KEV, fix version and the pipeline's rationale."),
 "admin-escalation-rules": ("Escalation rules (admin)", "Every rule with a switch, the replay of what each would move against the fleet as it stands, and locked rules with the reason they cannot be enabled."),
 "admin-firewall-source":  ("Firewall data source (admin)", "Index or accelerated data model, field mapping, entry points with their scan pressure, freshness; Test source and Show top 100 edges before Save."),
 "start-here":             ("Start here", "The default landing page. What every number on the other pages means and, just as importantly, what it does not."),
 "fleet-overview":         ("Fleet overview", "How stale the feed is, how many hosts are reporting, and where the open findings are concentrated."),
 "findings":               ("Findings", "Every finding ranked by EPSS rather than CVSS, with confidence, KEV status and the fixed version where one is known. Column filters narrow what is shown, not what was searched."),
 "remediation":            ("Remediation", "What was actually fixed, and what merely stopped being reported. Installer artifacts closed with their own reason are counted as neither."),
 "mitre-attack":           ("MITRE ATT&CK", "Which adversary techniques the open findings could enable, built from four kinds of evidence that carry different strengths of claim and are never blended into one number."),
 "attack-matrix-fuller":   ("ATT&CK matrix and its denominator", "Four evidence sources place a CVE on ATT&CK, each labelled and filterable. The caption is the honest denominator: unique open CVEs in scope, how many placed and through which source, how many not and why."),
 "kev-bridge":             ("Known exploited to technique", "MITRE's mapping of each CISA known exploited CVE to the technique that exploits it, coloured by the reach of the finding rather than the count: one known exploited package answering the network is drawn as loud as a thousand that answer nothing."),
 "capec-attack-patterns":  ("CAPEC attack patterns", "CAPEC's own words for the entry requirement and the opening move, per attack pattern, sorted by whether a copy of the vulnerable package answers the network. Measured reach on the left, MITRE's generic rating on the right."),
 "mitigation-coverage":    ("Mitigation coverage", "MITRE mitigations ranked by how many of the fleet's reachable techniques each would address, split by reach, so the highest leverage control is first. A mitigation reduces the technique; the CVEs still need fixing."),
 "config-surface":         ("Configuration surface", "What each host is configured to run: cron, systemd timers and services, SUID and SGID binaries, each carrying the ATT&CK technique it is the surface for. The half of ATT&CK a CVE feed cannot reach, counted in mechanisms rather than CVEs."),
 "exposure":               ("Exposure", "The priority matrix, open findings by network reach against exploitation likelihood, the most exposed hosts, and the chain the network takes: edge, listening process, container, package, CVE."),
 "host-detail":            ("Host detail", "Everything known about one machine, as a dossier: identity and four clocks, what has been measured and what has not, what to do first, its findings, configuration surface, exposure, patch level and unsupported software."),
 "hosts":                  ("Host overview", "Every host at a glance, split by filesystem root, so a package inside a container is never confused with the same package on the host."),
 "coverage":               ("Coverage", "The honest page. What the imported feed cannot assess and why, whether everything the collector found actually arrived, Windows patch level against Microsoft's own build data, and the support timeline."),
 "end-of-support":         ("End of support", "Software on the fleet that has run out of supported releases, placed on a timeline at the date support ends, with how much evidence there is that it runs. Who ships a copy decides whether it is really unsupported."),
 "end-of-support-hosts":   ("End of support, by host", "Where each end of support product is installed, so the timeline above can be turned into a list of machines."),
 "risk-exceptions":        ("Risk exceptions", "Findings someone accepted, why, until when, and who said so. Written to an audit index that is appended to and never rewritten."),
 "cve-encyclopaedia":      ("CVE encyclopaedia", "What any vulnerability the feed carries actually is, and where it sits in this fleet. Entirely offline."),
 "admin-ai-analysis":      ("AI analysis (admin)", "The model endpoint, its credential in Splunk's password store, and the master switch. Fetch models lists what the endpoint actually serves so the name is chosen rather than typed. Test connection and Test analysis prove it answers before the fleet's data is trusted to it. Under the Administration menu, drawn for administrators only."),
 "feed-administration":    ("Feed administration (admin)", "Build, upload and import bundles, fetch sources directly on an instance that has a route out, and set index names. Under the Administration menu of the app, drawn for administrators only."),
 "feed-import-progress":   ("Feed import in progress (admin)", "An import runs on the server and does not need the page kept open. The active feed stays searchable throughout, so importing never blinds the fleet."),
}
# The section at the top. Edit when a batch of pages changes.
RECENT_TITLE = "Changed on 2026-09-05"
# The four Administration captures, retaken because the previous ones showed
# these pages while they lived in a separate riskability-config app, and one
# added: the AI settings page had never been captured at all.
RECENT = ["feed-administration", "admin-ai-analysis", "admin-escalation-rules",
          "admin-firewall-source"]


def when(name):
    out = subprocess.run(["git", "log", "-1", "--format=%cs", "--", "%s/%s.png" % (SHOTS, name)],
                         cwd=ROOT, capture_output=True, text=True).stdout.strip()
    # A capture not yet in git gets today's date rather than the word
    # "uncommitted": this page is public, and a build run before the commit
    # once shipped that word under four captures. Run the build AFTER staging
    # the captures and the dates are exact; run it before and they are today's,
    # which is at worst a day out and never a wrong claim about the repo.
    if out:
        return out
    import datetime
    return datetime.date.today().isoformat()


def card(name):
    title, cap = CAPTIONS.get(name, (name.replace("-", " ").capitalize(), ""))
    capx = (' <span class="dim">%s</span>' % html.escape(cap)) if cap else ""
    return ('      <figure class="card" id="%s" data-name="%s">\n'
            '        <a href="screenshots/%s.png" target="_blank" rel="noopener"><img loading="lazy" src="screenshots/%s.png" alt="%s"></a>\n'
            '        <figcaption><b>%s</b>%s<span class="date">%s</span></figcaption>\n'
            '      </figure>' % (html.escape(name), html.escape(name), name, name, html.escape(title), html.escape(title), capx, when(name)))


def main():
    files = sorted(f[:-4] for f in os.listdir(os.path.join(ROOT, SHOTS)) if f.endswith(".png"))
    recent = [n for n in RECENT if n in files]
    rest = [n for n in files if n not in RECENT]
    tpl = open(os.path.join(ROOT, "tools", "gallery_template.html"), encoding="utf-8").read()
    page = (tpl.replace("{{RECENT_TITLE}}", html.escape(RECENT_TITLE))
               .replace("{{RECENT}}", "\n".join(card(n) for n in recent))
               .replace("{{REST}}", "\n".join(card(n) for n in rest)))
    open(os.path.join(ROOT, "docs", "index.html"), "w", encoding="utf-8").write(page)
    print("gallery: %d recent, %d others" % (len(recent), len(rest)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
