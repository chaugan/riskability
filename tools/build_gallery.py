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
 "network-evidence":       ("Network evidence", "Whether a permitted flow to a listening port has been observed, the coverage state that gates every grade, and where the app refused to name a host."),
 "netevidence-grades":     ("Network evidence, grades", "The grade donut: no green anywhere, because none of these grades means safe."),
 "routes":                 ("Routes", "The jumps a permitted flow has been seen to make: entry point, host reached, port, software listening, open findings."),
 "routes-drilldown":       ("Routes, drill-down", "Clicking a point on the route opens the findings behind it on the same page."),
 "routes-host-filter":     ("Routes, one host", "Filtered to one host: only the chains through it, at the hops the unfiltered graph gives them. Red edges land on software with a known-exploited or EPSS 50%+ finding open."),
 "admin-escalation-rules": ("Escalation rules (admin)", "Every rule with a switch, the replay of what each would move, and locked rules with the reason they cannot be enabled."),
 "admin-firewall-source":  ("Firewall data source (admin)", "Index or accelerated data model, field mapping, entry points, freshness; Test and top-100 preview before Save."),
 "escalations":            ("Escalation rules (earlier, main app)", "Before the page moved to the admin app."),
 "exposure":               ("Exposure", "The priority matrix and the reachability chain."),
 "fleet-overview":         ("Fleet overview", ""), "findings": ("Findings", ""), "remediation": ("Remediation", ""),
 "mitre-attack":           ("MITRE ATT&CK", ""), "hosts": ("Hosts", ""), "coverage": ("Coverage", ""),
 "risk-exceptions":        ("Risk exceptions", ""), "cve-encyclopaedia": ("CVE encyclopaedia", ""), "start-here": ("Start here", ""),
 "feed-administration":    ("Feed administration (admin)", ""), "feed-import-progress": ("Feed import progress (admin)", ""),
 "config-surface":         ("Configuration surface", ""), "kev-bridge": ("KEV bridge", ""), "mitigation-coverage": ("Mitigation coverage", ""),
 "capec-attack-patterns":  ("CAPEC attack patterns", ""), "attack-matrix-fuller": ("ATT&CK matrix", ""),
 "end-of-support":         ("End of support", ""), "end-of-support-hosts": ("End of support, hosts", ""),
}
# The section at the top. Edit when a batch of pages changes.
RECENT_TITLE = "Changed on 2026-09-03"
RECENT = ["ai-prioritization", "ai-explain-rendered", "network-evidence", "netevidence-grades",
          "routes", "routes-host-filter", "routes-drilldown", "admin-escalation-rules", "admin-firewall-source"]


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
    return ('      <figure class="card" data-name="%s">\n'
            '        <a href="screenshots/%s.png" target="_blank" rel="noopener"><img loading="lazy" src="screenshots/%s.png" alt="%s"></a>\n'
            '        <figcaption><b>%s</b>%s<span class="date">%s</span></figcaption>\n'
            '      </figure>' % (html.escape(name), name, name, html.escape(title), html.escape(title), capx, when(name)))


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
