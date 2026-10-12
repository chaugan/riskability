#!/usr/bin/env python3
"""Static checks on the Routes page and the chain chart's jump grading.

  python3 tools/test_routes_view.py

What is defended, and why each one is worth a test:

1. The chart's tooltip gets the edge label and class. They were built for every
   link and then dropped from the objects handed to ECharts, so every edge read
   "N CVEs through this hop" with N being its session count. A label that lies
   about its unit is worse than none.
2. Every jump class the view can emit is one the chart draws and explains, and
   the legend names each one. A class without a style falls back to the quiet
   default, which would show a CVE-enabled jump as an ordinary one.
3. The grading reads the CVSS vector for AV, PR and UI, and the view never
   grades from KEV or EPSS alone: exploited-in-the-wild says nothing about
   whether the flaw is reachable over this wire.
4. The macro the grading lives in walks findings to ports through lookup, not
   join: join has a row ceiling and would silently drop findings on a large
   estate.
5. The path table stops at the first jump that is not CVE-enabled and never
   revisits a host, so two hosts that talk both ways do not produce a path that
   goes back and forth.
6. The chart's row contract: node_mark is column 7 and rk_labels after it,
   because the chart reads rows by position.
"""
import re
import sys

ROOT = __file__.rsplit('/tools/', 1)[0]
VIEW = ROOT + '/app/riskability/default/data/ui/views/riskability_routes.xml'
VIZ = ROOT + '/app/riskability/appserver/static/visualizations/riskability_chart/src/visualization_source.js'
MACROS = ROOT + '/app/riskability/default/macros.conf'

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


view = open(VIEW, encoding='utf-8').read()
viz = open(VIZ, encoding='utf-8').read()
macros = open(MACROS, encoding='utf-8').read()

# 1. the tooltip reads what the link carries
link_block = viz[viz.index('var linkData = links.map'):viz.index('var linkData = links.map') + 2500]
check('rkLabel: l.rkLabel' in link_block and 'rkClass: l.rkClass' in link_block,
      'linkData must carry rkLabel and rkClass to the tooltip')
check("' CVEs through this hop'" in viz and "' sessions through this hop'" in viz,
      'the unlabelled tooltip must name sessions for host and port edges and CVEs otherwise')

# 2. every class the view emits is drawn and explained, and in the legend
classes = {'cve', 'foothold', 'unrated', 'permitted'}
for c in classes:
    check(re.search(r'\b%s:\s*\{\s*color:' % c, viz) is not None, 'EDGE_STYLE lacks %s' % c)
    check(re.search(r'\b%s: \'' % c, viz[viz.index('EDGE_SAYS'):]) is not None, 'EDGE_SAYS lacks %s' % c)
    check('"%s"' % c in view, 'the view never emits class %s' % c)
check('rk-exec-legend' in view, 'the chart has no legend')
for word in ('CVE-enabled', 'needs a foothold', 'unrated', 'permitted only', 'on CVEs alone'):
    check(word in view[view.index('rk-exec-legend'):view.index('rk-exec-legend') + 2000], 'legend lacks "%s"' % word)
check(re.search(r"permitted:\s*\{[^}]*type: 'dashed'", viz) is not None, 'permitted jumps must be dashed')
check("n.mark === 'reach'" in viz, 'the chart must ring a host marked reach')

# 3. the grading is the CVSS vector, not KEV or EPSS
reach = macros[macros.index('[riskability_cvss_reach]'):macros.index('[riskability_route_hop_class]')]
for letter in ('AV:[NA]', 'PR:N', 'UI:N'):
    check(letter in reach, 'riskability_cvss_reach does not read %s' % letter)
check('mvmap(' in reach, 'the rank must be computed per vector, a CVE can carry several')
chain = view[view.index('<title>Possible jumps'):view.index('<title>Every path')]
check('rk_exploit' not in chain and 'EPSS 50%' not in chain,
      'the chain must not grade an edge from KEV or EPSS')
check('`riskability_route_hop_class`' in chain, 'the chain must grade through riskability_route_hop_class')

# 4. the macro walks findings to ports with lookup, not join
hop = macros[macros.index('[riskability_route_hop_class]'):]
hop = hop[:hop.index('iseval')]
check(re.search(r'\|\s*join\b', hop) is None, 'riskability_route_hop_class must not join')
check('lookup riskability_exposure_lookup hostname, package OUTPUT port' in hop,
      'riskability_route_hop_class must reach ports through the exposure lookup')
check('rk_n_wire' in hop and 'rk_wire_text' in hop,
      'the macro must emit a count and a text, a join keeps only the first multivalue')

# 5. the path table
paths = view[view.index('<title>Every path'):view.index('<title>Findings at the clicked')]
check('NOT match(mvindex(split(rk_p1, "|"), 0), "(^|→)" . dst . "(→|$$)")' in paths,
      'path growth must refuse to revisit a host')
check('"^(C*).*$$"' in paths, 'the CVE-only run must be measured from the flags')
check('Where the CVE-only path stops' in paths, 'the path table must name the stop')
check('rk_p5' in paths and 'rk_p6' not in paths, 'paths are grown to five hops, the depth the chain walks')
check('mvjoin(rk_wire_text, " / ")' in paths and '"; "' not in paths,
      'multi-port text must not use the hop separator')

# 6. the row contract
check('| fields source, source_kind, target, target_kind, value, edge_label, edge_class, node_mark, rk_labels</query>' in chain,
      'node_mark must be column 7, before rk_labels')
check("rows[i][7]" in viz, 'the chart must read the mark from column 7')

# the findings grid says what each finding needs over the wire
find = view[view.index('<title>Findings at the clicked'):view.index('<title>The jumps, listed')]
check('`riskability_cvss_reach`' in find and '"Over the wire"' in find,
      'the findings grid must grade each finding over the wire')

if fails:
    for f in fails:
        print('FAIL', f)
    sys.exit(1)
print('ok: routes view, chain chart and grading macros')
