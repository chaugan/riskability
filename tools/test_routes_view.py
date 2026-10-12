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
6. The chart's row contract: node_mark is column 7, the edge's note and the
   point a click on it selects are columns 8 to 10, and rk_labels after them,
   because the chart reads rows by position.
7. The page reads the walk's collections and never the firewall index: the
   chart, the path table and the jump list all start from inputlookup, the
   chart trims through riskabilitywalk in view mode, what listens comes in
   through lookup rather than a subsearch with a row ceiling, the page opens
   on CVE-enabled jumps with a per-hop cap, and the two jobs that write the
   collections are scheduled after the assess job.
8. The software is on the jump, not in a column of its own. The chart's
   columns are the entry point and the hops only; every jump's label names
   its port and the software listening there; the tooltip lists every port
   the jump was seen on; a click on a jump selects those ports; and the panel
   grows with its densest hop. A "software listening" column fed by every hop
   put the first hop's nginx beside the fourth hop's samba with nothing to say
   which jump each belonged to.
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
walkpy = open(ROOT + '/app/riskability/bin/riskability/walk.py', encoding='utf-8').read()
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
    check('"%s"' % c in walkpy, 'the walk never emits class %s' % c)
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
check('`riskability_route_hop_class`' in macros[macros.index('[riskability_route_edges]'):],
      'the edge macro must grade through riskability_route_hop_class')

# 4. the macro walks findings to ports with lookup, not join
hop = macros[macros.index('[riskability_route_hop_class]'):]
hop = hop[:hop.index('iseval')]
check(re.search(r'\|\s*join\b', hop) is None, 'riskability_route_hop_class must not join')
check('lookup riskability_exposure_lookup hostname, package OUTPUT port' in hop,
      'riskability_route_hop_class must reach ports through the exposure lookup')
check('rk_n_wire' in hop and 'rk_wire_text' in hop,
      'the macro must emit a count and a text, a join keeps only the first multivalue')

# 5. the path table reads the walk's paths, worst first, capped and honest about it
paths = view[view.index('<title>Every path'):view.index('<title>Findings at the clicked')]
check('| inputlookup riskability_routepaths_lookup' in paths, 'the path table must read the paths collection')
check('sort 0 - full_cve, - jumps' in paths and '| head 500' in paths, 'paths come worst first and capped')
check('Where the CVE-only path stops' in paths, 'the path table must name the stop')
check('paths_truncated' in paths, 'the page must say when the walk cut the list')
check('full_cve == 1' in paths, 'the Show filter must narrow paths the way it narrows the graph')

# 6. the row contract
check('| fields source, source_kind, target, target_kind, value, edge_label, edge_class, node_mark, edge_note, edge_point, edge_point_kind, rk_labels, ' in chain,
      'node_mark must be column 7, the edge note and click point 8 to 10, before rk_labels')
check("rows[i][7]" in viz, 'the chart must read the mark from column 7')
check("rkNote: cell(8), rkPoint: cell(9), rkPointKind: cell(10)" in viz, 'the chart must read columns 8 to 10 off the edge')
check("params.data.rkPoint" in viz[viz.index("this.chart.on('click'"):], 'an edge click must report the edge point when the row named one')

# 7. collections in, firewall index out
check('| inputlookup riskability_routeedges_lookup\n| riskabilitywalk mode=view' in chain,
      'the chart must read the edge collection and trim through riskabilitywalk mode=view')
check('entry=$entry_filter|s$ host=$host_filter|s$ top=$top|s$ classes=$show|s$' in chain,
      'the view mode must take the four page inputs')
check('riskability_fw_edges' not in chain and 'riskability_netevidence_lookup' not in chain,
      'the chart must not read the firewall index or the evidence ledger itself')
check('| lookup riskability_routelisteners_lookup hostname AS dst, port AS rk_p OUTPUT' in chain,
      'what listens must come in through lookup, not a subsearch')
check(re.search(r'\|\s*join\b', chain) is None and 'append=true' not in chain,
      'the chart search must not join or append')

# 8. the software is on the jump, not in a column of its own
check('software listening' not in chain[chain.index('<query>'):chain.index('</query>')]
      and 'open findings' not in chain[chain.index('<query>'):chain.index('</query>')],
      'the chart must not draw software or findings columns')
check('c0:entry point,c1:hop 1" . if(rk_maxhop' in chain and ':software' not in chain,
      'the columns must be the entry point and the hops only')
check('| eval edge_label = protocol . "/" . port . " · " . rk_best_sw' in chain,
      'the jump label must name the port and the software listening there')
check('| mvexpand rk_p' in chain and 'list(rk_line) AS rk_lines' in chain and 'mvjoin(rk_lines, " · ")' in chain,
      'the tooltip must list every port the jump was seen on')
check('edge_point = dst . " · port"' in chain and 'edge_point_kind = "port"' in chain,
      'a click on a jump must select the ports it landed on')
findings = view[view.index('<title>Findings at the clicked'):view.index('<title>The jumps, listed')]
check('rex field=rk_sel "^(?&lt;rk_host_of_port&gt;.+?) · ports? (?&lt;rk_plist&gt;.+)$"' in findings
      and 'mvfind(rk_ports, rk_port_rx)' in findings,
      'the findings panel must read the host and every port out of a jump click')
check('<option name="riskability.riskability_chart.chainPitch">40</option>' in chain,
      'the routes chart must ask for forty pixels per host in the densest hop')
check("Math.max(8, num(config && config.chainPitch) || 15)" in viz and "chainPitch: this._opt(config, 'chainPitch')" in viz,
      'the chart must read chainPitch and grow with it')
check("Math.max(1600, LABEL_PITCH * 60)" in viz, 'the height ceiling must scale with the pitch')
check("show: /:host$/.test(l.sourceKind)" in viz and "emphasis: l.rkLabel ? { label: { show: true } }" in viz,
      'host-to-host jumps are labelled at rest, entry jumps on hover')
jumps = view[view.index('<title>The jumps, listed'):]
check('Listening' in jumps and '"This port needs"' in jumps and '| mvexpand rk_p' in jumps,
      'the jump list must say what listens on every port of a jump')
ss_block = open(ROOT + '/app/riskability/default/savedsearches.conf', encoding='utf-8').read()
roll = ss_block[ss_block.index('[Riskability - roll up route listeners]'):]
roll = roll[:roll.index('\n[', 1)]
check('inputlookup append=true riskability_exposure_lookup' in roll and 'BY hostname, port \\' in roll
      and 'values(rk_pkg_text) AS rk_summary' in roll,
      'the listeners roll-up must be one row per host and port, naming the software even with nothing open')
check('<default>cve</default>' in view and '<default>25</default>' in view,
      'the page must open on CVE-enabled jumps with a per-hop cap')
check('rk-route-status' in view and '$rk_hidden$' in view, 'the page must say how many hosts it left out')
jumps = view[view.index('<title>The jumps, listed'):]
check('| inputlookup riskability_routeedges_lookup' in jumps and '| head 1000' in jumps,
      'the jump list must read the edge collection, capped')
ss = open(ROOT + '/app/riskability/default/savedsearches.conf', encoding='utf-8').read()
walkjob = ss[ss.index('[Riskability - walk observed jumps]'):]
walkjob = walkjob[:walkjob.index('\n[', 1)]
check('riskabilitywalk mode=grade' in walkjob and 'riskabilitywalk mode=paths' in walkjob
      and 'outputlookup riskability_routeedges_lookup' in walkjob and 'outputlookup riskability_routepaths_lookup' in walkjob,
      'the walk job must write both collections')
import re as _re
def cron_minute(name):
    block = ss[ss.index('[%s]' % name):]
    return int(_re.search(r'cron_schedule = (\d+) ', block).group(1))
check(cron_minute('Riskability - assess observed permitted traffic') < cron_minute('Riskability - walk observed jumps')
      < cron_minute('Riskability - roll up route listeners'),
      'the walk runs after the assess job and before the listeners roll-up')
cmds = open(ROOT + '/app/riskability/default/commands.conf', encoding='utf-8').read()
check('[riskabilitywalk]' in cmds and 'local = true' in cmds[cmds.index('[riskabilitywalk]'):],
      'riskabilitywalk must be declared and local')
for coll in ('riskability_routeedges', 'riskability_routepaths', 'riskability_routelisteners'):
    cc = open(ROOT + '/app/riskability/default/collections.conf', encoding='utf-8').read()
    tc = open(ROOT + '/app/riskability/default/transforms.conf', encoding='utf-8').read()
    check('[%s]' % coll in cc and 'replicate = false' in cc[cc.index('[%s]' % coll):][:400],
          '%s must exist and not replicate' % coll)
    check('[%s_lookup]' % coll in tc, '%s_lookup must exist' % coll)

# the findings grid says what each finding needs over the wire
find = view[view.index('<title>Findings at the clicked'):view.index('<title>The jumps, listed')]
check('`riskability_cvss_reach`' in find and '"Over the wire"' in find,
      'the findings grid must grade each finding over the wire')

if fails:
    for f in fails:
        print('FAIL', f)
    sys.exit(1)
print('ok: routes view, chain chart and grading macros')
