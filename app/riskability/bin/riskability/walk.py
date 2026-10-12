"""Walk the observed-jump graph: hops from each entry point, the CVE-only reach,
every path worth listing, and the trimmed view a dashboard can draw.

Stdlib only and Splunk free, like ``route`` and ``escalate``: the walk has to
be exercised on a laptop under ``tools/test_walk.py``, because the graph it
walks exists only on a search head that has onboarded firewall logs, and a
walk that can only be tested there is a walk nobody tests.

WHY THIS IS PYTHON AND NOT SPL

The first version of the routes page walked the graph in the dashboard search
with one ``eventstats values()`` per hop and an ``mvfind`` per edge row. That
is edges times hosts per hop, five times over, on every page load. It worked
on fifteen hosts and would take minutes on five thousand, and ``values()`` is
capped by limits.conf at a size a large estate exceeds silently. A breadth
first search over the same edges is linear and finishes in milliseconds. The
graph is small by the standards of a search head; it was the SPL that was
expensive.

WHAT A JUMP IS, AND WHAT ITS CLASS MEANS

A jump is a permitted flow the firewall logged between two points the
inventory knows: an entry point (a declared network, outside) to a host, or
one host to another. The grade of the flow is someone else's job: the assess
job decides whether the flow was observed at all, and ``riskability_route_hop_class``
reads the CVSS vectors of the open findings on the listener where the flow
lands. This module is handed each edge with a rank already on it:

    3  cve        reachable over the network with no foothold
    2  foothold   reachable over the network, but wants credentials or a click
    1  unrated    an open finding with no CVSS vector, so nothing can be said
    0  permitted  the flow was allowed and nothing usable over the network is
                  open at the far end: the jump needs a zero-day or permissions

and it never changes a rank. What it adds is position: how many jumps out a
host sits from each entry, whether an attacker can get there on CVE-enabled
jumps all the way, and which paths say so.

WHY SEVERAL PORTS COLLAPSE TO ONE EDGE

A flow from A to B on 443 and another on 8080 are two listeners and one jump.
The chart draws the jump once, with the best rank among the ports, because an
attacker needs one way in, not all of them. The port and texts on the merged
edge are the best port's; the session count is the sum.

WHY PATHS ARE CAPPED, AND HOW

The number of simple paths in a lateral graph is exponential, and a table
with a million rows says nothing. Three caps, each deliberate:

* ``beyond_break``: after the first jump that is not CVE-enabled, a path is
  extended at most this many more jumps. The question a path answers is "how
  far on CVEs alone, and what stops it", and one jump past the stop is enough
  to show what the stop protects.
* ``fanout``: from any host, only the best ``fanout`` onward edges are
  followed, best meaning highest class then most sessions. The worst case
  goes through the best edges by construction; the long tail is still in the
  edge collection.
* ``budget``: a hard ceiling on expansions, so a pathological graph produces
  a truncated result and says so (``truncated`` on every row) rather than a
  search that never returns.

Paths come out worst first: CVE-enabled all the way before any other, then
longer before shorter, so the first rows of a capped table are the ones a
reader most needs to see.
"""
from __future__ import annotations

import hashlib
import time
from collections import deque

CLASS_OF_RANK = {3: "cve", 2: "foothold", 1: "unrated", 0: "permitted"}
PRIORITY = {"cve": 4, "foothold": 3, "unrated": 2, "permitted": 1}
LETTER = {"cve": "C", "foothold": "F", "unrated": "U", "permitted": "P"}
ARROW = " → "

DEFAULT_MAX_HOPS = 5


def _num(value, default=0):
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _first(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else ""
    return value if value is not None else ""


def _listify(value):
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None and v != ""]
    return [str(value)]


def _tidy(value):
    """Whole numbers come back as ints, so a session count prints as 1080 and
    not 1080.0 once Splunk has handed it over as a float."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return value
    return int(f) if f.is_integer() else f


def class_of(rank):
    try:
        r = int(float(rank))
    except (TypeError, ValueError):
        r = 0
    return CLASS_OF_RANK.get(max(0, min(3, r)), "permitted")


# ---------------------------------------------------------------- the graph


def merge_edges(rows):
    """Collapse rows (one per src, dst, port) into one edge per (src, dst).

    Returns (edges, entries): edges maps (src, dst) to a dict; entries is the
    set of sources that are entry points. The best rank wins and carries its
    port, protocol and texts; sessions add up; the newest sighting is kept.
    """
    edges = {}
    entries = set()
    for row in rows:
        src = str(_first(row.get("src")) or "").strip()
        dst = str(_first(row.get("dst")) or "").strip()
        if not src or not dst or src == dst:
            continue
        kind = str(_first(row.get("kind")) or "host").strip().lower()
        if kind == "entry":
            entries.add(src)
        rank = int(_num(_first(row.get("rk_rank")), 0))
        rank = max(0, min(3, rank))
        sessions = _num(_first(row.get("sessions")), 0)
        last_seen = _num(_first(row.get("edge_last_seen")), 0)
        port = str(_first(row.get("port")) or "")
        proto = str(_first(row.get("protocol")) or "tcp")
        # A graded row (one per pair, from the collection) already lists every
        # port the pair was seen on; a raw row (one per port) names only its
        # own. Both are honoured, so a view re-merging graded rows keeps the
        # whole port list rather than the best port alone.
        ports = []
        for item in _listify(row.get("ports")):
            for p in str(item).split(","):
                if p.strip() and p.strip() not in ports:
                    ports.append(p.strip())
        if not ports and port:
            ports = [port]
        key = (src, dst)
        cur = edges.get(key)
        fresh = cur is None
        if fresh:
            cur = edges[key] = {
                "src": src, "dst": dst, "kind": "entry" if kind == "entry" else "host",
                "rk_rank": rank, "rk_class": class_of(rank),
                "port": port, "protocol": proto,
                "sessions": sessions, "n_ports": 0,
                "edge_last_seen": last_seen,
                "wire_text": str(_first(row.get("wire_text")) or ""),
                "foot_text": str(_first(row.get("foot_text")) or ""),
                "ports": [],
            }
        else:
            cur["sessions"] += sessions
        for p in ports:
            if p not in cur["ports"]:
                cur["ports"].append(p)
        cur["n_ports"] = len(cur["ports"])
        if fresh:
            continue
        if last_seen > cur["edge_last_seen"]:
            cur["edge_last_seen"] = last_seen
        if rank > cur["rk_rank"]:
            cur["rk_rank"] = rank
            cur["rk_class"] = class_of(rank)
            cur["port"] = port
            cur["protocol"] = proto
            cur["wire_text"] = str(_first(row.get("wire_text")) or "")
            cur["foot_text"] = str(_first(row.get("foot_text")) or "")
    return edges, entries


def adjacency(edges):
    out = {}
    for (src, dst) in edges:
        out.setdefault(src, []).append(dst)
    return out


def _bfs(out, start, max_hops, allowed=None):
    """Depth of every node reachable from ``start`` within ``max_hops`` jumps.

    ``allowed`` is an optional predicate on (src, dst) that an edge must pass
    to be followed; the CVE-only reach uses it.
    """
    depth = {start: 0}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        d = depth[node]
        if d >= max_hops:
            continue
        for nxt in out.get(node, ()):
            if nxt in depth:
                continue
            if allowed is not None and not allowed(node, nxt):
                continue
            depth[nxt] = d + 1
            queue.append(nxt)
    return depth


def _ranked(edges, out):
    """Out-edges of each node, best first: highest class, then most sessions."""
    ranked = {}
    for node, nxts in out.items():
        ranked[node] = sorted(
            nxts,
            key=lambda d: (-edges[(node, d)]["rk_rank"], -edges[(node, d)]["sessions"], d),
        )
    return ranked


# ---------------------------------------------------------------- grading


def grade(rows, max_hops=DEFAULT_MAX_HOPS, now=None):
    """Position every edge: hops from each entry, and the CVE-only reach.

    Emits one row per merged edge that some entry point reaches within
    ``max_hops``. Fields a dashboard filters on are multivalue lists:

    * ``entries``: the entry points this edge is walked from
    * ``hops``: "entry:depth" per entry, depth being the hop the destination
      sits at when reached through this edge from that entry
    * ``hop``: the smallest of those depths
    * ``dst_reach`` / ``src_reach``: the entry points from which the host is
      reachable on CVE-enabled jumps alone

    An edge nobody reaches is dropped, not graded: a flow between two hosts
    neither of which any entry point reaches is not a jump an outsider can
    make, however it is classed.
    """
    walked_at = int(now if now is not None else time.time())
    edges, entries = merge_edges(rows)
    out = adjacency(edges)
    depth_from = {e: _bfs(out, e, max_hops) for e in entries}
    cve_ok = lambda s, d: edges[(s, d)]["rk_class"] == "cve"  # noqa: E731
    reach_from = {e: _bfs(out, e, max_hops, allowed=cve_ok) for e in entries}

    result = []
    for (src, dst), edge in edges.items():
        hops = []
        for e in sorted(entries):
            ds = depth_from[e].get(src)
            if ds is None or ds >= max_hops:
                continue
            hops.append((e, ds + 1))
        if not hops:
            continue
        row = dict(edge)
        row.pop("ports", None)
        row["ports"] = ",".join(edge["ports"])
        row["sessions"] = _tidy(row["sessions"])
        row["edge_last_seen"] = _tidy(row["edge_last_seen"])
        row["entries"] = [e for e, _ in hops]
        row["hops"] = ["%s:%d" % (e, d) for e, d in hops]
        row["hop"] = min(d for _, d in hops)
        row["dst_reach"] = [e for e in sorted(entries) if dst in reach_from[e]]
        row["src_reach"] = [e for e in sorted(entries) if src in reach_from[e] and src not in entries]
        row["walked_at"] = walked_at
        row["_key"] = "%s|%s" % (src, dst)
        result.append(row)
    result.sort(key=lambda r: (r["hop"], -r["rk_rank"], -r["sessions"], r["src"], r["dst"]))
    return result


# ---------------------------------------------------------------- paths


def _jump_text(edge):
    src, dst, cls = edge["src"], edge["dst"], edge["rk_class"]
    head = "%s%s%s: " % (src, ARROW, dst)
    if cls == "cve":
        return head + "CVE-enabled by " + (edge.get("wire_text") or "an open finding reachable over the network")
    if cls == "foothold":
        return head + ("needs a foothold first: %s reachable over the network but wanting credentials or a click"
                       % (edge.get("foot_text") or "an open finding"))
    if cls == "unrated":
        return head + "an open finding has no CVSS vector, so what it needs cannot be said"
    return head + "permitted flow only: needs a zero-day or permissions"


def paths(rows, max_hops=DEFAULT_MAX_HOPS, max_paths=2000, beyond_break=1,
          fanout=8, budget=200000, now=None):
    """Enumerate the paths worth listing, worst first, under the caps above.

    ``rows`` are graded edge rows (``grade`` output, or the collection it was
    written to). Only edges with a class are walked; the entry points are the
    sources of kind ``entry``.
    """
    walked_at = int(now if now is not None else time.time())
    edges, entries = merge_edges(rows)
    out = adjacency(edges)
    ranked = _ranked(edges, out)
    found = []
    expansions = 0
    truncated = False

    def extend(path_nodes, path_edges, breaks_after):
        nonlocal expansions, truncated
        node = path_nodes[-1]
        if len(path_edges) >= max_hops:
            return
        for nxt in ranked.get(node, ())[:fanout]:
            if nxt in path_nodes:
                continue
            if expansions >= budget:
                truncated = True
                return
            expansions += 1
            edge = edges[(node, nxt)]
            is_cve = edge["rk_class"] == "cve"
            next_after = breaks_after
            if breaks_after is not None:
                next_after = breaks_after + 1
            elif not is_cve:
                next_after = 0
            if breaks_after is not None and next_after > beyond_break:
                continue
            new_nodes = path_nodes + [nxt]
            new_edges = path_edges + [edge]
            found.append((new_nodes, new_edges))
            extend(new_nodes, new_edges, next_after)

    for entry in sorted(entries):
        extend([entry], [], None)

    rows_out = []
    for nodes, pedges in found:
        flags = "".join(LETTER[e["rk_class"]] for e in pedges)
        run = 0
        for ch in flags:
            if ch != "C":
                break
            run += 1
        jumps = len(pedges)
        full = 1 if run == jumps else 0
        each = [_jump_text(e) for e in pedges]
        stop = "" if full else each[run]
        text = ARROW.join(nodes)
        rows_out.append({
            "_key": hashlib.sha1(text.encode("utf-8")).hexdigest()[:24],
            "path_text": text,
            "entry": nodes[0],
            "last_host": nodes[-1],
            "hosts": nodes[1:],
            "jumps": jumps,
            "flags": flags,
            "cve_run": run,
            "full_cve": full,
            "stop_text": stop,
            "each_jump": each,
            "sessions_min": min(e["sessions"] for e in pedges),
            "walked_at": walked_at,
            "truncated": 0,
        })
    rows_out.sort(key=lambda r: (-r["full_cve"], -r["jumps"], -r["cve_run"],
                                 -r["sessions_min"], r["path_text"]))
    rows_out = rows_out[:max_paths]
    if truncated or len(found) > max_paths:
        for r in rows_out:
            r["truncated"] = 1
    return rows_out


# ---------------------------------------------------------------- the view


def view(rows, entry="*", host="*", top=25, classes=None, max_hops=DEFAULT_MAX_HOPS):
    """Trim graded edges to what one page can draw, and re-walk them.

    * ``entry``: keep only edges walked from this entry point ("*" for all)
    * ``classes``: keep only edges of these classes; hops are re-walked over
      what is left, so a host only reachable through a dropped class drops
      out rather than floating unattached
    * ``host``: keep only the chains through this host, its ancestors' edges
      and its descendants'
    * ``top``: at most this many hosts per hop, the best kept, best meaning
      highest incoming class then most sessions; dropping a host drops what
      only it led to, and the walk repeats until nothing more falls away

    Every row carries three counters so the page can say what it is not
    showing: ``rk_total_hosts`` before trimming, ``rk_shown_hosts`` after,
    and ``rk_hidden_hosts`` the difference.
    """
    classes = set(classes) if classes else None
    entry = (entry or "*").strip()
    host = (host or "*").strip()
    edges, entries = merge_edges(rows)

    # The entry filter. A graded row says which entries walk it.
    if entry != "*":
        keep = {}
        for row in rows:
            src = str(_first(row.get("src")) or "")
            dst = str(_first(row.get("dst")) or "")
            if entry in _listify(row.get("entries")) or (src == entry):
                keep[(src, dst)] = True
        edges = {k: v for k, v in edges.items() if k in keep}
        entries = {e for e in entries if e == entry}
    total_hosts = {d for (_, d) in edges}

    if classes:
        edges = {k: v for k, v in edges.items() if v["rk_class"] in classes}

    def walk(edges_now):
        out_now = adjacency(edges_now)
        depth = {}
        for e in entries:
            for node, d in _bfs(out_now, e, max_hops).items():
                if node in entries:
                    continue
                if node not in depth or d < depth[node]:
                    depth[node] = d
        kept = {}
        for (s, d), edge in edges_now.items():
            if s in entries:
                if d in depth:
                    kept[(s, d)] = edge
            elif s in depth and d in depth and depth[s] < max_hops:
                kept[(s, d)] = edge
        return kept, depth

    edges, depth = walk(edges)

    if host != "*" and host:
        out = adjacency(edges)
        rev = {}
        for (s, d) in edges:
            rev.setdefault(d, []).append(s)
        anc = set(_bfs(rev, host, max_hops + 1).keys())
        des = set(_bfs(out, host, max_hops + 1).keys())
        focus = {}
        for (s, d), edge in edges.items():
            if d in anc and (s in anc or s in entries):
                focus[(s, d)] = edge
            elif s in des and d in des:
                focus[(s, d)] = edge
        edges, depth = walk(focus)

    # The per hop cap, repeated until stable.
    top = int(top) if top else 0
    if top > 0:
        for _ in range(max_hops + 1):
            by_hop = {}
            best_in = {}
            for (s, d), edge in edges.items():
                h = depth.get(d)
                if h is None:
                    continue
                by_hop.setdefault(h, set()).add(d)
                cur = best_in.get(d)
                cand = (edge["rk_rank"], edge["sessions"])
                if cur is None or cand > cur:
                    best_in[d] = cand
            drop = set()
            for h, hosts in by_hop.items():
                if len(hosts) <= top:
                    continue
                order = sorted(hosts, key=lambda d: (-best_in[d][0], -best_in[d][1], d))
                drop.update(order[top:])
            if not drop:
                break
            edges = {k: v for k, v in edges.items() if k[1] not in drop and k[0] not in drop}
            edges, depth = walk(edges)

    out = adjacency(edges)
    cve_ok = lambda s, d: edges[(s, d)]["rk_class"] == "cve"  # noqa: E731
    reach = set()
    for e in entries:
        reach.update(n for n in _bfs(out, e, max_hops, allowed=cve_ok) if n not in entries)

    shown_hosts = {d for (_, d) in edges}
    result = []
    for (s, d), edge in edges.items():
        row = dict(edge)
        row.pop("ports", None)
        row["ports"] = ",".join(edge["ports"])
        row["sessions"] = _tidy(row["sessions"])
        row["edge_last_seen"] = _tidy(row["edge_last_seen"])
        # The hop is the edge's, not the destination's: one past where its
        # source sits. A host reached at hop 1 directly and at hop 5 through
        # four others is drawn in both columns, once per edge into it, so
        # the chain reads left to right and an edge never points backwards.
        # The cap above grouped hosts by their nearest hop, which is the
        # right measure of how far out a host is; this is the right measure
        # of where to draw an edge.
        row["hop"] = 1 if s in entries else depth[s] + 1
        row["src_hop"] = 0 if s in entries else depth[s]
        row["src_kind"] = "entry" if s in entries else "host"
        row["dst_mark"] = "reach" if d in reach else ""
        row["rk_total_hosts"] = len(total_hosts)
        row["rk_shown_hosts"] = len(shown_hosts)
        row["rk_hidden_hosts"] = max(0, len(total_hosts) - len(shown_hosts))
        result.append(row)
    result.sort(key=lambda r: (r["hop"], -r["rk_rank"], -r["sessions"], r["src"], r["dst"]))
    return result
