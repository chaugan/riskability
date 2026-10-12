#!/usr/bin/env python3
"""Tests for the observed-jump walk: hops, the CVE-only reach, paths and the view.

  python3 tools/test_walk.py

What is defended:

1. Ports collapse to one edge per host pair and the best rank wins. A pair
   with a CVE-enabled port and a permitted one is a CVE-enabled jump.
2. Hops are per entry point and an edge nobody reaches is dropped. A lateral
   flow between two hosts no entry reaches is not a jump an outsider makes.
3. The CVE-only reach stops at the first jump that is not CVE-enabled.
4. Paths never revisit a host, stop ``beyond_break`` jumps after the first
   break, are capped worst first, and say when they were truncated.
5. The view re-walks after a class filter, keeps only the chains through a
   focus host, caps hosts per hop with a cascade, and reports what it hid.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app" / "riskability" / "bin"))

from riskability import walk  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print("  ok   %s" % name)
    else:
        print("  FAIL %s%s" % (name, (" :: %s" % (detail,)) if detail else ""))
        FAILURES.append(name)


def edge(src, dst, rank, port="443", sessions=10, kind="host", wire="CVE-1", seen=100):
    return {"src": src, "dst": dst, "kind": kind, "port": port, "protocol": "tcp",
            "sessions": sessions, "edge_last_seen": seen, "rk_rank": rank,
            "wire_text": wire if rank == 3 else "", "foot_text": "CVE-9" if rank == 2 else ""}


# A chain from the internet edge: E -> a -> b -> c, all CVE-enabled; b also
# reaches d on a permitted flow only; d reaches e on a CVE; a also reaches f on
# a foothold jump. x -> y is a lateral flow nothing reaches.
ROWS = [
    edge("E", "a", 3, kind="entry", sessions=500),
    edge("E", "a", 0, port="8080", sessions=5, kind="entry"),
    edge("a", "b", 3, sessions=120),
    edge("b", "c", 3, sessions=80),
    edge("b", "d", 0, port="1433", sessions=60),
    edge("d", "e", 3, sessions=40),
    edge("a", "f", 2, port="3389", sessions=30),
    edge("x", "y", 3),
    edge("J", "b", 3, kind="entry", sessions=20),
]


def test_merge():
    edges, entries = walk.merge_edges(ROWS)
    e = edges[("E", "a")]
    check("merge: two ports become one edge", e["n_ports"] == 2 and e["ports"] == ["443", "8080"], e)
    check("merge: best rank wins and keeps its port", e["rk_class"] == "cve" and e["port"] == "443")
    check("merge: sessions add up", e["sessions"] == 505)
    check("merge: entries are the entry sources", entries == {"E", "J"})


def test_grade():
    rows = walk.grade(ROWS, max_hops=5, now=1000)
    by = {(r["src"], r["dst"]): r for r in rows}
    check("grade: unreachable lateral edge dropped", ("x", "y") not in by)
    check("grade: hop 1 from E", by[("E", "a")]["hop"] == 1 and by[("E", "a")]["hops"] == ["E:1"])
    check("grade: b is hop 2 from E and hop 1 from J",
          sorted(by[("a", "b")]["hops"]) == ["E:2"] and by[("J", "b")]["hops"] == ["J:1"], by[("a", "b")]["hops"])
    check("grade: c has entries E and J through b",
          sorted(by[("b", "c")]["entries"]) == ["E", "J"] and sorted(by[("b", "c")]["hops"]) == ["E:3", "J:2"])
    check("grade: CVE-only reach stops at the permitted jump",
          sorted(by[("b", "c")]["dst_reach"]) == ["E", "J"] and by[("b", "d")]["dst_reach"] == []
          and by[("d", "e")]["dst_reach"] == [])
    check("grade: a foothold jump is not reach", by[("a", "f")]["dst_reach"] == [])
    check("grade: walked_at and key", by[("E", "a")]["walked_at"] == 1000 and by[("E", "a")]["_key"] == "E|a")
    check("grade: sorted by hop then rank", [r["hop"] for r in rows] == sorted(r["hop"] for r in rows))
    short = walk.grade(ROWS, max_hops=2)
    check("grade: max_hops bounds the walk", ("b", "c") in {(r["src"], r["dst"]) for r in short}
          and ("d", "e") not in {(r["src"], r["dst"]) for r in short})


def test_paths():
    graded = walk.grade(ROWS)
    rows = walk.paths(graded, max_hops=5, max_paths=100, beyond_break=1)
    texts = [r["path_text"] for r in rows]
    check("paths: worst first is the full CVE chain",
          texts[0] == "E → a → b → c" and rows[0]["full_cve"] == 1 and rows[0]["flags"] == "CCC", texts[:3])
    stop = [r for r in rows if r["path_text"] == "E → a → b → d"][0]
    check("paths: the stop names the first non-CVE jump",
          stop["cve_run"] == 2 and stop["stop_text"].startswith("b → d: permitted flow only"), stop["stop_text"])
    check("paths: one jump past the break is listed, not two",
          "E → a → b → d → e" in texts, texts)
    deeper = walk.paths(graded, max_hops=5, max_paths=100, beyond_break=0)
    check("paths: beyond_break=0 stops at the break",
          "E → a → b → d → e" not in [r["path_text"] for r in deeper])
    check("paths: each_jump has one sentence per jump and the CVEs",
          len(stop["each_jump"]) == 3 and "CVE-1" in stop["each_jump"][0])
    check("paths: no path revisits a host", all(len(set(t.split(" → "))) == len(t.split(" → ")) for t in texts))
    capped = walk.paths(graded, max_paths=2)
    check("paths: the cap keeps the worst and says truncated",
          len(capped) == 2 and capped[0]["full_cve"] == 1 and all(r["truncated"] == 1 for r in capped))
    tiny = walk.paths(graded, budget=1000)
    check("paths: within budget is not truncated", all(r["truncated"] == 0 for r in tiny))


def test_view():
    graded = walk.grade(ROWS)
    rows = walk.view(graded, entry="*", host="*", top=0)
    pairs = {(r["src"], r["dst"]) for r in rows}
    check("view: everything reachable, nothing else", ("x", "y") not in pairs and ("d", "e") in pairs)
    back = [r for r in rows if r["src"] == "d" and r["dst"] == "e"][0]
    # d sits at depth 2 (J -> b -> d), so the edge out of it is hop 3.
    check("view: an edge's hop is one past its source's depth", back["hop"] == 3 and back["src_hop"] == 2, back["hop"])
    check("view: whole session counts come back as ints", isinstance(rows[0]["sessions"], int))
    ea = [r for r in rows if r["src"] == "E" and r["dst"] == "a"][0]
    check("view: every port of a jump comes back, best first", ea["ports"] == "443,8080" and ea["port"] == "443", ea["ports"])
    again = walk.view(walk.grade(ROWS), top=0)
    ea2 = [r for r in again if r["src"] == "E" and r["dst"] == "a"][0]
    check("view: re-merging graded rows keeps the port list and the session total",
          ea2["ports"] == "443,8080" and ea2["n_ports"] == 2 and ea2["sessions"] == 505, (ea2["ports"], ea2["sessions"]))
    marks = {r["dst"]: r["dst_mark"] for r in rows}
    check("view: reach marks c but not d or e", marks["c"] == "reach" and marks["d"] == "" and marks["e"] == "")
    only = walk.view(graded, entry="J", top=0)
    opairs = {(r["src"], r["dst"]) for r in only}
    check("view: entry filter re-walks from that entry",
          ("E", "a") not in opairs and ("J", "b") in opairs and [r for r in only if r["dst"] == "c"][0]["hop"] == 2)
    cve = walk.view(graded, classes=["cve"], top=0)
    cpairs = {(r["src"], r["dst"]) for r in cve}
    check("view: class filter drops the permitted jump and what only it led to",
          ("b", "d") not in cpairs and ("d", "e") not in cpairs and ("b", "c") in cpairs)
    focus = walk.view(graded, host="d", top=0)
    fpairs = {(r["src"], r["dst"]) for r in focus}
    check("view: host focus keeps ancestors, the host and descendants",
          fpairs == {("E", "a"), ("a", "b"), ("J", "b"), ("b", "d"), ("d", "e")}, fpairs)
    # From E alone: hop 1 is a; hop 2 is b over f; hop 3 is c over d, so d and
    # what only d led to, e, fall away. (With J as well, b is a hop 1 host and
    # competes with a there; the cap is per hop, not per path.)
    capped = walk.view(graded, entry="E", top=1)
    kpairs = {(r["src"], r["dst"]) for r in capped}
    check("view: top keeps the best host per hop and cascades",
          kpairs == {("E", "a"), ("a", "b"), ("b", "c")}, kpairs)
    check("view: counters say what was hidden",
          capped[0]["rk_total_hosts"] == 6 and capped[0]["rk_shown_hosts"] == 3 and capped[0]["rk_hidden_hosts"] == 3,
          (capped[0]["rk_total_hosts"], capped[0]["rk_shown_hosts"]))


if __name__ == "__main__":
    for fn in (test_merge, test_grade, test_paths, test_view):
        print(fn.__name__)
        fn()
    if FAILURES:
        print("\n%d failing" % len(FAILURES))
        sys.exit(1)
    print("\nAll checks passed.")
