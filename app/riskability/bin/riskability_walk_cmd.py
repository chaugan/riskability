"""``riskabilitywalk`` - position every observed jump, list the paths, trim a view.

Usage in SPL::

    | `riskability_route_edges` | riskabilitywalk mode=grade
    | inputlookup riskability_routeedges_lookup | riskabilitywalk mode=paths max_paths=2000
    | inputlookup riskability_routeedges_lookup
      | riskabilitywalk mode=view entry="10.0.45.0/24" host="*" top=25 classes="cve,foothold"

Why this is a command and not SPL. The routes page used to walk the graph in
its own search, one eventstats per hop and an mvfind per edge, which is edges
times hosts per hop on every page load. Fine on fifteen hosts, minutes on
five thousand, and silently capped by limits.conf before that. The walk is a
breadth first search and belongs in a language that has one.

Why it buffers. A walk needs the whole graph, and the chunked protocol hands
a command its input in pieces. Every chunk is kept and nothing is emitted
until the SDK marks the last one; the logic itself is in
``riskability.walk`` so it runs under ``tools/test_walk.py`` without Splunk.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch  # noqa: E402
from splunklib.searchcommands.validators import Integer  # noqa: E402
from riskability import walk  # noqa: E402

MODES = ("grade", "paths", "view")


@Configuration()
class RiskabilityWalkCommand(EventingCommand):
    mode = Option(require=False, default="grade",
                  doc="grade (position edges, hourly job), paths (enumerate paths, hourly job) "
                      "or view (trim for one page load).")
    max_hops = Option(require=False, default=walk.DEFAULT_MAX_HOPS, validate=Integer(1, 10),
                      doc="How many jumps out from an entry point the walk goes.")
    max_paths = Option(require=False, default=2000, validate=Integer(1, 100000),
                       doc="paths: at most this many paths, worst first.")
    beyond_break = Option(require=False, default=1, validate=Integer(0, 10),
                          doc="paths: jumps to keep following after the first that is not CVE-enabled.")
    fanout = Option(require=False, default=8, validate=Integer(1, 1000),
                    doc="paths: onward edges followed per host, best first.")
    budget = Option(require=False, default=200000, validate=Integer(1000, 50000000),
                    doc="paths: hard ceiling on expansions; rows say truncated=1 when it was hit.")
    entry = Option(require=False, default="*", doc="view: keep edges walked from this entry point, or *.")
    host = Option(require=False, default="*", doc="view: keep the chains through this host, or *.")
    top = Option(require=False, default=25, validate=Integer(0, 10000),
                 doc="view: hosts per hop at most, 0 for no cap.")
    classes = Option(require=False, default="",
                     doc="view: comma separated classes to keep (cve, foothold, unrated, permitted); empty or all keeps all.")

    def __init__(self):
        super().__init__()
        self._buffer = []

    def transform(self, records):
        self._buffer.extend(records)
        if not self._finished:
            return
        rows = self._buffer
        self._buffer = []
        mode = (self.mode or "grade").strip().lower()
        if mode not in MODES:
            self.error_exit(ValueError(mode), "mode must be one of %s" % ", ".join(MODES))
            return
        try:
            if mode == "grade":
                out = walk.grade(rows, max_hops=int(self.max_hops))
            elif mode == "paths":
                out = walk.paths(rows, max_hops=int(self.max_hops), max_paths=int(self.max_paths),
                                 beyond_break=int(self.beyond_break), fanout=int(self.fanout),
                                 budget=int(self.budget))
            else:
                # "all" and "" both mean no class filter; a dropdown cannot
                # carry an empty value through a URL, so the page sends "all".
                classes = [c.strip().lower() for c in str(self.classes or "").split(",") if c.strip()]
                if "all" in classes:
                    classes = []
                out = walk.view(rows, entry=str(self.entry or "*"), host=str(self.host or "*"),
                                top=int(self.top), classes=classes, max_hops=int(self.max_hops))
        except Exception as exc:  # the walk failing must be visible, not an empty graph
            self.error_exit(exc, "riskabilitywalk %s failed: %s" % (mode, exc))
            return
        for row in out:
            yield row


dispatch(RiskabilityWalkCommand, sys.argv, sys.stdin, sys.stdout, __name__)
