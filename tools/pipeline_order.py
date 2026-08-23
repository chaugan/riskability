#!/usr/bin/env python3
"""Print the app's scheduled searches in the order the scheduler would run them.

The order is not decoration. Closing a finding is gated on evidence that the
matcher's output actually reached the state collection, and that evidence is
produced by four different searches at four different minutes past the hour:
materialise at :17, the inventory snapshots at :19 and :20, the fold-in at :25,
the acknowledgement at :26, and only then close at :27. Dispatching those in any
other order produces a pipeline that either does nothing or -- worse -- closes
findings that are still present. So the harness reads the real cron_schedule
values out of the shipped conf file rather than carrying its own list, which
would go stale the moment a search moves.

Searches with enableSched = 0 are omitted, because the scheduler omits them.

    tools/pipeline_order.py [path/to/savedsearches.conf]

prints one saved-search name per line.
"""

from __future__ import annotations

import os
import sys


def parse(path: str) -> list:
    """Read stanza names, enableSched and cron_schedule out of savedsearches.conf.

    Hand-rolled rather than configparser: Splunk continues a value with a
    trailing backslash and the continuation lines here start in column zero,
    which configparser reads as malformed rather than as a continuation. Those
    lines are SPL, and plenty of them contain both "=" and "[", so they have to
    be skipped outright rather than parsed and discarded.
    """
    stanza = None
    sched: dict = {}
    cron: dict = {}
    continuing = False
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n").rstrip()
            if continuing:
                continuing = line.endswith("\\")
                continue
            if line.startswith("[") and line.endswith("]"):
                stanza = line[1:-1]
                continue
            if line.endswith("\\"):
                continuing = True
            if stanza and "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().rstrip("\\").strip()
                if key == "enableSched":
                    sched[stanza] = value
                elif key == "cron_schedule":
                    cron[stanza] = value
    return [(name, cron[name]) for name in cron
            if sched.get(name, "0") == "1"]


def sort_key(entry):
    name, schedule = entry
    fields = schedule.split()
    minute = fields[0] if fields else "0"
    hour = fields[1] if len(fields) > 1 else "*"

    def num(token, wildcard):
        token = token.split("/")[0].split(",")[0].split("-")[0]
        return int(token) if token.isdigit() else wildcard

    # An hourly search has hour "*", which sorts before a search pinned to one
    # hour of the day: within a single simulated hour the hourly ones are the
    # pipeline and the daily ones are alerts reading what it produced.
    return (num(minute, 0), num(hour, -1), name)


def main() -> int:
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "app", "riskability", "default", "savedsearches.conf")
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.normpath(default)
    entries = sorted(parse(path), key=sort_key)
    if not entries:
        print(f"no scheduled searches found in {path}", file=sys.stderr)
        return 1
    for name, _ in entries:
        print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
