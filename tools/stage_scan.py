#!/usr/bin/env python3
"""Stage one swinv scan into the forwarder's watch directory, stamped as now.

Why re-stamp rather than copy the fixture verbatim: every checked-in scan in
testdata/ndjson carries the wall-clock time it was captured at, and TIME_PREFIX
in TA-riskability makes that value the event's _time. The pipeline's searches
are bounded -- the matcher dispatches over -24h, the fold-in over -90m -- so a
fixture more than a day old is invisible to the very searches this test exists
to exercise, and every stage would report zero findings while nothing is
actually broken. Re-stamping is what makes the fixture look like a scan that
just landed, which is the only state the app is designed to see.

Only scanned_at changes. Component names, versions, paths and CPEs are the
sanitised fixture's, byte for byte, so what is matched is exactly what was
captured.

The file is written under a .partial name and renamed into place, because the
add-on monitors /var/lib/swinv/*.ndjson and would otherwise start reading a
half-written scan and stitch two runs together.

    tools/stage_scan.py SRC DEST [--at EPOCH]

prints the number of records written.
"""

from __future__ import annotations

import argparse
import json
import os
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src", help="fixture to read")
    ap.add_argument("dest", help="path to write, inside the forwarder's watch directory")
    ap.add_argument("--at", type=int, default=None,
                    help="epoch seconds to stamp every record with (default: now)")
    args = ap.parse_args()

    at = args.at if args.at is not None else int(time.time())
    # No fractional seconds. TA-riskability's TIME_FORMAT is %Y-%m-%dT%H:%M:%S%Z
    # with a 32-character lookahead, and the collector's own output has none.
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))

    tmp = args.dest + ".partial"
    written = 0
    with open(args.src, "r", encoding="utf-8") as fin, \
            open(tmp, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if "scanned_at" in rec:
                rec["scanned_at"] = stamp
            fout.write(json.dumps(rec, separators=(",", ":")) + "\n")
            written += 1
    os.replace(tmp, args.dest)
    print(written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
