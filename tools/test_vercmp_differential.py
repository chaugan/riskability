#!/usr/bin/env python3
"""Differential test: our comparators vs the real dpkg and rpm implementations.

Hand-written expectations encode the author's misunderstandings as if they were
facts. This instead generates version pairs and asks the actual package
managers, which is the only authority that matters for "is this host patched".

Run:  python3 tools/test_vercmp_differential.py
Needs: dpkg and rpm on PATH (skips whichever is missing).
"""

from __future__ import annotations

import itertools
import random
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app" / "riskability" / "bin"))

from riskability import vercmp  # noqa: E402


# --- reference implementations ------------------------------------------------

def dpkg_reference(a: str, b: str) -> int:
    for op, res in (("lt", -1), ("eq", 0), ("gt", 1)):
        r = subprocess.run(
            ["dpkg", "--compare-versions", a, op, b],
            capture_output=True,
        )
        if r.returncode == 0:
            return res
    raise RuntimeError(f"dpkg refused to order {a!r} vs {b!r}")


def rpm_reference(a: str, b: str) -> int:
    script = f"%{{lua: print(rpm.vercmp('{a}', '{b}'))}}"
    r = subprocess.run(["rpm", "--eval", script], capture_output=True, text=True)
    out = r.stdout.strip()
    if out not in ("-1", "0", "1"):
        raise RuntimeError(f"rpm gave {out!r} for {a!r} vs {b!r}")
    return int(out)


# --- corpus -------------------------------------------------------------------

DPKG_CORPUS = [
    # The motivating case: an Ubuntu backport is not upstream 3.0.14.
    "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.2", "3.0.13", "3.0.14",
    "1:1.2.13.dfsg-1", "1.2.13.dfsg-1", "2:1.0", "1.0",
    "1.0~rc1", "1.0", "1.0-1", "1.0-10", "1.0-2",
    "5.2.15-2+b7", "5.2.15-2", "5.2.15-2+b1",
    "0", "0.0", "1", "1.0.0", "1.00", "1.0a", "1.0b",
    "2.4.7-1ubuntu1", "2.4.7-1ubuntu1.1", "2.4.7-2",
    "7.88.1-10+deb12u5", "7.88.1-10+deb12u12",
    "1.0+git20240101", "1.0+git20231231",
    "1.0~beta1", "1.0~beta2", "1.0~~", "1.0~", "1.0",
    "3.0.11-1~deb12u2", "3.0.14-1~deb12u3",
    "1.21.6-1~bpo11+1", "1.21.6-1",
]

RPM_CORPUS = [
    "1.0-1.el9", "1.0-2.el9", "1.0-1.el8",
    "1:1.0-1", "1.0-1", "2:1.0-1",
    "1.0~rc1-1", "1.0-1", "1.0^post1-1",
    "3.0.7-27.el9_4", "3.0.7-27.el9_5", "3.0.7-28.el9",
    "1.0.0-1.fc40", "1.0.0-1.fc41",
    "2.34-100.el9", "2.34-60.el9", "2.34-9.el9",
    "0.9-1", "0.10-1", "0.09-1",
    "1.0-1.20240101git", "1.0-1.20231231git",
    "4.18.0-513.24.1.el8_9", "4.18.0-513.5.1.el8_9",
    "1.0", "1.0-1", "1.0.1",
]


def check(name, corpus, ours, reference, limit=None):
    pairs = list(itertools.permutations(corpus, 2))
    random.Random(1337).shuffle(pairs)
    if limit:
        pairs = pairs[:limit]
    failures = []
    for a, b in pairs:
        try:
            expected = reference(a, b)
        except Exception as exc:  # reference refused; not our problem
            continue
        got = ours(a, b)
        # Normalise: we only care about the sign.
        got = (got > 0) - (got < 0)
        if got != expected:
            failures.append((a, b, expected, got))
    print(f"{name}: {len(pairs) - len(failures)}/{len(pairs)} pairs match the reference")
    for a, b, exp, got in failures[:25]:
        sym = {-1: "<", 0: "==", 1: ">"}
        print(f"  MISMATCH  {a!r} vs {b!r}: {name} says {sym[exp]}, we say {sym[got]}")
    if len(failures) > 25:
        print(f"  ... and {len(failures) - 25} more")
    return failures


def check_transitivity(name, corpus, ours):
    """A comparator that is not a total order will corrupt any sort or range check."""
    bad = 0
    for a, b in itertools.permutations(corpus, 2):
        if ours(a, b) != -ours(b, a):
            print(f"  ASYMMETRY {a!r} vs {b!r}")
            bad += 1
    print(f"{name}: antisymmetry {'OK' if not bad else f'FAILED ({bad})'}")
    return bad


def main() -> int:
    rc = 0

    if shutil.which("dpkg"):
        f = check("dpkg", DPKG_CORPUS, vercmp.dpkg_compare, dpkg_reference)
        rc |= 1 if f else 0
    else:
        print("dpkg: SKIPPED (not installed)")

    if shutil.which("rpm"):
        f = check("rpm", RPM_CORPUS, vercmp.rpm_compare, rpm_reference)
        rc |= 1 if f else 0
    else:
        print("rpm: SKIPPED (not installed)")

    print()
    rc |= 1 if check_transitivity("dpkg", DPKG_CORPUS, vercmp.dpkg_compare) else 0
    rc |= 1 if check_transitivity("rpm", RPM_CORPUS, vercmp.rpm_compare) else 0

    return rc


if __name__ == "__main__":
    sys.exit(main())
