#!/usr/bin/env python3
"""Spec-derived tests for ecosystems with no reference binary on this machine.

Cases are taken from the ecosystems' own specifications and ordering docs
(SemVer 2.0 §11, PEP 440, Alpine apk version ordering, Maven ComparableVersion,
Go module versioning), not from what the implementation happens to do.

Run:  python3 tools/test_vercmp_spec.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app" / "riskability" / "bin"))

from riskability import vercmp  # noqa: E402

SYM = {-1: "<", 0: "==", 1: ">"}


def sign(n: int) -> int:
    return (n > 0) - (n < 0)


CASES = [
    # (comparator, a, expected, b)
    # --- SemVer 2.0 §11 precedence -----------------------------------------
    (vercmp.semver_compare, "1.0.0", "<", "2.0.0"),
    (vercmp.semver_compare, "2.0.0", "<", "2.1.0"),
    (vercmp.semver_compare, "2.1.0", "<", "2.1.1"),
    (vercmp.semver_compare, "1.0.0-alpha", "<", "1.0.0"),
    (vercmp.semver_compare, "1.0.0-alpha", "<", "1.0.0-alpha.1"),
    (vercmp.semver_compare, "1.0.0-alpha.1", "<", "1.0.0-alpha.beta"),
    (vercmp.semver_compare, "1.0.0-alpha.beta", "<", "1.0.0-beta"),
    (vercmp.semver_compare, "1.0.0-beta", "<", "1.0.0-beta.2"),
    (vercmp.semver_compare, "1.0.0-beta.2", "<", "1.0.0-beta.11"),
    (vercmp.semver_compare, "1.0.0-beta.11", "<", "1.0.0-rc.1"),
    (vercmp.semver_compare, "1.0.0-rc.1", "<", "1.0.0"),
    # Build metadata is ignored for precedence.
    (vercmp.semver_compare, "1.0.0+build1", "==", "1.0.0+build2"),
    # The classic numeric-vs-lexical trap.
    (vercmp.semver_compare, "1.9.0", "<", "1.10.0"),
    (vercmp.semver_compare, "4.17.20", "<", "4.17.21"),

    # --- PEP 440 ------------------------------------------------------------
    (vercmp.pep440_compare, "1.0.dev1", "<", "1.0a1"),
    (vercmp.pep440_compare, "1.0a1", "<", "1.0b1"),
    (vercmp.pep440_compare, "1.0b1", "<", "1.0rc1"),
    (vercmp.pep440_compare, "1.0rc1", "<", "1.0"),
    (vercmp.pep440_compare, "1.0", "<", "1.0.post1"),
    (vercmp.pep440_compare, "1.0", "==", "1.0.0"),
    (vercmp.pep440_compare, "1.0", "<", "1!0.1"),          # epoch wins
    (vercmp.pep440_compare, "1.0c1", "==", "1.0rc1"),      # c is an alias for rc
    (vercmp.pep440_compare, "2.25.1", "<", "2.26.0"),
    (vercmp.pep440_compare, "1.0.9", "<", "1.0.10"),
    (vercmp.pep440_compare, "1.0alpha1", "==", "1.0a1"),

    # --- Alpine apk ---------------------------------------------------------
    (vercmp.apk_compare, "1.0", "<", "1.1"),
    (vercmp.apk_compare, "1.0", "<", "1.0.1"),
    (vercmp.apk_compare, "1.0", "<", "1.0a"),
    (vercmp.apk_compare, "1.0_alpha1", "<", "1.0"),
    (vercmp.apk_compare, "1.0_alpha1", "<", "1.0_beta1"),
    (vercmp.apk_compare, "1.0_beta1", "<", "1.0_rc1"),
    (vercmp.apk_compare, "1.0_rc1", "<", "1.0"),
    (vercmp.apk_compare, "1.0", "<", "1.0_p1"),            # _p is a post-release
    (vercmp.apk_compare, "1.0-r0", "<", "1.0-r1"),
    (vercmp.apk_compare, "1.0-r1", "<", "1.0.1-r0"),
    (vercmp.apk_compare, "1.9", "<", "1.10"),

    # --- Maven --------------------------------------------------------------
    (vercmp.maven_compare, "1.0-alpha", "<", "1.0-beta"),
    (vercmp.maven_compare, "1.0-beta", "<", "1.0-milestone"),
    (vercmp.maven_compare, "1.0-milestone", "<", "1.0-rc"),
    (vercmp.maven_compare, "1.0-rc", "<", "1.0-snapshot"),
    (vercmp.maven_compare, "1.0-snapshot", "<", "1.0"),
    (vercmp.maven_compare, "1.0", "<", "1.0-sp"),
    (vercmp.maven_compare, "1.0", "==", "1.0.0"),
    (vercmp.maven_compare, "1.0", "<", "1.1"),
    (vercmp.maven_compare, "2.9", "<", "2.10"),
    (vercmp.maven_compare, "1.0-ga", "==", "1.0"),

    # --- Go modules ---------------------------------------------------------
    (vercmp.go_compare, "v1.0.0", "<", "v1.0.1"),
    (vercmp.go_compare, "v1.0.0-rc1", "<", "v1.0.0"),
    (vercmp.go_compare, "v0.3.6", "<", "v0.3.7"),
    (vercmp.go_compare, "v2.0.0+incompatible", ">", "v1.9.9"),
    # A pseudo-version precedes the release it anticipates.
    (vercmp.go_compare, "v1.2.3-0.20240101000000-abcdef123456", "<", "v1.2.3"),
    (vercmp.go_compare, "v1.9.0", "<", "v1.10.0"),
    # --- RPM: an empty release is not an absent one ----------------------------
    # Verified against rpm 6.0.1: absent < "" < any non-empty release.
    (vercmp.rpm_compare, "1.0", "<", "1.0-"),
    (vercmp.rpm_compare, "1.0-", "<", "1.0-0"),
    (vercmp.rpm_compare, "1.0-", "<", "1.0-1"),
    (vercmp.rpm_compare, "1.0-", "==", "1.0-"),
    (vercmp.rpm_compare, "1:1.0", "<", "1:1.0-"),
    # The half-open range check is installed < fixed, so collapsing these two
    # reported an installed version rpm considers BELOW the fix as not
    # vulnerable. It failed toward silence.
    (vercmp.rpm_compare, "1.0", "<", "1.0-1"),

]


def main() -> int:
    failures = []
    for fn, a, expected, b in CASES:
        got = sign(fn(a, b))
        want = {"<": -1, "==": 0, ">": 1}[expected]
        if got != want:
            failures.append((fn.__name__, a, expected, b, SYM[got]))

    passed = len(CASES) - len(failures)
    print(f"spec cases: {passed}/{len(CASES)} passed")
    for name, a, expected, b, got in failures:
        print(f"  FAIL {name}: expected {a!r} {expected} {b!r}, got {got}")

    # Antisymmetry across every comparator: a sort or bisect over a comparator
    # that is not a total order silently produces wrong ranges.
    corpora = {
        vercmp.semver_compare: ["1.0.0", "1.0.0-alpha", "1.0.0-beta.2", "1.10.0", "1.9.0", "2.0.0"],
        vercmp.pep440_compare: ["1.0.dev1", "1.0a1", "1.0rc1", "1.0", "1.0.post1", "1!0.1"],
        vercmp.apk_compare: ["1.0_alpha1", "1.0_rc1", "1.0", "1.0-r1", "1.0.1", "1.0_p1"],
        vercmp.maven_compare: ["1.0-alpha", "1.0-rc", "1.0", "1.0-sp", "1.1", "2.10"],
        vercmp.go_compare: ["v1.0.0-rc1", "v1.0.0", "v1.9.0", "v1.10.0", "v2.0.0+incompatible"],
    }
    asym = 0
    for fn, corpus in corpora.items():
        for a in corpus:
            for b in corpus:
                if sign(fn(a, b)) != -sign(fn(b, a)):
                    print(f"  ASYMMETRY {fn.__name__}: {a!r} vs {b!r}")
                    asym += 1
    print(f"antisymmetry: {'OK' if not asym else f'FAILED ({asym})'}")

    return 1 if (failures or asym) else 0


if __name__ == "__main__":
    sys.exit(main())
