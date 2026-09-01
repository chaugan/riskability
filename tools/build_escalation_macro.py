#!/usr/bin/env python3
"""Regenerate the compiled escalation macro from the rule file.

    python3 tools/build_escalation_macro.py [--check]

The rules live in default/riskability_escalations.conf as predicates a person
edits. The saved search cannot read a conf file mid-pipeline, so the rules are
compiled once into the riskability_escalation_rules macro, which the search
expands. This script is the compiler, and tools/test_escalations.py fails if
the macro and the rules disagree.

Why a generated macro rather than SPL written by hand into the saved search:
the rules are site data. An operator enables one by editing a conf file, and
the search that evaluates them must not have to be edited for that to take
effect. Why generated rather than stamped at runtime by an endpoint: the
compiled form is reviewable in the repository, diffs when a rule changes, and
cannot silently differ between two search heads.
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app", "riskability", "bin"))

from riskability import escalate  # noqa: E402

RULES = os.path.join(ROOT, "app", "riskability", "default", "riskability_escalations.conf")
MACROS = os.path.join(ROOT, "app", "riskability", "default", "macros.conf")
STANZA = "[riskability_escalation_rules]"


def compiled() -> str:
    rules, _problems = escalate.load_rules(open(RULES, encoding="utf-8").read())
    return escalate.to_spl(rules)


def current() -> str:
    text = open(MACROS, encoding="utf-8").read()
    i = text.index(STANZA)
    block = text[i:]
    m = re.search(r"^definition = (.*?)^iseval", block, re.S | re.M)
    if not m:
        raise SystemExit("could not read the definition out of %s" % STANZA)
    # conf continuations: a trailing backslash joins the next line
    return m.group(1).rstrip().replace("\\\n", "\n").rstrip()


def main() -> int:
    want = compiled()
    have = current()
    if want == have:
        print("up to date")
        return 0
    if "--check" in sys.argv:
        print("STALE. macros.conf holds:\n  %s\nthe rules compile to:\n  %s"
              % (have.replace("\n", "\n  "), want.replace("\n", "\n  ")))
        return 1
    text = open(MACROS, encoding="utf-8").read()
    i = text.index(STANZA)
    block = text[i:]
    body = "\\\n".join(want.split("\n"))
    block = re.sub(r"^definition = .*?^iseval", "definition = %s\niseval" % body,
                   block, count=1, flags=re.S | re.M)
    open(MACROS, "w", encoding="utf-8").write(text[:i] + block)
    print("regenerated:\n  %s" % want.replace("\n", "\n  "))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
