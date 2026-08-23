#!/usr/bin/env python
"""``riskabilityvercmp`` - compare two versions the way the matcher would.

Usage in SPL::

    | riskabilityvercmp ecosystem=deb a="1.1.1f-1ubuntu2.16" b="1.1.1f-1ubuntu2.20"
    | riskabilityvercmp ecosystem=npm a=1.2.3 b=1.10.0

Why this exists. "Is 1.1.1f-1ubuntu2.16 older than 1.1.1f-1ubuntu2.20" is the
single question every finding in this app rests on, and it is not a question
SPL can answer -- dpkg, RPM, apk, semver, PEP 440, Maven and Go all order
versions differently, and the differences are exactly where a false negative
hides. When somebody disputes a finding, or wonders why a package they think is
patched is still listed, this puts the matcher's own comparator in the search
bar so the reasoning can be checked directly rather than argued about.

It answers with the comparison AND with whether the ecosystem was recognised
and whether each version actually parsed under that ecosystem's rules, because
"these compared equal" and "neither of these could be parsed so they fell back
to a generic comparison" look identical if you only print the verdict.

Generating command: it takes literal arguments and produces one row. It reads
no index and no KV Store, so it costs nothing and cannot be affected by the
state of the feed.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch  # noqa: E402
from splunklib.searchcommands.validators import Boolean  # noqa: E402

from riskability import vercmp  # noqa: E402


@Configuration()
class RiskabilityVerCmpCommand(GeneratingCommand):

    ecosystem = Option(require=True, doc="Ecosystem or package type, e.g. deb, npm, python.")
    a = Option(require=True, doc="First version.")
    b = Option(require=True, doc="Second version.")
    strict = Option(require=False, validate=Boolean(),
                    doc="Fail on an unknown ecosystem instead of falling back to a generic "
                        "comparison. Defaults to false, which is what the matcher does.")

    def generate(self):
        eco = (self.ecosystem or "").strip()
        va, vb = str(self.a), str(self.b)

        known = True
        try:
            vercmp.comparator_for(eco)
        except vercmp.UnknownEcosystem:
            known = False

        row = {
            "_time": None,
            "_raw": "",
            "ecosystem": eco,
            "ecosystem_known": "yes" if known else "no",
            "a": va,
            "b": vb,
            "a_parses": "yes" if vercmp.parses(eco, va) else "no",
            "b_parses": "yes" if vercmp.parses(eco, vb) else "no",
        }

        try:
            result = vercmp.compare(eco, va, vb, strict=bool(self.strict))
        except vercmp.UnknownEcosystem as exc:
            row["error"] = f"unknown ecosystem {exc}"
            row["_raw"] = row["error"]
            yield row
            return
        except Exception as exc:  # a comparator raising is itself the answer
            row["error"] = f"{type(exc).__name__}: {exc}"
            row["_raw"] = row["error"]
            yield row
            return

        row["result"] = result
        row["ordering"] = "a < b" if result < 0 else ("a > b" if result > 0 else "a == b")
        row["comparator"] = "generic (ecosystem not recognised)" if not known else eco
        row["_raw"] = f"{va} {'<' if result < 0 else ('>' if result > 0 else '==')} {vb}"
        yield row


dispatch(RiskabilityVerCmpCommand, sys.argv, sys.stdin, sys.stdout, __name__)
