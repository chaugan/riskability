#!/usr/bin/env python3
"""Every flag the shipped wrappers pass must exist in the shipped tool.

There are three argument parsers in this repository that all present themselves
as "riskability-feed": tools/riskability-feed, the one build.py drives for the
admin page, and a third written inline by make-feedbuilder.sh into the zipapp.
The third is the one users actually run, and it is the easiest to forget.

--cve-list was added to the first two and not the third, so build-feed.sh passed
a flag the tool it invokes had never heard of. The wrapper was checked, the tool
was not, and the failure surfaced on a user's machine as:

    riskability-feed: error: unrecognized arguments: --cve-list

This compares the two halves directly, against the built artefact rather than
the sources, because the artefact is what ships.
"""
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ZIP = Path("app/riskability/appserver/static/scripts/riskability-feedbuilder.zip")


def main():
    if not ZIP.exists():
        print(f"  BAD   {ZIP} has not been built", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as d:
        with zipfile.ZipFile(ZIP) as z:
            z.extractall(d)
        pyz = Path(d) / "riskability-feed.pyz"
        if not pyz.exists():
            print("  BAD   the archive carries no riskability-feed.pyz", file=sys.stderr)
            return 1
        try:
            helptext = subprocess.run(
                [sys.executable, str(pyz), "build", "--help"],
                capture_output=True, text=True, timeout=120).stdout
        except Exception as exc:
            print(f"  BAD   could not run the shipped tool: {exc}", file=sys.stderr)
            return 1

        wanted = set()
        for name in ("build-feed.sh", "build-feed.ps1"):
            p = Path(d) / name
            if not p.exists():
                continue
            body = p.read_text(encoding="utf-8", errors="replace")
            # Long options only. Short ones are too easy to confuse with text.
            for m in re.finditer(r"--[a-z][a-z0-9-]+", body):
                flag = m.group(0)
                # The wrappers take options of their own that they never forward.
                if flag in ("--help", "--windows", "--everything", "--with-cve-list"):
                    continue
                wanted.add(flag)

        # Whole flags, not substrings. "--cve-list" occurs inside
        # "--cve-list-file", so a plain containment test reported a missing
        # flag as present whenever a longer one shared its prefix. That is the
        # same class of false pass this script exists to prevent, and it got in
        # here first.
        def advertised(flag):
            return re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", helptext) is not None

        missing = sorted(f for f in wanted if not advertised(f))
        if missing:
            for f in missing:
                print(f"  BAD   the wrappers pass {f}, which the shipped tool does not accept",
                      file=sys.stderr)
            return 1
        print(f"  ok    {len(wanted)} wrapper flags all accepted by the shipped tool")
    return 0


if __name__ == "__main__":
    sys.exit(main())
