#!/usr/bin/env python3
"""Parse .conf files the strict way the Splunk Packaging Toolkit does.

Splunk's own runtime parser is forgiving: a continuation line that lost its
trailing backslash is quietly absorbed, the app loads, every dashboard works,
and nothing anywhere says a word. The Packaging Toolkit is not forgiving, and
refuses the submission with "Expected a setting assignment" - which is the
first time anybody finds out, after the upload.

That is exactly what happened to a description in savedsearches.conf: one line
in the middle of a sixteen-line comment block ended without its backslash, so
the next line stopped being part of the value and started looking like a
setting with no "=" in it.

  tools/conf_lint.py app/riskability/default/*.conf
  tools/conf_lint.py            # every conf under app/
"""
import glob
import os
import re
import sys

STANZA = re.compile(r"^\[[^\]]*\]\s*$")


def continues(line):
    """True when this line continues onto the next.

    Only an ODD number of trailing backslashes continues: "foo \\\\" is a value
    ending in a literal backslash, not a continuation.
    """
    m = re.search(r"(\\+)$", line)
    return bool(m) and len(m.group(1)) % 2 == 1


def lint(path):
    bad = []
    in_continuation = False
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.rstrip("\n").rstrip("\r")
            if in_continuation:
                # A conf value continued with a backslash swallows everything
                # that follows, including a line that looks like a comment. SPL
                # has no "#" comment, so such a line becomes part of the search
                # and, worse, ends the value if it carries no continuation of
                # its own: the rest of the query is silently dropped. Splunk
                # accepts the file and the search is wrong.
                if line.strip().startswith("#"):
                    bad.append((n, "comment inside a continued value: "
                                   + line.strip()[:60]))
                in_continuation = continues(line)
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if STANZA.match(stripped):
                continue
            if "=" in line.split("#", 1)[0]:
                in_continuation = continues(line)
                continue
            bad.append((n, stripped[:88]))
    return bad


def main(argv):
    paths = argv[1:]
    if not paths:
        paths = sorted(glob.glob("app/*/default/*.conf")) + \
                sorted(glob.glob("app/*/local/*.conf")) + \
                sorted(glob.glob("app/*/metadata/*.meta"))
    fail = 0
    for p in paths:
        if not os.path.isfile(p):
            continue
        bad = lint(p)
        if bad:
            fail = 1
            for n, text in bad:
                print(f"  BAD   {p}:{n}: expected a setting assignment, got: {text}")
        else:
            print(f"  ok    {p}")
    return fail


if __name__ == "__main__":
    sys.exit(main(sys.argv))
