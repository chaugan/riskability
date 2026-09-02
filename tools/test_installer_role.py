#!/usr/bin/env python3
"""swinv's installer test table, run against the regexes that actually ship.

riskability_component_role in macros.conf is a port of swinv's classifyRole
(internal/wincollect/installer.go): the same four regular expressions, in the
same order, on the same fields. This test does not trust that claim. It reads
the regex literals OUT OF macros.conf, rebuilds the decision in Python, and
runs swinv's own table through it, including every case that must NOT trip.

Two copies of a rule is a promise to keep them equal. This is what makes the
promise checkable, and it fails in the direction that matters: the day someone
"improves" the file name rule here and starts matching a portable exe, the
portable-tool case in the table goes red.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "app" / "riskability" / "default" / "macros.conf"
SEARCHES = ROOT / "app" / "riskability" / "default" / "savedsearches.conf"

FAILURES = []


def check(name, ok, detail=""):
    print("  %s %s%s" % ("ok  " if ok else "FAIL", name, (" " + str(detail)) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def stanza(text, name):
    m = re.search(r"^\[%s\]\n(.*?)(?=^\[|\Z)" % re.escape(name), text, re.S | re.M)
    if not m:
        return ""
    body = m.group(1)
    body = re.sub(r"\\\n", "", body)          # join continuation lines
    m2 = re.search(r"^definition = (.*)$", body, re.M)
    return m2.group(1) if m2 else ""


def literal(definition, field, containing=""):
    """The regex literal in match(<field>, "..."), optionally the one that
    contains a marker. rk_r_orig is matched twice, once against the word rule
    and once against the stub rule, and the first version of this took the
    first literal for both: the stub rule was never exercised and the
    "7zSD.sfx.exe" case passed on the file name instead, which is exactly the
    kind of test that reads as coverage while asserting nothing."""
    for m in re.finditer(r'match\(%s, "((?:[^"\\]|\\.)*)"\)' % re.escape(field), definition):
        if containing in m.group(1):
            return m.group(1)
    return None


# swinv's table, verbatim from installer_test.go: (basename, file_description,
# original_filename, product_name) -> expected role.
CASES = [
    ("firefox setup", "Firefox Setup 121.0.exe", "Firefox Installer", "Firefox Installer.exe", "Firefox", "installer"),
    ("firefox stub by name only", "helper.exe", "", "", "Firefox Installer", "installer"),
    ("generic setup filename", "AppSetup.exe", "", "", "Some App", "installer"),
    ("underscore installer", "node-v20_installer.exe", "", "", "", "installer"),
    ("vc redist", "vc_redist.x64.exe", "", "", "Microsoft Visual C++", "installer"),
    ("inno description", "app.exe", "Setup", "", "My App", "installer"),
    ("7zip sfx stub", "Firefox Installer.exe", "Firefox", "7zS.sfx.exe", "Firefox", "installer"),
    ("7zip sfx renamed", "totally-legit.exe", "Firefox", "7zSD.sfx.exe", "Firefox", "installer"),
    ("real firefox", "firefox.exe", "Firefox", "firefox.exe", "Firefox", ""),
    ("real chrome", "chrome.exe", "Google Chrome", "chrome.exe", "Google Chrome", ""),
    ("firefox desktop launcher", "Firefox.exe", "", "desktop-launcher.exe", "Firefox", "launcher"),
    ("renamed desktop launcher", "Firefox-fnaskZenbook.exe", "", "desktop-launcher.exe", "Firefox", "launcher"),
    ("portable tool", "SuperTool.exe", "SuperTool", "SuperTool.exe", "SuperTool", ""),
    ("portable renamed by user", "my-tool.exe", "SuperTool", "SuperTool.exe", "SuperTool", ""),
    ("standalone with no version fields", "widget.exe", "", "widget.exe", "Widget", ""),
    ("reinstallation word", "reinstaller_tool.exe", "Reinstallation report generator", "", "Report Tool", ""),
    ("setup substring in word", "presetupdb.dll", "Preset up database", "", "Preset Manager", ""),
    # Cases from the dev fleet that the shipped rules must get right too.
    ("wireshark by description", "Wireshark-4.6.0-x64.exe", "Wireshark installer for Windows", "", "Wireshark", "installer"),
    ("teams by original filename", "MSTeamsSetup.exe", "Microsoft Teams", "Setup.exe", "Microsoft Teams", "installer"),
    ("onedrive setup stub", "OneDriveSetup.exe", "Microsoft OneDrive (64 bit) Setup", "OneDriveSetup.exe", "Microsoft OneDrive", "installer"),
    ("cursor by description", "CursorUserSetup-x64-1.6.23.exe", "Cursor Setup", "", "Cursor", "installer"),
    ("a real installed dll with Setup in its dotted name", "Microsoft.VisualStudio.Setup.Common.dll", "", "", "Visual Studio", ""),
    ("a venv python is real software", "python.exe", "Python", "python.exe", "Python", ""),
    ("a product literally named Setup is not an installer by name", "Compatibility.dll", "Product Compatibility Dynamic Library", "Compatibility.dll", "Setup", ""),
]


def main():
    text = MACROS.read_text(encoding="utf-8")
    definition = stanza(text, "riskability_component_role")
    check("the macro exists", bool(definition))
    check("its definition does not start with a pipe", not definition.lstrip().startswith("|"))

    word = literal(definition, "rk_r_desc")
    stub = literal(definition, "rk_r_orig", containing="7z")
    fname = literal(definition, "rk_r_base")
    launch = literal(definition, "trim(rk_r_orig)")
    check("word regex found", bool(word))
    check("stub regex found", bool(stub))
    check("file name regex found", bool(fname))
    check("launcher regex found", bool(launch))
    if not all((word, stub, fname, launch)):
        return finish()

    # Splunk lowercases every input before matching, so the Python does too.
    WORD, STUB, FNAME, LAUNCH = (re.compile(x) for x in (word, stub, fname, launch))

    def classify(base, desc, orig, prod):
        base, desc, orig, prod = (x.lower() for x in (base, desc, orig, prod))
        if WORD.search(desc):
            return "installer"
        if WORD.search(orig):
            return "installer"
        if STUB.search(orig):
            return "installer"
        if FNAME.search(base):
            return "installer"
        if "installer" in prod:
            return "installer"
        if LAUNCH.search(orig.strip()):
            return "launcher"
        return ""

    # The basename strip must survive conf-file escaping. Apply the literal
    # exactly as Splunk will: a conf string reaches eval as written, eval
    # unescapes \\ to \, and the result is the regex. Then it has to take a
    # Windows path down to its file name, or every rule above runs against the
    # whole path and a folder called "ws-install-4.6-gui" flags every DLL in it.
    m = re.search(r'rk_r_base = lower\(replace\(coalesce\(path, mvindex\(locations, 0\), ""\), "((?:[^"\\]|\\.)*)", ""\)\)', definition)
    check("basename regex found", bool(m))
    if m:
        conf_literal = m.group(1)
        as_regex = conf_literal.replace("\\\\", "\\")
        strip = re.compile(as_regex)
        win = strip.sub("", "C:\\dev\\ws-install-4.6-gui\\swscale-7.dll")
        check("basename strips a Windows path to the file name",
              win == "swscale-7.dll", repr(win))
        nix = strip.sub("", "/usr/lib/x86_64-linux-gnu/libavcodec.so.60")
        check("basename strips a POSIX path to the file name",
              nix == "libavcodec.so.60", repr(nix))
        check("a codec DLL under an install folder is NOT an installer",
              classify(win, "FFmpeg image rescaling library", "swscale-7.dll", "FFmpeg") == "")

    for name, base, desc, orig, prod, want in CASES:
        got = classify(base, desc, orig, prod)
        check("%-52s -> %r" % (name, want), got == want, "got %r" % got)

    # Both consumers must actually call it, with the pipe the definition omits.
    searches = SEARCHES.read_text(encoding="utf-8")
    check("riskability_latest_inventory calls it with a pipe",
          "| `riskability_component_role` | stats latest(rk_role) AS role" in
          re.sub(r"\\\n", "", text))
    joined = re.sub(r"\\\n", "", searches)
    closer = joined[joined.index("[Riskability - close findings behind installers]"):]
    closer = closer[:closer.index("\n[", 1)]
    check("the installer closer reads the raw inventory, latest role per file",
          "stats latest(rk_role) AS rk_inv_role BY hostname, name, path" in closer
          and "riskability_invstate_lookup" not in closer
          and "riskability_latest_inventory" not in closer)
    check("the installer closer classifies with the shared macro",
          "| `riskability_component_role`" in closer)
    check("the installer closer uses no subsearch",
          "append [" not in closer and "join " not in closer)
    check("the installer closer looks back thirty days",
          "dispatch.earliest_time = -30d" in closer)
    check("the installer closer names the role as its reason",
          'closure_reason = rk_role . "_artifact"' in searches)
    return finish()


def finish():
    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
