#!/usr/bin/env python3
"""Audit built packages against Splunkbase's published file standards.

Separate from package.sh --verify on purpose. That asserts our own packages
contain what this app needs to run. This asserts what Splunkbase will reject
regardless of whether the app works, taken from:

  https://dev.splunk.com/enterprise/docs/releaseapps/splunkbase/approvalcriteria/

A rejection costs a review cycle, so the checks run here rather than being
discovered on upload.
"""
import configparser, io, os, re, struct, sys, tarfile

FAIL, WARN, OK = "FAIL", "warn", "ok "
results = []


def note(level, package, msg):
    results.append((level, package, msg))


def png_size(blob):
    # PNG signature, then the IHDR chunk carries width and height as big-endian
    # uint32 at a fixed offset. No image library needed for this.
    if blob[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", blob[16:24])


def audit(path):
    name = os.path.basename(path)
    pkg = name

    if not re.search(r"\.(tar\.gz|tgz|spl)$", name):
        note(FAIL, pkg, "extension must be .tar.gz, .tgz or .spl")

    size_mb = os.path.getsize(path) / 1e6
    note(WARN if size_mb > 200 else OK, pkg,
         f"package size {size_mb:.1f} MB" + (" - over 200 MB needs justification" if size_mb > 200 else ""))

    with tarfile.open(path) as tf:
        members = tf.getmembers()
        names = [m.name for m in members]

        roots = {n.split("/")[0] for n in names}
        if len(roots) != 1:
            note(FAIL, pkg, f"must have exactly one root folder, found {sorted(roots)}")
            return
        root = roots.pop()

        for n in names:
            if ".." in n.split("/"):
                note(FAIL, pkg, f"invasive relative path: {n}")

        for n in names:
            base = os.path.basename(n)
            if base.startswith(".") and base not in ("",):
                note(FAIL, pkg, f"hidden file not allowed: {n}")
            if base.endswith((".pyc", ".pyo")):
                note(FAIL, pkg, f"compiled python not allowed: {n}")

        for n in names:
            parts = n.split("/")
            if len(parts) > 1 and parts[1] == "local":
                note(FAIL, pkg, f"local/ is the user's layer and must not ship: {n}")
        if f"{root}/metadata/local.meta" in names:
            note(FAIL, pkg, "metadata/local.meta must not ship")

        # "All scripts (.py, .sh, .bat and so on) and .exe files must be in the
        # bin directory." Vendored SDK packages under bin/ are still under bin/.
        for m in members:
            if not m.isfile():
                continue
            if m.name.endswith((".py", ".sh", ".bat", ".exe", ".ps1", ".cmd")):
                rel = m.name[len(root) + 1:]
                if not rel.startswith("bin/"):
                    note(FAIL, pkg, f"executable script outside bin/: {rel}")

        # "Files that indicate they are executable must actually be executable."
        for m in members:
            if m.isfile() and m.name.endswith(".py") and "/bin/" in m.name:
                stem = os.path.basename(m.name)
                # Only entry points need the bit; library modules do not claim to be runnable.
                if stem.startswith("riskability_") and not (m.mode & 0o111):
                    note(WARN, pkg, f"bin entry point is not executable: {m.name} (mode {m.mode:o})")

        # app.conf identity fields.
        try:
            data = tf.extractfile(f"{root}/default/app.conf").read().decode()
        except Exception:
            note(FAIL, pkg, "no default/app.conf")
            return
        cp = configparser.ConfigParser(strict=False)
        cp.read_string(data)

        for stanza, key in (("launcher", "description"), ("launcher", "author"),
                            ("launcher", "version")):
            if not cp.has_option(stanza, key):
                note(FAIL, pkg, f"app.conf [{stanza}] {key} is required")
            else:
                note(OK, pkg, f"app.conf [{stanza}] {key} = {cp.get(stanza, key)[:60]}")

        if cp.has_option("package", "id"):
            pid = cp.get("package", "id")
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", pid):
                note(FAIL, pkg, f"[package] id has illegal characters: {pid}")
            if pid != root:
                note(FAIL, pkg, f"[package] id {pid!r} must match root folder {root!r}")
            else:
                note(OK, pkg, f"[package] id matches root folder: {pid}")
        else:
            note(FAIL, pkg, "app.conf [package] id is required")

        if cp.has_option("ui", "label"):
            label = cp.get("ui", "label")
            if not 5 <= len(label) <= 80:
                note(FAIL, pkg, f"[ui] label must be 5-80 chars, is {len(label)}: {label!r}")
            else:
                note(OK, pkg, f"[ui] label = {label}")
        else:
            note(FAIL, pkg, "app.conf [ui] label is required")

        # Icons. Only the visible app needs them; a TA with no UI does not.
        is_visible = cp.has_option("ui", "is_visible") and cp.get("ui", "is_visible").strip() in ("1", "true", "True")
        want = {"appIcon.png": (36, 36), "appIcon_2x.png": (72, 72),
                "appIconAlt.png": (36, 36), "appIconAlt_2x.png": (72, 72)}
        for icon, dims in want.items():
            p = f"{root}/static/{icon}"
            if p not in names:
                note(FAIL if (is_visible and icon == "appIcon.png") else WARN, pkg,
                     f"missing static/{icon}" + (f" ({dims[0]}x{dims[1]})" if dims else ""))
                continue
            got = png_size(tf.extractfile(p).read())
            if got is None:
                note(FAIL, pkg, f"static/{icon} is not a PNG")
            elif got != dims:
                note(FAIL, pkg, f"static/{icon} is {got[0]}x{got[1]}, must be {dims[0]}x{dims[1]}")
            else:
                note(OK, pkg, f"static/{icon} is {got[0]}x{got[1]}")

        # Hard-coded developer paths and obvious secrets.
        leak = re.compile(rb"/opt/code/|/home/[a-z]+/|password\s*=\s*['\"][^'\"]{3,}")
        for m in members:
            if not m.isfile() or m.size > 2_000_000:
                continue
            if not m.name.endswith((".py", ".conf", ".xml", ".js", ".html", ".md", ".spec")):
                continue
            blob = tf.extractfile(m).read()
            rel_name = m.name[len(root) + 1:]
            # Splunk's own SDK ships docstring examples that read like
            # credentials (username="boris", password="natasha"). Reporting
            # those as suspected secrets every run trains the reader to skip
            # this section, which is how a real one gets through. Called out
            # separately rather than suppressed, so the count is still honest.
            vendored = rel_name.startswith("bin/splunklib/") or ".dist-info/" in rel_name
            for hit in set(leak.findall(blob)):
                txt = hit.decode(errors="replace")
                # The docs legitimately describe where a user puts their own file.
                if txt.startswith("password") and b"$SPLUNK_PASSWORD" in blob:
                    continue
                if vendored:
                    note(OK, pkg, f"vendored SDK example, not a credential: {rel_name}: {txt[:34]}")
                else:
                    note(WARN, pkg, f"possible dev path or secret in {rel_name}: {txt[:40]}")

        # AppInspect Cloud vetting, learned from a rejected submission.
        # is_configured = true asserts a setup has already been performed,
        # which cannot be true of an app somebody is installing for the
        # first time.
        if cp.has_option("install", "is_configured"):
            v = cp.get("install", "is_configured").strip().lower()
            if v in ("1", "true", "yes"):
                note(FAIL, pkg, "app.conf [install] is_configured must be false in a shipped app")
            else:
                note(OK, pkg, f"[install] is_configured = {v}")

        # An [id] stanza with a name is required for installation, and is where
        # the semantic-version check reads the version from.
        if not cp.has_section("id"):
            note(FAIL, pkg, "app.conf needs an [id] stanza with a name attribute")
        else:
            idn = cp.get("id", "name", fallback="")
            idv = cp.get("id", "version", fallback="")
            if idn != root:
                note(FAIL, pkg, f"[id] name {idn!r} must match the root folder {root!r}")
            else:
                note(OK, pkg, f"[id] name = {idn}")
            lv = cp.get("launcher", "version", fallback="")
            if idv and lv and idv != lv:
                note(FAIL, pkg, f"[id] version {idv} disagrees with [launcher] version {lv}")

        # Splunk Cloud accepts only these properties in indexes.conf, and every
        # path must sit under $SPLUNK_DB. A volume: path is refused even though
        # it works perfectly on-premises.
        ipath = f"{root}/default/indexes.conf"
        if ipath in names:
            allowed = {"homepath", "coldpath", "thawedpath", "frozentimeperiodinsecs",
                       "disabled", "datatype", "repfactor"}
            icp = configparser.ConfigParser(strict=False)
            icp.read_string(tf.extractfile(ipath).read().decode())
            offenders = 0
            for stanza in icp.sections():
                if stanza.startswith("volume:") or stanza == "default":
                    continue
                for key, val in icp.items(stanza):
                    if key.lower() not in allowed:
                        note(FAIL, pkg, f"indexes.conf [{stanza}]: {key} is not accepted by Splunk Cloud")
                        offenders += 1
                    elif key.lower().endswith("path") and "$SPLUNK_DB" not in val:
                        note(FAIL, pkg, f"indexes.conf [{stanza}]: {key} must contain $SPLUNK_DB")
                        offenders += 1
            if not offenders:
                note(OK, pkg, f"indexes.conf: {len(icp.sections())} stanzas, Cloud-safe properties only")

        # Splunkbase's own package validation - which is neither slim nor
        # AppInspect, and which no local tool reproduces - requires an icon for
        # every visualization stanza. That icon is preview.png in the
        # visualization's directory, the same file Splunk's own bundled
        # visualizations ship; visualizations.conf itself has no icon setting.
        vpath = f"{root}/default/visualizations.conf"
        if vpath in names:
            vcp = configparser.ConfigParser(strict=False)
            vcp.read_string(tf.extractfile(vpath).read().decode())
            for stanza in vcp.sections():
                png = f"{root}/appserver/static/visualizations/{stanza}/preview.png"
                if png not in names:
                    note(FAIL, pkg, f"visualization [{stanza}] has no appserver/static/visualizations/{stanza}/preview.png")
                    continue
                dims = png_size(tf.extractfile(png).read())
                if dims is None:
                    note(FAIL, pkg, f"visualization [{stanza}]: preview.png is not a PNG")
                else:
                    note(OK, pkg, f"visualization [{stanza}] preview.png is {dims[0]}x{dims[1]}")

        for doc in ("README.md", "README.txt", "README"):
            if f"{root}/{doc}" in names:
                note(OK, pkg, f"ships {doc}")
                break
        else:
            note(WARN, pkg, "no README inside the package (Splunkbase asks for one)")


if __name__ == "__main__":
    # Default to the .spl names only. package.sh writes each archive under both
    # .spl and .tar.gz, and they are byte-identical, so globbing every accepted
    # extension would audit the same bytes twice and report every finding twice.
    # An explicit path argument still audits whatever is named.
    paths = sys.argv[1:] or sorted(
        os.path.join("dist", f) for f in os.listdir("dist") if f.endswith(".spl"))
    for p in paths:
        audit(p)
    width = max(len(p) for _, p, _ in results)
    for level, pkg, msg in results:
        print(f"  {level}  {pkg:<{width}}  {msg}")
    bad = sum(1 for l, _, _ in results if l == FAIL)
    warn = sum(1 for l, _, _ in results if l == WARN)
    print(f"\n{bad} failures, {warn} warnings")
    sys.exit(1 if bad else 0)
