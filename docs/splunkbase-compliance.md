# Getting a package through Splunkbase

Everything this project learned submitting Riskability, written down because
every one of these cost a review cycle. Nothing here is theory: each rule below
is one we actually broke.

## The one thing to understand first

**Three separate gates run on an upload, and they do not check the same
things.** Passing one tells you nothing about the others.

| Gate | What it is | Can you run it yourself? |
|---|---|---|
| Splunk Packaging Toolkit (`slim`) | Structure and conf syntax | Yes |
| AppInspect | Several hundred rules, including Splunk Cloud vetting | Yes |
| Splunkbase package validation | Splunkbase's own layer, on top of both | **No** |

We were rejected three times in a row, each by a different gate, because we kept
checking a narrower set than Splunkbase does. The pattern is always the same:
whatever you are not running is where the next rejection comes from.

## Run the toolkits properly

### slim: the version matters

Splunk bundles `slim` at `$SPLUNK_HOME/bin/slim`, but the bundled copy lags. Ours
was **1.1.0** while the current release was **1.2.8**. "It passes slim locally"
is a weaker claim than it sounds if you validated with the older one.

```sh
docker run --rm -v "$PWD/dist":/pkg:ro python:3.9-slim bash -c \
  "pip install -q splunk-packaging-toolkit && slim validate /pkg/yourapp.tar.gz"
```

Validate the archive **and** an extracted directory. Splunkbase unpacks to
`/tmp/<uuid>/<app>/` before validating, and that is a different code path.

### AppInspect: do not filter the checks

This one cost a rejection on its own. Running

```sh
splunk-appinspect inspect app.tar.gz --mode precert --included-tags cloud
```

is **narrower** than what Splunkbase applies. Anything outside the `cloud` tag
is invisible to you. Run both, every time:

```sh
splunk-appinspect inspect app.tar.gz --mode precert                      # all checks
splunk-appinspect inspect app.tar.gz --mode precert --included-tags cloud
```

Installing it needs `libmagic`, which is not obvious from the import error:

```sh
docker run --rm -v "$PWD/dist":/pkg:ro python:3.9-slim bash -c \
  "apt-get update -qq && apt-get install -y -qq gcc libxml2-dev libxslt1-dev libmagic1 && \
   pip install -q splunk-appinspect && \
   splunk-appinspect inspect /pkg/yourapp.tar.gz --mode precert"
```

Use Python 3.9. On 3.12 and later `slim` fails on the removed `imp` module, and
`lxml` may have no wheel for a very new interpreter.

### Splunkbase's own layer cannot be reproduced

It checks things neither toolkit does. The one that caught us: **every stanza in
`visualizations.conf` needs an icon**, meaning a `preview.png` in that
visualization's directory. `visualizations.conf` has no icon setting at all, so
nothing in the spec tells you this. Splunk's own bundled visualizations ship one;
compare against `splunk_monitoring_console/appserver/static/visualizations/heatmap/`.

Assume this layer exists and will find something you cannot predict. Encode each
rule as a build failure once you learn it.

## The rules we broke

### Conf continuation lines

A line ending in `\` continues. Miss one in the middle of a long `description`
and the value ends there, so the next line looks like a setting with no `=` in
it. **Splunk's own parser tolerates this silently.** The app loads, dashboards
work, nothing warns. slim refuses the whole submission:

```
line 973: Expected a setting assignment, not "A collector that has nothing..."
```

Ours survived a fresh install test, ninety five assertions and a bespoke audit.
The submission form was the first thing to object. `tools/conf_lint.py` in this
repo parses the strict way; an even number of trailing backslashes is a literal,
not a continuation.

### indexes.conf, for Splunk Cloud

Cloud accepts **only** `homePath`, `coldPath`, `thawedPath`,
`frozenTimePeriodInSecs`, `disabled`, `datatype`, `repFactor`. Every path must
contain `$SPLUNK_DB`.

We shipped `tstatsHomePath = volume:_splunk_summaries/...`, which fails twice
over: the property is not allowed, and a `volume:` path is not `$SPLUNK_DB`.
Deleting it changed nothing, because Splunk's own
`system/default/indexes.conf` already sets that value globally for every index.
It had only ever restated the default.

### is_configured

`is_configured = 1` asserts a setup has already been performed, which cannot be
true of an app someone is installing. It must be `0` in `default/app.conf`. If
your app has a setup page, clear the flag at runtime once setup succeeds, by
posting `configured=1` to `/servicesNS/nobody/<app>/apps/local/<app>`.

### The [id] stanza

AppInspect wants an `[id]` stanza with a `name`, separate from `[package] id`,
and reads the version from it for the semantic version check:

```ini
[id]
name = myapp
version = 0.1.3
```

`name` must match `[package] id` and the root directory.

### python.version is on its way out

Splunk 10.2 deprecates `python.version` in favour of `python.required`. Splunk
9.x accepts `python.required` and ignores it, so declare **both** and be correct
on every version you support:

```ini
python.version = python3
python.required = 3.9, 3.13
```

We had both in `commands.conf` and `inputs.conf` but only the old spelling in
`restmap.conf`, which AppInspect reported as a `future_failure`.

### Version numbers cannot be reused

A resubmission needs a new version. This also stops two different archives
answering to one number, which we managed briefly: the build Splunkbase accepted
and a later rebuild were both called 0.1.2 with different bytes. Publish the
exact accepted artefact and move the repository on.

## Everything else, as a checklist

Structure:

- Exactly **one root folder**, named the same as `[package] id`.
- No `local/`, no `metadata/local.meta`. That layer belongs to the user, and
  shipping it overwrites their customisations on upgrade.
- No `.pyc`, `.pyo`, `__pycache__`.
- No hidden files. `.DS_Store` is the usual offender.
- No `..` anywhere in a member path.
- All `.py`, `.sh`, `.bat`, `.ps1`, `.exe` under `bin/`.

Metadata:

- `[launcher]` needs `description`, `author`, `version`.
- `[ui] label` must be 5 to 80 characters.
- `[package] id` from `A-Z a-z 0-9 _ - .`, matching the root folder.

Icons, in `static/`, case sensitive:

- `appIcon.png` 36x36, `appIcon_2x.png` 72x72
- `appIconAlt.png` 36x36, `appIconAlt_2x.png` 72x72
- `preview.png` 364x230 per visualization, in its own directory

Documentation:

- A README **inside** the package covering version support, requirements,
  installation, configuration and troubleshooting.
- A support contact. An issue tracker URL counts.
- The licence inside the package, not merely referenced from a repository.

Permissions:

- A file that declares itself executable must be executable. Every script with a
  shebang needs the bit set. Enforce this at package time rather than trusting a
  checkout: a clone made with an unhelpful umask will otherwise build a package
  that fails review.

Format:

- `.tar.gz`, `.tgz` or `.spl`, which are the same gzipped tar. Splunkbase's
  upload form asks for `.tar.gz`; Splunk Web's "install app from file" expects
  `.spl`. Build both names for the one archive so nobody has to rename a file
  and wonder whether it is still the artefact you tested.
- Over 200 MB needs justification.
- A 623x350 PNG for the listing page, uploaded separately from the package.

## What to automate

Encode every rule you learn as a build failure. In this repo:

| Tool | Catches |
|---|---|
| `tools/conf_lint.py` | Broken conf continuations, before slim sees them |
| `tools/splunkbase_audit.py` | Structure, metadata, icons, index properties, `is_configured`, `[id]`, visualization previews |
| `tools/package.sh --verify` | Runs both, plus `slim validate` when the dev container is up |

Two habits worth more than any single check.

**Verify a check by breaking something.** After adding a rule, rebuild a package
with the defect deliberately reintroduced and confirm the tool reports it. A
check that has never failed is a check you have not tested. Ours were verified
that way, which is how we know they fire.

**Never let a check pass silently when it did not run.** `slim validate` is
skipped when the dev container is down, and it says so loudly. A gate that
quietly does nothing is worse than no gate, because it reads as a pass.
