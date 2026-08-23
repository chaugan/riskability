<img src="docs/riskability-logo.png" alt="Riskability" width="100%">

# Riskability

**Offline software vulnerability correlation for Splunk.**

Riskability takes the software inventory that [`swinv`](https://github.com/chaugan/swinv)
collects from every host, correlates it against vulnerability data an operator
supplies by hand, and reports what is actually exposed - on a search head that
has no route to the internet.

**Matching, the dashboards and the import path make no outbound network
requests.** Nothing on a search head reaches for the internet to decide whether
a package is vulnerable, and nothing needs to.

The one exception is deliberate and opt-in: **Feed administration** offers a
*Fetch directly* button that downloads the upstream feeds and builds a bundle on
the search head itself, for instances that do have a route out. It tests
reachability first and reports the failure immediately on an instance that does
not, rather than starting a download that dies minutes later. Nothing invokes it
on your behalf; on an air-gapped search head it is a button that reports it
cannot work.

---

## Why this exists rather than "just match CPEs against NVD"

Because that approach produces a flood of false positives on exactly the hosts
people care about, and a vulnerability tool that cries wolf gets switched off.

Ubuntu ships `openssl 3.0.13-0ubuntu3.4` carrying the backported fix for a CVE
that upstream fixed in 3.0.14. NVD says "anything below 3.0.14 is vulnerable".
Both statements are true; only one of them is about your host. Riskability is
built around getting that distinction right:

| Rule | Why |
|---|---|
| Distro advisory beats ecosystem advisory beats NVD/CPE | Only the vendor knows whether *their* build is patched |
| An upstream range about a `deb`/`rpm`/`apk` is *informational*, never asserted | The distro version is not comparable to the upstream one |
| A vendor "not affected" beats everything | It is the most specific claim available |
| Per-ecosystem version comparators, never one generic one | `3.0.13-0ubuntu3.4` is not `3.0.14`, and `1.10` is not below `1.9` |
| A comparison that could not be made properly is *low confidence*, not a finding | A guess reported as fact is worse than no finding |

The Debian and RPM comparators are differentially tested against the real
`dpkg` and `rpm` binaries: **2450/2450** and **1190/1190** version pairs match
the reference implementations exactly. That test earns its keep - it caught a
collation bug where digits were ordered as punctuation rather than as
end-of-string, which mis-sorted every component whose version could not be
determined.

---

## What it does that most scanners get wrong

**It knows a filesystem contains more than one operating system.** A single
Ubuntu 26.04 host in testing reported four different `openssl` packages: the
host's own, one inside `/snap/core18` (Ubuntu 18.04), one inside `/snap/core20`
(20.04), and one in an unpacked container rootfs. 810 components (5.6%) live in
a root that is not the host's, and every one of them inherits the host's
`os_id`/`os_version_id` from the flat inventory record, because each row repeats
host identity. Riskability resolves each to its own root, infers the release a
base snap is built on, and reports findings against the root they belong to.

**It recovers source packages.** Debian and RPM advisories are keyed on the
*source* package while an inventory reports the *binary* one - `libssl3t64` is
advised as `openssl`. Syft encodes this in the PURL's `upstream` qualifier.
Parsing it took deb coverage on the test host from 260 to 770 matched
components, a 2.96× improvement.

**It distinguishes "fixed" from "stopped being reported".** A finding that
disappears may have been remediated, or the scan may have failed, or the host
may be gone, or the feed may have been re-imported without that ecosystem.
Riskability classifies every closed finding by what the current inventory says
about that exact install path: `mitigated` (still installed, different version,
with the version change recorded), `removed`, or `unknown`.

**It says what it cannot assess.** Of 14,349 components on the test host, 6,905
- **48%** - were kernel modules that no vulnerability feed covers. The Coverage
dashboard puts that in front of you, because a scanner silently blind to half a
host is more dangerous than one that admits it.

**It knows whether anything is listening.** EPSS says how likely the world is to
exploit a vulnerability and the KEV catalogue says whether anyone already has;
neither can know whether *this* copy answers a socket. swinv reports each host's
listening ports, the process holding each one, and the containers behind them,
and Riskability joins that to the findings. Every finding gets one of five
labels: *answers any address* (a wildcard bind), *answers one address* (bound to
a specific non-loopback address - treated as reachable, because it is),
*loopback only*, *no listening port*, or *not assessed* when the host never
reported its ports at all. On the test fleet, of 22,925 open findings, 17
answered a network address - two of them known-exploited - 383 answered only
loopback, and 22,525 had nothing listening. Those four figures are a live
instance snapshot rather than something `audit_claims.py` can recompute. It is a re-ordering, never a filter: an unreachable vulnerability is still a
vulnerability, and a host running a collector too old to report ports is shown as
*not assessed* rather than counted as safe.

**It says how strong the evidence is, and separates that from severity.**
Every finding carries a confidence band, and only one of them should drive
patching:

| Band | Means |
|---|---|
| `high` | Package identity and version both read from a package record |
| `informational` | An upstream version range covers a package the distribution installs and maintains. Ubuntu and Red Hat backport fixes without changing the upstream version, so the package may already be patched. Shown, never asserted |
| `low` | The identity was inferred - from a generated CPE, which is every Windows finding, or from a binary - or the versions could not be compared properly |

**It matches a container against the operating system inside it.** A named
container root takes its distribution from the package's own purl qualifier - an
apk inside an Alpine image is stamped `distro=alpine-3.21.6` - so its packages
are assessed against Alpine advisories rather than against the host's. A
container merely *inferred* from a path under `/var/lib/docker/overlay2` still
refuses to assert a release, because a component whose evidence spans two roots
can arrive carrying the host's qualifier.

**It matches Alpine on the security branch.** Alpine publishes advisories for
`3.21` while the installed system reports `3.21.6`. Compared literally they
never meet, so an Alpine host or container matched no Alpine advisory at all -
which is indistinguishable from a clean bill of health. Only Alpine is folded to
the branch; Debian-family releases are dotted minor versions in their own right,
and folding `24.04` to `24` would match it against `24.10`.

**It reports one vulnerability once.** OSV routinely describes the same CVE in
several advisories: on the test feed, 11,122 (package, CVE) pairs are covered by
more than one advisory record, and the worst is described by nine. Keyed on
advisory id, a single flaw is reported up to nine times.

---

## Architecture

```
  host                          search head (air-gapped)
  ┌──────────────┐              ┌────────────────────────────────────┐
  │ swinv        │   NDJSON     │ index=riskability_inventory        │
  │  ↓           │ ───────────► │        ↓ latest state per path     │
  │ universal    │  forwarder   │ riskabilitymatch (Python)          │
  │ forwarder    │              │        ↓ KV Store lookup           │
  └──────────────┘              │ index=riskability_findings         │
                                │        ↓                           │
  ┌──────────────┐   upload     │ dashboards / alerts                │
  │riskability-  │ ───────────► │ KV Store: advisories, ranges       │
  │feed (offline)│   by hand    └────────────────────────────────────┘
  └──────────────┘
```

Three packages ship, because Splunk resolves these settings on different tiers
and putting them in one app puts most of them in the wrong place:

| Package | Deploy to | Contains |
|---|---|---|
| **`riskability`** | search heads | dashboards, matcher, admin backend, KV Store collections, search-time field extraction |
| **`TA-riskability`** | **forwarders and indexers** | the file input (forwarders) and index-time parsing (indexers) |
| **`TA-riskability-indexes`** | **indexers only** | the index definitions |

`indexes.conf` is a separate package deliberately. A universal forwarder does
not index, and loading index definitions there makes it log
`Required parameter=tstatsHomePath not configured` on every start.

### Installing

```sh
tools/package.sh --verify        # builds dist/*.spl and checks each is complete
```

Install `riskability-<version>.spl` on the search heads,
`TA-riskability-<version>.spl` on **both** forwarders and indexers, and
`TA-riskability-indexes-<version>.spl` on indexers only.

Everything the app needs at runtime is inside those archives - the KV Store
collections and their indexes, the search commands, the modular input and its
spec file, the admin endpoint and its Splunk Web exposure, the dashboards, and
the vendored SDK. `--verify` exists because a fix that only lives on a
developer's instance is not a fix; it is a difference between what was tested
and what a user installs.

Three things are **not** app configuration and must be done on the deployment:

1. **Enable receiving on the indexers**, if it is not already on:
   `splunk enable listen 9997`. Shipping this in an app would silently open a
   port on someone's instance.
2. **Enable the file input on the forwarders** - see below. It ships disabled
   deliberately.
3. **Import a feed.** The app has no vulnerability data until you give it some,
   and says so on every dashboard rather than showing zeroes that look like
   good news.

The KV Store must be running on the search head; the feed lives there.

### What the app reads from the collector

Every line the forwarder ships is one JSON object. The app reads four kinds,
distinguished by `record_type`:

| `record_type` | Carries | Without it |
|---|---|---|
| *(absent)* | one installed component | there is nothing to assess |
| `heartbeat` | a digest and a component count, sent when nothing changed | every quiet scan ships the whole inventory again |
| `exposure` | one listening port, the process holding it, and the package behind it | every finding is reported as **not assessed** on the Exposure page - never as safe |
| `container` | one container, its image, its state and its published ports | container findings are still matched, but nothing says which of them are running or reachable |

The last two are what the **Exposure** page is built on. A collector that does
not emit them leaves the page honest but empty: hosts appear under "never
reported a listening port" and their findings sit in the dashed *not assessed*
row of the matrix, which is deliberately not the same place as "nothing is
listening".

An `exposure` record carries one port and one component, so a port served by
three packages arrives as three records. The package **name** is derived here
rather than shipped: from the purl's name segment, with the distro namespace
dropped for `deb`, `rpm` and `apk`, and from the `Name@Version` string on
Windows, where there is no purl to give. Checked against the component records
of both dev hosts - 22 of 22 Linux purls and 18 of 18 Windows strings derive the
same name the inventory reports, which is what lets a finding be joined to a
port by package alone.

`os_component` on an exposure record means the port is answered by the operating
system itself - Windows `System` and `svchost`. Those are counted separately
from ports nothing could be attributed to, because they are not the same fact:
one is a listener the app can see and cannot assess against a package feed, the
other is one it could not identify at all.

### Configuring the universal forwarder

`TA-riskability` already contains the input; it ships **disabled**, because
installing an add-on must not silently start reading a customer's filesystem.
Enable it the way you enable anything else - a deployment server, or a
`local/inputs.conf` on the forwarder:

```ini
# TA-riskability/local/inputs.conf on the forwarder
[monitor:///var/lib/swinv/*.ndjson]
disabled = 0
index = riskability_inventory
sourcetype = riskability:swinv
crcSalt = <SOURCE>
```

and point the forwarder at your indexers as usual:

```ini
# outputs.conf
[tcpout]
defaultGroup = riskability_indexers

[tcpout:riskability_indexers]
server = idx1.example.net:9997, idx2.example.net:9997
```

### Index names

The app writes to four indexes, and `TA-riskability-indexes` defines them:

| Index | Holds | Retention |
|---|---|---|
| `riskability_inventory` | what swinv reported | 30 days |
| `riskability_findings` | findings as they were produced | 1 year |
| `riskability_findings_archive` | what was found and when it was fixed | 2 years |
| `riskability_audit` | the risk-exception trail, append-only | 5 years |

The names are not hardcoded. Four macros - `riskability_index_inventory`,
`_findings`, `_archive` and `_audit` - are the only place they appear in SPL, so
a site with its own naming scheme overrides them in `local/macros.conf` and
everything follows: dashboards, the matcher, the lifecycle jobs, the audit
trail. The **Feed administration** page writes those overrides for you.

Two things do not follow automatically, because they are not the app's to
change: the forwarder's `inputs.conf` must send to the same index, and the
indexes themselves must exist. `TA-riskability-indexes` creates the default
four; a site using its own names creates its own.

### The forwarder input, and what it inherits

That `local/` stanza does not repeat everything the input needs, and does not
have to. Splunk merges configuration per attribute: `local/` wins for the
attributes it names, and every attribute it does not name is still taken from
`default/`. So the two settings below apply whether or not you write them out.

- **`crcSalt = <SOURCE>`**, shown above and also in the shipped default. swinv's
  output is deterministic apart from the timestamps, so two scans of an
  unchanged host share a long identical prefix. Without a source-based CRC salt
  Splunk recognises the new file as one it has already read and skips it
  entirely.
- **`blacklist = -latest\.ndjson$`**, in the shipped default only - it is not in
  the example above because there is no need to restate it. swinv writes a
  `<host>-latest.ndjson` symlink beside each scan. Monitoring the symlink as
  well would re-read the whole inventory every run: re-pointing a symlink does
  not reliably raise a new-file event, and its target changes name every scan.

Read the shipped file at `TA-riskability/default/inputs.conf` if you want to see
exactly what you are inheriting; it carries both settings and the reasoning.

Have swinv write NDJSON, which is the format the input expects:

```sh
swinv --format ndjson --out /var/lib/swinv
```

Index-time parsing (line breaking and the timestamp) lives in the same add-on
and takes effect on the **indexer**, because a universal forwarder does not
parse. Both tiers get `TA-riskability`; only the indexers also get
`TA-riskability-indexes`.

Matching runs in Python because Splunk cannot express dpkg or RPM version
ordering in SPL. It never streams over raw inventory: the caller reduces to
latest state first, and each chunk becomes a handful of KV Store queries keyed
on `(ecosystem, package)`, so work scales with distinct packages rather than
hosts × packages.

---

## Getting vulnerability data in

On a machine with internet access:

You do not need this repository. **Feed administration** offers a
self-contained `riskability-feedbuilder.zip` for download: unzip it on a
connected workstation and run the wrapper for your platform. It carries its own
code and needs no checkout and no install step. `tools/riskability-feed` is the
same builder for anyone who does have the repo.

```sh
tools/riskability-feed sources                 # what can be fetched, and how big

tools/riskability-feed build --out riskability-feed.tar.gz \
    --ecosystem Ubuntu --ecosystem npm --ecosystem PyPI \
    --ecosystem Go --ecosystem crates.io \
    --kev --epss --mitre
```

Only the sources you name are downloaded. Name the distributions you actually
run: add `--ecosystem Debian`, `--ecosystem Alpine`, `--ecosystem Rocky` and so
on. **`--mitre` is not optional if you want the MITRE ATT&CK page** - without
the technique-to-tactic mapping that flag fetches, that dashboard is empty, and
the page says so rather than implying nothing is exposed.

The bundle measured below is Ubuntu plus npm, Go, PyPI and crates.io, with
EPSS - which is what the command above builds, minus `--kev` and `--mitre`. It is
**40.9 MB** and holds 323,387 advisories and 2,960,955 affected
ranges, normalised down from about 884 MB of raw upstream feeds. It imports into
the KV Store in roughly five minutes. (The size and advisory counts are
recomputed by `audit_claims.py`; the raw-feed size and the import time are
measurements from a run, not from a file in this repository.)

Carry the bundle across, then either drop it in
`$SPLUNK_HOME/var/run/riskability/incoming/` or upload it on the **Feed
administration** page, and click Import. An import replaces the previous feed
rather than merging with it, and the old one stays queryable until the new one
has finished.

### Why a normalised bundle rather than the raw feeds

- Upstream formats disagree wildly (OSV JSON, OVAL XML, CSAF, `updateinfo.xml`,
  CSV). Parsing all of them inside Splunk's Python would be slow, fragile, and
  would need an app upgrade for every new format.
- Redistribution terms differ per source. A bundle **you** built from sources
  **you** chose sidesteps the question of what this app may ship - which is why
  nothing is shipped pre-loaded.
- The matcher wants exactly one shape.

### Licensing

OSV aggregates sources that are individually CC-BY-4.0 (GitHub, Red Hat),
CC-BY-SA-4.0 (Ubuntu), MIT (AlmaLinux) and BSD (Rocky); CISA KEV is
US-government public domain; EPSS is published by FIRST and expects
attribution. Every record keeps the source it came from, so attribution
survives into Splunk. Building a bundle for your own organisation is
uncontroversial; redistributing one is your decision, not this app's.

---

## Accepting a risk, and proving you did

Not every finding gets patched. **Risk exceptions** records the ones that do not:
the CVE, what it applies to, why, what control is in place instead, who decided,
and when it must be reviewed again. Accepted findings are removed from every risk
number on every page and counted separately, so they are never quietly dropped -
"no open findings" alongside four hundred accepted ones is not a clean fleet, and
the pages say so.

The decisions are also written to a separate append-only index, `riskability_audit`,
kept for five years. That is deliberate: a register that can be rewritten by
whoever can write the register is not an audit trail. Expiries are reconciled by a
scheduled search, so a lapsed exception puts its findings back into the open counts
without anyone remembering to do it.

---

## What makes it work on a fleet rather than a laptop

Matching every component on every host against the whole feed, every hour, does
not scale, and neither does a dashboard that re-derives fleet totals on each load.
Two mechanisms avoid both.

**Only changed hosts are re-matched.** The collector can send a small heartbeat
carrying a digest of its component list; the app checkpoints each host against
`(inventory digest, feed generation, matcher version)` and re-runs the matcher only
where one of the three moved. An unchanged host costs one row per scan instead of
its entire inventory. There is a daily floor as well, so a host that failed to
match for any reason heals itself rather than staying stale forever, and the app
computes the digest itself for collectors that send no heartbeat.

**Dashboards read rollups, not the finding state.** Hourly scheduled searches
maintain per-host, per-CVE and per-dimension summaries, so a fleet total is a read
of a few thousand rows rather than a few million. The cost is that those pages lag
by up to an hour, which **Fleet overview** states next to the numbers and warns
about when the lag is longer than it should be.

---

## Dashboards

Ten views, in nav order.

| View | Answers |
|---|---|
| **Start here** | What the numbers on every other page mean, and what they do not. The default landing page |
| **Fleet overview** | How stale is the feed, how many hosts report, where is the risk concentrated |
| **Findings** | Every finding, ranked by EPSS (exploitation likelihood) rather than CVSS |
| **Remediation** | What was actually fixed, and what merely stopped being reported |
| **MITRE ATT&CK** | Which adversary techniques the open findings could enable. Context, not evidence |
| **Exposure** | Which findings the network can reach, and which sit inside containers |
| **Hosts** | Per-host detail, split by filesystem root |
| **Coverage** | What the feed *cannot* say anything about |
| **Risk exceptions** | Findings someone accepted, why, until when, and who said so |
| **Feed administration** | Build, upload and import bundles |

### Exposure

Reachability re-orders the work. It never shortens it.

![Exposure](docs/screenshots/exposure.png)

### Fleet overview

![Fleet overview](docs/screenshots/fleet-overview.png)

### Coverage

The page that says what the app cannot assess, which is the one a low finding
count has to be read against.

![Coverage](docs/screenshots/coverage.png)

### MITRE ATT&CK

![MITRE ATT&CK](docs/screenshots/mitre-attack.png)

More in [`docs/screenshots/`](docs/screenshots).

---

## Development

```sh
docker/                       Splunk 9.4 plus a real universal forwarder
tools/deploy-dev.sh           sync the search-head app into it (preserves local/)
tools/deploy-uf.sh            install the add-on into the forwarder
tools/build-viz.sh            build the two custom visualizations, bump the cache key
tools/make-feedbuilder.sh     build the downloadable feed builder
tools/riskability-feed        build a bundle from upstream feeds
tools/riskability-scan        run the exact matching logic offline, no Splunk
tools/test_*.py               the test suites
```

Run the tests:

```sh
python3 tools/test_vercmp_differential.py   # vs the real dpkg and rpm
python3 tools/test_vercmp_spec.py           # vs each ecosystem's spec
python3 tools/test_match.py                 # matching and precedence
python3 tools/test_scope_purl.py            # regressions from real inventory
python3 tools/audit_claims.py               # recompute the inventory and feed numbers
```

`audit_claims.py` exists because a claim in this README was once a
generalisation from a single example rather than a measurement. Every number
drawn from the inventory or the feed is recomputed by that script, so it can be
checked rather than trusted.

Four figures are not, and are marked in the text where they appear: the size of
the raw upstream feeds, how long an import takes, and the fleet-wide exposure
and reachability splits. Those come from a running instance rather than from a
file in this repository, so the script cannot reach them.

`tools/riskability-scan` is the fastest way to sanity-check behaviour, because
it runs the app's matching logic against a `swinv` file with no Splunk involved:

```sh
tools/riskability-scan inventory.json riskability-feed.tar.gz
```

---

## Status

Working and verified end to end against real inventory from a 14,349-component
Ubuntu host and a 502-component Windows host, both checked in under
`testdata/ndjson/` so the numbers in this file can be recomputed rather than
taken on trust.

**Windows is supported, at low confidence only.** swinv emits no PURL for
Windows software, so identity comes from CPEs generated from the display name
and version - 488 of 502 components on the test host carry at least one. The
matcher tries several candidate CPEs per component and caps every resulting
finding at `low`, because the product identity is inferred rather than read from
a package record. Treat them as leads to verify.

Installed hotfixes are collected but not yet matched. Doing that properly means
MSRC CSAF data keyed CVE → KB → OS build, asking whether the KB that fixes a CVE
is installed, rather than comparing version ranges. That is not implemented.

## Licence

Apache-2.0. See `LICENSE`.
