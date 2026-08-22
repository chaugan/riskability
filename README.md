# Riskability

**Offline software vulnerability correlation for Splunk.**

Riskability takes the software inventory that [`swinv`](https://github.com/chaugan/swinv)
collects from every host, correlates it against vulnerability data an operator
supplies by hand, and reports what is actually exposed — on a search head that
has no route to the internet.

The app makes **no outbound network requests at all**. That is the point.

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
the reference implementations exactly. That test earns its keep — it caught a
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
*source* package while an inventory reports the *binary* one — `libssl3t64` is
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
— **48%** — were kernel modules that no vulnerability feed covers. The Coverage
dashboard puts that in front of you, because a scanner silently blind to half a
host is more dangerous than one that admits it.

**It knows whether anything is listening.** EPSS says how likely the world is to
exploit a vulnerability and the KEV catalogue says whether anyone already has;
neither can know whether *this* copy answers a socket. swinv reports each host's
listening ports, the process holding each one, and the containers behind them,
and Riskability joins that to the findings. On the test fleet it splits 22,578
open findings into 17 reachable from any network — two of them known-exploited —
335 reachable only from the machine itself, and 22,226 with nothing listening at
all. It is a re-ordering, never a filter: an unreachable vulnerability is still a
vulnerability, and a host running a collector too old to report ports is shown as
*not assessed* rather than counted as safe.

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

Everything the app needs at runtime is inside those archives — the KV Store
collections and their indexes, the search commands, the modular input and its
spec file, the admin endpoint and its Splunk Web exposure, the dashboards, and
the vendored SDK. `--verify` exists because a fix that only lives on a
developer's instance is not a fix; it is a difference between what was tested
and what a user installs.

Three things are **not** app configuration and must be done on the deployment:

1. **Enable receiving on the indexers**, if it is not already on:
   `splunk enable listen 9997`. Shipping this in an app would silently open a
   port on someone's instance.
2. **Enable the file input on the forwarders** — see below. It ships disabled
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
| `exposure` | one listening port, the process holding it, and the packages behind it | every finding is reported as **not assessed** on the Exposure page — never as safe |
| `container` | one container, its image, its state and its published ports | container findings are still matched, but nothing says which of them are running or reachable |

The last two are what the **Exposure** page is built on. A collector that does
not emit them leaves the page honest but empty: hosts appear under "never
reported a listening port" and their findings sit in the dashed *not assessed*
row of the matrix, which is deliberately not the same place as "nothing is
listening".

### Configuring the universal forwarder

`TA-riskability` already contains the input; it ships **disabled**, because
installing an add-on must not silently start reading a customer's filesystem.
Enable it the way you enable anything else — a deployment server, or a
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

Two details in that input are not decoration:

- **`crcSalt = <SOURCE>`** — swinv's output is deterministic apart from the
  timestamps, so two scans of an unchanged host share a long identical prefix.
  Without a source-based CRC salt Splunk recognises the new file as one it has
  already read and skips it entirely.
- **`blacklist = -latest\.ndjson$`** (in the shipped default) — swinv writes a
  `<host>-latest.ndjson` symlink beside each scan. Monitoring it as well would
  re-read the whole inventory every run.

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

```sh
tools/riskability-feed sources                 # what can be fetched, and how big

tools/riskability-feed build --out riskability-feed.tar.gz \
    --ecosystem Ubuntu --ecosystem Debian --ecosystem Alpine \
    --ecosystem npm --ecosystem PyPI --ecosystem Go --ecosystem Maven \
    --kev --epss
```

Only the sources you name are downloaded. A bundle covering Ubuntu plus four
language ecosystems is **40.9 MB** and holds 323,387 advisories and 2,960,955
affected ranges — built from 884 MB of raw upstream feeds, because everything
that is not needed for matching is normalised away. It imports into the KV Store
in about five minutes.

Carry the bundle across, then either drop it in
`$SPLUNK_HOME/var/run/riskability/incoming/` or upload it on the **Feed
administration** page, and click Import.

### Why a normalised bundle rather than the raw feeds

- Upstream formats disagree wildly (OSV JSON, OVAL XML, CSAF, `updateinfo.xml`,
  CSV). Parsing all of them inside Splunk's Python would be slow, fragile, and
  would need an app upgrade for every new format.
- Redistribution terms differ per source. A bundle **you** built from sources
  **you** chose sidesteps the question of what this app may ship — which is why
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

## Dashboards

| View | Answers |
|---|---|
| **Fleet overview** | How stale is the feed, how many hosts report, where is the risk concentrated |
| **Findings** | Every finding, ranked by EPSS (exploitation likelihood) rather than CVSS |
| **Remediation** | What was actually fixed, and what merely stopped being reported |
| **Exposure** | Which findings the network can reach, and which sit inside containers |
| **Hosts** | Per-host detail, split by filesystem root |
| **Coverage** | What the feed *cannot* say anything about |
| **Feed administration** | Upload and import bundles |

---

## Development

```sh
docker/                       lean single-instance Splunk for development
tools/deploy-dev.sh           sync the app into it (preserves local/)
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
python3 tools/audit_claims.py               # recompute every number in this file
```

`audit_claims.py` exists because a claim in this README was once a
generalisation from a single example rather than a measurement. Every
quantitative statement above is recomputed by that script from the actual
inventory and feed, so it can be checked rather than trusted.

`tools/riskability-scan` is the fastest way to sanity-check behaviour, because
it runs the app's matching logic against a `swinv` file with no Splunk involved:

```sh
tools/riskability-scan inventory.json riskability-feed.tar.gz
```

---

## Status

Working and verified end to end against real inventory from a 14,349-component
Ubuntu host and a 501-component Windows host. **Windows is not yet supported**:
swinv currently emits no PURL or CPE for Windows components
([swinv#1](https://github.com/chaugan/swinv/issues/1)), so there is no
identifier to match on. Windows also needs a different approach — MSRC CSAF
data keyed CVE → KB → OS build, checked against installed hotfixes — rather
than version-range matching.

## Licence

Apache-2.0. See `LICENSE`.
