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
`dpkg` and `rpm` binaries — 1482/1482 and 702/702 version pairs match the
reference implementations exactly.

---

## What it does that most scanners get wrong

**It knows a filesystem contains more than one operating system.** A single
Ubuntu 26.04 host in testing reported four different `openssl` packages: the
host's own, one inside `/snap/core18` (Ubuntu 18.04), one inside `/snap/core20`
(20.04), and one in an unpacked container rootfs. All four inherit the host's
identity in the raw inventory. Riskability resolves each to its own root,
infers the release a base snap is built on, and reports findings against the
root they belong to.

**It recovers source packages.** Debian and RPM advisories are keyed on the
*source* package while an inventory reports the *binary* one — `libssl3t64` is
advised as `openssl`. Syft encodes this in the PURL's `upstream` qualifier.
Parsing it tripled deb coverage on the test host.

**It distinguishes "fixed" from "stopped being reported".** A finding that
disappears may have been remediated, or the scan may have failed, or the host
may be gone, or the feed may have been re-imported without that ecosystem.
Riskability classifies every closed finding by what the current inventory says
about that exact install path: `mitigated` (still installed, different version,
with the version change recorded), `removed`, or `unknown`.

**It says what it cannot assess.** Of 14,349 components on the test host, 6,905
were kernel modules that no vulnerability feed covers. The Coverage dashboard
puts that in front of you, because a scanner silently blind to half a host is
more dangerous than one that admits it.

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

Two packages ship:

- **`riskability`** — the search-head app: dashboards, the matcher, the admin
  backend, the KV Store collections.
- **`TA-riskability`** — the add-on for forwarders (inputs) and indexers
  (index-time parsing). Index-time and search-time settings live on different
  tiers; shipping them as one app puts them in the wrong place.

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
language ecosystems is **~41 MB** and holds 323,387 advisories and 2.96M
affected ranges — built from ~880 MB of raw upstream feeds, because everything
that is not needed for matching is normalised away.

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
```

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
