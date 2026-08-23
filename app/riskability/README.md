# Riskability

Offline software vulnerability correlation for Splunk Enterprise.

## Purpose

Correlates the software inventory collected by swinv (https://github.com/chaugan/swinv)
against vulnerability data that an operator supplies by hand, and reports which
installed packages are actually exposed. Built for a search head with no route
to the internet: the app makes no outbound network requests.

Matching is precedence-aware. A distribution's own advisory beats an upstream
ecosystem advisory, which beats an NVD/CPE assertion, and an explicit vendor
"not affected" beats all of them. This is what stops a patched Ubuntu package
such as openssl 3.0.13-0ubuntu3.4 being reported as vulnerable to a CVE that
upstream fixed in 3.0.14.

## Prerequisites

- Splunk Enterprise 9.0 or later. Python 3.9 or 3.13.
- The KV Store must be running; the vulnerability feed lives there.
- swinv installed on monitored hosts, writing NDJSON.
- On a **single instance** - one Splunk that is both search head and indexer -
  nothing else. The four indexes and the index-time parsing ship inside this
  app.
- On a **distributed** deployment, two additions. A universal forwarder cannot
  run this app: it has no Python for the modular input and would log an error
  on every restart. See "Three things this app cannot do for you" below for the
  forwarder input, and copy this app's `default/indexes.conf` and the
  `[riskability:swinv]` stanza from its `props.conf` to the indexers - a
  forwarder does not parse, so index-time settings belong where data is
  indexed. Without the indexes every dashboard reads zero and reports it as "no
  findings" rather than as an error, because a search against an index that
  does not exist returns no events rather than failing.

## Installing

Install with **`splunk install app riskability-0.1.0.spl`**, or through
*Manage Apps → Install app from file* in Splunk Web.

If instead you unpack the package by hand - which is the natural thing to do on
an air-gapped box - the files end up owned by whoever ran `tar`, usually root,
and splunkd cannot write inside its own app directory. The visible symptom is
that **"this app has not been fully configured yet" keeps interrupting every
navigation forever**, even with a feed fully imported, because clearing that
gate is itself a write. Put the ownership back:

```
chown -R splunk:splunk $SPLUNK_HOME/etc/apps/riskability
```

## Three things this app cannot do for you

These are deliberate. Each one would mean an app changing something about a
Splunk instance that is not the app's to change, and each is a single command.

1. **Enable receiving on the indexer**, if forwarders are not already sending:
   `splunk enable listen 9997`
2. **Add the inventory input on each forwarder.** This app does not go on a
   universal forwarder, and an app must not silently start reading a customer's
   filesystem. Six lines, in an app of your own on the forwarder or pushed from
   a deployment server:
   ```
   [monitor:///var/lib/swinv/*.ndjson]
   disabled = 0
   index = riskability_inventory
   sourcetype = riskability:swinv
   crcSalt = <SOURCE>
   blacklist = -latest\.ndjson$
   ```
   `crcSalt` is not optional: swinv output is deterministic apart from
   timestamps, so without it Splunk mistakes each new scan for one it has
   already read. The blacklist keeps it off the `-latest` symlink, which would
   re-read the whole inventory every scan.
   Note `local/`, not `default/`: Splunk resolves configuration by layer before
   app name, so an override in another app's `default/` loses to this add-on's
   own `default/`.
3. **Import a feed.** Until you do, every number is zero, and a zero here means
   "nothing has been assessed", not "nothing is wrong". The Feed administration
   page says so explicitly rather than showing a clean-looking dashboard.

## Inventory heartbeats (optional, and worth it above a few dozen hosts)

swinv writes one NDJSON record per component per scan. That is the right shape
for correctness - every scan is a complete statement of what is installed, so a
package that disappears is genuinely gone rather than merely unmentioned - and
it is the wrong shape for volume. Fourteen thousand components on five thousand
hosts scanned hourly is 1.68 billion events a day, and the app's hourly "which
hosts changed" decision reads every one of them. The matcher only works on hosts
that changed; the search that decides which ones those are does not.

A **heartbeat** fixes that. swinv sends one small record per host per scan
carrying a digest of its component list, and sends the full component list only
when that digest changes:

```json
{"record_type":"heartbeat","hostname":"web01","digest":"sha256:9f2c…",
 "n_components":14425,"os_id":"ubuntu","os_version_id":"24.04",
 "architecture":"amd64","scanned_at":"2026-08-22T06:47:35Z"}
```

The app prefers a heartbeat where one exists and computes the digest itself
where it does not, so a fleet part-way through the rollout works throughout, and
so does one that never adopts it.

Three things worth knowing if you are implementing the collector side:

- **The digest is opaque to the app.** It is never recomputed and never compared
  against anything but the previous value stored for the same host. Hash it
  however you like, as long as it is stable and changes when the inventory does.
  A host switching from computed to heartbeat digests looks changed exactly once.
- **Keep sending full lists on change.** The app deliberately does not accept
  deltas. A delta cannot express a removal, and "this package is no longer here"
  is the fact that decides whether a vulnerability is fixed or merely unreported.
- **Whichever record is newer wins.** If heartbeats stop arriving, the app goes
  back to computing the digest from the component list rather than trusting a
  stale heartbeat forever.

## How vulnerability data gets in

The app ships no vulnerability data. An operator runs the riskability-feed tool
on an internet-connected machine, carries the resulting bundle across, and
imports it on the Feed administration page. Bundles record the source and
licence of every record so attribution survives into Splunk.

## Support

Developed by chaugan. Issues: https://github.com/chaugan/riskability/issues

## Licence

Apache-2.0.
