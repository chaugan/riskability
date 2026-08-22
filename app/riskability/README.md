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
- **TA-riskability** deployed to forwarders (inputs) and indexers (parsing).
- **TA-riskability-indexes** deployed to indexers. It creates the four indexes
  this app writes to. Without it every dashboard reads zero and reports it as
  "no findings" rather than as an error, because a search against an index that
  does not exist returns no events rather than failing.
- swinv installed on monitored hosts, writing NDJSON.

## Installing

Install with **`splunk install app riskability-0.1.0.spl`**, or through
*Manage Apps → Install app from file* in Splunk Web.

If instead you unpack the package by hand — which is the natural thing to do on
an air-gapped box — the files end up owned by whoever ran `tar`, usually root,
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
2. **Enable the inventory input.** `TA-riskability` ships its monitor input
   **disabled**, because installing an add-on must not silently start reading a
   customer's filesystem. Enable it from your deployment server, or with a
   `local/inputs.conf` on the forwarder:
   ```
   [monitor:///var/lib/swinv/*.ndjson]
   disabled = 0
   ```
   Note `local/`, not `default/`: Splunk resolves configuration by layer before
   app name, so an override in another app's `default/` loses to this add-on's
   own `default/`.
3. **Import a feed.** Until you do, every number is zero, and a zero here means
   "nothing has been assessed", not "nothing is wrong". The Feed administration
   page says so explicitly rather than showing a clean-looking dashboard.

## How vulnerability data gets in

The app ships no vulnerability data. An operator runs the riskability-feed tool
on an internet-connected machine, carries the resulting bundle across, and
imports it on the Feed administration page. Bundles record the source and
licence of every record so attribution survives into Splunk.

## Support

Developed by chaugan. Issues: https://github.com/chaugan/riskability/issues

## Licence

Apache-2.0.
