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
- TA-riskability deployed to forwarders (inputs) and indexers (parsing).
- swinv installed on monitored hosts, writing NDJSON.

## How vulnerability data gets in

The app ships no vulnerability data. An operator runs the riskability-feed tool
on an internet-connected machine, carries the resulting bundle across, and
imports it on the Feed administration page. Bundles record the source and
licence of every record so attribution survives into Splunk.

## Support

Developed by chaugan. Issues: https://github.com/chaugan/riskability/issues

## Licence

Apache-2.0.
