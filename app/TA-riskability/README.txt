Riskability Add-on (TA-riskability)
===================================

What it does
------------
Reads the NDJSON software inventory written by the swinv collector
(https://github.com/chaugan/swinv) and applies the index-time parsing the
Riskability search-head app expects. It performs no correlation of its own and
makes no network requests.

This add-on carries no index definitions on purpose. Those ship separately in
TA-riskability-indexes, which belongs on indexers only and must NOT be
deployed to universal forwarders.

Version support
---------------
Splunk Enterprise 9.0 or later. Platform independent: the monitor input and the
parsing rules use no platform-specific features. Requires no Python at runtime.

System requirements
-------------------
- A universal forwarder, heavy forwarder or single instance that can read the
  directory swinv writes to (/var/lib/swinv by default).
- The swinv collector installed on each host you want inventoried.

Installation
------------
On each forwarder that collects inventory, and on the indexers (or the single
instance) that parse it:

  1. Install the add-on: Apps > Manage Apps > Install app from file, or unpack
     the archive into $SPLUNK_HOME/etc/apps.
  2. Restart Splunk.

Forwarders need the inputs; indexers need the parsing in props.conf. Installing
it in both places is correct and harmless.

Configuration
-------------
The monitor input ships DISABLED. Installing an add-on must not silently begin
reading a filesystem, so you enable it deliberately.

Create local/inputs.conf in this add-on and override only what you need:

  [monitor:///var/lib/swinv/*.ndjson]
  disabled = 0

Change the path if swinv writes elsewhere. Do not edit default/inputs.conf:
an upgrade replaces default/ and your change would be lost.

The input targets index riskability_inventory and sourcetype riskability:swinv.
If you rename the index, rename it in the search-head app's setup page too, or
the app will search an index that receives nothing.

Note the blacklist on -latest.ndjson. swinv writes one file per scan plus a
"<host>-latest.ndjson" symlink; monitoring the symlink would re-read the whole
inventory on every scan.

Parsing
-------
From 0.1.30 this add-on parses on the forwarder. swinv writes NDJSON, one JSON
object per line, and Splunk with no sourcetype configuration merges any line
that does not begin with a timestamp: the lines become blobs of a few hundred,
each blob stops being valid JSON, and the default 10,000 byte truncation
discards most of what is left. A host reporting 3,993 components then arrives as
15, produces no findings, and reads as clean.

Previously the fix was to install the same parsing on the indexers, which is
infrastructure the person installing this app often does not own, and missing it
is silent. force_local_processing makes the universal forwarder run the line
breaker and aggregator itself, so the data arrives already split and no longer
depends on the indexing tier being configured.

It costs the forwarder some CPU and memory. For one inventory scan an hour that
is small, and it is the price of the failure above being impossible rather than
invisible.

Installing the parsing on the indexers as well is still correct and harmless,
and remains the right answer for anything that reaches the indexers by another
route.

Troubleshooting
---------------
No data arriving:
  - Confirm the input is enabled: ./splunk btool inputs list --debug | grep swinv
  - Confirm the forwarder can read the files: they are owned by the account
    swinv runs as, which is often root, while Splunk usually is not.
  - Check the forwarder is connected: ./splunk list forward-server

Events arrive but timestamps are wrong:
  - The parsing in props.conf must be present on the machine that indexes the
    data, not only on the forwarder. A universal forwarder does not parse.

Events arrive but the app shows nothing:
  - The search-head app also needs a vulnerability feed imported. Without one
    there is nothing to correlate against and every dashboard reads zero.

Support
-------
Issues and questions: https://github.com/chaugan/riskability/issues

Licence
-------
Apache License 2.0. The full text ships in the LICENSE file alongside this one.
