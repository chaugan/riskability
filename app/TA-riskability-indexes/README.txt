Riskability Indexes (TA-riskability-indexes)
============================================

What it does
------------
Defines the four indexes the Riskability app reads and writes. It contains
nothing else: no inputs, no scripts, no searches, no network access.

Deploy this to INDEXERS ONLY (or to a single instance). Do not deploy it to
universal forwarders. A forwarder that carries index definitions it cannot
serve produces confusing errors and no benefit.

Indexes created
---------------
  riskability_inventory        software inventory from the swinv collector
  riskability_findings         findings the matcher produces, and per-host receipts
  riskability_findings_archive findings retired out of the live state collection
  riskability_audit            who accepted which risk, when, and what they said

All four use the default $SPLUNK_DB location and Splunk's default retention.
Adjust retention to your own policy before you rely on it: the archive and audit
indexes are the ones that answer "what did we know, and when", so a short
retention there quietly removes your evidence.

Version support
---------------
Splunk Enterprise 9.0 or later. Platform independent.

System requirements
-------------------
Indexer, indexer cluster peer, or single instance. On an indexer cluster,
deploy through the cluster master's configuration bundle rather than installing
directly on peers.

Installation
------------
  1. Apps > Manage Apps > Install app from file, or unpack the archive into
     $SPLUNK_HOME/etc/apps.
  2. Restart Splunk.

On an indexer cluster, place it in the master's manager-apps (or master-apps)
directory and apply the bundle instead.

Configuration
-------------
None required. To change index names or retention, create
local/indexes.conf and override only the attributes you want changed. Splunk
merges configuration per attribute, so naming one attribute in local/ leaves
the rest of the stanza intact.

If you rename an index here, rename it in the search-head app's setup page and
in the add-on's inputs as well. Those three have to agree or data lands in one
place and is searched for in another.

Troubleshooting
---------------
"Index not found" in the app:
  - This add-on is not installed on the indexers, or the bundle was not applied.

Data is being forwarded but is not searchable:
  - Confirm the index exists on the indexers: ./splunk btool indexes list
  - Confirm the name matches what the add-on's inputs.conf sends to.

Support
-------
Issues and questions: https://github.com/chaugan/riskability/issues

Licence
-------
Apache License 2.0. The full text ships in the LICENSE file alongside this one.
