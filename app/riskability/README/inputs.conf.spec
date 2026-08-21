# Splunk only introspects a modular input whose stanza is declared here. Without
# this spec file the script is never run, the scheme is never registered, and
# the input simply does not appear under /services/data/inputs -- with nothing
# in splunkd.log to say why.

[riskability_feedworker://<name>]
* Performs vulnerability feed imports and online fetches queued from the
* Riskability admin page. This work cannot run in the REST handler that
* requests it: splunkd recycles the persistent-script process when it goes
* idle, which kills a long import partway through.
* The input does nothing until a request is queued, so leaving it enabled
* costs one KV Store read per interval.
interval = <integer>
* How often to check for queued work, in seconds.
* Default: 60
