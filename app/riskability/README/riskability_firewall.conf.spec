# Firewall data source settings. One stanza, [settings], written by the admin
# app's firewall page through the conf API. The riskability_fw_* macros in
# macros.conf are GENERATED from these on every save; edit the settings, not
# the macros, or the page will report the macros as out of step.

[settings]
mode = index | datamodel
* Where edges come from. "index" reads raw events from the index below and
  reduces them to unique permitted edges. "datamodel" runs tstats over an
  accelerated data model, which is the right choice for a real firewall
  volume: the reduction is already summarised on the indexers. Default index.

index = <string>
* The index holding the firewall's permitted-flow events. Empty means not
  configured, and the network evidence pipeline grades everything unknown.

sourcetype = <string>
* Optional. Restricts the source to one sourcetype.

extra_filter = <string>
* Optional. Additional search terms ANDed into the base search, for example
  a device or zone. A filter, not a search: no pipes, brackets or backticks.

src_field = <field>
dest_field = <field>
port_field = <field>
proto_field = <field>
* The event fields carrying the source address, destination address,
  destination port and transport protocol. Defaults follow the Splunk CIM
  Network Traffic model (src_ip, dest_ip, dest_port, transport).

action_field = <field>
action_allowed = <string>
* Only permitted flows are edges. Events are kept where action_field equals
  action_allowed. Leave action_field empty to skip the filter, only if the
  source already contains permitted flows and nothing else.

datamodel = <string>
dm_object = <string>
* Data model mode only. The model and the dataset within it. Defaults to
  the CIM Network_Traffic model and its All_Traffic dataset. The model must
  be accelerated: tstats runs with summariesonly=true, so an unaccelerated
  model yields no edges rather than a slow search.

dm_src_field = <Object.field>
dm_dest_field = <Object.field>
dm_port_field = <Object.field>
dm_proto_field = <Object.field>
dm_action_field = <Object.field>
* Data model mode only. Fields as the model exposes them, dataset-prefixed
  (All_Traffic.src, not src). Permitted flows are those where the action
  field equals action_allowed.

dm_where = <string>
* Data model mode only. Optional extra tstats WHERE terms, for example
  All_Traffic.dvc="edge-fw-1". A filter, not a search.

entry_points = <text>
* One per line:  cidr | name | pressure.  A bare address is /32 or /128.
  pressure is "constant" (the internet: unsolicited traffic arrives
  continuously, so silence means something) or "occasional" (a jump network).
  Only a constant entry point can ever produce a "not observed" grade.

fresh_days = <integer>
* An edge newer than this many days grades "confirmed observed"; older
  grades "historically observed". Default 7.

stale_days = <integer>
* If the newest edge in the whole source is older than this, the feed is
  stale and every row grades unknown. Default 2. Must not exceed fresh_days.

identity_grace_days = <integer>
* The widest gap in a host's hold on an address that still counts as
  continuous. Default 7.
