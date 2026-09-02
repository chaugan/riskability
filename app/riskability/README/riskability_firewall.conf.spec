# Firewall data source settings. One stanza, [settings], written by the admin
# app's firewall page through the conf API. The riskability_fw_* macros in
# macros.conf are GENERATED from these on every save; edit the settings, not
# the macros, or the page will report the macros as out of step.

[settings]
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
