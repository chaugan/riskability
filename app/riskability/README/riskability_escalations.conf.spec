# Deterministic escalation rules: one stanza per rule, each a boolean
# predicate over measured fields that raises a single finding by a single
# tier. The shipped rules, with the reasoning behind each, are in
# default/riskability_escalations.conf; site rules belong in
# local/riskability_escalations.conf, because default/ is replaced wholesale
# on upgrade.
#
# Nothing here can lower a priority, reach P0, or move a finding by more than
# one tier. Those are properties of the engine rather than of any rule, and
# they are what make a rule set safe to read: the worst a wrong rule can do is
# lift one thing one place.

[<rule_name>]
# The stanza name is the rule's identity. It appears in the escalation's own
# audit trail, so it should say what the rule catches rather than what it
# tests: sole_listener_availability rather than impact_a_and_flag.
description = <string>
# What the rule catches, AND why the five scoring signals cannot catch it.
# Both halves are required, and the second is the one that matters. The score
# is computed from KEV listing, EPSS band, CVSS band, measured exposure and
# version match confidence. A rule that fires on something those five could
# have weighted is not an escalation, it is a sixth weight applied to a
# subset, and it belongs in the scorer where it can be argued with against the
# other five rather than here where it looks like an exception somebody made.
# Writing the second half is the check that catches that before it ships.
# Long values continue with a trailing backslash, as everywhere else in this
# app's conf files.
when = <eval-boolean-expression>
# A Splunk eval boolean expression, evaluated natively by SPL. The rule fires
# on a finding when this is true.
#
# There is no new interpreter here, deliberately. SPL already has one, it is
# already what every other calculation in this app is written in, and an
# operator can paste an expression into a search bar and see which findings it
# selects before switching the rule on.
#
# VALIDATED AGAINST AN ALLOWLIST. This value is read out of a conf file and
# expanded into a scheduled search, so an unvalidated one is SPL injection
# into the app's own prioritisation pipeline. The validator accepts, and
# accepts only:
#
#   * field identifiers on the allowlist below
#   * numeric literals
#   * double quoted string literals
#   * the operators  =  ==  !=  <  <=  >  >=  AND  OR  NOT
#   * matched parentheses
#
# Everything else is rejected: backticks, pipes, commas, subsearch brackets,
# single quotes, semicolons, dollar signs, and any function call at all.
# Rejection is by allowlist and never by blocklist, because a blocklist is a
# list of the attacks somebody happened to think of.
#
# A rule naming a field that is not on the allowlist is rejected rather than
# evaluated. That is the second reason the allowlist exists, and on most days
# it is the one that earns its keep: in SPL an unknown field is null and a
# comparison against null is false, so a misspelt identifier makes a rule that
# never fires, with no error, no log line and no result. An operator would go
# on believing the escalation was running. Rejecting the rule turns that
# silence into a loud failure at validation.
#
# The allowlisted fields, all computed on the finding before any rule runs:
#
#   rk_esc_attack_vector          "N", "A", "L", "P", ""
#   rk_esc_impact_c               "N", "L", "H", ""
#   rk_esc_impact_i               "N", "L", "H", ""
#   rk_esc_impact_a               "N", "L", "H", ""
#   rk_esc_reach_rank             3, 2, 1, 0, -1
#   rk_esc_load_rank              3, 2, 1, 0
#   rk_esc_eol_support            "supported", "vendor extended support",
#                                 "supported by the distribution",
#                                 "distribution lifecycle unknown",
#                                 "no supported release", ""
#   rk_esc_has_fix                1, 0
#   rk_esc_sole_listener          1, 0
#   rk_esc_root_autorun_writable  1, 0
#
# Each is a normalised value, never a raw lookup output. The prefix is the
# point: world_writable arrives from the scanner as the string "true" on some
# hosts, as 1 on others and blank on every Windows host, and a rule must not
# be one more place that has to know that. Compare against the vocabularies
# above and nothing else.
#
# An empty string is not a negative. rk_esc_eol_support = "" means the
# lifecycle feed has never heard of the component, and rk_esc_impact_a = ""
# means the advisory carried no CVSS v3 vector. Absence of a measurement is
# not a measurement of absence, and a rule that reads it as one fires hardest
# on exactly the components about which least is known.
bump = 1
# How many tiers the rule raises the finding. The only accepted value is 1.
#
# A rule raises by one tier and can never produce P0. P0 stays the
# deterministic scorer's to give, so the top of the queue is always something
# the five signals agreed on rather than something a local rule decided. Two
# rules matching one finding still move it one tier: escalations do not stack,
# because a finding matched by three rules is not three times worse, it is one
# finding somebody has three reasons to look at.
enabled = <boolean>
# Whether the rule runs. Every rule in default/ ships with enabled = 0 and
# that is not caution, it is the app's posture: nothing changes a risk number
# without a person deciding it should. A rule arriving switched on with an
# upgrade is an ordering change the site did not ask for, on a Tuesday, with
# no ticket and nothing to point at.
#
# Switch on one rule at a time and look at what moved. A rule that escalates a
# large share of the queue is not an escalation, it is a rescoring, and the
# honest place for a rescoring is the scorer.
# Default: 0
