# Observed permitted traffic evidence

## What this document is

Riskability decides today whether a vulnerable thing is exposed by looking at
how its process bound a socket. A wildcard bind reads as *answers any address*,
and the app has been willing to turn that into an exposure zone called
`internet-facing`.

That label asserts something the collector cannot observe. swinv runs **on** the
host. From there it cannot see NAT, a firewall rule, a security group, a reverse
proxy or a load balancer. A wildcard bind on a machine with no route to anything
is reported the same way as a wildcard bind on a machine sitting on a public
address, because from inside the host the two are identical. Exposure in a real
estate is usually several security layers stacked on top of each other, and the
socket is only the innermost one.

Firewall logs record exactly the layer the host collector cannot see. This
document describes what the app does with them, and it spends most of its length
on what that does **not** entitle anyone to conclude, because the ways this
feature can mislead are more interesting than the ways it can help.

The feature is additive. A site with no firewall data behaves exactly as it did
before. This change set produces the evidence and exposes it; it moves no
scoring weight, and whether the evidence should ever influence ordering is a
separate decision for a later commit.

---

## What a permitted edge is, and what it proves

The input is a set of unique permitted edges, reduced from a firewall index:

```
index=<fw> action=allowed
  | stats count AS sessions, min(_time) AS edge_first_seen,
          max(_time) AS edge_last_seen BY src_ip, dest_ip, port
```

One row means: at some time inside the searched window, at least one flow from
`src_ip` to `dest_ip` on `port` traversed an enforcement point that logs to this
index, and that enforcement point permitted it.

**That is the whole of it.** Written out, the row proves:

* a flow was permitted, at some time T inside the window
* the device that logged it was in the path at T
* the device was configured, at T, to allow that tuple

It does **not** prove:

* **that the rule is still in place.** The window may be a month wide. Rules
  change, and no edge disappears retroactively when one does.
* **that the path is bidirectional.** A permitted SYN says nothing about whether
  anything came back.
* **that a service answered.** Layer 3 and layer 4 permission is not a layer 7
  response. A permitted flow to a closed port is still a permitted flow, and it
  is still logged as allowed by a device that allows it.
* **that the host still holds that address.** See *Identity drift* below, which
  is the longest section here for a reason.
* **that anything was exploitable.** A firewall log records addresses, ports and
  a verdict. It records no credential, no privilege and no trust relationship.

## Why the term is never "reachability"

The term used throughout the app and this document is **observed permitted
traffic evidence**. Never "reachability", never "reachable", never
"exposed" on its own.

The distinction is load bearing rather than fussy. "Reachable" is a claim about
the present tense and about the world: it says that if you tried this now, you
would get through. Nothing in a log can support a present-tense claim. What the
log supports is a past-tense observation: something got through once, and it was
permitted when it did.

Every word in the term is doing work.

* **Observed**: it happened and was recorded. Not inferred, not modelled, not
  read out of a rule base nobody exported.
* **Permitted**: the enforcement point allowed it. Not that it succeeded, not
  that it was answered.
* **Traffic**: a flow, at layer 3 and 4. Not a service, not an application, not
  a session that completed.
* **Evidence**: something attached to a finding to help a person judge it. Not a
  verdict, and not a number that reorders a queue on its own.

The vocabulary is enforced in the one place that decides a grade: no function in
`bin/riskability/route.py` returns a boolean a caller could mistake for
reachability, and the four grade strings are constants rather than literals
scattered through SPL. If a panel, a field name or a piece of prose in this app
ever shortens the term to "reachable", that is a defect, because the shortened
form is the claim the evidence cannot carry.

---

## The error direction flips, and the new direction is worse

This is the single most important thing to understand before trusting the
feature, and it is not intuitive.

**The old label over-claims.** A wildcard bind becomes `internet-facing`
regardless of five layers of network control in front of it. The failure mode is
a finding that looks more urgent than it is. Somebody patches something that did
not need patching first. That is waste, and waste is visible: the person doing
the work notices.

**An observed-edge graph under-claims, and it does so systematically.** A
firewall rule that permits traffic nobody has sent generates no log line, so it
generates no edge. The evidence then says "no observed edge" for a path that is
wide open and merely untried. The failure mode is a finding that looks safer
than it is.

Under-claiming produces false reassurance, and false reassurance in this product
is worse than noise. A person who is told a service is noisy checks it. A person
who is told a service was never reached stops looking. The evidence quietly
argues for doing nothing, and nothing is exactly what an attacker needs from the
defender.

So the absence of an edge is never rendered as safety. It is rendered as
absence, and it is graded rather than counted.

### The evidence is strongest at the boundary and degrades inward

There is one nuance that makes the under-claim uneven rather than uniform, and
the app encodes it rather than glossing it.

**Internet scan pressure is constant.** Anything permitted from an internet
entry point to a listening port gets touched, usually within hours, by
somebody's scanner. So at the boundary hop, the absence of an edge is
comparatively informative: if the segment is covered by logging, the feed is
current, and nothing has ever been permitted inbound to that address and port,
that absence means something.

**Inward, it means very little.** East-west traffic is driven by what the estate
happens to do. A permitted path from one internal segment to another that no
application has ever used produces no edge for years, and "nobody tried yet" is
the ordinary state of most internal permitted paths rather than an exception.

Three mechanisms carry that asymmetry rather than averaging it away.

* A site declares each entry point's **scan pressure** as `constant` or
  `occasional`. Only a constant pressure entry point, which is true of the
  internet and of very little else, produces an informative absence.
* Confidence in a positive **decays per hop** away from the entry point.
* Confidence in an absence is **materially lower for an internal entry point**
  than for a public one, and the reason string on the row says so in words.

---

## The four grades

The term is graded, and it is never a boolean. Four states, and the vocabulary
is fixed in `route.py` so that panels, fields, escalation rules and prose all
use the same words.

| Grade | Means | Typical cause |
|---|---|---|
| `confirmed observed` | A permitted flow to this host's address and port was logged within the freshness window, from a declared entry point | Anything reachable from the internet edge, and most things actually used internally |
| `historically observed` | Such a flow was logged, but not within the freshness window | A path used once during a migration, or a service that has since gone quiet |
| `unknown` | The question could not be answered | No firewall data, coverage of the segment incomplete, the feed itself stale or empty, or the address could not be tied to exactly one host |
| `not observed` | The segment is covered, the feed is current, and no permitted flow to this host and port has been logged from the declared entry point | A genuinely quiet path, subject to everything in the section above |

Three rules govern the grades.

**`unknown` never collapses to `not observed`.** They are different answers to
different questions. `not observed` says the app looked at data that could have
contained an edge and found none. `unknown` says the app could not look. Any
code, panel or export that treats a missing value as `not observed` has erased
the distinction the whole feature exists to preserve, and any grouping that
sorts them together is wrong even when the counts look tidier. The floor is
applied in the macro that attaches evidence to findings: a row with no evidence
becomes `unknown`, so a missing lookup, an empty collection or a host the join
has never reached cannot present as `not observed`.

**A coverage gap is asymmetric, and the code says so on one line.** An
incomplete feed cannot invent an edge, so it does not weaken an edge that was
seen. What it destroys is the ability to say an edge was *not* seen. So partial
coverage leaves a positive alone and turns every negative into `unknown`.

**Every grade carries its reason.** A grade on its own is not evidence. Each row
records why it got the grade it did: which entry point, how many sessions, when
the edge was last seen, how many hops, how the address resolved to this host,
and, when the answer is `unknown`, which cause applied. A person should be able
to disagree with the grade by reading the reason, without querying the firewall
index themselves. A `unknown` row that does not say why it is unknown is a bug.

### Confidence is separate from the grade

A grade says which of the four sentences is true. A confidence says how much
weight the sentence carries, and it moves with things the grade cannot express:
how many sessions were behind the edge, how many hops from the entry point, and
whether an absence was observed at a boundary under constant scan pressure or on
an internal path where absence is close to worthless. A positive never falls to
zero confidence however far away it was seen, because a positive is never worth
nothing.

---

## Missing firewall data reduces confidence, never the score

Most sites will not have firewall logs onboarded into this Splunk instance.
Several will have them for one perimeter and not for the internal fabric. That
is the normal case, not a misconfiguration.

**A host must never be reported as unexposed because the customer did not send
data.** Absence of evidence is not evidence of absence. This is not a new
position for this app: the retire gate on every per-host rollup already passes a
host that has no row in `riskability_hoststate`, deliberately, so that an empty
or broken host state cannot empty a downstream collection. The same direction of
failure applies here. When the evidence layer knows nothing, it says so, and
everything downstream behaves as it did before the layer existed.

Concretely:

* **No firewall data configured.** Every finding grades `unknown`, with a reason
  that says nothing is known about permitted traffic to this host and that this
  is not evidence that nothing can reach it. Priorities, tiers and scores are
  byte for byte what they were.
* **Coverage incomplete.** Findings on covered segments grade normally.
  Elsewhere the grade is `unknown`, because a permitted path could exist through
  an enforcement point that does not log here.
* **The feed has stopped.** If the newest edge anywhere in the feed is older
  than the staleness threshold, every negative collapses to `unknown`: the
  absence of an edge is a broken forwarder until proven otherwise. This is a
  feed health check rather than a per host one, because the newest edge anywhere
  is the clock on the ingestion pipeline.
* **The feed is present but empty.** Also `unknown`. Silence from a feed that
  has produced no events at all cannot be read as quiet.

An empty result set and an unconfigured feature look identical in SPL, and this
is where that fact bites hardest. A search that returns nothing must be
distinguishable from a search that could not run, which is why coverage is
recorded separately rather than inferred from the edges that happened to turn
up, and why an unrecognised coverage value raises rather than defaulting: a
config typo that defaulted to full coverage would turn into a fleet reported as
unexposed.

---

## Identity drift, the failure this join introduces

Neither app has this problem alone. The join manufactures it.

A firewall log records that `10.2.3.4:445` was permitted at time T1. swinv
records that host `A` holds `10.2.3.4` at time T2. Joined on the address, the
system concludes that host `A`'s vulnerable SMB service was reached from
outside. Both records are correct. The conclusion can be entirely false, because
nothing in either record says the address meant the same machine at T1 and T2.

One reviewer called it identity laundering, and the name is fair: a weak,
time-bound association is passed through a join and comes out the other side
looking like a fact about a host, silently, at scale, with a confident label on
the front.

### The worked example

A site scans with swinv nightly at 02:00 and sends the results to Splunk.

* **13:40**, Tuesday. The DHCP lease on `10.2.3.4` expires. The desktop that
  held it, a laptop that has gone home, does not renew.
* **13:50**. The address is handed to a different machine, a contractor's laptop
  that has just joined the wireless network.
* **14:02**. The perimeter firewall logs a permitted inbound flow to
  `10.2.3.4:445`. It is a scanner, and the enforcement point allowed it.
* **22:15**. The contractor leaves. The address goes back into the pool.
* **02:00**, Wednesday. swinv runs on `fileserver-07`, which was given
  `10.2.3.4` overnight. The scan reports `fileserver-07` holding `10.2.3.4`.
* Riskability matches `fileserver-07` against the feed and finds a critical SMB
  vulnerability.

Joined naively, the app now reports that a critical SMB vulnerability on
`fileserver-07` was reached from the internet, and puts it at the top of
somebody's queue. Nothing in that sentence is true. The flow at 14:02 reached a
contractor's laptop, which does not run SMB, and `fileserver-07` did not hold
the address until twelve hours later.

DHCP is the easiest version to narrate. The same manufacture happens with:

* **NAT.** The address in the log is a translated one. It belongs to a mapping,
  not to a machine, and the mapping is a configuration that changes.
* **Virtual addresses and clusters.** The address moves between nodes on
  failover. Both nodes report it, at different times, quite correctly.
* **Load balancer front ends.** The address belongs to the balancer. The hosts
  behind it never hold it and never report it.
* **Containers and bridges.** A container address is reused constantly by
  whatever the runtime scheduled next, and `172.17.0.2` belongs to a different
  container on every host in the fleet.
* **Any address the estate reuses on purpose.** Test benches, imaging VLANs,
  build agents.

### The time window, and why it cannot be tightened away

The obvious guard is to join a firewall edge only to a host observation that is
close to it in time. That is the right guard, and it is weaker than it looks,
because of what swinv actually records.

**swinv has no first-seen or last-seen for an address.** There is no per
address, per interface or per MAC timestamp anywhere in the collector's output.
The only clock near host identity is the scan itself. A host's address is
therefore a **point observation**, not an interval. The app knows the host held
that address at the instant of the scan and nothing else.

**The `--since` delta does not help.** It diffs components only. A host changing
its IP address, its MAC set or its whole interface inventory produces no delta
entry and no warning at all.

So the interval this app holds is an **observation bound**, and the app calls it
that rather than calling it a lease. The host certainly held the address between
the first and the last scan that saw it, and it probably held it for some
unknown time either side. On a nightly scan the hole at each end is a day wide,
which is far wider than a DHCP lease. Tightening the window means scanning more
often, and no interval a site can afford makes the join safe on its own. The
window narrows the hole. It does not close it.

Because the bound is an observation and not a fact, the resolver's tolerance
defaults to **zero**. Widening a claim window is the caller asserting that an
address did not move between two scans, and that assertion is not in the data.
It is a number a site has to type rather than one it inherits, and an edge that
falls just outside a bound is treated as unresolved rather than as a match or a
miss.

### A refusal to resolve is a first class answer

When the address cannot be tied to exactly one host at the moment the flow was
observed, the result is a refusal, recorded with its reason, and that is a
**complete and correct answer** rather than a gap to be filled in later by a
heuristic.

This is the rule that keeps the whole feature honest, so it is stated as plainly
as possible: **the app would rather say nothing about a host than say something
about the wrong host.** A best guess here is not a smaller version of the right
answer. It is a different host's evidence, attached to this host's finding, with
the app's own credibility lent to it.

Asking who held an address requires saying when, so the observation time is a
mandatory argument rather than a convenience: the version of the question
without a time has no true answer, only a plausible one. Six outcomes come back
in the same shape, and only one of them is a host:

| Outcome | What it means |
|---|---|
| `resolved` | Exactly one host held the address across the observation. The only outcome that names a host |
| `shared` | Two or more hosts held it at the same time, so it is a shared address, a virtual address or a NAT mapping rather than one machine |
| `reassigned` | Several hosts have held it at different times and none held it at the observation, so the flow cannot be attributed |
| `stale` | The only host that ever claimed it did not hold it at the observation, so the inventory is too old or too young to say |
| `outside estate` | No host in the inventory ever claimed it. This is the **expected** answer for an internet entry point and not a failure, which is the case that shows the shape is right |
| `malformed address` | Not an address, so no host can be held to it |

Even a `resolved` answer carries a confidence that falls when the evidence for
it is thin: when the observation sits in the tolerance rather than inside the
window, when the claim is open at the end so holding it is an extrapolation past
the last scan, when the address has been held by several hosts over time and so
demonstrably moves, and when some claim on the address could not be read, which
means another host may have held it unseen. A claim with no readable bound
counts its host as a claimant and never as a holder, so an unreadable record can
only ever push the answer towards a refusal.

### Where the addresses come from, and why that is narrow on purpose

The join needs to know which addresses a host holds. As things stand the
collector does not tell this app.

swinv records `host.ipv4` and `host.ipv6`, documented as the non-loopback
addresses of interfaces that are up. Those fields reach its JSON report, its
CycloneDX output and its HTML report. **They are on none of its NDJSON records,
and NDJSON is the only thing this app ingests.** No `ipv4`, `ipv6`, `macs` or
`interfaces` key exists on any NDJSON record type.

So the honest source today is the bind address of a listening socket. A process
bound to a **specific** address proves the host holds that address, which is a
sound inference and a narrow one: it sees only addresses something is listening
on, so a host with no specific binds contributes nothing and is reported as
having no known addresses rather than as having none. The source is a macro,
`riskability_host_addresses`, so that when the collector puts host addresses on
the heartbeat a site replaces one definition and nothing downstream changes. A
site with authoritative address records from a CMDB, a DHCP server or DNS, which
are systems that **do** hold first-seen and last-seen, has better identity data
than either of these two apps can produce, and pointing that macro at them makes
every guard above stronger.

Three exclusions in the default definition are identity guards rather than
tidiness:

* **Wildcard and loopback binds.** `0.0.0.0` and `127.0.0.1` are not addresses
  anybody routes to.
* **Link-local addresses.** An `fe80::` address is not unique across hosts, so
  joining on one would merge unrelated machines.
* **Container binds.** An address inside a container's network namespace belongs
  to the container, not to the host. Attributing one to the host is precisely
  the false entity equivalence this whole section exists to prevent.

---

## What a site has to configure

Two macros, edited in `local/macros.conf`. Both ship resolving to nothing, and
until at least the first is wired up the feature grades everything `unknown` and
changes no number anywhere.

Both are called with **no leading pipe**, at the start of a search. The shipped
stub and a real `index=...` definition both parse that way, and neither parses
with a pipe in front of it.

### The edge macro

`riskability_fw_edges` supplies the unique permitted edges:

```
[riskability_fw_edges]
definition = index=firewall action=allowed \
| stats count AS sessions, min(_time) AS edge_first_seen, \
    max(_time) AS edge_last_seen BY src_ip, dest_ip, port
```

The field contract is seven fields, all required except `protocol`:

| Field | What it is |
|---|---|
| `src_ip` | Source address of the permitted flow |
| `dest_ip` | Destination address |
| `port` | Destination port, numeric |
| `protocol` | `tcp` or `udp`. Omit it and the match ignores protocol, which is recorded on the evidence row rather than assumed away |
| `sessions` | How many flows were permitted |
| `edge_first_seen` | Epoch of the earliest permitted flow on this edge |
| `edge_last_seen` | Epoch of the latest |

The two timestamps are an addition to FW Route Explorer's shape and they are not
optional. Without `edge_last_seen` there is no freshness, and without freshness
every grade collapses to `unknown`, which is the shipped behaviour already and
not worth scheduling a job for.

The reduction belongs on the indexers, and it is the only part of this feature
that touches raw firewall volume. A site with an accelerated data model over
months of history supplies the same seven fields from a `tstats` variant
instead: the contract is the shape of the output, not the way it was computed.

### The entry point macro

`riskability_fw_entry_points` declares what counts as coming from outside.
Evidence is only interesting relative to somewhere an attacker could plausibly
start, and this app has no way to guess which of a site's ranges that is.

| Field | What it is |
|---|---|
| `entry_cidr` | A CIDR, or a bare address, which is treated as a `/32` or `/128` |
| `entry_name` | What to call it on screen |
| `entry_scan_pressure` | `constant` or `occasional` |

`entry_scan_pressure` is the field that carries the boundary asymmetry.
`constant` means unsolicited traffic arrives at this boundary continuously,
which is true of the internet and of very little else. **Only a constant
pressure entry point can produce a `not observed` grade**, because only there
does the absence of an edge mean anything. Anything else, and anything unset,
degrades to `unknown`.

### The thresholds

Four macros, each a number with an argument attached to it in the comment
beside it rather than buried in a `case()`.

| Macro | Ships as | What it decides |
|---|---|---|
| `riskability_fw_fresh_days` | 7 | Newer than this is `confirmed observed`; older drops to `historically observed` |
| `riskability_fw_stale_days` | 2 | How old the newest edge in the whole feed may be before the data is declared stale and every negative collapses to `unknown` |
| `riskability_fw_absence_days` | 30 | How long a confirmed path must have been unobserved before it reappearing counts as a regression rather than as ordinary quiet |
| `riskability_fw_identity_grace_days` | 7 | Slack on each end of an address observation bound. An edge just outside a bound is unresolved, not a match and not a miss |

None of the four is a safe default, and each comment says which way it
misleads. Seven days for freshness is a compromise: too short and a genuinely
permitted path that is merely quiet gets demoted every week, so the grade tracks
traffic volume rather than policy; too long and a rule removed months ago still
reads as confirmed.

### What happens when a site configures neither macro

Nothing changes, and that is the requirement rather than a consolation.

Every finding grades `unknown`. No panel empties, no count moves, no priority
shifts, and no page implies the fleet is quieter than it was yesterday. What a
reader is owed at that point is the sentence "this is not configured", which is
a different sentence from "no exposure found", and anywhere the two collapse
into one empty table is a defect rather than a cosmetic problem.

The half-configured case is worth stating separately, because it is the one a
site can arrive at by accident. **Edges wired up, entry points forgotten**: with
no entry point declared, nothing can be graded `not observed` at all, because
"no permitted path from nowhere" is not a finding about the world. That site
gets `unknown` everywhere rather than a fleet that quietly reports itself
unexposed, and the same is true if the entry macro is broken rather than empty,
because an edge is marked as coming from an entry point only by a positive
match.

---

## A ledger, not an attack path generator

The artefact is a per host and per port evidence ledger, attached to findings.
It is not a generated multi-step narrative of how somebody gets in.

The reason is not squeamishness about presentation. It is that **permitted
network edges are not exploitability edges.** A firewall log says a packet was
allowed. Moving from one machine to the next after a compromise needs a
privilege, a credential, a trust relationship, an unpatched service that
actually answers, or a person who clicks something. A firewall records none of
those and cannot record them. A chain of permitted edges rendered as an attack
path takes evidence about packets and puts an exploitability badge on it, and
the badge is the part that was never measured.

The failure to avoid is specific: a path graph wearing an attack-path badge. It
is convincing, it is easy to build once the edges exist, it produces exactly the
kind of picture people screenshot for a steering committee, and its central
claim is unmeasured. The objection was never that the first hop is wrong. The
first hop is often the best-evidenced thing in the app. The objection is what
happens to the meaning of the picture at hop two.

That decision is enforced rather than described. Everything this app writes is
**one hop**: a direct edge from a declared entry point to an address the host
itself holds, which is the only claim it can make honestly. The second hop
exists as an extension point, `riskability_fw_route_expand`, and it ships as a
no-op, because the `hops` field on an evidence row has to mean something. A site
that replaces that definition to append two-hop rows must mark them `hops = 2`,
and must accept that it has left what the evidence supports.

What the ledger does instead is boring and defensible. For a finding it says:
this host, this port, this grade, this entry point, this many sessions, last
seen at this time, this many hops, resolved to this host by this address inside
this bound, or not resolved at all and here is why. A person reads that and
draws their own conclusion about what it means for their estate, which is a
thing they are qualified to do and the app is not.

Two joins refuse rather than guess, and both refusals are worth knowing about:

* **A finding scoped to a container is graded `unknown`.** A container's
  published port is a host port, but nothing in this app records the mapping
  between the two, so joining a container finding to a host port would attach
  evidence about one listener to a finding about another.
* **A package with no listening port on this host is graded `unknown`**, with
  the reason that no permitted edge could name it, rather than being counted as
  quiet.

Where a package answers several ports, the **strongest** evidence is kept rather
than the first or the weakest. Keeping the weakest would report a confirmed
observed path as `unknown` purely because the same package also answers a quiet
port, which is the under-claiming error this whole section is built around.

### Exposure regression detection

There is one derived signal that is cheap, needs no model, and is worth having:
say when the world changed.

A permitted route to a risky port from a sensitive entry point that is observed
for the **first time**, or that **reappears after an absence longer than
`riskability_fw_absence_days`**, is a change in the estate. Somebody added a
rule, moved a host, published a service or restored a configuration from before
a hardening exercise. That is worth an alert in a way that a static grade is
not, because it has a cause and a date, and somebody can go and find out what
happened.

The absence threshold is deliberately much longer than the freshness one. A path
that lapses to `historically observed` for a fortnight and comes back is a quiet
service rather than a change in the world, and alerting on that trains people to
ignore the alert that matters.

Note the direction this signal fails in, which is the good one. It fires on
appearance rather than on absence, so the under-claiming problem does not touch
it: an edge that shows up is a positive observation, and the constant scan
pressure at the boundary means a newly permitted internet-facing path shows up
quickly. It says nothing when nothing changes, and it never argues that a path
is safe.

---

## The relationship to FW Route Explorer

[FW Route Explorer](https://github.com/chaugan/Find-Route) is a separate Splunk
app by the same author, installed as `fw_route_explorer`. It reduces a firewall
index to unique permitted edges, runs a two-sided Dijkstra plus a budget-pruned
depth-first search to find routes between an entry point and a destination, and
renders the result as a tree. It is a network engineering tool, and it is good
at a question Riskability does not ask.

**Riskability does not depend on it, does not call it, and does not require it
to be installed.** What the two share is the edge contract: the same reduction
of a firewall index to unique permitted edges by `src_ip`, `dest_ip` and `port`,
with the two timestamps added here because grading needs a clock. A site that
already runs FW Route Explorer has done the reduction and points the edge macro
at the same summary. A site that has never heard of it writes the three line
reduction above and is finished.

The separation is deliberate in both directions. Riskability must not require a
second app to be installed to do vulnerability work, and FW Route Explorer must
not inherit Riskability's constraints on what may be claimed about a route.
Consuming a contract rather than an app is what keeps both true. If the contract
ever needs to change, it changes in a macro the site owns rather than in a
dependency the site has to upgrade.

---

## What this change set does not do

Stated plainly, so that none of it has to be discovered.

* **It does not change any scoring weight.** The deterministic priority weights
  are untouched. The evidence is produced and exposed, and whether it should
  influence ordering is a separate change for the owner to approve.
* **It does not replace the socket-binding exposure labels.** `reach_class`,
  `reach_rank` and `exposure_zone` behave exactly as they did. The new evidence
  sits beside them and is a different measurement of a different layer.
* **It involves no model.** Nothing on this path makes an outbound call, and
  nothing here reads or writes anything a model produced.
* **It builds no attack paths**, for the reasons above, and the second hop ships
  as a no-op rather than as a switch somebody might flip by accident.
* **It asserts nothing about layer 7.** A permitted flow is not a response.
* **It does not verify firewall rule bases.** It reads logs. A rule nobody has
  exercised is invisible to it, permanently, by construction.
* **It does not turn any escalation rule on.** A rule that names this evidence
  ships `enabled = 0` like every other shipped rule, and fires only on the
  `confirmed observed` grade, never on the absence of evidence. The rule
  language, its allowlist and its guards are in
  [docs/AI-ESCALATION.md](docs/AI-ESCALATION.md).
