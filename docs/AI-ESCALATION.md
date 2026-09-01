# Escalation rules

## What this document is now

It used to ask one question: can the model raise a priority? The answer it
argued its way to was yes, but never by writing a number, and the first move is
not to add a model at all. That first move is now built, so this document is no
longer a proposal for an AI feature. It describes a rule engine that works
today, and it keeps the argument that shaped it because every guard in the
engine was designed against a failure that was measured rather than imagined.

The engine is deterministic. A rule is a predicate over measured fields plus a
fixed bump of one tier. It lives in a conf file, it is rejected at validation if
it names anything the app does not measure, it ships switched off, and a person
turns it on after being shown exactly which findings it moves. Ordering stays a
pure function of measurements and an inspected rule set.

**There is no model integration, and no part of the engine depends on one.** No
rule may name anything a model wrote, nothing here makes an outbound call, and
the language, its validator, its reference evaluator and its tests all run with
no endpoint configured and no model anywhere. A model may later become one
optional source of CANDIDATE rules. If that day comes, every control such a
source needs is already here as an ordinary feature: the host evaluates
predicates, replay shows blast radius before acceptance, the rule set has a
guard of its own, and mutation testing separates a rule that found a path from a
rule that tells a story. Those are not model safeguards bolted on afterwards.
They are how a person uses the engine when there is no model anywhere near it.

One limit, stated here rather than left to be discovered. As the app stands, the
only pipeline that APPLIES a bump is the verdict expansion search, and that
search ships disabled and stays disabled until an administrator switches AI
analysis on. So a site with AI off today has the rule language, the shipped
rules, the validator and the off-instance replay, and nothing that moves a tier.
Nothing in the engine's design requires that arrangement: closing the gap means
running the same stage on a path that does not wait for a model, which is a
scheduled search this app already has four of the shape of. As the tree stands,
that path is not written, and this document will not claim otherwise.

## The gap the engine closes

The priority is computed from measured facts because the model could not be
trusted with a number: asked for 0 to 100 on 1,020 real findings it produced
seven distinct integers, 663 of them the value 85, and never once answered P3 or
P4. See `docs/MODEL-SELECTION.md`.

That failure was on "rate this". The different question is "given everything
this app measured about this fleet, is there a path here that the fixed rule set
has no term for?" There is real headroom for it, because the score uses five
signals and the app measures far more:

* loader-accurate link records, which executable loads which library, resolved
  the way ld.so and the Windows loader resolve, vendored private copies included
* the listening process behind each open port, and the container it runs in
* cron, systemd, scheduled tasks, SUID binaries and autoruns, each already
  carrying a MITRE ATT&CK technique id
* end-of-life status per product
* the accepted-risk register, with justifications in free text

A CVSS 5.3 denial of service scored P4, sitting in the one process that answers
the only DNS port on the estate, stays P4. A low-severity local privilege
escalation on a host whose cron runs a world-writable script as root stays low.
Every fact is measured. No rule combined them.

Both of those examples are the shape of a predicate over measured fields, and
that is the insight the engine is built on. The missing thing was never
intelligence, it was a rule language, and a model that proposes rules you could
have written yourself is an expensive way to notice you were missing a `for`
loop. So the rule language came first, and it is usable on its own.

With one qualification the engine makes visible rather than hides. Two of the
fields those two examples need are not measured yet: nothing in the app groups
exposure by port, and the configuration surface has no per-host rollup. So the
DNS case can now be WRITTEN, and cannot yet FIRE, and the rules that express it
ship saying so. That is a better place than the one before it, where the fact
could not be stated at all, and it is a smaller job than it was: what remains is
one rollup search each, not a language.

## The rule language

One stanza per rule, in `riskability_escalations.conf`. `description` says what
the rule catches and why the five scoring signals cannot catch it, `when` is the
predicate, `bump` is how far it moves a finding, and `enabled` says whether it
runs.

```
[listener_loads_the_library]
description = A flaw in a library that a listening process actually loads, on \
  a host where the library's own package looks unexposed. ...
when = rk_esc_load_rank = 3 AND rk_esc_reach_rank < 1
bump = 1
enabled = 0
```

That is one of the four rules the app ships, and it is the one worth reading
first because every field it names is measured today. It exists because of a
join the scorer cannot make. Exposure is keyed on the host and on the FINDING'S
package, so a flaw in `libssl3t64` is given the reach of `libssl3t64`, which
owns no port, answers no address and reads as no listening port. The process
that does own the port is a different package entirely, and the record joining
the two is the loader-accurate link data, measured every hour and consulted by
no scoring signal. So the score steps the finding DOWN for being isolated at the
moment the measured evidence says a listener has the library mapped. The second
term, `rk_esc_reach_rank < 1`, is what keeps this a rule rather than a weight:
where the package is already scored as exposed, the five signals have the
finding covered and escalating there would be scoring exposure twice.

Five properties, each a decision rather than a detail.

**`when` is a Splunk eval boolean expression, evaluated natively by SPL.** There
is no new interpreter, and that is the point rather than a shortcut. SPL already
has one, it is what every other calculation in this app is written in, and an
operator can paste the expression into a search bar and see which findings it
selects before switching anything on. A second implementation of "what does this
predicate mean" is a second thing that can disagree with the first.

**Every identifier in `when` must appear in the field allowlist.** A rule naming
anything else is rejected at validation, never shipped, and never silently
evaluated. See the validator, below, for why that is the guard that earns its
keep on ordinary days rather than on hostile ones.

**`bump` is 1, structurally.** The compiled SPL computes `rk_esc_bump` as a
boolean over whether ANY rule matched, not as a sum with a `min()` over it, so
there is no expression anywhere in the fragment that can produce a 2. Alongside
it, `rk_esc_rules` carries every rule that matched, so an operator looking at an
escalated finding sees all three reasons even though only one tier was given.
Losing the other two would make the same finding unexplainable. A rule cannot
name a target tier and cannot set a score. It also cannot produce P0: the ceiling is
the `riskability_escalation_floor` macro, `"P1"`, so a P1 finding matched by a
rule stays P1 and the rule is a no-op on it. P0 stays the deterministic
scorer's to give, so the top of the queue is always something the five signals
agreed on rather than something a local rule decided, and a site-authored
predicate never sits next to a KEV listing on a confirmed internet-facing match
with nothing on the row saying which was which.

**Escalations do not stack.** The cap is one tier per finding per run, no matter
how many rules match it, and it is a macro so a site that wants matching rules to
compound can say so deliberately rather than by accident. That is a
guard rather than a preference, and the reason is visible in the shipped set
itself. A locally exploitable flaw in a library a listener loads, on an
unsupported product with no fix, satisfies three of the four examples without
any of them being wrong. Summing the bumps would move it three tiers on the
strength of one enablement decision per rule and no decision at all about the
combination, which is how a rule set stops being reviewable. A site that raises
the cap should then watch not how many findings moved but how many moved more
than once.

**Rules ship `enabled = 0`.** An escalation that arrives switched on is an
ordering change the site did not ask for: somebody upgrades on a Tuesday and the
queue is different on Wednesday, with no ticket, no decision and nothing to
point at. The shipped rules are worked examples with the reasoning attached, not
defaults.

`description` carries a requirement that is easy to read as a style note and is
not one. It has to say what the rule catches AND why the five signals cannot
catch it, and the second half is the one that matters, because a rule that fires
on something those five could have weighted is not an escalation. It is a sixth
weight applied to a subset, and it belongs in the scorer where it can be argued
with against the other five, rather than here where it looks like an exception
somebody made. Writing that half is the check that catches it before it ships.

## What a rule can name

Ten field names, all carrying the `rk_esc_` prefix. Eight of them are computed
by one macro, `riskability_escalation_facts`, on the finding before any rule is
evaluated, and that macro is the only place any of them is computed. Two are
named by the allowlist and computed by nothing yet, which is a state the engine
reports rather than hides.

What the macro computes and what the allowlist accepts have to move together,
and that is why the engine guards at both ends: the allowlist catches a
MISSPELLED field, the macro catches an UNMEASURED one, and only rejecting at
both ends makes a typo and a missing rollup fail differently from each other.
Collapsing them would make a rule that cannot work look exactly like a rule that
cannot work, with no way to tell which.

| field | values | measured today |
|---|---|---|
| `rk_esc_attack_vector` | `"N"`, `"A"`, `"L"`, `"P"`, `""` | yes, from the advisory's CVSS v3 vector |
| `rk_esc_impact_c` | `"N"`, `"L"`, `"H"`, `""` | yes, same vector |
| `rk_esc_impact_i` | as above | yes |
| `rk_esc_impact_a` | as above | yes |
| `rk_esc_reach_rank` | 3, 2, 1, 0, -1 | yes, hourly, per host and package |
| `rk_esc_load_rank` | 3, 2, 1, 0 | yes, hourly, and read by nothing in the prioritisation pipeline |
| `rk_esc_eol_support` | the five lifecycle values, or `""` | yes, per component |
| `rk_esc_has_fix` | 1, 0 | yes, from the finding |
| `rk_esc_sole_listener` | 1, 0 | **no** |
| `rk_esc_root_autorun_writable` | 1, 0 | **no** |

The prefix is the point rather than a naming habit. Each value is normalised,
never a raw lookup output, and `rk_esc_reach_rank` is the case that shows why
that is more than hygiene: the stored `reach_rank` on the reachability rollup is
3, 2, 1 or -1, with no branch that produces 0, and a binding whose bind scope
the rollup did not recognise is written -1 while the same row is labelled "no
listening port". A rule needs 0 to mean measured and not listening and -1 to
mean not measured at all, so the escalation stage reads the class and recomputes
the rank from it rather than passing the stored number through. A rule written
against the raw field would have read a measured host as an unmeasured one.

`world_writable` is the other case that proves the point. It arrives from the
collector as the string `"true"` on some hosts, as `1` on others and blank on
every Windows host, and two dashboard panels already test all three spellings. A
rule must never become the fourth place that has to know that.

An empty string is not a negative. `rk_esc_eol_support = ""` means the lifecycle
feed has never heard of the component, and `rk_esc_impact_a = ""` means the
advisory carried no CVSS v3 vector. Absence of a measurement is not a
measurement of absence, and a rule that reads it as one fires hardest on exactly
the components about which least is known.

**Two of the ten are not available to a rule today, and the document says so
rather than implying otherwise.** The validator marks both unproduced and
refuses any rule naming one. `rk_esc_sole_listener` needs a fleet-wide rollup
grouped by port, and nothing in the app groups exposure by port: it would first
have to
settle what counts as one listener, given that the raw exposure grain is one row
per host, port, protocol and package, and which hosts count as assessed, given
that a host running an older collector contributes no rows at all.
`rk_esc_root_autorun_writable` needs a per-host reduction of the configuration
surface, which is stored one row per mechanism and has no per-host rollup at
all. Reaching it from a finding without one costs a full scan of that collection
inside a join subsearch, which Splunk finalises silently at 50,000 rows or 60
seconds, and a rule whose fact quietly ran out of subsearch is the same silence
the whole design is arranged against.

Those two are absent from the escalation stage rather than stubbed to 0 or to
null, and rules that name them are refused rather than shipped. A stub is a
measurement the app does not have wearing the clothes of one it does, and a rule
over a stub reads as evaluated-and-false when the truth is not-yet-answerable.
So the honest state of the motivating example is this: the engine can express
it, the fact it turns on has still to be computed, and the file says so beside
the rule instead of leaving an operator to discover it from a queue that never
changes.

## What ships

Four rules, all `enabled = 0`, each with its reasoning written above it in the
file.

| rule | fires when | can fire today |
|---|---|---|
| `listener_loads_the_library` | a listening process loads the library and the library's own package is not scored as exposed | yes |
| `no_supported_release_no_fix` | the component's vendor has no supported release left and no fixed version is known | yes |
| `sole_listener_availability` | an availability-affecting flaw in the only process answering a port nothing else in the fleet answers | no, refused as unproduced until a fleet-wide rollup by port exists |
| `writable_root_autorun_local_flaw` | a locally exploitable flaw on a host whose scheduled or persistent mechanisms already run a world-writable target as root | no, refused as unproduced until the configuration surface has a per-host rollup |

The last one is deliberately blunt and its description says so: it escalates
every locally exploitable finding on such a host rather than a chosen one,
because the weakness belongs to the host and no measured field says which flaw
reaches the writable target. That is the sort of thing a description is for.
A reader can disagree with it before enabling it, which they cannot do with a
rule whose description only restates its predicate.

## The validator, and why it allowlists

`when` is read out of a conf file that any admin with write access to the app
directory can edit, and it is expanded into a scheduled search that runs on the
search head as the app. Whatever the validator lets through, the search head
runs. A permissive validator here is not a lax setting, it is SPL injection into
the app's own prioritisation pipeline, with the app's own privileges, on a cron,
on a machine that is deliberately air gapped. The validator is the control.

It accepts exactly this and nothing else: identifiers that appear in the field
allowlist, integer and decimal literals with a leading minus only where a number
may start, double-quoted string literals over a fixed charset with no escapes at
all, the operators `=` `==` `!=` `<` `<=` `>` `>=`, the keywords `AND` `OR`
`NOT`, and parentheses matched by parsing rather than by counting.

Refused, with what each would otherwise reach:

| refused | reaches |
|---|---|
| backtick | macro expansion, and therefore every macro in the app including the index macros |
| pipe | the next command, and therefore `delete`, `outputlookup`, `collect`, `sendemail` |
| square bracket | a subsearch, which takes the pipe restriction with it |
| comma outside a string | an argument separator, only useful next to a function call |
| semicolon | a second search |
| single quote | SPL's quoting for a field name containing anything at all, and the standard way out of a double-quoted context |
| dollar sign | token substitution, anywhere this string is later rendered into a dashboard or an alert action |
| backslash | both an SPL escape and a conf line continuation, so one character can end the setting and start the next |
| any identifier followed by `(` | a function call, refused whether or not the identifier is an allowlisted field |

There is no function this language needs, and every function is an argument
list, and an argument list is a comma away from somewhere else. Arithmetic is
absent for the same reason: negative numbers exist because `rk_esc_reach_rank`
is -1, but a minus as an infix operator would be the first crack in a grammar
whose whole value is that it contains no expressions, only comparisons.

Those refusals are the ones that matter today. **They are not the control.** The
control is that anything not named as accepted is refused, including whatever
nobody thought of, and that is the whole difference between an allowlist and a
blocklist.

Why that difference is not a preference. A blocklist has to enumerate every way
SPL can be made to do something, and SPL is a large language with hundreds of
eval functions, macro expansion, token substitution and subsearches, which grows
with each Splunk release. A blocklist is therefore a standing bet that no future
version adds a capability nobody thought to forbid, and that nobody finds an
encoding of one that is already there. Worse than the size of that bet is its
direction: a blocklist fails OPEN, because anything unanticipated passes. A
blocklist is a list of the attacks somebody happened to think of. An allowlist
fails closed, and it bets only on what a rule needs, which is ten field names,
some numbers, some strings, seven comparisons and three connectives. A grammar
that small can be read in one sitting and argued about, which is what makes it
reviewable at all.

Everything is bounded as well: the expression, its token count, the length of a
string literal, the rule name and the number of rules. The reason is the file
format rather than paranoia. A conf value is continued with a backslash, so a
value that runs away takes the rest of the stanza with it, and a rule nobody can
read is a rule nobody can review. Rule names are restricted to lowercase
letters, digits and underscores because a name is written into a double-quoted
SPL string literal in the compiled fragment, which makes that quoting safe by
construction rather than by escaping.

**And on most days the allowlist earns its keep on typos rather than on
attacks.** In SPL an unknown field is null and a comparison against null is
false, so a rule reading `rk_esc_load_rnak` would simply never fire: no error,
no log line, no result, and an operator who believes an escalation is running
when nothing is. That failure is silent for ever. This codebase has found the
"named upstream, evalled nowhere, silently empty" defect five separate times,
and it is the most expensive class of bug in it. Rejecting the rule turns the
silence into a loud failure at validation, and the rejection names the offending
token and its offset, because the person fixing it is reading a conf file and
has nothing else to go on.

### Three verdicts, because two questions

"The operator must be told" and "the rule must not run" are different questions,
and collapsing them loses one of the answers.

**Rejected.** Malformed, unsafe, or naming something that is not a field. Never
shipped.

**Unproduced.** Well formed and allowlisted, but naming a field nothing computes
yet. Also not shipped, and that is the point of the status existing: shipping it
would mean an operator switching on a rule that evaluates null for ever with
nothing anywhere saying so. This is what the two shipped rules over
`rk_esc_sole_listener` and `rk_esc_root_autorun_writable` do today. They are
refused with the reason said out loud rather than quietly running to no effect.

**Suspect.** Shipped, and reported. An equality against a value outside a
measured vocabulary, for instance `rk_esc_eol_support = "unsupported"` when the
measured value is `"no supported release"`. That is the same silent nothing as a
misspelt field, but the vocabularies come from feed data rather than from code,
so refusing would make the app the thing that decides what a feed is allowed to
say. It warns instead.

That third verdict is worth pausing on, because it is exactly the failure the
one real model proposal produced: a predicate over a real field comparing it to
`"external"`, a value that is not in that field's enum. A rule like that is well
formed, passes any syntax check, cites only measured fields, and cannot fire. It
is the reason the engine reports value vocabularies as well as names.

One further property, which is a decision rather than an implementation detail:
a malformed rule never disables the whole set. The engine degrades to the rules
that are sound, because the alternative is that one typo in one stanza silently
changes the priority of every finding in the estate, which is a bigger ordering
change than any rule in the file could make.

### What a rule may deliberately never name

Three things are absent from the allowlist on purpose, and the absences say more
about the design than the entries do.

**Anything a model wrote.** The verdict cache carries a tier, a score, a
confidence and a list of techniques, and not one of them may reach a rule.
Nothing a model says can move an ordering, and an escalation engine that could
read model output would be exactly that with extra steps.

**The five scoring signals themselves.** KEV, EPSS, CVSS, exposure zone and
version match confidence. A rule over those is a sixth scoring weight wearing a
rule's clothes, and it belongs in the scorer where it can be reasoned about
against the other five, rather than here where it fires on a subset and reads as
an exception somebody made. `rk_esc_reach_rank` looks like a counterexample and
is not: it is there so a rule can say WHERE the score already covers the finding
and decline to escalate, which is the opposite use.

**The accepted-risk register.** Findings reach this pipeline through the
`riskability_open_findings` macro, which excludes `accepted="1"` at source, so an
accepted finding is not escalated because it is not there. A rule that could
reach past an acceptance would make the register advisory, and the register is
the one place in this app where a human decision is final.

The validator itself is stdlib-only and Splunk-free, deliberately: a validator
that can only be run on a search head against a live KV store is a validator
nobody runs, and this one runs on a laptop.

## Where rules live, and how to add one

The rules that ship with the app are in its own
`default/riskability_escalations.conf`, each with the reasoning written above it. A site's own rules belong in
`local/riskability_escalations.conf`, which is ordinary Splunk layering:
`default` is the app's and is replaced wholesale on upgrade, `local` is the
site's and survives it. A rule edited in `default` is a rule an upgrade will
throw away, silently, along with whatever ordering it was producing.

Adding one is four steps, and the order is the point.

**1. Write the predicate against fields on the allowlist, and only those.**
Check each identifier against the list rather than trusting the name to be what
you remember. Say in `description` what path the rule claims exists and why the
five signals cannot see it. The mechanics in `when` are not in dispute; the
claim is.

**2. Put it in `local`, with `enabled = 0`.**

```
[unpatchable_in_a_listener]
description = A flaw in a library a listening process loads, on a product \
  whose vendor has no supported release left. Neither half is a scoring \
  signal: the load record is measured hourly and the scorer never reads it, \
  and lifecycle is measured per component and reaches no scoring input at \
  all, so the score describes a flaw that can be reached and says nothing \
  about there being nowhere to go once it is.
when = rk_esc_load_rank = 3 AND rk_esc_eol_support = "no supported release"
bump = 1
enabled = 0
```

**3. Validate it.** The rule set is validated when it is loaded, and a refused
rule is refused by name with the reason attached: the offending token and its
offset for a malformed one, the missing measurement for a rule over a field
nothing computes, a warning for a comparison against a value outside a measured
vocabulary. A refused rule does not become a disabled rule that might work
later. It is not part of the rule set at all, and the rules around it still
load, because one typo must never take an estate's ordering with it.

**4. Replay it, then enable it, then look at what moved.** Setting
`enabled = 1` is the whole of turning a rule on and setting it back to `0` is
the whole of turning it off. Nothing about an escalation is baked into a finding
in a way that has to be unwound, which is what makes the act reversible rather
than merely regrettable. A rule that escalates a large share of the queue is not
an escalation, it is a rescoring, and the honest place for a rescoring is the
scorer.

A rule that is on is not thereby permanent. See graduation, below.

**Checking a rule without a search head.** The rule language, its allowlist and
its validator are stdlib-only Python with no Splunk imports, and
`tools/test_escalations.py` exercises them on a laptop: every rejected token
class has its own case, on the principle that a validator with an untested
reject clause has an untested reject clause, and the one nobody wrote a case for
is the one that stopped working. The same module carries a reference evaluator
and a `mutate` helper, which is what makes replay and the mutation test
something a rule author can run while writing the rule rather than a review step
that happens to somebody else later. The suite passed on this working tree when
this document was written.

## Replay, and why a person must be shown blast radius

Fail-closed protects enforcement. It does not protect acceptance, and the
unsound component in this design is the human.

A predicate is evaluated by the host, but a person reads a sentence to decide
whether to accept the rule, and a sentence is aimed squarely at them. "An
availability-only flaw in the sole listener for a port" reads as narrow and
disciplined. Whether it is narrow is not a property of that sentence. It is a
property of this fleet, and two rules with identical descriptions can differ by
three orders of magnitude in what they touch, depending on what the estate
happens to run.

So the acceptance step is a counterfactual replay: compile the candidate rule on
its own, evaluate it over the findings as they stand, and write nothing. Same
predicate, same fields, same evaluator, differing from the live pipeline only in
that nothing is stored. What it has to show is a set of counts rather than a
paragraph: how many findings the rule bumps, on how many hosts, out of how many
it was evaluated against, which rules it overlaps with, and what the tier
distribution looks like before and after.

That last one is the number that matters most, because the distribution is the
thing this project bought and the thing a bad rule spends. The deterministic
score gives 1% of findings above the waterline and 17 distinct scores, where the
model-assigned priority gave 82% above the waterline and seven distinct scores,
663 of 1,020 findings sharing one of them. A rule that moves the first of those
numbers is visible in a replay before anyone lives with it, and invisible in any
description of the rule.

Two ways to take that reading exist today. Off the instance, the reference
evaluator applies a parsed rule set to evidence rows, which is what
`tools/test_escalations.py` uses and what makes a rule testable while it is being
written. On the instance, a rule is ordinary SPL over fields one macro computes,
so the same predicate can be run from a search bar against the open findings.
Neither is a packaged acceptance view, and no such view exists in this app today.

Replay is also what makes a rule arguable in a review. A count is not aimed at
the reader; a rationale is.

Two counts are worth naming separately, because a rule can be wrong in either
direction and only one of them is visible from the total. A rule that fires on
nothing is not safe, it is unfinished, and the usual cause is a comparison
against a value outside the measured vocabulary, which the validator warns about
for exactly this reason. A rule that fires on a large share of the queue is not
an escalation, it is a rescoring, and the honest place for a rescoring is the
scorer rather than a rule set whose whole premise is that it applies to the few
findings the five signals cannot see.

## The rule-set guard, and the composition problem it exists for

Every rule is judged on its own merits, and that is exactly why the set needs a
guard of its own. Ten individually reasonable acceptances can rebuild the
distribution this project spent a day flattening, one sensible decision at a
time, with no single decision that was wrong. Nobody in that story is careless.
The failure is compositional, so the control has to be compositional too.

The guard has two halves, and only one of them is a mechanism.

**The structural half is built and it bounds the worst case.** A bump is one
tier, capped in the compiled SPL by construction rather than by arithmetic; the
ceiling is P1, so no rule set of any size can put a locally authored predicate at
the top of the queue; a rule that would raise a finding past that ceiling is a
no-op on it rather than a partial success; and every rule ships off, so a set
grows only by decisions somebody made one at a time. Together those mean the
worst a badly chosen rule set can do is what the best-argued single rule in it
would have done.

**The measured half is a number rather than a mechanism, and it has to be
watched.** What share of open findings the enabled set bumps, and what share it
raises into the tiers that carry alerts. That is the question no rule can answer
about itself: how much of the ordering is now coming from rules rather than from
measurements. Every prioritised row carries whether it was escalated and by
which rule, so the number is one search away, but nothing computes it on a
schedule today and this document is not going to imply otherwise. A rule set is
reviewed by looking at it.

The asymmetry is worth keeping in view while reading that number. A rule that
never fires costs a finding that stayed where it was. Inflation costs the
waterline, which is the property the whole prioritisation rests on, and it
arrives gradually and looks like diligence the entire way.

The same asymmetry says something about any future source of candidate rules,
including a model. The chokepoint a proposer misses is silent and costs more
than the story it invents, because the story runs into replay, the guard and the
mutation test on its way in. That argues for running a proposer wide and
filtering hard rather than prompting it to be cautious, which is the opposite of
the instinct, and it is only affordable because the filters exist first.

## The mutation test

A rule that fires is not thereby a rule that found something. The discriminator
is cheap and mechanical: take a case where the rule fired, perturb the fact the
rule claims is decisive, and evaluate it again.

Worked example on `listener_loads_the_library`, whose two terms are
`rk_esc_load_rank = 3` and `rk_esc_reach_rank < 1`. It claims a specific path:
a listening process maps this library, and the library's own package is not
itself scored as exposed. Both halves are one field wide, so both are one
mutation wide.

| perturbation | what it makes false | the rule should |
|---|---|---|
| the listening loader stops loading it, so `rk_esc_load_rank` falls to 2 | a listener has it mapped | stop firing |
| the package acquires its own listening port, so `rk_esc_reach_rank` becomes 1 | the exposure signal cannot see it | stop firing, and correctly: the five signals now cover it |
| the host, the port number or the CVE id changes, with both ranks intact | neither claim | keep firing |

The third row is what gives the first two meaning. A rule that stops firing
under every perturbation is not sensitive, it is brittle, and one that keeps
firing under all three is not a rule about this fleet at all.

Mutating means destroying the fact, not swapping it for another one: the field
is set to unknown, because unknown is the state a lookup miss actually produces,
and "some other value" quietly chooses one, which for an ordering comparison
decides the answer on its own. A specific counterfactual is still available where
that is the point, such as taking `rk_esc_reach_rank` from 0 to 3. The field
being mutated is itself checked against the allowlist, and that check is not
tidiness: a mutation test that mutates a misspelt field mutates nothing, the rule
goes on firing, the assertion that it stopped is the one that fails, and the next
person deletes the assertion. Assert instead that the rule STILL fires and the
typo makes the test pass while proving nothing at all.

The same test on the motivating case is the one the argument below was settled
by: move the port from 53 to 5353, or add a second listener so the process is no
longer sole, and a rule that found the real path stops firing. A plausible story
keeps firing, because story predicates are invariant under semantically decisive
mutations. That separates insight from narrative better than any amount of
reading rationales. It is worth running on a rule a person wrote. It is the
entrance exam for any rule a model ever proposes.

One limit, stated rather than left to be assumed. The reference evaluator that
makes replay and mutation testable without a search head is a MODEL of SPL's
three-valued logic, not SPL. It has not been run against a Splunk instance as
part of this work. Trust it for what a rule's shape is and which facts a rule
depends on. It is not evidence of what a search head will return.

## Graduation, and what a rule that never graduates is

A rule that keeps earning its place belongs in the scorer.

That is not a reward, it is where such a thing should live. A signal that fires
usefully across the estate, month after month, is a sixth thing worth measuring:
it can then be computed for every finding, weighed against the other five,
ordered rather than bumped, and it stops occupying a slot in a rule set whose
whole footprint is under a guard. Graduation also takes it out of the acceptance
path entirely, which is where the unsound component is.

The inverse is the honest part. A rule that fires for a season and never
graduates has done one thing: it has raised some findings a tier. That is
inflation with extra steps, dressed as care, and it costs the waterline the same
way a bad rule does. The engine's own answer to "is this working" is the
graduation record. Rules that graduate were signal. Rules that neither graduate
nor get retired are the feature failing quietly.

The bookkeeping for this already exists rather than needing to be invented. An
escalated finding carries the tier the five signals gave it, a flag saying it was
escalated, and the names of the rules that matched, and its rationale gains a
sentence naming the move and the rule that made it, so "which rules are doing the
work" is a question the findings themselves answer and "why is this a P2" never
has to be reconstructed.
Graduating a rule then means two edits and a subtraction: the signal joins the
scorer, the rule is set back to `enabled = 0`, and the replay afterwards should
show the same findings sitting at the same tiers for a better reason.

How to tell which is which, on outcomes rather than on opinion, is at the end of
this document.

---

The rest of this document is the argument the engine was built out of. It is
kept because the guards above are answers to specific measured failures, and a
guard whose failure is forgotten is a guard someone eventually removes for being
in the way.

## If a model is ever added, this is the shape it must take

Four independent reviewers converged on the same mechanism, which is worth
recording because it is not the obvious one, and because the engine that now
exists is exactly its ground floor.

**The model proposes a RULE, not a priority.** It is given the measured facts
under the stable `rk_esc_` names and returns a predicate over those fields plus
the fixed bump. It never returns a score, never names a target tier, and never
decides how much to raise. The language it would write in is the one an operator
already writes in, which means a proposal is reviewable by the same reading.

**The host evaluates the predicate, and the prose is ignored for enforcement.**
A claim the engine cannot evaluate is not a rule; it is prose, and belongs in an
annotation beside the rationale where it changes nothing.

**A proposal is evaluated across the whole estate before anyone accepts it,** so
its blast radius is visible rather than inferred from the one finding that
prompted it.

**A human accepts it once, into a rule set that is a file under version
control.** After that, ordering remains a pure function of measurements and an
inspected rule set. That is the property the deterministic scoring bought and
the one this whole design exists to keep: a model swap changes what gets
PROPOSED, never what gets ORDERED.

**A rule that keeps firing usefully graduates into the scorer and the model
comes off that path entirely.** A per-finding bump that never graduates is the
inflation this design exists to prevent.

Failure at any check leaves the finding with its deterministic score, and the
proposal should be recorded as refused rather than dropped, so the rejection
rate is a number somebody can look at rather than an impression. None of this is
built, and none of it needs to be for the engine to be useful, which is the
point of building it in this order.

## Why citation checking is not enough

The obvious guard, if a model ever proposes rules, is to make it cite the
measured facts that justify its escalation and void the claim if a citation does
not resolve. That is necessary and nowhere near sufficient, and the reason is
worth stating plainly because it is easy to feel safe with it.

Citation proves the model read the evidence. It does not prove the inference.
The failure mode is **valid citations, invalid composition**: a model can quote
the DNS listener and the vulnerable library perfectly, and still conclude the
library is reachable when the vendored copy's symbols never run on that path, or
read `AV:L` as remotely triggerable, or treat "cron runs as root" as privilege
escalation when the script is not writable, or infer "the only resolver in the
fleet" from a truncated host slice, or restate one of the five existing signals
as a new discovery.

And the gate has almost no discriminating power against the case it is meant to
catch: a model handed the evidence block cites it perfectly by construction, so
it passes nearly everything. The only check that binds is deterministic
re-evaluation of the claim itself, which is what the engine does with every rule
whatever wrote it.

## What happened when this was actually tried

One shot, the Instruct variant, the rule grammar above, and a hand-built
evidence block describing the DNS example: a CVSS 5.3 availability-only flaw in
bind9, scored P4, in the sole process listening on the only port 53 in the
fleet, with exposure_zone measured as "internal".

It answered in 14.9 seconds with a well-formed, machine-checkable rule. The
mechanism works: the model can emit a predicate over named fields rather than
prose. And then:

```json
{"field": "exposure_zone", "op": "eq", "value": "external"}
```

The evidence block says exposure_zone is "internal", and "external" is not even
a member of that field's enum. Its stated reason was "indicating it may be
exposed to the internet", which contradicts the measurement it had been given.
It also set already_covered_by to null while proposing a predicate over
exposure_zone, one of the five signals the scorer already weighs.

So in a single attempt it produced valid field names, invalid composition, and a
restatement of an existing weight dressed as a discovery. Every one of those is a
failure the reviewers named in advance, and citation checking would have passed
all of them: every field it cited was real.

What caught it was the host evaluating the predicate. The rule is false against
the measured facts, so the escalation is void and the finding keeps its
deterministic score. That is the design working exactly as intended, on the first
real example, and it is the reason the honour path must be evaluation rather than
inspection.

Worth noting what it missed: the actual insight in that evidence, the sole
listener on the only resolver port in the fleet, was sitting in two fields it did
not use.

## Offensive tuning: wrong for two jobs, right for this one

An earlier survey dismissed offensive and red-team tuned models as pointing the
wrong way. That was too broad, and the owner was right to push back:
prioritisation IS an attacker-perspective question, and a model that hedges about
exploitation is worse at it, not better.

The distinction that holds up is per job.

* **Scoring: irrelevant.** The model is out of that loop entirely.
* **Explaining: a liability.** Recall is forbidden and the prose is what a human
  reads. An attacker-tuned model dramatises, and inventing an exploit path is a
  worse failure here than hedging.
* **Proposing escalation rules: an asset.** This is the one job where attacker
  framing is the right framing, and it is fail-closed, so an aggressive proposer
  costs a voided predicate rather than a wrong priority.

Measured, same prompt, same evidence block, same card. The block described a CVSS
5.3 availability-only flaw in bind9, scored P4, in the sole process listening on
the only port 53 in the fleet.

| model | found the decisive field | predicate valid | time |
|---|---|---|---|
| Foundation-Sec-1.1-8B-Instruct (defensive) | no, used exposure_zone, already a scorer signal | no, invented the enum value "external" and contradicted the measurement | 14.9s |
| DeepHat-V1-7B, published earlier as WhiteRabbitNeo-V3-7B (offensive, Apache-2.0, Qwen2.5-Coder-7B base) | yes, process_is_sole_listener_for_port | yes, evaluates true | 150.3s |

The offensive model found the chokepoint the defensive one walked past, and
correctly reported that no existing signal covers it.

Two things temper that. Its rule is too broad: it bumps every sole listener,
without tying the bump to the CVE actually being an availability flaw or to that
port having one listener fleet-wide. A reviewer narrows it, which is the loop
working, and the narrowed version is the worked example at the top of this
document. And 150 seconds is ten times the Instruct variant, so this belongs on a
deliberate rule-proposal path, never in the hourly pass.

The sharper observation, and the one to keep: what the defensive model failed at
was not aggression, it was FIELD FIDELITY. It invented an enum value. Nothing
about offensive tuning buys fidelity either, and output-aggressive training
probably cuts against it. Offensive framing buys salience, knowing which fact
matters. The host evaluating the predicate is what buys fidelity, and the field
allowlist is what buys it before the predicate ever runs. Those are two different
problems and only one of them is solved by the model.

## The experiment that would settle attacker framing

Two controls, because otherwise the result measures lineage rather than tuning.
DeepHat is a Qwen2.5-Coder-7B finetune, so the control is that same base with a
defensively framed prompt. Foundation-Sec is a Llama-3.1-8B finetune, so its
control is vanilla Llama 3.1.

The discriminator is the mutation test, which is now a feature of the engine
rather than a proposed experimental step. Take a block where a rule fired, then
perturb the decisive fact: move the port from 53 to 5353, or add a second
listener so the process is no longer sole. A rule that found the real path stops
firing. A plausible story keeps firing.

## A reasoning model does not change this

Cisco ships Foundation-Sec-8B-Reasoning, advertised for exactly this work:
prioritising vulnerabilities by contextual risk, modelling attacker behaviour,
predicting attacker next steps. It is the model the original build spec named for
the T3 tier that was never built.

Measured on the reference RTX 3060, both at Q4_K_M, same card, same Ollama: the
Instruct variant answered a grounded explanation prompt in 12.1 seconds. The
Reasoning variant, given one rule-proposal prompt with a 700 token budget, had
not returned after 181 seconds and was killed. That is more than fifteen times
slower on a comparable task, and the batch path has a 0.35 request per second
budget to work inside. Whatever else it is good for, it is not the hourly pass.
If it earns a place at all it is on the on-demand path, where a person has asked
about one finding and can wait.

It may well propose better candidates and format them more usefully. It does not
change the honour path, because the failure being guarded is not a shortage of
deliberation. The collapse to 85 everywhere was not too few thinking tokens; it
was a distribution collapse. More chain of thought produces more fluent wrong
joins, and thinking harder is not a control boundary.

## How to tell insight from noise

This is the measurement behind graduation, and it applies to rules a person
wrote just as much as to any a model might one day propose.

If the escalation path fires on a few per cent of findings, that number alone
says nothing. Tag every honoured raise as provisional and hold a matched control:
findings in the same deterministic band that were not escalated. Measure lift
against the control on outcomes that arrive later and were not available at
decision time: a subsequent KEV listing, an EPSS band crossing, a patch rather
than a dismissal. Cluster the raises by rule and graduate only the rules that
show lift.

Retire the engine, or a rule in it, if after a season escalated findings show no
lift against the matched control; if a false escalation ever reaches the P0 or P1
alert path; or if one cheap unused signal turns out to dominate every rule
written. That last one is not insight. It is a sixth weight, and it belongs in
the scorer.

If a model is ever added as a source of candidates, one further kill criterion
applies to that source rather than to the engine: if a second model or a reworded
prompt disagrees about most of the escalations, the signal is the model rather
than the fleet.
