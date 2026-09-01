# Can the model raise a priority?

Short answer: yes, but never by writing a number, and the first move is not to
add a model at all.

## The question, and why it is not the one the model failed

The priority is computed from measured facts because the model could not be
trusted with a number: asked for 0 to 100 on 1,020 real findings it produced
seven distinct integers, 663 of them the value 85, and never once answered P3
or P4. See `docs/MODEL-SELECTION.md`.

That failure was on "rate this". The different question is "given everything
this app measured about this fleet, is there a path here that the fixed rule
set has no term for?" There is real headroom for it, because the score uses
five signals and the app measures far more:

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
Every fact is measured. No rule combines them.

## Do this before reaching for a model

Both examples above are ALREADY expressible as predicates over measured fields.
If "sole listener on the only resolver port in the fleet" cannot be written
today, that is a gap in the rule language, and the honest fix is to extend the
rule language. A model that proposes rules you could have written yourself is
an expensive way to notice you were missing a `for` loop.

Extend the terms first. Reach for the model only for the combinations nobody
thought to write.

## If the model is used, this is the shape

Four independent reviewers converged on the same mechanism, which is worth
recording because it is not the obvious one.

**The model proposes a RULE, not a priority.** It is given the measured facts
with stable field names, and it returns a predicate over those fields plus a
fixed bump. It never returns a score, never names a target tier, and never
decides how much to raise.

**The host evaluates the predicate. The model's prose is ignored for
enforcement.** A claim the engine cannot evaluate is not a rule; it is prose,
and belongs in the annotation layer beside the rationale.

**A proposed rule is evaluated across the whole estate before anyone accepts
it,** so its blast radius is visible rather than inferred from one finding.

**A human accepts it once, into a versioned rule set.** After that, ordering
remains a pure function of measurements and an inspected rule set. This is the
part that preserves the property the deterministic scoring bought: a model swap
changes what gets PROPOSED, never what gets ORDERED.

**A rule that keeps firing usefully graduates into the scorer and the model
comes off that path.** A per-finding bump that never graduates is exactly the
inflation this design exists to prevent.

Failure at any check: the escalation is void, the finding keeps its
deterministic score, and the proposal is logged as voided so the rejection rate
is measurable.

## Why citation checking is not enough

The obvious guard is to make the model cite the measured facts that justify its
escalation and void the claim if a citation does not resolve. That is necessary
and nowhere near sufficient, and the reason is worth stating plainly because it
is easy to feel safe with it.

Citation proves the model read the evidence. It does not prove the inference.
The failure mode is **valid citations, invalid composition**: a model can quote
the DNS listener and the vulnerable library perfectly, and still conclude the
library is reachable when the vendored copy's symbols never run on that path,
or read `AV:L` as remotely triggerable, or treat "cron runs as root" as
privilege escalation when the script is not writable, or infer "the only
resolver in the fleet" from a truncated host slice, or restate one of the five
existing signals as a new discovery.

And the gate has almost no discriminating power against the case it is meant to
catch: a model handed the evidence block cites it perfectly by construction, so
it passes nearly everything. The only check that binds is deterministic
re-evaluation of the claim itself.

## A reasoning model does not change this

Cisco ships Foundation-Sec-8B-Reasoning, advertised for exactly this work:
prioritising vulnerabilities by contextual risk, modelling attacker behaviour,
predicting attacker next steps. It is the model the original build spec named
for the T3 tier that was never built.

It may well propose better candidates and format them more usefully. It does
not change the honour path, because the failure being guarded is not a shortage
of deliberation. The collapse to 85 everywhere was not too few thinking tokens;
it was a distribution collapse. More chain of thought produces more fluent
wrong joins, and thinking harder is not a control boundary.

## How to tell insight from noise

If the escalation path fires on a few per cent of findings, that number alone
says nothing. Tag every honoured raise as provisional and hold a matched
control: findings in the same deterministic band that were not escalated.
Measure lift against the control on outcomes that arrive later and were not
available at decision time: a subsequent KEV listing, an EPSS band crossing, a
patch rather than a dismissal. Cluster the raises by rule and graduate only the
rules that show lift.

Kill the feature if, after a season, escalated findings show no lift against
the matched control; if a second model or a reworded prompt disagrees about
most of the escalations, which would mean the signal is the model rather than
the fleet; if a false escalation ever reaches the P0 or P1 alert path; or if
one cheap unused signal turns out to dominate every rule proposed. That last
one is not insight. It is a sixth weight, and it belongs in the scorer.
