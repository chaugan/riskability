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

So in a single attempt it produced valid field names, invalid composition, and
a restatement of an existing weight dressed as a discovery. Every one of those
is a failure the reviewers named in advance, and citation checking would have
passed all of them: every field it cited was real.

What caught it was the host evaluating the predicate. The rule is false against
the measured facts, so the escalation is void and the finding keeps its
deterministic score. That is the design working exactly as intended, on the
first real example, and it is the reason the honour path must be evaluation
rather than inspection.

Worth noting what it missed: the actual insight in that evidence, the sole
listener on the only resolver port in the fleet, was sitting in two fields it
did not use.

## Offensive tuning: wrong for two jobs, right for this one

An earlier survey dismissed offensive and red-team tuned models as pointing the
wrong way. That was too broad, and the owner was right to push back:
prioritisation IS an attacker-perspective question, and a model that hedges
about exploitation is worse at it, not better.

The distinction that holds up is per job.

* **Scoring: irrelevant.** The model is out of that loop entirely.
* **Explaining: a liability.** Recall is forbidden and the prose is what a human
  reads. An attacker-tuned model dramatises, and inventing an exploit path is a
  worse failure here than hedging.
* **Proposing escalation rules: an asset.** This is the one job where attacker
  framing is the right framing, and it is fail-closed, so an aggressive
  proposer costs a voided predicate rather than a wrong priority.

Measured, same prompt, same evidence block, same card. The block described a
CVSS 5.3 availability-only flaw in bind9, scored P4, in the sole process
listening on the only port 53 in the fleet.

| model | found the decisive field | predicate valid | time |
|---|---|---|---|
| Foundation-Sec-1.1-8B-Instruct (defensive) | no, used exposure_zone, already a scorer signal | no, invented the enum value "external" and contradicted the measurement | 14.9s |
| DeepHat-V1-7B, published earlier as WhiteRabbitNeo-V3-7B (offensive, Apache-2.0, Qwen2.5-Coder-7B base) | yes, process_is_sole_listener_for_port | yes, evaluates true | 150.3s |

The offensive model found the chokepoint the defensive one walked past, and
correctly reported that no existing signal covers it.

Two things temper that. Its rule is too broad: it bumps every sole listener,
without tying the bump to the CVE actually being an availability flaw or to
that port having one listener fleet-wide. A reviewer narrows it, which is the
loop working. And 150 seconds is ten times the Instruct variant, so this
belongs on a deliberate rule-proposal path, never in the hourly pass.

The sharper observation, and the one to keep: what the defensive model failed
at was not aggression, it was FIELD FIDELITY. It invented an enum value.
Nothing about offensive tuning buys fidelity either, and output-aggressive
training probably cuts against it. Offensive framing buys salience, knowing
which fact matters. The host evaluating the predicate is what buys fidelity.
Those are two different problems and only one of them is solved by the model.

## Two leaks the fail-closed argument does not cover

Fail-closed protects enforcement. It does not protect acceptance.

**The human is the unsound component.** The predicate is evaluated by the host,
but a person reads the prose to decide whether to accept the rule, and the
story is aimed squarely at them. The acceptance view must show the predicate's
counterfactual replay, which findings it would have bumped across history, not
the model's narrative.

**Individually sound rules compose.** Ten reasonable acceptances can rebuild the
distribution this project spent a day flattening, one sensible decision at a
time. The rule set needs its own guard: the share of findings bumped, capped or
alerted on, independent of any single rule's merit.

And the risk is not symmetric. A voided predicate is silent; inflation is
visible. The chokepoint the model misses costs more than the story it invents,
which argues for running the proposer wide and filtering hard rather than
prompting it to be cautious.

## The experiment that would settle attacker framing

Two controls, because otherwise the result measures lineage rather than tuning.
DeepHat is a Qwen2.5-Coder-7B finetune, so the control is that same base with a
defensively framed prompt. Foundation-Sec is a Llama-3.1-8B finetune, so its
control is vanilla Llama 3.1.

The discriminator is a **mutation test**, and it is cheap. Take a block where a
rule fired, then perturb the decisive fact: move the port from 53 to 5353, or
add a second listener so the process is no longer sole. A rule that found the
real path stops firing. A plausible story keeps firing, because story
predicates are invariant under semantically decisive mutations. That single
test separates insight from narrative better than any amount of reading the
rationales.

## A reasoning model does not change this

Cisco ships Foundation-Sec-8B-Reasoning, advertised for exactly this work:
prioritising vulnerabilities by contextual risk, modelling attacker behaviour,
predicting attacker next steps. It is the model the original build spec named
for the T3 tier that was never built.

Measured on the reference RTX 3060, both at Q4_K_M, same card, same Ollama:
the Instruct variant answered a grounded explanation prompt in 12.1 seconds.
The Reasoning variant, given one rule-proposal prompt with a 700 token budget,
had not returned after 181 seconds and was killed. That is more than fifteen
times slower on a comparable task, and the batch path has a 0.35 request per
second budget to work inside. Whatever else it is good for, it is not the
hourly pass. If it earns a place at all it is on the on-demand path, where a
person has asked about one finding and can wait.

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
