# Choosing the model

The endpoint is configurable and this app is not bonded to any particular
model. This note records what the model is actually for, what was measured, and
how to test a replacement, so the next person choosing one is not choosing on
vibes.

## What the model is for, as of now

Two things changed, and together they changed the requirement.

**The priority is no longer the model's.** Asked for a 0 to 100 score on 1,020
real findings, Foundation-Sec-1.1-8B-Instruct produced seven distinct integers,
663 of them the single value 85, never once answered P3 or P4, and returned a
tier that contradicted its own score on 842 of them. The score is now computed
from measured facts and the model's number is recorded and ignored. See
`ai_config.priority_score`.

**Recall is forbidden.** A CVE published in six months is one no model has
heard of. Asking "what is this vulnerability" is asking for recall, and for a
CVE outside the training data the answer is invention delivered in the same
confident register as fact. The prompts now state that the model has never
heard of the CVE and must work only from the evidence block.

So the job is: read an evidence block, write a short honest explanation, answer
a few closed enums, and say plainly when the evidence does not establish
something. It is never trusted with a number.

## What that means for the choice

A security domain-tuned model was the right buy when the job was knowledge. It
is a worse buy now, and possibly an actively bad one: a model that has
memorised CVE patterns has MORE to leak past a "do not recall" instruction, not
less. The property to buy is context-boundedness, the trained-in habit of
treating the prompt as the only world, plus closed-enum discipline and a
willingness to abstain. Those are ordinary instruction-tuning properties.

## The grounding matters more than the model

Before spending an afternoon on model selection, check the evidence block. The
queue was fetching `cvss_score` and `title` from the advisory store and nothing
else, while that store held CVSS vectors on 85% of rows and CWE lists on 79%.
Wiring those through moved the share of queue rows carrying any description
from 19% to 91%, with 73% carrying a CWE and 61% a full vector.

A CVSS vector is the important one. It is machine readable, it is written by
the people who published the CVE, and it is accurate for a vulnerability
disclosed this morning regardless of when the model was trained:
`AV:N/AC:L/PR:N/UI:N` says network reachable, low complexity, no privileges, no
user interaction. A model that cannot recall a CVE can still read that
correctly. Grounding beats model choice here, and it is cheaper.

## How to test a candidate

Run it against the two cases in `tools/` style described below, on the real
endpoint, and score mechanically. The failure mode that matters is confident
invention about a CVE the model has never seen, so the test has to contain one.

1. **Grounded case.** A real recent CVE with a description, a CWE and a vector.
   Pass: every claim traceable to the evidence block. Fail: any statement about
   exploitation, affected components or impact that the block does not support.
2. **No-evidence case.** A FABRICATED CVE identifier with every descriptive
   field set to "not recorded", leaving only severity, EPSS, package and
   version. This is the important one, because any specific claim is invention
   by construction. Pass: the model says the evidence does not establish what
   the vulnerability does. Fail: anything else, including a hedged invention.
3. **Latency and residency.** One request warm, and whether it fits beside a
   second sequence slot at 16k context in 12 GB.

Measured on the reference RTX 3060 with the current prompts:

| model | grounded | fabricated CVE | notes |
|---|---|---|---|
| foundation-sec-8b (1.1-Instruct Q4_K_M) | 12.1s, worked from the description | 13.2s, correctly refused: "the advisory title, CWE, CVSS vector and other detailed information are not recorded" | ignores "no preamble" and writes a letter |

Candidates worth trying, and why: **llama3.1:8b** as the control, because
Foundation-Sec is a tune of exactly that base, so a match means the tune was
never the value; **qwen2.5 or qwen3 8B** for enum discipline; a **14B at Q4**,
which fits at one slot and trades concurrency for capability at roughly
0.18 requests a second.

One caution learned the hard way: a thinking model spends its token budget on
reasoning before it answers. qwen3:8b at a 380 token budget did not return in
the time the other two took to answer twice.

## The option worth considering before any of this

Every structured field expands deterministically. The CVSS vector has a fixed
grammar, the CWE has a canonical name, the reachability is measured. A template
renders all of that faithfully, is unit testable, costs nothing, cannot drift
when the model is swapped, and has no hallucination surface at all. The only
part that genuinely needs a language model is compressing a free-text advisory
description into one relevant sentence.

If the explanation is ever found to be adding little, the honest move is to
template the structured part and leave the model exactly one sentence to write.
That is a smaller feature than the one that exists, and a more defensible one.
