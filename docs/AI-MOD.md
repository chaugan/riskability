# The AI analysis mod

Riskability's core promise has always been that no data leaves the search
head unintentionally. This mod does not break that promise; it makes a
second, louder one next to it: **the pipeline is invisible until an
administrator deliberately configures it, and the only hosts it ever contacts
are the ones that administrator typed into the configuration page.** Nothing
here calls out until somebody sets an endpoint URL, and setting one is the
deliberate act that makes egress possible: from that point the page's test
buttons reach the endpoint even with the master switch off, because you have
to be able to prove an endpoint answers before you trust the fleet to it.

A model reads what Riskability has already measured (severity, CVSS, EPSS,
KEV status, the advisory title, the fleet's worst-case reach and version
evidence) and returns a priority: a tier from P0 to P4, a score, a rationale
written in prose, concrete mitigations and the ATT&CK techniques that apply.
The model runs on a GPU box on your own network (the reference build is a
single RTX 3060 12 GB; anything larger only makes it faster). No cloud
service sees your fleet unless an administrator points the pipeline at one.

Two facts shape everything below, and both differ from what an earlier draft
of this design assumed.

* **The CVE, not the finding, is the unit of analysis.** One verdict is
  produced per CVE, cached, and then expanded onto every affected host by
  deterministic SPL. A CVE on five thousand machines costs one model call,
  not five thousand.
* **Splunk pushes. Nothing pulls.** A custom search command runs on the
  search head, reads the queue, calls the endpoint and writes the verdicts
  back into the KV Store. Nothing runs on the GPU box except the inference
  server itself: no orchestrator, no queue reader, no HEC writeback.

---

## 1. What was added

| Package | What it is | Where it installs |
|---|---|---|
| `riskability-config` | **New.** The configuration app: feed administration (moved here) and the AI analysis settings. Readable only by `admin` and `sc_admin`. | Search head |
| `riskability` | The main app. Gains the AI capability and endpoints, the `riskabilityaianalyze` search command, the four AI saved searches, the verdict cache collection, and one new dashboard that removes itself when AI is off. Feed admin UI **moved out** to the config app. | Search head |
| `TA-riskability-ai` | **New.** The three pipeline indexes and their sourcetype parsing. | Indexers (single instance: everywhere) |

Install order: `TA-riskability-ai` and `TA-riskability-indexes` on the
indexers, then `riskability` and `riskability-config` on the search head. The
config app links to the main app's data and vice versa; both ship in the same
release.

### The two apps, and why

Everything an analyst needs sits in the main app. Everything that *changes*
how the app works sits in `riskability-config`, whose
`metadata/default.meta` grants read access to admins only:

```ini
[app/ui]
access = read : [ admin, sc_admin ], write : [ admin ]
```

The feed administration page moved there from the main app. The main app's
nav no longer mentions it; its first-run setup view now points at the config
app. The REST endpoints the pages call stay registered in the main app and
guard themselves by **capability**: `admin_all_objects` for the feed,
`riskability_ai_admin` for AI. The app-level restriction is ergonomics and
the capability is the control. A site can hand the model endpoint to one team
and the feed to another by granting the two capabilities differently.

---

## 2. The guarantee about normal users

**If no administrator ever switches AI on, a normal user sees no AI anywhere
and cannot learn it exists.**

Concretely:

* The one AI endpoint a normal user can reach is `GET /riskability/ai_status`.
  While AI is off it answers exactly one bit, `{"enabled": false}`, and
  nothing else: no URL, no model name, no hint that any AI component exists.
  Only once an admin has switched the pipeline on does the same reply start
  carrying the overview payload the page draws.
* The "AI prioritization" page ships with read permission restricted to
  admins (`[views/riskability_ai]` in default.meta), and Splunk filters
  navigation entries by view read permission **server side**. So while AI is
  off, the page is not in anyone's navigation bar at all, not even for the
  instant before a script could hide it, and a user who types its URL gets
  Splunk's own 404, exactly as for a page that does not exist. Switching AI
  on rewrites the view's ACL to everyone; switching off closes it again. A
  JavaScript gate runs anyway as belt and braces, drawing nothing unless the
  status endpoint says on.
* The master switch owns all four AI saved searches and writes their
  `disabled` flag together, so switching AI off stops every schedule the
  pipeline has.
* The search command refuses to work by itself as well: `riskabilityaianalyze`
  reads the master switch before anything else and raises rather than contact
  any endpoint while AI is off. A user who found the command name and typed it
  into the search bar gets an error, not a request.
* All four AI stanzas ship with `disabled = 1` in
  `default/savedsearches.conf`, so on an instance where nobody has ever
  opened the configuration page nothing is scheduled and nothing appears in
  the job system. An earlier draft of this mod shipped them enabled, which
  leaked no data (the analysis command refused to contact anything and the
  expansion had no verdicts to expand) but did leak the pipeline's existence
  into the job list and fired the daily watch every day for want of a result.
  The master switch owns the flag from then on.
* No existing dashboard changed by one character. Riskability's numbers are
  exactly what they were.

Switching AI off reverses the pipeline: page vanishes, schedules stop, no
further findings are sent. It does not disarm the configuration page's test
buttons, which reach the configured endpoint whatever the switch says, and
which is what makes it possible to fix an endpoint without turning the fleet
back on.

---

## 3. The pipeline

Three saved searches an hour, all on the search head, plus a daily health
watch. Nothing else moves.

```
┌───────────────────────── search head ──────────────────────────┐
│                                                                │
│ :50  Riskability AI - generate candidate queue                 │
│        open findings → one row per distinct CVE, worst case    │
│        across the fleet; T0 extremes decided in SPL and        │
│        dropped; verdict-cache hits dropped; ordered KEV first  │
│        then EPSS; cut to the budget                            │
│                          │ collect                             │
│                          ▼                                     │
│              index=riskability_ai_candidates                   │
│                          │                                     │
│ :52  Riskability AI - analyze latest queue                     │
│        | riskabilityaianalyze   (chunked=true, local=true)     │
│        cache read → thread pool → schema validation → upsert   │
│              │                             │                   │
│              ▼                             ▼ HTTPS             │
│      KV riskability_aiverdicts     POST /v1/chat/completions   │
│        (the cache, and the                  to the configured  │
│         dashboard's source)                 model endpoint     │
│              │                                                 │
│ :55  Riskability AI - expand verdicts to findings              │
│        one verdict per CVE × per-asset adjustment              │
│                          │ collect + KV summary row            │
│                          ▼                                     │
│              index=riskability_ai_prioritized                  │
│              index=riskability_ai_alerts (P0 and P1 only)      │
│                                                                │
│ 06:15 Riskability AI - results stopped arriving                │
│        fires when a full day passed with no result at all      │
└────────────────────────────────────────────────────────────────┘
```

### :50 The candidate queue

The `riskability_open_findings` macro, reduced to one row per CVE. Each row
carries the fleet's worst case for that CVE: reach class and listening
evidence from `riskability_reach_lookup`, CVSS and advisory title from
`riskability_advisory_lookup`, KEV status, and the version-match verdict
Riskability already computed.

Three filters run before the budget cut, in this order:

1. **T0, deterministic.** KEV plus internet-facing plus confirmed version
   match plus CVSS 7 or above is P0 without a model; CVSS under 4 plus EPSS
   under 5% plus not KEV plus not internet-facing plus a version that is not
   in the affected range is P4 without a model. Both rules are written in SPL
   here and again, identically, at expansion time, so a CVE that never
   reaches the model still gets its tier. (`ai_config.t0_rules` is the same
   pair in Python. The shipped pipeline runs the SPL copies; the Python one
   is what the test suite exercises, which is also what would catch the two
   drifting apart.)
2. **The verdict cache.** Each row's content signature (`rk_sig`) is compared
   against the signature stored on the cached verdict for that CVE. Equal
   means the stored verdict still applies and the row is dropped from the
   queue entirely.
3. **The budget.** What survives is ordered KEV first, then by EPSS
   descending, and cut to `riskability_ai_candidate_cap`. The cut is
   deliberately at the tail of an urgency ordering: the rows that fall off
   are the least urgent ones known this hour, and they are still in the
   queue next hour.

### :52 The analysis

`riskabilityaianalyze` is registered `chunked = true` and `local = true` in
commands.conf. `local` is not a preference. The command must run on the
search head, because that is where the stored secret is readable, where
`riskability_ai.conf` lives and where the outbound route to the endpoint
exists.

What one run does:

* Loads the configuration and the secret through `riskability/ai_settings.py`,
  and refuses to continue if the master switch is off.
* Recomputes any missing signature with `riskability/ai_config.verdict_sig`,
  and backfills finding context from `riskability_findings_state` for rows
  whose queue copy has gone stale. Context is display material; if that read
  fails the analysis still runs.
* Reads every input CVE's cached verdict in one KV query. A signature match
  is served from the cache: no model call, and the row is marked
  `analysis_source = cache`.
* Sends the rest to the endpoint through a `ThreadPoolExecutor` sized by
  `t2_concurrency`, one OpenAI-compatible chat completion per CVE, bounded by
  `candidate_cap` so one run can never cost more than the budget.
* Validates every answer against the schema in `ai_config.validate_result`
  before it is allowed anywhere: tier, score, confidence, rationale and the
  four enumerated signals must all be right, mitigations must be a list of
  strings, and technique ids that do not look like technique ids are dropped
  rather than voiding an otherwise sound answer.
* Upserts each verdict into `riskability_aiverdicts`, keyed `cve:<CVE id>`,
  carrying the signature it was computed for, the latency, and the finding
  context the prompt used.
* Emits one row per input CVE. A CVE the model could not answer for gets an
  explicit conservative placeholder (P2, score 50, confidence 0.0, a rationale
  that names the failure) marked `analysis_source = fallback`. A CVE beyond
  the budget gets `analysis_source = deferred` and **no verdict at all**.
  Neither is ever dressed up as an analysis, and neither is written to the
  verdict cache: a failure that cached itself would stop the CVE ever being
  asked about again.

The saved search ends in a `stats` that counts verdicts, model calls,
fallbacks and cache hits, so the job history for the run says what the run
cost.

### :55 The expansion

The verdict is about a CVE. A finding is about a CVE on a particular host,
and the difference between those two is not something to ask a model twice.
The expansion search joins the cached verdicts back onto every open finding
and adjusts deterministically:

| Signal | Effect on the score |
|---|---|
| internet-facing / internal / isolated | 0 / -5 / -15 |
| version match yes / unknown / no | +10 / -5 / -25 |
| asset criticality high / low | +5 / -5 |

The result is clamped to 0-100 and banded into tiers at 85, 65, 45 and 25.
The model's score is a fleet worst case, so per-asset adjustment mostly steps
down from it. T0-decided findings take their fixed tier instead. A finding
whose CVE has no verdict, or whose verdict is older than seven days, is left
out of the results rather than given an invented tier: waiting is honest,
guessing is not.

The same search writes the dashboard's summary row into the
`riskability_aistate` collection, which is why the AI page runs no searches
at all when it loads.

### Why the search head calls the model

Determinism is load-bearing. Which CVEs get analysed, in what order, with
which prompt and on which schedule are all decided by Splunk and by plain
Python. The model sees one CVE at a time, answers in a strict schema, and
every answer is validated before it is stored. The model is the only
non-deterministic component in the pipeline, and nothing autonomous decides
anything.

Putting the queue consumer in the search command rather than on the GPU box
buys three things: the GPU box needs no Splunk credentials and no HEC token,
there is exactly one place where a verdict can be written, and a failure has
a job id and a search log instead of living in someone else's journal.

### What is deliberately not here

* **No orchestrator.** The GPU box runs an OpenAI-compatible inference server
  and nothing else. `docs/GPU-ENDPOINT-SETUP.md` is the brief for standing
  that up, and it stops where the endpoint answers.
* **No HEC writeback.** Results are written by `collect` from a search head
  search, under the search head's own identity.
* **No deep-reasoning second tier.** `t3_max_tokens` and `t3_deep_threshold`
  are still validated settings and still appear on the admin page; nothing in
  the shipped pipeline reads them. They are honest to leave configurable and
  dishonest to describe as active, so they are described here as inert.
* **The ATT&CK BERT classifier is optional and ships off.** `bert_url` is
  empty by default, and with it empty every technique comes from the model's
  own answer. Set it and the pipeline does use it: `riskabilityaianalyze`
  attaches the configured URL to each call, and `analyze_finding` posts the
  CVE description and process ancestry chain there for a tactic pre-tag
  before the chat request goes out. That makes it a second endpoint receiving
  fleet-derived text, which section 8 counts as such. The URL is taken from
  the configuration and never from the candidate row, so an event written into
  the queue index cannot aim that POST somewhere else.
* Some module docstrings in the AI code still describe the earlier
  orchestrator shape. The code around them does what this document says; the
  prose above them has not caught up.

### The verdict signature

A cached verdict is valid only while the signature it was computed for still
matches. The signature is computed in two places that must agree exactly: as
an `md5()` in SPL in the queue and expansion searches (field `rk_sig`), and
in Python in `riskability/ai_config.py verdict_sig()`. If the two ever
disagree, every CVE re-analyses forever and the cache silently stops being a
cache, so the pair is worth reading together before either is touched.

What it covers, and why each part:

* the CVE id, the severity, and the KEV bit, because any of those changing
  changes the answer;
* CVSS and EPSS as **bands**, not raw numbers: CVSS split at 4, 7 and 9, EPSS
  at 1%, 5%, 20% and 50%. SPL's `tostring` and Python's `str` disagree about
  how to render the same float ("14" against "14.000000"), and a signature
  that drifts between the SPL writer and the Python writer re-analyses
  forever. Banding takes the float out of the comparison and keeps the
  signal: a CVE that crosses a band boundary is re-analysed, one that wobbles
  inside a band is not;
* the advisory title, because a revised description is a revised prompt;
* a salt, `"<schema version>:<model name>"`, so that changing the model or
  the prompt invalidates every stored verdict at once. A verdict is one
  model's judgement under one prompt, not a fact about the CVE, and neither
  half of that should be quietly attributed to a successor. The schema half
  is `SIG_SCHEMA_VERSION` in `riskability/ai_settings.py`, one line to bump
  when the prompt or the answer schema changes. The whole string has exactly
  one home, the `riskability_ai_sig_salt` macro: the SPL half expands it
  directly, the Python half is handed the same expansion, and saving the
  connection settings re-stamps it from the model name.

Deliberately excluded: anything per-asset (exposure, version match, asset
criticality). Those are applied by the expansion search after the verdict, so
they can never trigger a model call. Freshness is time-bounded on top of the
signature: the expansion treats a verdict older than seven days as stale.

---

## 4. Configuring it (admin flow)

Open **Riskability Configuration → AI analysis**:

1. **Connection.** Endpoint URL (OpenAI-compatible, no `/v1`), auth style
   (`none`, `bearer` for vLLM's `--api-key`, `basic` for a proxy), the model
   name exactly as `/v1/models` reports it, and TLS verification. The secret
   is typed once, stored in **Splunk's encrypted storage-password store**,
   and never sent back to any browser: the page learns only `password_set`.
   *Test connection* probes `/v1/models`; *Test analysis* sends one synthetic
   CVE (the xz backdoor, which every security model has seen, so a P4 answer
   is itself diagnostic) and validates the reply end to end.
2. **Hardware profile.** A preset (RTX 3060 12 GB / RTX 4090 / A100-H100 /
   custom) fills concurrency, token budgets, the request timeout and the
   queue budget. Edit anything afterwards. Four of those numbers reach the
   shipped pipeline: `t2_concurrency`, `t2_max_tokens`, `request_timeout` and
   `candidate_cap`. Concurrency describes what the **model server** serves in
   parallel rather than how eager this app is; it ships at 1, and section 6
   has the measurements behind that. Worth knowing before you touch the
   dropdown: the presets still carry the numbers chosen before those
   measurements (the 3060 preset sets concurrency 8 and a queue of 2,000), so
   selecting one overwrites the shipped defaults with numbers the reference
   box does not support. Selecting a preset is a decision, not a reset.
3. **Master switch.** *Switch AI analysis ON*. This schedules the three
   pipeline searches and the health watch, publishes the enabled bit, opens
   the dashboard's ACL to everyone, and not before. Note what it does not
   gate: the two test buttons above it call the endpoint whether it is on or
   off, by design, so an admin can prove the connection before committing the
   fleet's data to it. Neither test sends fleet data. *Test connection* only
   asks for the model list, and *Test analysis* sends the synthetic CVE.

Saving re-stamps two macros from the settings it just wrote:
`riskability_ai_candidate_cap` from the `candidate_cap` field, and
`riskability_ai_sig_salt` from the model name. A saved search can expand a
macro and cannot read a conf file, so this is the bridge that keeps one
source of truth. Hand editing `riskability_ai.conf` leaves both macros
stating the previous values until somebody presses Save; edit the macro too,
or press Save once.

The queue is bounded by that budget (shipped at 1,000 distinct CVEs a run)
and ordered by exploit urgency, so the budget limits cost rather than
quality: what falls off the end is the least urgent thing known this hour,
and it is still there next hour. `request_timeout` is the one setting that
must fit the slowest hardware you will run. A loaded 12 GB card answering a
long prompt can legitimately need a minute, and a timeout shorter than the
card produces the same symptom as a broken endpoint.

---

## 5. Indexes, sourcetypes and the fields that travel

Created by `TA-riskability-ai` on the indexers; named in the main app through
the `riskability_index_ai_*` macros.

| Index | Sourcetype | Written by | Retention |
|---|---|---|---|
| `riskability_ai_candidates` | `riskability:ai:candidate` | the :50 queue search, by `collect` | 7 days |
| `riskability_ai_prioritized` | `riskability:ai:prioritized` | the :55 expansion search, by `collect` | 14 days |
| `riskability_ai_alerts` | `riskability:ai:alert` | the same expansion search, in an `appendpipe`, P0 and P1 rows only | 1 year |

All three are `KV_MODE = auto`, because `collect` writes Splunk's stash
format (`key="value"`), not JSON. `KV_MODE = json` on a stash event extracts
nothing at all and reports success, which is the worst kind of empty.

The alerts index is the one to check if you knew this app before: it was
defined and documented as the feed for SOAR or chat forwarding, and until
this change set nothing wrote to it, because its writer was the HEC design
that was abandoned. The expansion search now writes it, from the same rows it
prioritises, in a branch that cannot disturb the main one.

Two stores carry the state the dashboards actually read, and neither is an
index:

| Collection | What it holds |
|---|---|
| `riskability_aiverdicts` | one row per analysed CVE: the verdict, the signature it was computed for, when and how it was produced, and the finding context the prompt used |
| `riskability_aistate` | the enabled bit `/riskability/ai_status` serves, and the summary row the expansion search writes |

Field mappings worth knowing, because they are judgements rather than
transport:

* Riskability ships no CVE prose corpus, so the queue's `cve_description` is
  the advisory's `title`: one honest sentence per CVE rather than invented
  detail.
* `version_match` is Riskability's own match confidence (`high` becomes
  `yes`, `informational` becomes `no`, anything else `unknown`).
* `exposure_zone` comes from measured reach (answers any address becomes
  `internet-facing`, no listening port becomes `isolated`, and a host where
  exposure was never assessed stays `unknown` rather than being flattened
  into the calmest value).
* `asset_criticality` defaults to `medium` through the
  `riskability_ai_asset_criticality` macro. Riskability has no asset register
  to read one from; a site that has one overrides the macro with an eval
  against its own lookup.
* `asset_id` is the one mapping that is currently broken rather than
  judged. The queue emits the fleet-worst host as `worst_asset` and the
  prompt reads `asset_id`, so the model is handed an empty asset on every
  request. Section 8 says what that means for what actually leaves.

---

## 6. What to expect at scale

Measured on the reference box: RTX 3060 12 GB, Ollama serving
Foundation-Sec-1.1-8B-Instruct Q4_K_M.

* One analysis call on its own answers in about **3.1 seconds**.
* At `t2_concurrency = 8`, the median across 21 real verdicts was **23.4
  seconds** each. Individual verdicts arrived roughly seven times slower.
* Aggregate throughput was **0.34 CVEs per second at eight threads against
  0.32 single threaded**: about six per cent, which is nothing. A single card
  serving a single model is saturated by one request, and the extra threads
  queue inside the server where nothing can see them.

That measurement is why `t2_concurrency` ships at 1. The setting stays because
a server configured for real parallelism (vLLM batching, Ollama's
`OLLAMA_NUM_PARALLEL`) will use it, but it describes the model server's
capacity, not this app's appetite, and a number above the server's own buys
latency rather than throughput.

The consequences, stated plainly rather than dressed up:

* The reference box sustains roughly **1,150 to 1,220 verdicts an hour**,
  which is why `candidate_cap` ships at 1,000: one run's work, with headroom,
  inside the hour it has before the next run starts.
* First runs are therefore slow. A fresh install has every distinct open CVE
  waiting, and at a thousand model calls an hour a backlog of ten thousand
  CVEs is most of a day. It drains in urgency order, KEV first and then EPSS,
  so the useful part arrives first, but it drains over hours and not minutes.
* Nothing is lost while it drains. CVEs beyond the budget are reported as
  deferred, never given a placeholder tier, and they return to the head of
  the next queue.
* **The cache is what makes the steady state cheap.** Once a CVE has a
  verdict it costs nothing until one of its signature inputs moves. Every run
  after the first is dominated by newly seen CVEs, which on a settled fleet is
  a small fraction of the catalogue.
* **One edge in the cache, stated rather than glossed.** The expansion search
  drops a verdict older than seven days (`rk_stale`), while the queue search
  reselects a CVE only on a signature mismatch and never on age. A CVE whose
  signature never moves therefore falls off the AI prioritization page a week
  after it was analysed and is not requeued. Changing the model name rotates
  the salt and requeues everything, which is the blunt way back; matching the
  two windows is the real fix and is not in this change set.
* Faster hardware moves the constant, not the shape. Measure the sustained
  rate on your own card, raise `candidate_cap` to what fits inside an hour of
  it, and the same pipeline finishes sooner.

These numbers are one card, one quantisation, one prompt shape. Measure your
own before promising anyone a completion time.

---

## 7. Testing before the hardware exists

The admin page speaks the OpenAI chat-completions dialect, so every control
works against a hosted endpoint. Bearer auth, the hub's model id, and:

| Hub | Base URL | Notes |
|---|---|---|
| **Hugging Face Inference Providers** | `https://router.huggingface.co/v1` | The home of `fdtn-ai/Foundation-Sec-8B` and `sarahwei/MITRE-v15-tactic-bert-case-based`, the models the reference build uses. An HF token is the bearer secret; availability of a given model depends on the provider routed to. |
| **OpenRouter** | `https://openrouter.ai/api/v1` | Open-weight models including DeepSeek-R1-Distill-Qwen-7B; good for exercising the pipeline shape with a different model. |
| **Together AI** | `https://api.together.xyz/v1` | Hosted Qwen and DeepSeek open weights. |
| **Ollama, local** | `http://127.0.0.1:11434/v1` | `ollama pull` a GGUF (a Foundation-Sec-8B or cybersecurity Qwen quant, say); a laptop stands in for the GPU box at small scale. |

Two local things also help:

* `python3 tools/ai_mock_server.py --port 8000 --delay-ms 300` stands in for
  the inference server (and for the classifier sidecar) in one process, with
  simulated latency. Point the admin page at `http://127.0.0.1:8000` and
  every button works. `--invalid` makes it answer prose, so the validation
  path can be watched rejecting it.
* `python3 tools/test_ai_mod.py` runs the whole Splunk-side test suite:
  settings validation, the answer schema, auth headers, the T0 rules, the
  signature's stability, conf parsing, and the probes against the mock, with
  no Splunk and no GPU. It is the first thing to run after any change.

Two cautions for hosted testing. A hosted model answers with *its* judgement,
so expect different rationales than the reference build; the schema and the
plumbing are what you are validating. And a hosted endpoint is off-box data
egress by definition: test with the synthetic CVE, not with production
findings, until the endpoint is approved.

---

## 8. Security posture, stated plainly

* **The secret** lives in Splunk storage passwords (`realm=riskability`,
  `user=riskability_ai`). It is written only by the admin endpoint, readable
  back only by holders of storage-password listing rights, never returned to
  a browser, never written to a conf file, never logged.
* **`riskability_ai_admin`** is a dedicated capability, granted only to
  `admin` and `sc_admin`. Configuring an endpoint is the decision that lets
  anything leave for it at all, and enabling the pipeline is the decision that
  lets CVE data follow; both decisions have a one-word answer in the role
  config. One honest caveat about delegation: the pages behind
  this capability also touch admin-tier resources (conf writes, saved-search
  scheduling and storage passwords), so a custom role holding only
  `riskability_ai_admin` without admin-tier rights can save the connection
  and flip the switch, but cannot rotate the secret or enable the schedules.
  Grant it alongside `admin_all_objects`, as the shipped roles do.
* **No command in this mod runs anything.** An earlier design carried a
  `trigger_command` setting: an arbitrary command Splunk would run as the
  service account after each queue build. It was the app's only
  remote-code-execution surface, nothing in the shipped push architecture
  used it, and it has been removed outright rather than defended. There is no
  alert action, no substituted run id and no shell anywhere in this pipeline.
* **The master switch does not gate the test buttons.** Once an endpoint URL
  is saved, *Test connection* and *Test analysis* call it whether the switch
  is on or off, by design: an endpoint has to be provable before it is
  trusted. Neither sends fleet data. *Test connection* is a `GET /v1/models`;
  *Test analysis* sends `SYNTHETIC_CVE`, whose values are literals in
  `ai_config.py`. Egress therefore starts at configuration, not at the switch,
  and an approval process should treat saving a URL as the reviewable moment.
* **Data sent off-box** is the analysis prompt, one HTTP request per CVE, and
  it is exactly what `ai_config.build_user_payload` renders. Read that
  function rather than this list if the two ever disagree. It carries the CVE
  id and CWE id, the CVSS vector, base score and severity, the EPSS score, KEV
  status, the advisory title as the CVE description, the affected package and
  the version considered, and then the running-process evidence: the process
  name, its version, **its absolute path on disk**, **the ports it is
  listening on**, the asset id and asset criticality, the exposure zone, and
  the version match and confidence. The two that a reviewer will stop on are
  the path and the ports, because both describe the inside of a production
  host rather than a public CVE. The inventory itself and the findings index
  do not leave. Sending is governed by the master switch, the source fields
  are readable in the queue index before anything is sent, and switching off
  stops it on the next run.
* **Host names do not currently leave, although the design intends them to.**
  The queue search emits the fleet-worst host as `worst_asset`; the prompt
  reads `asset_id`; nothing renames one to the other, so `asset_id` renders
  empty in every request. The switch-on dialog tells the administrator that
  hosts are among what is sent, and that describes the intended design rather
  than today's behaviour. Review the approval against the intent, because
  closing the gap is a one-line rename.
* **A configured classifier is a second endpoint.** If `bert_url` is set, each
  analysis first posts the CVE description and the process ancestry chain,
  truncated to 4,000 characters, to that URL. It is optional and ships empty,
  but an approval that covers only the chat endpoint does not cover it.
* **Model output is data, not instruction.** It lands in a KV collection and
  an index, is validated against a schema, and is rendered as text. No field
  of a model answer is ever executed, searched as SPL, or inserted into HTML.
* **User-facing silence** when disabled is itself a control: an attacker
  enumerating a Splunk instance learns nothing about AI capability from any
  user-facing surface.

---

## 9. File map

```
app/riskability-config/                 the configuration app (admin-only)
  default/data/ui/views/riskability_admin.xml   feed admin (moved here)
  default/data/ui/views/riskability_ai.xml      AI connection & pipeline
  appserver/static/riskability_ai.js|css        the AI admin page
  metadata/default.meta                         read: admin, sc_admin

app/riskability/
  bin/riskabilityaianalyze.py           the queue consumer search command
  bin/riskability/ai_config.py          settings, schema, prompts, probes,
                                        T0 rules, verdict_sig (tested)
  bin/riskability/ai_settings.py        conf + storage-password loaders
  bin/riskability_ai_rest.py            /riskability/ai (admin)
  bin/riskability_ai_status_rest.py     /riskability/ai_status (everyone)
  default/commands.conf                 riskabilityaianalyze (chunked, local)
  default/riskability_ai.conf           connection settings (no secrets)
  default/collections.conf              riskability_aistate (the enabled bit
                                        and the summary row) and
                                        riskability_aiverdicts (the cache)
  default/transforms.conf               the two KV lookup definitions
  default/authorize.conf                riskability_ai_admin capability
  default/restmap.conf, web.conf        endpoints + proxy exposure
  default/savedsearches.conf            queue, analyse, expand, health watch
  default/macros.conf                   AI index macros, budget, cache salt,
                                        asset criticality
  default/data/ui/views/riskability_ai.xml      user-facing overview (self-hiding)
  appserver/static/riskability_ai_overview.js   the gate + the page

app/TA-riskability-ai/                  the three indexes + parsing (indexers)

docs/GPU-ENDPOINT-SETUP.md              standing up the inference endpoint
tools/ai_mock_server.py                 inference-server stand-in for testing
tools/test_ai_mod.py                    the test suite (no Splunk needed)
```
