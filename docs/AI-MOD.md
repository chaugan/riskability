# The AI analysis mod

Riskability's core promise has always been that the search head never calls
out. This mod does not break that promise; it makes a second, louder one
next to it: **the pipeline is invisible until an administrator deliberately
switches it on, and it runs on hardware the organisation owns.**

An AI model reads what Riskability has already measured — open findings, each
one carrying its reach class, version-match evidence, EPSS, KEV status and
exposure zone — and returns a priority: a tier from P0 to P4, a score, a
rationale written in prose, concrete mitigations and the ATT&CK techniques
that apply. The model runs on a GPU box on your own network (the reference
build is a single RTX 3060 12 GB; anything larger only makes it faster). No
cloud service sees your fleet unless an administrator points the pipeline at
one.

---

## 1. What was added

| Package | What it is | Where it installs |
|---|---|---|
| `riskability-config` | **New.** The configuration app: feed administration (moved here) and the AI analysis settings. Readable only by `admin` and `sc_admin`. | Search head |
| `riskability` | The main app. Gains the AI capability and endpoints, the candidate-queue and run-health saved searches, the dispatch alert action, and one new dashboard that removes itself when AI is off. Feed admin UI **moved out** to the config app. | Search head |
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
guard themselves by **capability** — `admin_all_objects` for the feed,
`riskability_ai_admin` for AI — so the app-level restriction is ergonomics
and the capability is the control. A site can hand the GPU box to one team
and the feed to another by granting the two capabilities differently.

---

## 2. The guarantee about normal users

**If no administrator ever switches AI on, a normal user sees no AI anywhere
and cannot learn it exists.**

Concretely:

* The one AI endpoint a normal user can reach is `GET /riskability/ai_status`,
  and it answers exactly one bit: `{"enabled": false}`. No URL, no model
  name, no hint that any AI component exists.
* The "AI prioritization" page ships with read permission restricted to
  admins (`[views/riskability_ai]` in default.meta), and Splunk filters
  navigation entries by view read permission **server side**. So while AI is
  off, the page is not in anyone's navigation bar at all — not even for the
  instant before a script could hide it — and a user who types its URL gets
  Splunk's own 404, exactly as for a page that does not exist. Switching AI
  on rewrites the view's ACL to everyone; switching off closes it again. A
  JavaScript gate runs anyway as belt and braces, drawing nothing unless the
  status endpoint says on.
* The candidate-queue search, the run-health watch and the dispatch alert
  action all ship **disabled** and are flipped only by the admin master
  switch. Nothing schedules, nothing runs, nothing appears in the job system.
* No existing dashboard changed by one character. Riskability's numbers are
  exactly what they were.

Switching AI off reverses all of it: page vanishes, schedules stop, no
further data leaves.

---

## 3. The pipeline

```
┌───────────────────────────── search head ─────────────────────────────┐
│                                                                       │
│  "Riskability AI - generate candidate queue"   (hourly, disabled       │
│   open findings × measured reach → one queue row per CVE per host      │
│   → index=riskability_ai_candidates)                                   │
│        │                                                               │
│        │ alert action riskability_ai_trigger                          │
│        │ runs the admin-configured command (ssh / curl / none)         │
└────────┼──────────────────────────────────────────────────────────────┘
         ▼
┌───────────────────────────── GPU box ────────────────────────────────┐
│  orchestrator: reads the queue over Splunk REST                       │
│    T0  deterministic rules (KEV+exposure+confirmed version → P0 …)    │
│    T1  BERT sidecar: MITRE ATT&CK v15 tactic pre-tag                  │
│    T2  Foundation-Sec-8B via vLLM — bulk prioritization, batched      │
│    T3  deep reasoning for the survivors (score ≥ threshold)           │
│  schema-validates every answer, caches, writes back over HEC          │
└──────────────────────────────┬───────────────────────────────────────┘
                               ▼  HEC
      riskability_ai_prioritized   → the "AI prioritization" dashboard
      riskability_ai_alerts        → P0/P1, for SOAR / chat forwarding
```

The GPU side is built from `cve-orchestrator-build-spec.md` (in the
`splunk-ai-cve` package this mod ships alongside). The spec's Splunk sections
are replaced by this mod: the indexes, the queue search, the trigger and the
admin page are here; the spec remains the instruction set for the box itself.

### Why the GPU box is where the LLM is

Determinism is load-bearing. Which findings get analysed, in what order, with
which prompt and which schedule are all decided by Splunk and by plain Python
rules. The model sees one finding at a time, answers in a strict schema, and
every answer is validated twice — once on the GPU box, once if you press
*Test analysis* here. The model is the only non-deterministic component in
the pipeline, and nothing autonomous ever decides anything.

---

## 4. Configuring it (admin flow)

Open **Riskability Configuration → AI analysis**:

1. **Connection** — endpoint URL (OpenAI-compatible, no `/v1`), auth style
   (`none` / `bearer` for vLLM's `--api-key` / `basic` for a proxy), the
   model name exactly as `/v1/models` reports it, and TLS verification.
   The secret is typed once, stored in **Splunk's encrypted storage-password
   store**, and never sent back to any browser: the page learns only
   `password_set`. *Test connection* probes `/v1/models`; *Test analysis*
   sends one synthetic finding and validates the answer end to end.
2. **Hardware profile** — a preset (RTX 3060 12 GB / RTX 4090 / A100-H100 /
   custom) fills concurrency, token budgets, the deep-reasoning threshold,
   the request timeout and the queue cap. Edit anything afterwards. The same
   numbers must be set on the orchestrator; the save confirmation spells them
   out (`T2_CONCURRENCY=8 T2_MAX_TOKENS=400 …`).
3. **Dispatch** — the command Splunk runs when a queue is ready, with
   `$run_id$` substituted. Leave empty for poller mode (below). Only an admin
   with `riskability_ai_admin` can set it, and the alert action validates the
   run id and the command shape before running anything.
4. **Master switch** — *Switch AI analysis ON*. This schedules the queue
   search, arms the run-health watch, makes the dashboard exist for users —
   and not before.

The queue itself is bounded (`candidate_cap`) and ordered by EPSS, so the cap
limits cost, never quality: on a 3060 you analyse the 2,000 most-exploited
open findings per run; on an A100 you raise the cap and the concurrency and
the identical pipeline simply finishes sooner. Timeout is the one setting
that must fit the slowest hardware you will run — a loaded 12 GB card doing
deep reasoning can legitimately need a minute.

### Poller or trigger

* **Trigger** (default shape): Splunk runs the dispatch command after each
  queue build — typically `ssh … "sudo systemctl start
  cve-orchestrator@$run_id@.service"`. Splunk owns scheduling and audit.
* **Poller**: leave the command empty. The orchestrator watches the queue
  index itself and starts on new `run_id`s. The alert action then does
  nothing, on purpose, so the two modes can never double-run a queue.

---

## 5. The HEC contract (what the GPU box needs from you)

Give the GPU box's operator, and put in its `/etc/cve-orchestrator/secrets.env`:

| Value | Value |
|---|---|
| `SPLUNK_SH_URL` | `https://<search-head>:8089` |
| `SPLUNK_HEC_URL` | `https://<indexer-or-SH>:8088` |
| `SPLUNK_HEC_TOKEN` | a HEC token allowed into the three AI indexes only |
| `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` | service account with a read-only role limited to the AI indexes |
| `VLLM_URL` / `VLLM_API_KEY` | the values configured on the admin page |
| `VLLM_MODEL` | the model name from the admin page |
| `BERT_URL` | the classifier URL from the admin page (optional) |
| `T2_CONCURRENCY`, `T2_MAX_TOKENS`, `T3_MAX_TOKENS`, `T3_DEEP_THRESHOLD` | the hardware-profile numbers from the admin page |

Indexes and sourcetypes (created by `TA-riskability-ai`, macros
`riskability_index_ai_*` in the main app):

| Index | Sourcetype | Written by |
|---|---|---|
| `riskability_ai_candidates` | `riskability:ai:candidate` | the queue search (`collect`) |
| `riskability_ai_prioritized` | `riskability:ai:prioritized` | the orchestrator over HEC |
| `riskability_ai_alerts` | `riskability:ai:alert` | the orchestrator over HEC |

Result events carry the schema fields (`priority_tier`, `priority_score`,
`confidence`, `rationale`, `recommended_action`, `recommended_mitigations`,
`attck_techniques`, …) plus the candidate fields the orchestrator copies
through, including `run_id` and `asset_id`.

One field mapping to know: Riskability does not ship a CVE prose corpus, so
the queue's `cve_description` is the feed advisory's `title` — one honest
sentence per CVE rather than invented detail. `version_match` is derived from
Riskability's own match confidence (`high → yes`, `informational → no`,
otherwise `unknown`) and `exposure_zone` from measured reach (`answers any
address → internet-facing`, `no listening port → isolated`).
`asset_criticality` defaults to `medium` via the
`riskability_ai_asset_criticality` macro; override it with an eval against a
lookup of your critical hosts.

---

## 6. Testing before the hardware exists

The admin page speaks the OpenAI chat-completions dialect, so every control
works against a hosted endpoint. Bearer auth, the hub's model id, and:

| Hub | Base URL | Notes |
|---|---|---|
| **Hugging Face Inference Providers** | `https://router.huggingface.co/v1` | The home of `fdtn-ai/Foundation-Sec-8B`, `Foundation-Sec-8B-Reasoning` and `sarahwei/MITRE-v15-tactic-bert-case-based` — the exact models in the reference build. An HF token is the bearer secret; availability of a given model depends on the provider routed to. |
| **OpenRouter** | `https://openrouter.ai/api/v1` | Open-weight models including DeepSeek-R1-Distill-Qwen-7B; good for exercising the pipeline shape with a different model. |
| **Together AI** | `https://api.together.xyz/v1` | Hosted Qwen / DeepSeek open weights. |
| **Ollama, local** | `http://127.0.0.1:11434/v1` | `ollama pull` a GGUF (e.g. a Foundation-Sec-8B or cybersecurity Qwen quant); a laptop stands in for the GPU box at small scale. |

Two local things also help:

* `python3 tools/ai_mock_server.py --port 8000 --delay-ms 300` stands in for
  vLLM *and* the BERT sidecar in one process, with simulated latency. Point
  the admin page at `http://127.0.0.1:8000` and every button works.
* `python3 tools/test_ai_mod.py` runs the whole Splunk-side test suite —
  settings validation, the answer schema, auth headers, conf parsing, and the
  probes against the mock — with no Splunk and no GPU. It is the first thing
  to run after any change.

Two cautions for hosted testing: a hosted model answers with *its* judgement,
so expect different rationales than the reference build — the schema and the
plumbing are what you are validating. And a hosted endpoint is off-box data
egress by definition: test with the synthetic finding, not with production
findings, until the endpoint is approved.

---

## 7. Security posture, stated plainly

* **The secret** lives in Splunk storage passwords (`realm=riskability`,
  `user=riskability_ai`). It is written only by the admin endpoint, readable
  back only by holders of storage-password listing rights, never returned to
  a browser, never written to a conf file, never logged.
* **`riskability_ai_admin`** is a dedicated capability, granted only to
  `admin` and `sc_admin`. Enabling the pipeline is the decision that lets
  findings data leave for the GPU box; that decision has a one-word answer in
  the role config. One honest caveat about delegation: the pages behind this
  capability also touch admin-tier resources — conf writes, saved-search
  scheduling and storage passwords — so a custom role holding only
  `riskability_ai_admin` (without admin-tier rights) can save the connection
  and flip the switch, but cannot rotate the secret or enable the schedules.
  Grant it alongside `admin_all_objects`, as the shipped roles do.
* **`trigger_command`** is an arbitrary command run as the Splunk service
  account — that is its job. It is writable only through the capability-
  guarded endpoint, and the alert action validates both it and the substituted
  run id against strict character rules before executing. The documented
  sudoers pattern on the GPU box narrows it further (`NOPASSWD: /bin/systemctl
  start cve-orchestrator@*.service`).
* **Data sent off-box** is the candidate queue: CVE ids, package names,
  versions, hosts, reach and exploit signals. It is governed by the master
  switch and visible in the queue index. Nothing else leaves, and switching
  off stops everything immediately.
* **Model output is data, not instruction.** It lands in an index, is
  validated against a schema, and is rendered as text. No field of a model
  answer is ever executed, searched as SPL, or inserted into HTML.
* **User-facing silence** when disabled is itself a control: an attacker
  enumerating a Splunk instance learns nothing about AI capability from any
  user-facing surface.

---

## 8. File map

```
app/riskability-config/                 the configuration app (admin-only)
  default/data/ui/views/riskability_admin.xml   feed admin (moved here)
  default/data/ui/views/riskability_ai.xml      AI connection & pipeline
  appserver/static/riskability_ai.js|css        the AI page
  metadata/default.meta                         read: admin, sc_admin

app/riskability/
  bin/riskability/ai_config.py          pure settings+probe logic (tested)
  bin/riskability_ai_rest.py            /riskability/ai + /riskability/ai_status
  bin/riskability_ai_trigger.py         the dispatch alert action
  default/riskability_ai.conf           connection settings (no secrets)
  default/collections.conf              riskability_aistate: the user-readable
                                        enabled bit the status endpoint serves
  default/authorize.conf                riskability_ai_admin capability
  default/restmap.conf, web.conf        endpoints + proxy exposure
  default/alert_actions.conf            the dispatch action
  default/savedsearches.conf            queue search + run-health watch
  default/macros.conf                   AI index macros, queue cap, criticality
  default/data/ui/views/riskability_ai.xml      user-facing overview (self-hiding)
  appserver/static/riskability_ai_overview.js   the gate + the page

app/TA-riskability-ai/                  the three indexes + parsing (indexers)

tools/ai_mock_server.py                 vLLM+BERT stand-in for testing
tools/test_ai_mod.py                    the test suite (no Splunk needed)
```
