# Brief: stand up the OpenAI-compatible inference endpoint for Riskability

You are an AI agent with shell access to a machine on the same network as a
GPU server (or to the GPU server itself). Your entire mission is below —
nothing more, nothing less.

**End state:** an OpenAI-compatible chat-completions endpoint serving a
security-tuned 8B model, reachable from the Splunk search head over HTTP,
protected by an API key, and verified — with the exact request shape Splunk
sends — to return schema-valid prioritisation JSON.

**Out of scope, on purpose:** consuming Splunk's candidate queue, writing
results back over HEC, orchestrators, pollers. This brief stands up the
endpoint only. Without a separate queue-consumer component, Splunk's *Test
connection* and *Test analysis* buttons work against this endpoint, but no
scheduled analysis runs. Say this plainly in your final report.

---

## 0. Rules of engagement

1. **Never invent a value marked STOP-ASK.** Ask the human operator. Invented
   credentials, IPs or firewall rules are worse than a stopped job.
2. **Detect → show → stop.** When stopping services that hold the GPU, list
   what you found, classify it, stop gracefully, and record every action in
   `/root/riskability-endpoint-notes.md`. Never `kill -9` as a first resort.
3. **Touch only LLM inference services.** If a process is not clearly an LLM
   server (see the classification list), leave it alone and ask.
4. **Pin everything.** Record the exact model revision (commit hash) and
   package versions you install. Never auto-update a model behind a running
   pipeline.
5. **Stop and report** on anything irrecoverable (no driver and no permission
   to install one, no disk, no route to Splunk). A half-working endpoint is
   worse than an honest failure.
6. **The API key is a secret.** It goes in a root-owned file and into your
   final report as `sk-…<last 4 chars>` only.

---

## 1. Phase 0 — facts about the box

Collect and print these before changing anything:

```bash
uname -a && cat /etc/os-release | grep PRETTY
nvidia-smi || echo "NO NVIDIA DRIVER"          # note driver + CUDA version
nvidia-smi --query-gpu=name,memory.total,memory.used,temperature.gpu --format=csv
df -h / && free -h
ip -brief addr
python3 --version
curl -sI --max-time 10 https://huggingface.co | head -1 || echo "NO ROUTE TO HUGGING FACE"
```

**STOP-ASK** if: no NVIDIA driver and you lack permission to install one;
less than ~25 GB free disk; no route to huggingface.co **and** the human has
no offline model weights to hand you.

---

## 2. Phase 1 — stop anything currently using the GPU for LLM work

This phase runs **before** any install, so you start from a silent GPU.

### 2.1 Inventory

```bash
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv
fuser -v /dev/nvidia* 2>&1 | head -20
systemctl list-units --type=service --state=running | grep -iE \
  'ollama|vllm|llama|tgi|text-generation|localai|fastchat|open-webui|comfy|sglang|xinference'
docker ps 2>/dev/null   # look for containers with GPU devices attached
ps aux | grep -iE 'python.*(vllm|serve|uvicorn)|ollama' | grep -v grep
```

### 2.2 Classify

* **LLM inference services — stop these:** ollama, vLLM, llama.cpp servers,
  TGI, text-generation-webui, LocalAI, FastChat, Open WebUI, SGLang,
  Xinference, ComfyUI, and any python process serving a model on a port.
* **Do not touch:** `nvidia-persistenced` (we want it running), monitoring
  agents, backups, Xorg/display manager **unless the human confirms the box
  is headless** — a desktop session holding 500 MB of VRAM is a question,
  not a decision.
* Anything you cannot classify: leave running, list it, ask.

### 2.3 Stop, in this order

```bash
systemctl disable --now <service>        # graceful, and it stays down
docker stop <container>                  # for containerised servers
kill -TERM <pid>; sleep 15; kill -KILL <pid>   # only for bare processes
```

Record each: what it was, how it was stopped, whether autostart was
disabled. The human may want them back; that must be reversible from your
notes.

### 2.4 Verify the GPU is actually free

```bash
nvidia-smi --query-gpu=memory.used --format=csv
```

Proceed only when used memory is near idle levels (a few hundred MB).

---

## 3. Phase 2 — prerequisites

* Driver 545+ with CUDA 12.x (`nvidia-smi` shows it). If missing and you may
  install: use NVIDIA's Ubuntu repo (`cuda-drivers-545`), reboot, re-verify.
  **STOP-ASK** if you may not.
* Persistence mode on, and kept on:

```bash
nvidia-smi -pm 1 && systemctl enable --now nvidia-persistenced
```

* Python 3.10/3.11 + venv, `git`, `curl`, `ufw`.
* Outbound HTTPS to huggingface.co (Phase 3 downloads ~6–17 GB depending on
  path). If offline, **STOP-ASK** the human for the weights directory.

---

## 4. Phase 3 — choose the serving path by measured VRAM

**Do the arithmetic before installing.** An 8B model at FP16 needs ~16 GB of
weights alone; a 12 GB card cannot run it FP16 no matter what any older
document claims. Measure, then choose one path:

| Measured VRAM | Path |
|---|---|
| ≥ 20 GB (4090, A-series) | **A**: vLLM, official `fdtn-ai/Foundation-Sec-8B`, FP16 |
| 10–16 GB (RTX 3060 12 GB, 4070…) | **B**: vLLM with a pre-quantised AWQ/GPTQ build, or **C**: Ollama serving a GGUF quant |

**Path B, finding a quant honestly:** search huggingface.co for an AWQ or
GPTQ 4-bit quantisation of `Foundation-Sec-8B`. Report in your notes exactly
which repository you used, its licence, and its commit hash. If the repo
ships `.bin` files rather than safetensors, reject it and keep looking —
pickle weights are a supply-chain risk. If no credible quant exists, use
path C.

**Path C, Ollama:** install Ollama, pull a GGUF quant of the model
(Q4_K_M ≈ 5 GB or Q8_0 ≈ 8.5 GB — on 12 GB prefer Q4_K_M if you also want
16k context), and set `OLLAMA_HOST=0.0.0.0:11434`. Ollama exposes an
OpenAI-compatible endpoint at `/v1` and fits this brief. Note honestly: it
does not enforce API keys — that is acceptable only inside a trusted VLAN;
say so in your report.

---

## 5. Phase 4 — install and run (vLLM path)

```bash
adduser --disabled-password --gecos "" rkai   # unprivileged service user
mkdir -p /opt/riskability-ai/models && chown -R rkai:rkai /opt/riskability-ai
sudo -u rkai python3.11 -m venv /opt/riskability-ai/venv
sudo -u rkai /opt/riskability-ai/venv/bin/pip install \
  vllm==0.6.3.post1 transformers==4.46.3 huggingface-hub==0.26.3

# Model — pin the revision; record the hash you used
sudo -u rkai /opt/riskability-ai/venv/bin/huggingface-cli download \
  fdtn-ai/Foundation-Sec-8B --local-dir /opt/riskability-ai/models/Foundation-Sec-8B
find /opt/riskability-ai/models -name '*.bin' -o -name '*.pickle'   # must print nothing

# API key — 32 random bytes; goes to the human afterwards
install -d -m 700 /etc/riskability-ai
printf 'VLLM_API_KEY=%s\n' "$(openssl rand -hex 32)" > /etc/riskability-ai/secrets.env
chmod 600 /etc/riskability-ai/secrets.env
```

`/etc/systemd/system/vllm-riskability.service`:

```ini
[Unit]
Description=vLLM — Riskability CVE prioritisation endpoint
After=network.target nvidia-persistenced.service

[Service]
User=rkai
# systemd does not run $(...) in ExecStart — the key comes in as an
# environment variable from this file and is expanded as ${VLLM_API_KEY}.
EnvironmentFile=/etc/riskability-ai/secrets.env
ExecStart=/opt/riskability-ai/venv/bin/vllm serve /opt/riskability-ai/models/Foundation-Sec-8B \
  --host 0.0.0.0 --port 8000 \
  --served-model-name foundation-sec-8b \
  --api-key ${VLLM_API_KEY} \
  --dtype float16 --enforce-eager \
  --max-model-len 16384 --gpu-memory-utilization 0.85
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

On path B (quantised) change to: `--quantization awq --max-model-len 8192
--gpu-memory-utilization 0.90`, and lower context further if it OOMs. Enable
and start:

```bash
systemctl daemon-reload && systemctl enable --now vllm-riskability
journalctl -u vllm-riskability -f        # wait for "Uvicorn running on ..."
```

**Firewall** — the endpoint must be reachable *only* where it is used:

```bash
ufw allow from <SPLUNK-CIDR> to any port 8000 proto tcp   # STOP-ASK for the CIDR
ufw enable
```

---

## 6. Phase 5 — verify with the exact request Splunk sends

```bash
KEY=$(sed -n 's/^VLLM_API_KEY=//p' /etc/riskability-ai/secrets.env)

curl -s http://127.0.0.1:8000/v1/models -H "Authorization: Bearer $KEY"
# expect: {"object":"list","data":[{"id":"foundation-sec-8b", ...}]}

curl -s http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{
    "model": "foundation-sec-8b",
    "messages": [
      {"role": "system", "content": "You are a CVE prioritization assistant for a Security Operations Center. Combine the CVE metadata, the running-process evidence and the asset context into one priority decision. Strict rules: Respond with a single JSON object and nothing else. priority_tier: P0, P1, P2, P3 or P4. priority_score: integer 0-100. confidence: float 0.0-1.0. exploitability_signal: active-exploit, proof-of-concept, theoretical or none. exposure_signal: internet-facing, internal or isolated. process_match_confidence: confirmed, probable, unlikely or unknown. recommended_action: patch-now, mitigate, monitor, accept or risk-accept-with-compensation. recommended_mitigations: up to 5 short concrete strings. attck_techniques: list of MITRE ATT&CK technique ids such as T1059.004, empty list if unsure. Never invent CVE data."},
      {"role": "user", "content": "CVE-ID: CVE-2024-3094\nCWE-ID: CWE-506\nCVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (base 10.0, severity critical)\nEPSS: 0.94\nKEV: true\nCVE description: Malicious code in xz allowed unauthenticated remote code execution through sshd.\nAffected product: xz version 5.6.0\nRunning process evidence:\n  - process: xz\n  - version: 5.6.0\n  - path: /usr/bin/xz\n  - listening ports: 22\n  - asset: edge-ssh-01 (criticality high)\n  - exposure zone: internet-facing\n  - version match confidence: yes (high)\n\nRespond ONLY with a single JSON object matching the schema."}
    ],
    "temperature": 0.1, "max_tokens": 400
  }'
```

The answer's `choices[0].message.content` must be a single JSON object with
**every** field: `priority_tier` (P0–P4), `priority_score` (0–100),
`confidence` (0.0–1.0), `rationale`, `exploitability_signal`,
`exposure_signal`, `process_match_confidence`, `recommended_action`,
`recommended_mitigations` (≤5), `attck_techniques`. For this input a healthy
endpoint answers P0 / patch-now; the schema is what matters, the tier is
indicative. On a 3060 expect roughly 5–25 s — tell the human so they keep
Splunk's request timeout at ≥120 s.

---

## 7. Phase 6 — handoff (put this block verbatim in your final report)

```text
RISKABILITY ENDPOINT — HANDOFF
  URL            : http://<this-box-ip>:<port>
  Auth           : Bearer, key stored at /etc/riskability-ai/secrets.env (mode 600)
  Model name     : foundation-sec-8b        (exactly as /v1/models reports)
  Serving path   : vLLM <version>, model revision <hash>   [or Ollama <version>, GGUF <repo>]
  Verified       : /v1/models OK · schema-valid completion OK · latency <N>s
  Firewall       : port <p> open to <CIDR> only
  Stopped to free the GPU: <service — method — autostart disabled y/n> (one per line)
  Notes          : anything the human must know
```

The human then enters URL + auth (Bearer) + model name on **Riskability
Configuration → AI analysis** in Splunk, presses *Test connection* and *Test
analysis* — those two buttons are the cross-check that your endpoint and
their config agree. Hardware profile: keep the RTX 3060 preset unless the
card is larger, and if it is larger, raise `T2_CONCURRENCY` on **both** sides.
If Splunk runs in a container, give them the address Splunk can actually
route to (often the docker bridge gateway, not 127.0.0.1).
