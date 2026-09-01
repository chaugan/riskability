# Configuration for the AI analysis pipeline. Written by the admin UI in the
# Riskability Configuration app; editable by hand, validated against the
# schema in bin/riskability/ai_config.py.

[connection]
endpoint_url = <string>
# (the key is spelled endpoint_url, not url: splunklib cannot write a
# settings entity containing a key literally named "url")
# Base URL of the OpenAI-compatible inference endpoint, without /v1. Example:
#   https://gpu-cve-01.example.internal:8000
# Must be http(s) and must not embed credentials.
auth_type = none|bearer|basic
# bearer is what vLLM's --api-key expects; basic is what a reverse proxy in
# front of the GPU box usually wants.
username = <string>
# Only used when auth_type = basic.
model = <string>
# The model name exactly as the endpoint reports it in /v1/models.
bert_url = <string>
# Optional. Base URL of the MITRE ATT&CK tactic classifier sidecar (the
# FastAPI service exposing /health and /classify). Empty means the pipeline
# runs without pre-tagging.
enabled = <boolean>
# Master switch. Off hides AI from the entire user-facing app, disables the
# candidate queue search and the two searches behind it, and is the
# shipped default.
verify_tls = <boolean>
# Set to 0 when the GPU box presents a self-signed certificate.
request_timeout = <integer>
# Seconds allowed for one inference call. Must fit the slowest hardware the
# site will run; presets on the admin page set this per GPU class.
t2_concurrency = <integer>
# Concurrent bulk-prioritisation calls. Set this to match what the model
# server actually serves in parallel. Measured on the reference RTX 3060:
# a single request returns in 3,142 ms, while the median at concurrency 8
# was 23,419 ms for the same aggregate throughput, because the threads
# simply queued. Raising it past the server's own parallelism buys nothing.
t2_max_tokens = <integer>
t3_max_tokens = <integer>
t3_deep_threshold = <integer>
# A bulk score at or above this is re-analysed with deep reasoning.
candidate_cap = <integer>
# Largest candidate queue one run hands to the GPU box.
last_test = <string>
# One-line history of the last connection or analysis test. Written by the
# admin endpoint; not meant for hand editing.
