#!/usr/bin/env python3
"""A stand-in for the GPU box: vLLM and the BERT sidecar in one process.

  python3 tools/ai_mock_server.py --port 8000 --delay-ms 250

Endpoints, exactly the ones riskability_ai_rest.py probes and the pipeline
uses:

    GET  /v1/models              OpenAI-compatible model list
    POST /v1/chat/completions    returns a schema-valid prioritization
    GET  /health                 BERT sidecar health
    POST /classify               BERT sidecar tactic tagging

Point the Riskability Configuration page at http://127.0.0.1:<port> and every
button on it works: Test connection, Test analysis, Test classifier. That
exercises the whole Splunk side of the pipeline — validation, auth header,
answer parsing, schema check — with no GPU, no model and no network beyond
localhost.

The prioritization the mock returns is deterministic and deliberately
sensible: for the synthetic xz finding the config module sends (KEV, EPSS
0.94, internet-facing, confirmed version match) it answers P0, because a mock
that answered P4 would be testing the alerting, not the plumbing. --delay-ms
simulates a small card's latency so timeout behaviour can be observed, and
--invalid makes the model return prose so the validation path can be seen
rejecting it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ARGS = None

# What a well-behaved T2 answer looks like. Byte-for-byte the schema the
# orchestrator's prompt demands and ai_config.validate_result accepts.
VALID_RESULT = {
    "priority_tier": "P0",
    "priority_score": 96,
    "confidence": 0.9,
    "rationale": "Known-exploited (CISA KEV), EPSS 0.94, internet-facing with a "
                 "confirmed vulnerable version of xz; unauthenticated RCE through "
                 "sshd. Patch immediately and verify no compromised keys.",
    "exploitability_signal": "active-exploit",
    "exposure_signal": "internet-facing",
    "process_match_confidence": "confirmed",
    "recommended_action": "patch-now",
    "recommended_mitigations": [
        "Upgrade xz to 5.6.1 or later on every host",
        "Rotate SSH host and user keys; assume compromise since 2024-03",
        "Restrict inbound 22/tcp at the edge while patching",
    ],
    "attck_techniques": ["T1195.001", "T1078.003"],
}

CLASSIFY_RESULT = {
    "tactics": ["TA0001", "TA0008"],
    "scores": [0.93, 0.61],
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, payload: dict):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _maybe_delay(self):
        if ARGS.delay_ms:
            time.sleep(ARGS.delay_ms / 1000.0)

    def do_GET(self):
        if self.path == "/v1/models":
            self._send(200, {"object": "list", "data": [
                {"id": ARGS.model, "object": "model"},
            ]})
        elif self.path == "/health":
            self._send(200, {"ok": True, "model": ARGS.bert_model, "labels": 14})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/v1/chat/completions":
            self._maybe_delay()
            self._read_json()  # accepted and ignored; the answer is canned
            if ARGS.invalid:
                content = "I would give this vulnerability my highest concern, " \
                          "kind regards, the model."
            else:
                content = "```json\n" + json.dumps(VALID_RESULT) + "\n```"
            self._send(200, {
                "id": "mock", "object": "chat.completion",
                "choices": [{"index": 0, "message": {
                    "role": "assistant", "content": content}, "finish_reason": "stop"}],
            })
        elif self.path == "/classify":
            self._maybe_delay()
            self._read_json()
            self._send(200, CLASSIFY_RESULT)
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock] " + fmt % args + "\n")


import sys  # noqa: E402  (used in log_message above)


def main():
    global ARGS
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address. Use 0.0.0.0 when the caller is a "
                             "Splunk running in a container and the mock runs "
                             "on the docker host")
    parser.add_argument("--model", default="foundation-sec-8b",
                        help="model id /v1/models reports")
    parser.add_argument("--bert-model", default="MITRE-v15-tactic-bert")
    parser.add_argument("--delay-ms", type=int, default=0,
                        help="simulate inference latency (a 3060 is roughly 300-1500 "
                             "at T2 concurrency)")
    parser.add_argument("--invalid", action="store_true",
                        help="answer with prose instead of JSON, for negative tests")
    ARGS = parser.parse_args()

    server = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    print("mock inference server on http://%s:%d "
          "(model=%s delay=%sms invalid=%s)"
          % (ARGS.host, ARGS.port, ARGS.model, ARGS.delay_ms, ARGS.invalid))
    print("Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
