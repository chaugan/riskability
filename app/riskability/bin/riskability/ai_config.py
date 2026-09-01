"""Configuration and probe logic for the AI analysis pipeline.

Everything in this module is stdlib-only and Splunk-free, on purpose:

* ``riskability_ai_rest.py`` (the admin REST handler) imports it for validation
  and the network probes.
* ``riskability_alert_ai_trigger.py`` (the alert action) imports the settings
  schema.
* ``tools/test_ai_mod.py`` exercises all of it on a laptop, against
  ``tools/ai_mock_server.py``, with no Splunk and no GPU in sight. A module
  that could only be tested on a search head against a real model server
  would never be tested at all, and this one guards secrets.

The pipeline this configures is the one described in
``docs/AI-MOD.md``: a GPU box runs vLLM (Foundation-Sec-8B or any
OpenAI-compatible server) and an optional MITRE-ATT&CK BERT classifier;
Splunk builds a candidate queue and the GPU box reads it, analyses it and
writes prioritised results back over HEC. Splunk owns the schedule and the
audit trail; the GPU box owns the inference.

Nothing here ever logs or returns a secret. The password lives in Splunk
storage passwords and is passed around only in memory for the duration of a
probe.
"""

from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Settings schema
# ---------------------------------------------------------------------------
# One stanza, [connection], in riskability_ai.conf. Every field is listed here
# exactly once, with its type and bounds, and both the REST handler and the
# tests validate through this table. A field added to the conf file without
# being added here is rejected as unknown, the same way the feed endpoint
# rejects unknown index macros: a typo in a settings form must not silently
# write a setting nothing reads.

FIELD_SPECS: Dict[str, dict] = {
    "endpoint_url": {
        # Named endpoint_url, NOT url: conf values travel through splunklib's
        # Entity.post(**query), and splunklib's own HTTP layer names a parameter
        # "url" (binding.py). A conf key called url collides with it and every
        # save dies with "post() got multiple values for argument 'url'". The
        # same applies to count, offset, sort_mode and search — never use them
        # as conf keys written through splunklib entities.
        "kind": "url", "required_for_enable": True, "max": 500,
        "default": "",
    },
    # How the endpoint authenticates. vLLM's --api-key is a bearer token; a
    # reverse proxy in front of it usually wants basic auth. Username is only
    # read for basic.
    "auth_type": {
        "kind": "enum", "values": ("none", "bearer", "basic"),
        "default": "none",
    },
    "username": {
        "kind": "text", "max": 128, "default": "",
    },
    # OpenAI-compatible model name as the server itself reports it in /v1/models.
    "model": {
        "kind": "text", "max": 128, "pattern": r"^[A-Za-z0-9._/:@-]{0,128}$",
        "default": "foundation-sec-8b",
    },
    # The BERT ATT&CK tactic sidecar. Optional: the pipeline degrades to
    # prompting the LLM for techniques without it.
    "bert_url": {
        "kind": "url_optional", "max": 500, "default": "",
    },
    # The master switch. Drives the user-facing AI page (which hides itself
    # entirely when this is off) and the candidate-queue saved search.
    "enabled": {
        "kind": "bool", "default": False,
    },
    # Verifying TLS against a GPU box with a self-signed certificate fails in
    # a way that looks exactly like a network fault, so the choice is explicit
    # rather than an undocumented verify=False.
    "verify_tls": {
        "kind": "bool", "default": True,
    },
    # Seconds for one inference call. A 12 GB card doing T3 deep reasoning on
    # a long prompt can legitimately take a minute; an A100 answers in two.
    # The timeout has to fit the SLOWEST hardware the site will run, or the
    # same pipeline that works on a big card fails on a small one purely
    # because Splunk hung up first.
    "request_timeout": {
        "kind": "int", "min": 5, "max": 600, "default": 120,
    },
    # Concurrent T2 calls the GPU box accepts. This mirrors the orchestrator's
    # T2_CONCURRENCY: both must be set to the same budget for the same card.
    "t2_concurrency": {
        "kind": "int", "min": 1, "max": 128, "default": 8,
    },
    "t2_max_tokens": {
        "kind": "int", "min": 64, "max": 4000, "default": 400,
    },
    "t3_max_tokens": {
        "kind": "int", "min": 256, "max": 8000, "default": 1200,
    },
    # A T2 score at or above this goes back to the model for deep reasoning.
    "t3_deep_threshold": {
        "kind": "int", "min": 0, "max": 100, "default": 70,
    },
    # Largest candidate queue one run will hand the GPU box. The small-card
    # presets lower this; the queue is ordered by EPSS so the head of the
    # queue is always the most worth analysing.
    "candidate_cap": {
        "kind": "int", "min": 10, "max": 100000, "default": 5000,
    },
    # What the alert action runs to poke the GPU box when a queue is ready.
    # Admin-set, admin-owned: it runs with the Splunk service account's rights,
    # which is exactly why only the AI admin capability may write it.
    "trigger_command": {
        "kind": "text", "max": 2000, "default": "",
    },
}

# Hardware presets. A preset is a starting point the admin can then edit; the
# numbers mirror what one vLLM process per card can actually sustain. The 3060
# preset is the reference: it is the slowest hardware this is expected to run
# on, and the pipeline is identical on faster cards, only faster.
PRESETS = {
    "rtx3060": {
        "label": "RTX 3060 12 GB (single card)",
        "values": {
            "t2_concurrency": 8, "t2_max_tokens": 400, "t3_max_tokens": 1200,
            "t3_deep_threshold": 70, "request_timeout": 120,
            "candidate_cap": 2000,
        },
    },
    "rtx4090": {
        "label": "RTX 4090 / 24 GB (single card)",
        "values": {
            "t2_concurrency": 32, "t2_max_tokens": 400, "t3_max_tokens": 1200,
            "t3_deep_threshold": 70, "request_timeout": 90,
            "candidate_cap": 5000,
        },
    },
    "a100": {
        "label": "A100 / H100 40 GB+",
        "values": {
            "t2_concurrency": 64, "t2_max_tokens": 400, "t3_max_tokens": 1200,
            "t3_deep_threshold": 70, "request_timeout": 60,
            "candidate_cap": 20000,
        },
    },
    "custom": {
        "label": "Custom",
        "values": {},
    },
}


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def normalize_url(value: str) -> str:
    """Trim, strip a trailing slash, and reject anything unusable."""
    url = (value or "").strip().rstrip("/")
    if not url:
        return ""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            "the URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("the URL has no host in it")
    # Credentials embedded in the URL would end up in conf files, search
    # results and browser screenshots. The username and password fields exist;
    # this is the error you want instead of a secret in a lookup.
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise ValueError(
            "put the credentials in the username and password fields, not in "
            "the URL")
    if parsed.query or parsed.fragment:
        raise ValueError("the URL must not carry a query string or fragment")
    return url


def validate_settings(updates: dict, current: dict) -> Dict[str, str]:
    """Validate proposed settings against the schema and merge with current.

    Returns the complete merged setting map (strings, as conf stores them).
    Raises ValueError with a message meant for the admin page when anything
    is wrong. Unknown keys are rejected rather than ignored, so a form field
    that no longer exists cannot quietly write dead configuration.
    """
    if not isinstance(updates, dict):
        raise ValueError("settings must be a JSON object")
    unknown = sorted(set(updates) - set(FIELD_SPECS))
    if unknown:
        raise ValueError("unknown setting(s): " + ", ".join(unknown))
    merged = {}
    for key, spec in FIELD_SPECS.items():
        raw = updates[key] if key in updates else current.get(key, spec["default"])
        if raw is None:
            raw = spec["default"]
        if spec["kind"] == "bool":
            merged[key] = "1" if _coerce_bool(raw) else "0"
        elif spec["kind"] == "int":
            try:
                num = int(str(raw).strip())
            except (TypeError, ValueError):
                raise ValueError("%s must be a whole number" % key)
            if num < spec["min"] or num > spec["max"]:
                raise ValueError(
                    "%s must be between %s and %s" % (key, spec["min"], spec["max"]))
            merged[key] = str(num)
        elif spec["kind"] == "enum":
            text = str(raw).strip().lower()
            if text not in spec["values"]:
                raise ValueError(
                    "%s must be one of: %s" % (key, ", ".join(spec["values"])))
            merged[key] = text
        else:
            text = str(raw or "").strip()
            if len(text) > spec["max"]:
                raise ValueError("%s is too long (max %s characters)" % (key, spec["max"]))
            if spec.get("pattern") and text and not re.match(spec["pattern"], text):
                raise ValueError("%s contains characters that are not allowed" % key)
            if spec["kind"] == "url":
                text = normalize_url(text)
            elif spec["kind"] == "url_optional":
                text = normalize_url(text) if text else ""
            merged[key] = text

    if merged["enabled"] == "1":
        if not merged["endpoint_url"]:
            raise ValueError(
                "set the GPU endpoint URL before switching AI analysis on")
        if merged["auth_type"] == "basic" and not merged["username"]:
            raise ValueError(
                "basic authentication needs a username")
    return merged


# ---------------------------------------------------------------------------
# LLM output contract
# ---------------------------------------------------------------------------
# The schema the GPU pipeline's prompts demand, validated here independently of
# the orchestrator. The orchestrator validates before writing HEC; this
# validates again at test time, because the whole point of the "Send test
# analysis" button is to answer "will this endpoint produce something the
# pipeline accepts" before a run depends on it. Duplicated deliberately: the
# two checks disagreeing is a finding, not a bug.

ALLOWED_TIERS = ("P0", "P1", "P2", "P3", "P4")
ALLOWED_EXPLOITABILITY = ("active-exploit", "proof-of-concept", "theoretical", "none")
ALLOWED_EXPOSURE = ("internet-facing", "internal", "isolated")
ALLOWED_PROCESS_MATCH = ("confirmed", "probable", "unlikely", "unknown")
ALLOWED_ACTION = ("patch-now", "mitigate", "monitor", "accept",
                  "risk-accept-with-compensation")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def parse_llm_json(content: str):
    """Pull a JSON object out of a chat completion's text answer.

    Models wrap JSON in code fences more often than not. Accepts bare JSON,
    ```json fences, and leading prose before the first brace -- the last is
    the one failure mode a strict parser turns into a false "endpoint broken".
    """
    if content is None:
        raise ValueError("the model returned an empty answer")
    text = content.strip()
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            candidate = part.strip()
            if candidate.startswith("json"):
                candidate = candidate[4:]
            candidate = candidate.strip()
            if candidate.startswith("{"):
                text = candidate
                break
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("the model's answer contained no JSON object")
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError("the model's answer was not valid JSON: %s" % exc)
    if not isinstance(parsed, dict):
        raise ValueError("the model's answer was not a JSON object")
    return parsed


def validate_result(payload: dict) -> Tuple[Optional[dict], Optional[str]]:
    """Validate one prioritisation result. Returns (clean, None) or (None, why).

    Technique ids that merely look wrong are dropped rather than rejected:
    one hallucinated technique should not void an otherwise sound analysis.
    """
    if not isinstance(payload, dict):
        return None, "not an object"
    clean = {}
    tier = payload.get("priority_tier")
    if tier not in ALLOWED_TIERS:
        return None, "priority_tier must be one of %s" % "|".join(ALLOWED_TIERS)
    clean["priority_tier"] = tier
    try:
        score = int(payload.get("priority_score"))
    except (TypeError, ValueError):
        return None, "priority_score must be an integer"
    if not 0 <= score <= 100:
        return None, "priority_score out of range"
    clean["priority_score"] = score
    try:
        confidence = float(payload.get("confidence"))
    except (TypeError, ValueError):
        return None, "confidence must be a number"
    if not 0.0 <= confidence <= 1.0:
        return None, "confidence out of range"
    clean["confidence"] = round(confidence, 3)
    rationale = payload.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        return None, "rationale missing"
    clean["rationale"] = rationale.strip()[:2000]
    for key, allowed in (
            ("exploitability_signal", ALLOWED_EXPLOITABILITY),
            ("exposure_signal", ALLOWED_EXPOSURE),
            ("process_match_confidence", ALLOWED_PROCESS_MATCH),
            ("recommended_action", ALLOWED_ACTION)):
        value = payload.get(key)
        if value not in allowed:
            return None, "%s must be one of %s" % (key, "|".join(allowed))
        clean[key] = value
    mitigations = payload.get("recommended_mitigations")
    if mitigations is None:
        mitigations = []
    if not isinstance(mitigations, list) \
            or any(not isinstance(m, str) for m in mitigations):
        return None, "recommended_mitigations must be a list of strings"
    clean["recommended_mitigations"] = [m for m in mitigations if m.strip()][:5]
    techniques = payload.get("attck_techniques")
    if techniques is None:
        techniques = []
    if not isinstance(techniques, list):
        return None, "attck_techniques must be a list"
    clean["attck_techniques"] = [t for t in techniques
                                 if isinstance(t, str) and _TECHNIQUE_RE.match(t)]
    return clean, None


# ---------------------------------------------------------------------------
# Prompts and the synthetic test finding
# ---------------------------------------------------------------------------

# A trimmed T2 prompt. The GPU box carries the full one; this exists so the
# "Send test analysis" button exercises the same output contract without the
# two prompts having to be kept byte-identical across two machines.
SYSTEM_PROMPT_T2 = """You are a CVE prioritization assistant for a Security Operations Center.
Combine the CVE metadata, the running-process evidence and the asset context
into one priority decision.

Strict rules:
- Respond with a single JSON object and nothing else. No prose, no markdown,
  no code fences.
- priority_tier: "P0", "P1", "P2", "P3" or "P4".
- priority_score: integer 0-100. confidence: float 0.0-1.0.
- exploitability_signal: "active-exploit", "proof-of-concept", "theoretical"
  or "none".
- exposure_signal: "internet-facing", "internal" or "isolated".
- process_match_confidence: "confirmed", "probable", "unlikely" or "unknown".
- recommended_action: "patch-now", "mitigate", "monitor", "accept" or
  "risk-accept-with-compensation".
- recommended_mitigations: up to 5 short concrete strings.
- attck_techniques: list of MITRE ATT&CK technique ids such as "T1059.004".
  Empty list if unsure.
- Never invent CVE data. Use only what was provided."""

# A finding with every field filled, because the test's job is to see whether
# the endpoint can produce the schema, not to exercise the model's opinions
# about a real CVE. The values describe the xz backdoor, which every security
# model has seen and every prioritisation should slam to P0 -- so a result
# that comes back P4 is itself diagnostic.
SYNTHETIC_CVE = {
    "cve_id": "CVE-2024-3094",
    "cwe_id": "CWE-506",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_base_score": 10.0,
    "severity": "critical",
    "epss": 0.94,
    "kev": "true",
    "cve_description": "Malicious code inserted into the xz compression "
                       "library's build allowed unauthenticated remote code "
                       "execution through systemd-linked sshd.",
    "affected_product": "xz",
    "affected_version": "5.6.0",
    "process_name": "xz",
    "process_version": "5.6.0",
    "process_path": "/usr/bin/xz",
    "listening_ports": "22",
    "asset_id": "edge-ssh-01",
    "asset_criticality": "high",
    "exposure_zone": "internet-facing",
    "version_match": "yes",
    "confidence": "high",
}


def build_user_payload(cve: dict) -> str:
    """Render one finding the way the pipeline's T2 prompt expects it."""
    return (
        "CVE-ID: {cve_id}\n"
        "CWE-ID: {cwe_id}\n"
        "CVSS: {cvss_vector} (base {cvss_base_score}, severity {severity})\n"
        "EPSS: {epss}\n"
        "KEV: {kev}\n"
        "CVE description: {cve_description}\n"
        "Affected product: {affected_product} version {affected_version}\n"
        "Running process evidence:\n"
        "  - process: {process_name}\n"
        "  - version: {process_version}\n"
        "  - path: {process_path}\n"
        "  - listening ports: {listening_ports}\n"
        "  - asset: {asset_id} (criticality {asset_criticality})\n"
        "  - exposure zone: {exposure_zone}\n"
        "  - version match confidence: {version_match} ({confidence})\n"
        "\n"
        "Respond ONLY with a single JSON object matching the schema."
    ).format(**{k: cve.get(k, "") for k in
                ("cve_id", "cwe_id", "cvss_vector", "cvss_base_score", "severity",
                 "epss", "kev", "cve_description", "affected_product",
                 "affected_version", "process_name", "process_version",
                 "process_path", "listening_ports", "asset_id",
                 "asset_criticality", "exposure_zone", "version_match",
                 "confidence")})


# ---------------------------------------------------------------------------
# HTTP probes
# ---------------------------------------------------------------------------

def auth_header(auth_type: str, username: str, secret: str) -> dict:
    """The Authorization header for the configured auth style.

    bearer  what vLLM's --api-key expects: the secret itself as the token.
    basic   what a reverse proxy in front of the GPU box usually wants.
    """
    if auth_type == "bearer" and secret:
        return {"Authorization": "Bearer " + secret}
    if auth_type == "basic" and secret:
        blob = base64.b64encode(
            ("%s:%s" % (username or "", secret)).encode("utf-8")).decode("ascii")
        return {"Authorization": "Basic " + blob}
    return {}


def _http(url: str, method: str = "GET", headers: Optional[dict] = None,
          body: Optional[dict] = None, timeout: int = 30,
          verify_tls: bool = True) -> Tuple[int, bytes]:
    """One request. Returns (status, body bytes); raises ValueError in prose.

    urllib reports TLS verification failures with an error message that names
    the certificate, which is the detail that separates "self-signed cert, set
    verify accordingly" from "wrong port". Surfaces it instead of flattening
    every failure to "request failed".
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    # A named agent, never the default Python-urllib string: Cloudflare (which
    # fronts several GPU deployments through tunnels) is commonly configured
    # to challenge or block the stock python user-agent outright, and the
    # challenge is a 403 that reads exactly like a broken endpoint.
    req.add_header("User-Agent", "riskability-ai/1.3 (+splunk)")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    ctx = None
    if url.startswith("https:") and not verify_tls:
        ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ValueError("could not reach %s: %s" % (url, reason))
    except TimeoutError:
        raise ValueError(
            "no answer from %s within %s seconds. A loaded GPU box can "
            "legitimately be slower than this; raise the timeout." % (url, timeout))
    except Exception as exc:
        raise ValueError("request to %s failed: %s" % (url, exc))


def probe_models(url: str, auth_type: str, username: str, secret: str,
                 verify_tls: bool, timeout: int) -> dict:
    """GET {url}/v1/models -- the OpenAI-compatible handshake."""
    started = time.time()
    status, raw = _http(
        url.rstrip("/") + "/v1/models", headers=auth_header(auth_type, username, secret),
        timeout=max(5, min(int(timeout), 60)), verify_tls=verify_tls)
    latency = int((time.time() - started) * 1000)
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        raise ValueError("the endpoint answered HTTP %s but not with JSON" % status)
    if status != 200:
        hint = {401: "authentication failed -- check the auth type, username "
                     "and secret",
                403: "authenticated, but not allowed",
                404: "no /v1/models there -- is this the inference server's "
                     "root URL?"}.get(status, "")
        raise ValueError("HTTP %s. %s" % (status, hint))
    models = [str(m.get("id")) for m in payload.get("data", []) if isinstance(m, dict)]
    return {"ok": True, "status": status, "latency_ms": latency, "models": models}


def probe_completion(url: str, auth_type: str, username: str, secret: str,
                     model: str, verify_tls: bool, timeout: int) -> dict:
    """One chat completion over the synthetic finding, validated end to end.

    This is the closest thing to a dry run the search head can do by itself:
    same endpoint, same auth, same prompt shape and same output contract as a
    real T2 call.
    """
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_T2},
            {"role": "user", "content": build_user_payload(SYNTHETIC_CVE)},
        ],
        "temperature": 0.1,
        "max_tokens": 400,
    }
    started = time.time()
    status, raw = _http(
        url.rstrip("/") + "/v1/chat/completions", method="POST",
        headers=auth_header(auth_type, username, secret), body=body,
        timeout=max(10, min(int(timeout), 300)), verify_tls=verify_tls)
    latency = int((time.time() - started) * 1000)
    if status != 200:
        detail = raw[:300].decode("utf-8", "replace") if raw else ""
        hint = {401: "authentication failed",
                404: "no /v1/chat/completions there"}.get(status, "")
        raise ValueError("HTTP %s. %s %s" % (status, hint, detail))
    try:
        answer = json.loads(raw.decode("utf-8", "replace"))
        content = answer["choices"][0]["message"]["content"]
    except Exception:
        raise ValueError(
            "the endpoint answered HTTP 200 but the completion could not be "
            "read -- is this an OpenAI-compatible server?")
    # A prose answer is a finding, not a network fault: report it in the same
    # shape as a schema violation so the admin page and the test history both
    # show "endpoint reachable, output unusable" rather than a bare error.
    try:
        parsed = parse_llm_json(content)
    except ValueError as exc:
        return {"ok": False, "status": status, "latency_ms": latency,
                "validation_error": str(exc), "raw": content[:500]}
    clean, error = validate_result(parsed)
    if error:
        return {"ok": False, "status": status, "latency_ms": latency,
                "validation_error": error,
                "raw": content[:500]}
    return {"ok": True, "status": status, "latency_ms": latency, "result": clean}


def probe_bert(bert_url: str, verify_tls: bool, timeout: int) -> dict:
    """Health-check the ATT&CK tactic sidecar and classify one sample.

    The sidecar is optional, so failure here is reported as its own result
    and never fails the whole connection test.
    """
    base = bert_url.rstrip("/")
    started = time.time()
    status, raw = _http(base + "/health", timeout=max(5, min(int(timeout), 30)),
                        verify_tls=verify_tls)
    latency = int((time.time() - started) * 1000)
    if status != 200:
        return {"ok": False, "latency_ms": latency,
                "error": "health check answered HTTP %s" % status}
    sample = ("A remote code execution vulnerability in a public-facing web "
              "server allows an unauthenticated attacker to gain initial "
              "access and execute commands.")
    status, raw = _http(base + "/classify", method="POST",
                        body={"text": sample, "top_k": 3},
                        timeout=max(5, min(int(timeout), 30)),
                        verify_tls=verify_tls)
    if status != 200:
        return {"ok": False, "latency_ms": latency,
                "error": "/classify answered HTTP %s" % status}
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"ok": False, "latency_ms": latency,
                "error": "/classify answered with something that is not JSON"}
    return {"ok": True, "latency_ms": latency,
            "tactics": payload.get("tactics", []),
            "scores": payload.get("scores", [])}


def summarize_test(kind: str, ok: bool, detail: str) -> str:
    """The one-line history kept in conf so the page can show the last result
    after a reload, not only the one it just ran. Never carries a secret: the
    detail is prose the probes above wrote."""
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    return "%s · %s · %s · %s" % (stamp, kind, "ok" if ok else "failed", detail[:300])


# ---------------------------------------------------------------------------
# T0 deterministic triage and single-finding analysis
# ---------------------------------------------------------------------------

def _f(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def t0_rules(cve: dict):
    """Deterministic verdicts that never reach the model: auto-P0 for the
    known-exploited/reachable/confirmed combination, auto-P4 for the
    provably-boring one, None to defer everything else to T2.

    Queue fields are coerced defensively — the advisory store has no CVSS
    for every CVE (cvss_base_score arrives as "" sometimes) and kev arrives
    as the strings "true"/"false".
    """
    epss = _f(cve.get("epss"), 0.0)
    kev = _bool(cve.get("kev"))
    cvss = _f(cve.get("cvss_base_score"), 0.0)
    exposure = str(cve.get("exposure_zone") or "internal").strip().lower()
    version_match = str(cve.get("version_match") or "unknown").strip().lower()
    internet = exposure == "internet-facing"

    if cvss < 4.0 and epss < 0.05 and not kev and not internet \
            and version_match == "no":
        return {
            "priority_tier": "P4", "priority_score": 10, "confidence": 0.95,
            "rationale": "Low CVSS, EPSS under 5%, not in KEV, not "
                         "internet-facing, and the installed version is not "
                         "in the affected range.",
            "exploitability_signal": "none", "exposure_signal": exposure,
            "process_match_confidence": "unlikely", "recommended_action": "accept",
            "recommended_mitigations": [], "attck_techniques": [],
        }

    if kev and internet and version_match == "yes" and cvss >= 7.0:
        return {
            "priority_tier": "P0", "priority_score": 95, "confidence": 0.9,
            "rationale": "CISA KEV-listed, internet-facing, version "
                         "confirmed affected, CVSS %.1f." % cvss,
            "exploitability_signal": "active-exploit", "exposure_signal": exposure,
            "process_match_confidence": "confirmed", "recommended_action": "patch-now",
            "recommended_mitigations": [
                "Apply the vendor patch immediately",
                "Verify compensating controls (WAF, EDR, segmentation)",
            ],
            "attck_techniques": [],
        }

    return None


def analyze_finding(url: str, auth_type: str, username: str, secret: str,
                    model: str, verify_tls: bool, timeout: int,
                    cve: dict, max_tokens: int = 400) -> dict:
    """Analyse one finding: optional tactic pre-tag, one chat call, validate.

    Returns a result dict: {"ok", "latency_ms", "source", "result"| "error"}.
    Never raises for model-side problems — analysis failures become
    structured results the pipeline can report per finding.
    """
    tactics = []
    started = time.time()
    if cve.get("_bert_url"):
        try:
            status, raw = _http(
                cve["_bert_url"].rstrip("/") + "/classify", method="POST",
                body={"text": (str(cve.get("cve_description", "")) + " " +
                               str(cve.get("process_chain", "")))[:4000],
                      "top_k": 3},
                timeout=max(5, min(int(timeout), 30)), verify_tls=verify_tls)
            if status == 200:
                tactics = json.loads(raw.decode("utf-8", "replace")).get("tactics", [])
        except Exception:
            tactics = []
        # the marker key is transport, not analysis data
        cve = {k: v for k, v in cve.items() if k != "_bert_url"}

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_T2},
        {"role": "user", "content": build_user_payload(cve)
         + (("\n\nATT&CK tactic pre-tag: " + ", ".join(tactics)) if tactics else "")},
    ]
    auth = auth_header(auth_type, username, secret)
    status, raw = _http(
        url.rstrip("/") + "/v1/chat/completions", method="POST", headers=auth,
        body={"model": model, "messages": messages,
              "temperature": 0.1, "max_tokens": int(max_tokens)},
        timeout=max(10, min(int(timeout), 300)), verify_tls=verify_tls)
    latency = int((time.time() - started) * 1000)

    if status != 200:
        detail = raw[:200].decode("utf-8", "replace") if raw else ""
        return {"ok": False, "latency_ms": latency, "source": "T2",
                "error": "HTTP %s %s" % (status, detail)}
    try:
        answer = json.loads(raw.decode("utf-8", "replace"))
        content = answer["choices"][0]["message"]["content"]
    except Exception:
        return {"ok": False, "latency_ms": latency, "source": "T2",
                "error": "completion unreadable (not OpenAI-compatible?)"}
    try:
        parsed = parse_llm_json(content)
    except ValueError as exc:
        return {"ok": False, "latency_ms": latency, "source": "T2",
                "error": str(exc), "raw": content[:300]}
    clean, error = validate_result(parsed)
    if error:
        return {"ok": False, "latency_ms": latency, "source": "T2",
                "error": error, "raw": content[:300]}
    return {"ok": True, "latency_ms": latency, "source": "T2", "result": clean}


def verdict_sig(cve: dict) -> str:
    """Content signature of every input that may change a CVE's verdict.

    Computed identically on the SPL side (md5 of the same joined fields in
    the saved searches) and here in the command. The stored verdict is valid
    only while this signature matches: an EPSS move, a new KEV listing, a
    severity change or a revised description produces a new signature and
    forces one re-analysis. Deliberately EXCLUDED: anything per-asset
    (exposure, version match, criticality) — those are applied per finding
    by deterministic SPL after the verdict, so they can never trigger model
    calls.

    Strings only — deliberately NO float pieces: SPL's tostring and
    Python's str format the same number differently ("14" vs "14.000000"),
    and a signature that drifts between the SPL writer and the Python
    writer would re-analyse forever. EPSS is therefore NOT in the
    signature; verdict freshness is time-bounded instead (the expansion
    treats verdicts older than 7 days as stale), and the queue's urgency
    ordering always uses live EPSS regardless.
    """
    import hashlib

    kev01 = "1" if _bool(cve.get("kev")) else "0"
    basis = "|".join([
        str(cve.get("cve_id") or ""),
        str(cve.get("severity") or "").strip().lower(),
        kev01,
        str(cve.get("cvss_score") or cve.get("cvss_base_score") or "").strip(),
        str(cve.get("title") or cve.get("cve_description") or "").strip(),
    ])
    return hashlib.md5(basis.encode("utf-8")).hexdigest()
