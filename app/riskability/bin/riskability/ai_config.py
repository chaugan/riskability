"""Configuration, output contract and outbound HTTP for the AI pipeline.

Everything in this module is stdlib-only and Splunk-free, on purpose:

* ``riskability_ai_rest.py`` (the admin REST handler) imports it for validation
  and the network probes.
* ``riskabilityaianalyze.py``, the custom search command that does the real
  work, imports it for the T0 rules, the request path and the verdict
  signature. Every call this app makes to a model endpoint leaves through
  ``_http`` below, which is why the scheme, redirect and response-size limits
  live there rather than in each caller.
* ``tools/test_ai_mod.py`` exercises all of it on a laptop, against
  ``tools/ai_mock_server.py``, with no Splunk and no GPU in sight. A module
  that could only be tested on a search head against a real model server
  would never be tested at all, and this one guards secrets.

The pipeline this configures: a GPU box runs vLLM (Foundation-Sec-8B or any
OpenAI-compatible server) and an optional MITRE-ATT&CK BERT classifier, and
nothing else. Every step runs on the search head. A saved search builds the
candidate queue, the riskabilityaianalyze custom command calls the endpoint
directly and caches each verdict, and a third saved search expands the cached
verdicts onto findings. There is no orchestrator on the GPU side and no HEC
writeback, which is what ``docs/AI-MOD.md`` describes as well: Splunk owns the
schedule, the audit trail and the data, and the GPU box owns the inference
alone.

Nothing here ever logs or returns a secret. The password lives in Splunk
storage passwords and is passed around only in memory for the duration of a
probe. Model output gets the opposite treatment: it is the one input nobody on
this side wrote, so it is parsed, schema-checked and bounded here, and the
deterministic SPL rules downstream override it.
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
    # rather than an undocumented verify=False. Switching it off turns off
    # certificate chain AND hostname checking, for the model endpoint and for
    # the BERT sidecar alike: the configured bearer or basic secret then goes
    # to whoever answers on that address, and whoever that is writes every
    # verdict this search head caches, trusts and expands onto its fleet. It
    # is a setting for a lab box on a segment you own, nowhere else.
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
    # Concurrent T2 calls in flight from the search command, which is the only
    # caller there is: no orchestrator runs on the GPU side to agree with. Set
    # it to what one inference process on that card can genuinely serve at
    # once, which is usually far less than the number of threads it accepts.
    "t2_concurrency": {
        "kind": "int", "min": 1, "max": 128, "default": 1,
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
        "kind": "int", "min": 10, "max": 100000, "default": 1000,
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
            # Concurrency 1, measured rather than guessed. On the reference
            # 3060 a single request returns in 3,142 ms, but the median across
            # 21 real verdicts at concurrency 8 was 23,419 ms: the threads
            # queue behind a server that is not serving them in parallel, so
            # aggregate throughput went from ~0.32 to ~0.34 CVEs per second
            # for eight times the outstanding requests. Raise this only to
            # match a server actually configured to batch (Ollama's
            # OLLAMA_NUM_PARALLEL, vLLM's continuous batching), never hopefully.
            "t2_concurrency": 1, "t2_max_tokens": 400, "t3_max_tokens": 1200,
            "t3_deep_threshold": 70, "request_timeout": 150,
            "candidate_cap": 1000,
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
# The schema the prompt demands, enforced on everything a model says: the
# "Send test analysis" button and every real verdict go through the same
# validate_result, because the button's whole job is to answer "will this
# endpoint produce something the pipeline accepts" before a run depends on it.
# Nothing outside the schema survives the trip, and every string that does is
# bounded, because this is text an outside party influenced.

ALLOWED_TIERS = ("P0", "P1", "P2", "P3", "P4")
ALLOWED_EXPLOITABILITY = ("active-exploit", "proof-of-concept", "theoretical", "none")
ALLOWED_EXPOSURE = ("internet-facing", "internal", "isolated")
ALLOWED_PROCESS_MATCH = ("confirmed", "probable", "unlikely", "unknown")
ALLOWED_ACTION = ("patch-now", "mitigate", "monitor", "accept",
                  "risk-accept-with-compensation")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Model text ends up in a KV Store field, an event written by collect, a
# drilldown table and splunkd.log, and control characters make all four hard
# to read while an unbounded mitigation string makes the table unusable.
# Stripping and bounding is display hygiene and log cleanliness, nothing more.
# It is explicitly NOT an event-forging defence: collect escapes a newline
# inside a field value to a literal backslash and writes one event with no
# extra fields, measured on a live search head rather than assumed.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_RATIONALE = 2000
_MAX_MITIGATION = 300

# How many FAILED decode attempts one answer is worth. Counting failures
# rather than scan positions matters: a failure advances by a single
# character, so a budget spent on positions is exhausted by a run of bare
# braces before the real object is ever reached, and brace spam would deny a
# verdict rather than merely cost CPU. Successful decodes do not draw on it.
# The residual is honest: enough leading garbage still gives up, and that
# costs one finding on one run, because a failed analysis is reported and
# never cached, so the next run asks again.
_MAX_JSON_FAILURES = 2000
# And a bound on how much of an answer is worth scanning at all. The HTTP
# read cap is megabytes; a chat completion carrying a verdict is not.
_MAX_JSON_TEXT = 256 * 1024


def _clean_text(value, limit: int) -> str:
    """Control characters out, length bounded. See _CONTROL_RE above for why."""
    return _CONTROL_RE.sub(" ", str(value)).strip()[:limit]


def _json_objects(text: str):
    """Every top-level JSON object in an answer, in the order they appear.

    Returns (objects, last decode error as prose). Decodes forward from each
    "{" instead of slicing between the first "{" and the last "}": that slice
    is exactly what breaks when an answer carries two objects, which is the
    case that matters here rather than a curiosity. Stepping past a decoded
    object also keeps its own members from being offered as candidates.
    """
    decoder = json.JSONDecoder()
    text = text[:_MAX_JSON_TEXT]
    objects = []
    last_error = None
    index = text.find("{")
    failures = 0
    while index >= 0 and failures < _MAX_JSON_FAILURES:
        try:
            value, end = decoder.raw_decode(text, index)
        except Exception as exc:
            # Deliberately Exception and not JSONDecodeError. A deeply nested
            # answer raises RecursionError, which is not a ValueError, so it
            # would escape parse_llm_json's contract, escape analyze_finding's
            # "except ValueError", and take the whole batch down over one bad
            # answer. Everything that goes wrong in here leaves as prose.
            last_error = str(exc)
            failures += 1
            index = text.find("{", index + 1)
            continue
        if isinstance(value, dict):
            objects.append(value)
        index = text.find("{", max(end, index + 1))
    return objects, last_error


def parse_llm_json(content: str):
    """Pull the model's verdict object out of a chat completion's text answer.

    Lenient about wrapping on purpose: models really do put the object in a
    ```json fence, or behind a sentence of prose, or both, and a strict parser
    turns that into a false "endpoint broken".

    When an answer holds more than one object the LAST schema-valid one wins,
    not the first. Advisory titles are written outside this organisation,
    arrive in the imported CVE bundle and go into the prompt as
    cve_description, so a title can try to talk the model into emitting a
    complete, schema-valid decoy verdict ahead of its own answer. Preferring
    the first object hands that decoy the win, and a verdict is CVE-level: it
    is cached and then expanded onto every affected host, so one advisory
    string could suppress a CVE across the whole fleet. Taking the last object
    rests on a habit rather than a guarantee: a model that echoes something
    then answers usually puts its own answer after the echo. That is a
    heuristic, it has not been measured against this model, and an answer that
    echoes a decoy last would still win.

    That is a mitigation, not a fix. The control that actually holds is
    deterministic and downstream: the expansion search recomputes the T0 rules
    in SPL and lets them override the cached verdict, so KEV plus
    internet-facing plus version-confirmed plus CVSS>=7 stays P0 at score 95
    whatever the model said. Nothing here may weaken that.
    """
    if content is None:
        raise ValueError("the model returned an empty answer")
    objects, error = _json_objects(str(content))
    if not objects:
        if error is not None:
            raise ValueError("the model's answer was not valid JSON: %s" % error)
        raise ValueError("the model's answer contained no JSON object")
    for candidate in reversed(objects):
        if validate_result(candidate)[1] is None:
            return candidate
    # Nothing in the answer matched the schema. Hand back the last object so
    # the caller reports the schema violation it can see and quote, which is a
    # far better diagnosis than "no JSON object".
    return objects[-1]


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
    clean["rationale"] = _clean_text(rationale, _MAX_RATIONALE)
    if not clean["rationale"]:
        return None, "rationale missing"
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
    clean["recommended_mitigations"] = [
        m for m in (_clean_text(v, _MAX_MITIGATION) for v in mitigations) if m][:5]
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

# The T2 prompt. The GPU box runs an inference server and nothing else, so
# this constant is the only copy of it anywhere: the "Send test analysis"
# button and a scheduled run send the same system prompt, and a change here
# changes both at once.
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


# A chat completion is a few kilobytes. Four megabytes is room for an answer
# nobody sane would send and still small enough that a search head can hold a
# few of them per thread without noticing.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect handler that refuses every redirect instead of following it.

    urllib's default opener follows up to ten of them, counts ftp among the
    schemes it will follow to, and carries the Authorization header along even
    when the redirect changes host or scheme. On a search head that is a
    server-side request forgery primitive with the model endpoint's own token
    attached: an endpoint answering "302 Location:
    http://127.0.0.1:8089/services/..." gets this app to make an authenticated
    call to splunkd on its behalf. No inference server needs us to follow a
    redirect, so this declines them all (returning None is urllib's own way for
    a handler to say no) and _http turns the refusal into a clear error.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(ctx: Optional[ssl.SSLContext]) -> urllib.request.OpenerDirector:
    """An opener carrying only the handlers this app is allowed to have.

    Neither urlopen()'s global opener nor build_opener(): both register
    FileHandler, FTPHandler and DataHandler, so an endpoint_url of
    file:///etc/passwd is a working request rather than an error, and both
    follow redirects. Built by hand, the handler list is the whole answer to
    "what can this reach": http, https, and nothing else.

    ProxyHandler({}) is empty deliberately. It pins the proxy set to nothing,
    so http_proxy or https_proxy in splunkd's environment cannot silently
    reroute an air-gapped search head's inference traffic off the box.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler({}),
                    urllib.request.HTTPHandler(),
                    urllib.request.HTTPSHandler(context=ctx),
                    _NoRedirects(),
                    urllib.request.HTTPErrorProcessor(),
                    urllib.request.HTTPDefaultErrorHandler(),
                    urllib.request.UnknownHandler()):
        opener.add_handler(handler)
    return opener


def _read_capped(stream, url: str) -> bytes:
    """Read one response body up to _MAX_RESPONSE_BYTES and refuse more.

    read() with no argument reads to EOF, which lets the endpoint decide how
    much memory this search head spends. max_tokens bounds nothing here: it is
    a request parameter the server is free to ignore, and a server worth
    defending against ignores it by definition.
    """
    blob = stream.read(_MAX_RESPONSE_BYTES + 1)
    if len(blob) > _MAX_RESPONSE_BYTES:
        raise ValueError(
            "%s sent more than %s bytes for one answer and was cut off. A chat "
            "completion is kilobytes, so this is either the wrong URL or a "
            "server sending something that is not an answer."
            % (url, _MAX_RESPONSE_BYTES))
    return blob


def _http(url: str, method: str = "GET", headers: Optional[dict] = None,
          body: Optional[dict] = None, timeout: int = 30,
          verify_tls: bool = True) -> Tuple[int, bytes]:
    """One request. Returns (status, body bytes); raises ValueError in prose.

    This function is the trust boundary. Everything the app sends to a model
    endpoint leaves here and everything an endpoint says arrives here, so the
    scheme check, the refusal to follow redirects and the read cap live here
    rather than in the callers, who each have their own reasons to forget.

    urllib reports TLS verification failures with an error message that names
    the certificate, which is the detail that separates "self-signed cert, set
    verify accordingly" from "wrong port". Surfaces it instead of flattening
    every failure to "request failed".

    verify_tls=False disables certificate chain AND hostname checking, and the
    cost is worth stating plainly: the configured bearer or basic secret is
    handed to whoever answers on that address, and anyone on the path can be
    whoever answers. They then choose every verdict this search head caches
    and expands onto its fleet. It is a setting for a self-signed lab box on a
    segment you own.
    """
    # normalize_url() gates the admin page, but riskabilityaianalyze.py reads
    # endpoint_url straight out of conf, and conf can be written by a
    # deployment server or edited by hand without passing that gate. This is
    # the check on the path every request actually takes.
    scheme = urllib.parse.urlparse(url or "").scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(
            "refusing to request %s: only http:// and https:// endpoints are "
            "allowed" % ((url or "")[:200],))
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
    if scheme == "https" and not verify_tls:
        ctx = ssl._create_unverified_context()
    try:
        with _opener(ctx).open(req, timeout=timeout) as resp:
            return resp.status, _read_capped(resp, url)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            # Reported, never followed: see _NoRedirects. An admin who meant
            # to point at a URL that redirects needs to see that and fix the
            # setting, and an endpoint trying to steer us somewhere else needs
            # to fail loudly here.
            location = ""
            if exc.headers:
                location = str(exc.headers.get("Location", ""))[:200]
            raise ValueError(
                "%s answered HTTP %s and asked us to go to %s instead. "
                "Redirects are not followed; set the endpoint URL to the "
                "address that answers directly." % (url, exc.code, location or "(no Location)"))
        return exc.code, (_read_capped(exc, url)
                          if getattr(exc, "fp", None) is not None else b"")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ValueError("could not reach %s: %s" % (url, reason))
    except TimeoutError:
        raise ValueError(
            "no answer from %s within %s seconds. A loaded GPU box can "
            "legitimately be slower than this; raise the timeout." % (url, timeout))
    except ValueError:
        # Already prose from _read_capped: re-raising keeps it from being
        # wrapped into a second, vaguer sentence by the catch-all below.
        raise
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
                "validation_error": str(exc), "raw": _clean_text(content, 500)}
    clean, error = validate_result(parsed)
    if error:
        return {"ok": False, "status": status, "latency_ms": latency,
                "validation_error": error,
                # The echo the admin page shows so a broken answer can be read
                # rather than guessed at, cleaned like any other model text.
                "raw": _clean_text(content, 500)}
    return {"ok": True, "status": status, "latency_ms": latency, "result": clean}


def probe_bert(bert_url: str, verify_tls: bool, timeout: int) -> dict:
    """Health-check the ATT&CK tactic sidecar and classify one sample.

    The sidecar is optional, so failure here is reported as its own result
    and never fails the whole connection test.
    """
    base = bert_url.rstrip("/")
    started = time.time()
    # Both calls are guarded because the docstring above promises they are:
    # _http refuses redirects, oversized bodies and non-http schemes by
    # raising, and an unguarded raise here would fail the whole connection
    # test on the one component this app calls optional.
    try:
        status, raw = _http(base + "/health", timeout=max(5, min(int(timeout), 30)),
                            verify_tls=verify_tls)
    except ValueError as exc:
        return {"ok": False, "latency_ms": int((time.time() - started) * 1000),
                "error": str(exc)}
    latency = int((time.time() - started) * 1000)
    if status != 200:
        return {"ok": False, "latency_ms": latency,
                "error": "health check answered HTTP %s" % status}
    sample = ("A remote code execution vulnerability in a public-facing web "
              "server allows an unauthenticated attacker to gain initial "
              "access and execute commands.")
    try:
        status, raw = _http(base + "/classify", method="POST",
                            body={"text": sample, "top_k": 3},
                            timeout=max(5, min(int(timeout), 30)),
                            verify_tls=verify_tls)
    except ValueError as exc:
        return {"ok": False, "latency_ms": latency, "error": str(exc)}
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
    detail is prose the probes above wrote.

    One line means one line: this ends up as a conf value, and conf files are
    line-based, so a stray newline in a detail string has nowhere good to go.
    Today every caller passes prose written on this side, and _clean_text
    keeps that true if one day a caller passes something a model influenced.
    """
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    return "%s · %s · %s · %s" % (stamp, kind, "ok" if ok else "failed",
                                  _clean_text(detail, 300))


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
    # _http raises ValueError for the things it now refuses outright: a
    # redirect, a body past the read cap, a scheme that is not http or https.
    # Those must arrive here as a per-finding failure, not as an exception.
    # This function is called through a thread pool whose results are consumed
    # with list(pool.map(...)), so an escaping exception re-raises in the main
    # thread and takes down the whole scheduled run, discarding every verdict
    # already earned in that batch. One hostile or misconfigured endpoint must
    # cost one finding, never the run.
    try:
        status, raw = _http(
            url.rstrip("/") + "/v1/chat/completions", method="POST", headers=auth,
            body={"model": model, "messages": messages,
                  "temperature": 0.1, "max_tokens": int(max_tokens)},
            timeout=max(10, min(int(timeout), 300)), verify_tls=verify_tls)
    except ValueError as exc:
        return {"ok": False, "latency_ms": int((time.time() - started) * 1000),
                "source": "T2", "error": str(exc)}
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
                "error": str(exc), "raw": _clean_text(content, 300)}
    clean, error = validate_result(parsed)
    if error:
        return {"ok": False, "latency_ms": latency, "source": "T2",
                "error": error, "raw": _clean_text(content, 300)}
    return {"ok": True, "latency_ms": latency, "source": "T2", "result": clean}


def _cvss_band(value) -> str:
    """CVSS as one of four band characters, or "" when there is no score.

    A band rather than the number itself, because the signature has two
    writers. SPL's tostring and Python's str disagree about how to print the
    same float ("14" against "14.000000"), so a number in the signature drifts
    between the two writers and every CVE re-analyses forever. The SPL half
    computes this with tonumber() and the same three thresholds, and tonumber()
    of a missing or unparseable score is null, which is why anything this
    cannot read becomes "" here rather than 0.
    """
    try:
        score = float(value)
    except (TypeError, ValueError):
        return ""
    if score < 4:
        return "0"
    if score < 7:
        return "1"
    if score < 9:
        return "2"
    return "3"


def _epss_band(value) -> str:
    """EPSS as one of five band characters, absent or unparseable meaning 0.0.

    Banded for the format-stability reason above, and present at all because
    the version 1 signature left EPSS out entirely: a CVE could go from 0.002
    to 0.70 on the morning it was added to KEV and keep serving a verdict
    written when nobody was exploiting it, for a week, until the staleness
    clock ran out. The bands are coarse enough that ordinary daily noise does
    not re-analyse the fleet, and sharp enough that a real move does.
    """
    try:
        epss = float(value)
    except (TypeError, ValueError):
        epss = 0.0
    if epss < 0.01:
        return "0"
    if epss < 0.05:
        return "1"
    if epss < 0.20:
        return "2"
    if epss < 0.50:
        return "3"
    return "4"


def verdict_sig(cve: dict, salt: str) -> str:
    """Content signature of every input that may change a CVE's verdict.

    Version 2: md5 of salt, CVE id, lowercased severity, KEV as 1/0, CVSS
    band, EPSS band and advisory title, joined with "|". The identical
    computation lives in savedsearches.conf as an SPL md5(), in the candidate
    queue and the expansion searches. The two halves must agree byte for byte:
    a divergence does not fail, it silently splits the cache into one half that
    never gets read and one that never gets written, and nothing anywhere
    reports it. That is why the normalisation here is exactly what SPL does and
    nothing more, no trimming of stray whitespace and no clever coercion. A
    tidying step that exists in only one of the two writers is the divergence.

    Deliberately EXCLUDED: anything per-asset (exposure, version match,
    criticality). Those are applied per finding by deterministic SPL after the
    verdict, so they can never trigger model calls.

    The salt is passed in rather than derived here, and it is not optional.
    It carries the schema version and the model name, so swapping the model or
    editing the prompt invalidates every cached verdict exactly once instead of
    leaving the old model's judgements alive under the new model's name. Its
    one source of truth is the riskability_ai_sig_salt macro, which the SPL
    half expands directly; the caller reads that macro and hands the value
    over. Reconstructing it here from the model name would make a second
    source of truth for the one string whose whole job is to be the same in
    both writers.
    """
    import hashlib

    # Refuse an empty salt rather than hash one. The caller already raises if
    # the macro is unreadable, but this is the function every future caller
    # will reach for, and the failure it prevents is the worst kind: an empty
    # salt hashes perfectly well, matches nothing the SPL half ever wrote, and
    # so re-analyses every CVE on every run forever with no error anywhere.
    # Loud here, once, beats silent there, always.
    if not str(salt or "").strip():
        raise ValueError(
            "verdict_sig needs the riskability_ai_sig_salt value; an empty "
            "salt would silently invalidate the whole verdict cache")

    kev01 = "1" if _bool(cve.get("kev")) else "0"
    basis = "|".join([
        str(salt),
        str(cve.get("cve_id") or ""),
        str(cve.get("severity") or "").lower(),
        kev01,
        _cvss_band(cve.get("cvss_score") if cve.get("cvss_score") not in (None, "")
                   else cve.get("cvss_base_score")),
        _epss_band(cve.get("epss")),
        # cve_description first: it is the field the queue search writes, and
        # it holds exactly what the SPL half hashed, the advisory title with
        # the finding's own title as fallback. A row that has neither is a row
        # the model was given no title for, and "" is the honest signature.
        str(cve.get("cve_description") or cve.get("title") or ""),
    ])
    return hashlib.md5(basis.encode("utf-8")).hexdigest()
