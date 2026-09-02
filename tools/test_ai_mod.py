#!/usr/bin/env python3
"""Tests for the AI mod, runnable on a laptop with no Splunk and no GPU.

  python3 tools/test_ai_mod.py

Covers the two things that must not silently rot:

1. The settings and output contract in bin/riskability/ai_config.py: the
   validation the admin endpoint depends on, and the result schema the whole
   pipeline hangs off.
2. The HTTP probes end to end against tools/ai_mock_server.py: the same
   functions the admin page's Test buttons call, over real sockets.
3. The conf files the mod adds parse the strict way the Splunk Packaging
   Toolkit parses them (borrowing tools/conf_lint.py), because a continuation
   line that lost its backslash is invisible until an app submission fails.
"""

from __future__ import annotations

import json
import re
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "app", "riskability", "bin"))

from riskability import ai_config  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print("  ok   %s" % name)
    else:
        FAILURES.append(name)
        print("  FAIL %s %s" % (name, detail))


def raises(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
        return None
    except ValueError as exc:
        return str(exc)
    except Exception as exc:
        return "wrong exception: %r" % exc


# ---------------------------------------------------------------------------
# Settings validation
# ---------------------------------------------------------------------------

def test_settings():
    print("validate_settings:")
    base = {"endpoint_url": "http://127.0.0.1:8000", "enabled": "0"}
    merged = ai_config.validate_settings(base, {})
    # t2_concurrency defaults to 2, matching the two sequence slots the Measured on the reference
    # 3060: 3,142 ms for a single request against a 23,419 ms median at
    # concurrency 8, for the same aggregate throughput. The default must not
    # drift back up without a server that actually batches.
    check("defaults fill in", merged["model"] == "foundation-sec-8b"
          and merged["t2_concurrency"] == "2"
          and merged["candidate_cap"] == "1000")
    check("url keeps scheme, loses trailing slash",
          ai_config.validate_settings({"endpoint_url": "http://x:8000/"}, {})["endpoint_url"]
          == "http://x:8000")

    err = raises(ai_config.validate_settings, {"endpoint_url": "ftp://x"}, {})
    check("non-http scheme rejected", err and "http" in err, err)
    err = raises(ai_config.validate_settings, {"endpoint_url": "https://user:pw@host"}, {})
    check("credentials in URL rejected", err and "username" in err, err)
    err = raises(ai_config.validate_settings, {"nope": 1}, {})
    check("unknown key rejected", err and "nope" in err, err)
    err = raises(ai_config.validate_settings, {"t2_concurrency": "1000"}, {})
    check("concurrency bound enforced", err and "between" in err, err)
    err = raises(ai_config.validate_settings, {"t2_concurrency": "abc"}, {})
    check("non-number rejected", err, err)
    err = raises(ai_config.validate_settings, {"enabled": "1"}, {})
    check("enable without URL refused", err and "URL" in err, err)
    err = raises(ai_config.validate_settings,
                 {"auth_type": "basic", "username": "", "endpoint_url": "http://x",
                  "enabled": "1"}, {})
    check("basic auth without username refused", err and "username" in err, err)
    ok = ai_config.validate_settings(
        {"enabled": "true", "endpoint_url": "http://x:8000", "auth_type": "bearer"}, {})
    check("bool coercion", ok["enabled"] == "1")
    check("merge keeps current values",
          ai_config.validate_settings({}, {"model": "qwen-7b"})["model"] == "qwen-7b")


# ---------------------------------------------------------------------------
# LLM answer contract
# ---------------------------------------------------------------------------

GOOD = {
    "priority_tier": "P0", "priority_score": 92, "confidence": 0.8,
    "rationale": "Known exploited, internet facing, version confirmed vulnerable.",
    "exploitability_signal": "active-exploit", "exposure_signal": "internet-facing",
    "process_match_confidence": "confirmed", "recommended_action": "patch-now",
    "recommended_mitigations": ["patch"], "attck_techniques": ["T1195.001", "bogus"],
}


def test_result():
    print("validate_result / parse_llm_json:")
    clean, err = ai_config.validate_result(GOOD)
    check("valid result accepted", err is None and clean["model_tier"] == "P0"
          and "priority_tier" not in clean)
    check("invalid technique dropped, valid kept",
          clean and clean["attck_techniques"] == ["T1195.001"])
    for key, bad in (("priority_tier", "P9"), ("recommended_action", "yolo"),
                     ("exposure_signal", "the-moon")):
        broken = dict(GOOD); broken[key] = bad
        _, err = ai_config.validate_result(broken)
        check("bad %s rejected" % key, err is not None and key in err, str(err))
    broken = dict(GOOD); broken["priority_score"] = 101
    _, err = ai_config.validate_result(broken)
    check("score bound enforced", err is not None)
    broken = dict(GOOD); broken["rationale"] = ""
    _, err = ai_config.validate_result(broken)
    check("empty rationale rejected", err is not None)

    check("bare json parses",
          ai_config.parse_llm_json(json.dumps(GOOD))["priority_tier"] == "P0")
    check("fenced json parses",
          ai_config.parse_llm_json("```json\n" + json.dumps(GOOD) + "\n```") is not None)
    check("prose-wrapped json parses",
          ai_config.parse_llm_json("Here you are:\n" + json.dumps(GOOD)) is not None)
    err = raises(ai_config.parse_llm_json, "no json at all")
    check("prose without json rejected", err is not None, err)


def test_priority_is_deterministic():
    print("priority from measured facts:")
    hot = {"kev": "true", "epss": "0.6", "cvss_base_score": "9.5",
           "exposure_zone": "internal", "version_match": "yes"}
    dull = {"kev": "false", "epss": "0.02", "cvss_base_score": "7.5",
            "exposure_zone": "internal", "version_match": "unknown"}
    hs, ds = ai_config.priority_score(hot), ai_config.priority_score(dull)
    check("KEV plus confirmed version reaches P0",
          ai_config.tier_for_score(hs) == "P0", str(hs))
    check("unconfirmed low-EPSS internal stays low",
          ai_config.tier_for_score(ds) in ("P3", "P4"), str(ds))
    # The whole point: nothing the model says can move these numbers.
    check("model cannot influence the score",
          ai_config.priority_score(dict(dull, priority_score=99,
                                        priority_tier="P0")) == ds)
    check("no affected version is a real downgrade",
          ai_config.priority_score(dict(hot, version_match="no")) < hs)


def test_auth_header():
    print("auth_header:")
    check("bearer",
          ai_config.auth_header("bearer", "", "sekrit")["Authorization"] == "Bearer sekrit")
    import base64
    expected = "Basic " + base64.b64encode(b"svc:pw").decode()
    check("basic",
          ai_config.auth_header("basic", "svc", "pw")["Authorization"] == expected)
    check("none", ai_config.auth_header("none", "", "") == {})


# ---------------------------------------------------------------------------
# Probes against the mock server
# ---------------------------------------------------------------------------

def test_probes(port, invalid=False):
    url = "http://127.0.0.1:%d" % port
    print("probes against %s:" % url)

    r = ai_config.probe_models(url, "none", "", "", True, 10)
    check("models probe", r["ok"] and r["models"] == ["foundation-sec-8b"],
          json.dumps(r))

    r = ai_config.probe_completion(url, "none", "", "irrelevant",
                                   "foundation-sec-8b", True, 30)
    if invalid:
        check("invalid answer reported not-ok", r["ok"] is False
              and r.get("validation_error"), json.dumps(r))
    else:
        check("completion probe ok", r["ok"] is True, json.dumps(r)[:400])
        check("completion validated to model tier",
              r["ok"] and r["result"]["model_tier"] == "P0")
        check("latency measured", r.get("latency_ms", 0) >= 0)

    r = ai_config.probe_bert(url, True, 10)
    check("bert probe", r["ok"] and r["tactics"] == ["TA0001", "TA0008"],
          json.dumps(r))

    # A dead endpoint must fail with prose a human can act on, not a traceback.
    err = raises(ai_config.probe_models, "http://127.0.0.1:9", "none", "", "", True, 2)
    check("unreachable endpoint fails in prose", err and "reach" in err, err)


# ---------------------------------------------------------------------------
# Conf lint
# ---------------------------------------------------------------------------

def test_conf_files():
    print("conf parsing (packaging-toolkit rules):")
    sys.path.insert(0, HERE)
    import conf_lint
    targets = [os.path.join(ROOT, "app", "riskability", "default", n)
               for n in ("riskability_ai.conf", "restmap.conf", "web.conf",
                         "authorize.conf", "macros.conf",
                         "savedsearches.conf", "app.conf")]
    targets.append(os.path.join(ROOT, "app", "riskability-config", "default", "app.conf"))
    targets += [os.path.join(ROOT, "app", "TA-riskability-ai", "default", n)
                for n in ("indexes.conf", "props.conf", "app.conf")]
    for path in targets:
        problems = conf_lint.lint(path)
        check(os.path.relpath(path, ROOT), not problems, str(problems))


# ---------------------------------------------------------------------------

class MockServer:
    """Runs tools/ai_mock_server.py as a subprocess, like the real thing."""

    def __init__(self, port, extra=()):
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "ai_mock_server.py"),
             "--port", str(port)] + list(extra),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port = port

    def wait(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/v1/models" % self.port, timeout=1).read()
                return True
            except Exception:
                time.sleep(0.1)
        return False

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)


def test_t0_and_analyze(port):
    print("T0 rules and single-finding analysis:")
    kev_row = {"kev": "true", "cvss_base_score": 9.4, "epss": 0.5,
               "exposure_zone": "internet-facing", "version_match": "yes"}
    r = ai_config.t0_rules(kev_row)
    check("T0 auto-P0 on KEV+exposed+confirmed", r and r["priority_tier"] == "P0")
    boring = {"kev": "false", "cvss_base_score": 3.1, "epss": 0.01,
              "exposure_zone": "isolated", "version_match": "no"}
    r = ai_config.t0_rules(boring)
    check("T0 auto-P4 on the provably boring", r and r["priority_tier"] == "P4")
    mid = {"kev": "false", "cvss_base_score": "", "epss": 0.3,
           "exposure_zone": "internal", "version_match": "unknown"}
    check("T0 defers the undecided middle", ai_config.t0_rules(mid) is None)

    url = "http://127.0.0.1:%d" % port
    r = ai_config.analyze_finding(url, "bearer", "", "k", "foundation-sec-8b",
                                  True, 60, mid, 300)
    check("analyze_finding ok", r["ok"] and r["result"]["model_tier"] == "P0",
          json.dumps(r)[:200])


def test_verdict_sig():
    print("verdict_sig:")
    salt = "v2:foundation-sec-8b"
    sig = lambda cve: ai_config.verdict_sig(cve, salt)
    base = {"cve_id": "CVE-1", "severity": "High", "kev": "false",
            "epss": "0.12345", "cvss_score": "7.5", "title": "Some flaw"}
    a, b = sig(base), sig(dict(base))
    check("deterministic", a == b)
    # Version 2 bands EPSS rather than excluding it. Two values inside one
    # band must still agree: that is what keeps the SPL and Python writers
    # from drifting on float formatting, which is why EPSS was excluded
    # outright in version 1.
    same_band = dict(base); same_band["epss"] = "0.13"
    check("epss inside a band -> same sig", sig(same_band) == a)
    # And the half version 1 could not do: a move that crosses a band MUST
    # invalidate the verdict. An EPSS jump from 12% to 70% on a KEV add is
    # the case that used to leave a stale verdict alive for a week.
    cross_band = dict(base); cross_band["epss"] = "0.70"
    check("epss crossing a band -> new sig", sig(cross_band) != a)
    cvss_band = dict(base); cvss_band["cvss_score"] = "9.1"
    check("cvss crossing a band -> new sig", sig(cvss_band) != a)
    changed2 = dict(base); changed2["title"] = "Different advisory text"
    check("title change -> new sig", sig(changed2) != a)
    case = dict(base); case["severity"] = "high"
    check("severity case-insensitive", sig(case) == a)
    check("kev string/false split", sig(dict(base, kev="true")) != a)
    # The salt is the whole point of version 2: change the model or the
    # prompt and every cached verdict must be re-earned exactly once.
    check("salt change -> new sig",
          ai_config.verdict_sig(base, "v2:some-other-model") != a)
    # A missing salt would quietly match nothing and re-analyse the fleet on
    # every run, with no error anywhere. It must not be silently tolerated.
    check("empty salt refused",
          _raises(lambda: ai_config.verdict_sig(base, "")))


def _raises(fn):
    try:
        fn()
    except Exception:
        return True
    return False


def test_dashboard_weights_match_the_scorer():
    """The AI page prints the scoring table; this fails when it drifts.

    The weights live in ai_config.py and are written a second time in
    riskability_ai_overview.js so a reader can check the arithmetic against the
    number in front of them. Two copies of a constant is a promise to keep them
    equal, and a dashboard that explains the score wrongly is worse than one
    that does not explain it at all: it is confidently wrong about the only
    thing on the page a reader might verify.
    """
    js_path = (Path(__file__).resolve().parents[1] / "app" / "riskability" /
               "appserver" / "static" / "riskability_ai_overview.js")
    if not js_path.exists():
        check("the dashboard script exists", False, str(js_path))
        return
    js = js_path.read_text(encoding="utf-8")

    def weights(block_name):
        m = re.search(block_name + r"\s*=\s*\[(.*?)\n    \];", js, re.S)
        if not m:
            return {}
        found = {}
        for label, value in re.findall(r'\["([^"]+)",\s*"([^"]+)"', m.group(1)):
            clean = (value.replace("\\u2212", "-").replace("+", "").strip())
            try:
                found[label] = int(clean)
            except ValueError:
                pass
        return found

    got = weights("SCORE_ROWS")
    check("the dashboard prints a scoring table", bool(got), str(len(got)))

    expected = {
        "On CISA KEV": ai_config._W_KEV,
        "EPSS \\u2265 50%": ai_config._W_EPSS["4"],
        "EPSS 20\\u201350%": ai_config._W_EPSS["3"],
        "EPSS 5\\u201320%": ai_config._W_EPSS["2"],
        "EPSS 1\\u20135%": ai_config._W_EPSS["1"],
        "EPSS < 1%": ai_config._W_EPSS["0"],
        "CVSS \\u2265 9": ai_config._W_CVSS["3"],
        "CVSS 7\\u20139": ai_config._W_CVSS["2"],
        "CVSS 4\\u20137": ai_config._W_CVSS["1"],
        "CVSS < 4, or none": ai_config._W_CVSS["0"],
        "Internet-facing": ai_config._W_EXPOSURE["internet-facing"],
        "Internal": ai_config._W_EXPOSURE["internal"],
        "Isolated": ai_config._W_EXPOSURE["isolated"],
        "Exposure unknown": ai_config._W_EXPOSURE_UNKNOWN,
        "Version confirmed vulnerable": ai_config._W_VERSION["yes"],
        "Version unknown": ai_config._W_VERSION["unknown"],
        "Version confirmed NOT vulnerable": ai_config._W_VERSION["no"],
    }
    for label, want in expected.items():
        check("dashboard weight for %r is %s" % (label, want),
              got.get(label) == want, "page says %s" % got.get(label))

    # Every weight the scorer can add must appear on the page. A term that is
    # in the arithmetic and not in the table is the same silent gap in a
    # different place.
    check("the page lists every weight the scorer uses",
          len(got) == len(expected), "%d on the page, %d expected"
          % (len(got), len(expected)))

    tiers = re.search(r"TIER_ROWS\s*=\s*\[(.*?)\n    \];", js, re.S)
    check("the dashboard prints a tier table", bool(tiers))
    if tiers:
        floors = [int(x) for x in re.findall(r'"(\d+)\\u2013\d+"', tiers.group(1))]
        want_floors = [cut for cut, _ in ai_config.TIER_THRESHOLDS] + [0]
        check("tier floors match TIER_THRESHOLDS", floors == want_floors,
              "page %s, scorer %s" % (floors, want_floors))



def main():
    test_settings()
    test_result()
    test_auth_header()
    test_verdict_sig()
    test_priority_is_deterministic()
    test_conf_files()
    test_dashboard_weights_match_the_scorer()

    server = MockServer(8931)
    try:
        if not server.wait():
            check("mock server started", False)
        else:
            test_t0_and_analyze(8931)
            test_probes(8931, invalid=False)
    finally:
        server.stop()

    bad = MockServer(8932, extra=["--invalid"])
    try:
        if bad.wait():
            test_probes(8932, invalid=True)
        else:
            check("invalid mock server started", False)
    finally:
        bad.stop()

    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
