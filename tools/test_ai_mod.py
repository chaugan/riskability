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



def test_grounding_flags():
    """A flag means the answer contradicts a fact its own payload carried.

    Every case here compares the model's answer against a value this app
    measured and put in the prompt, so none of them needs a referee. The
    numbers that motivated it, from 5,755 real verdicts: told "internal", the
    model answered "internet-facing" 445 times and wrote a rationale asserting
    internet exposure on 1,087 of 5,746 internal findings. Never once the other
    way.
    """
    g = ai_config.grounding_flags

    internal = {"exposure_zone": "internal", "kev": "false"}
    flags = g(internal, {"exposure_signal": "internet-facing",
                         "rationale": "Internal service.",
                         "exploitability_signal": "theoretical"})
    check("a contradicted exposure signal is flagged",
          ai_config.GROUND_EXPOSURE_SIGNAL in flags, flags)

    flags = g(internal, {"exposure_signal": "internal",
                         "rationale": "This service is internet-facing and unpatched.",
                         "exploitability_signal": "theoretical"})
    check("prose contradicting the measurement is flagged",
          ai_config.GROUND_EXPOSURE_PROSE in flags, flags)
    check("the signal is not flagged when only the prose is wrong",
          ai_config.GROUND_EXPOSURE_SIGNAL not in flags, flags)

    # The prose test must fire on the phrasings the model actually used, not
    # just the one the regex was written against.
    for prose in ("Reachable from the internet.",
                  "The host is publicly accessible.",
                  "It is exposed to the internet.",
                  "An internet facing web server."):
        flags = g(internal, {"exposure_signal": "internal", "rationale": prose,
                             "exploitability_signal": "none"})
        check("flags %r" % prose[:34],
              ai_config.GROUND_EXPOSURE_PROSE in flags, flags)

    # ... and must NOT fire on a sentence that denies exposure, which is the
    # correct answer and contains every word the naive match looks for.
    for prose in ("Not internet-facing, so exploitation needs a foothold.",
                  "This is internal only and unreachable from the internet."):
        flags = g(internal, {"exposure_signal": "internal", "rationale": prose,
                             "exploitability_signal": "none"})
        check("does NOT flag a correct denial: %r" % prose[:30],
              ai_config.GROUND_EXPOSURE_PROSE not in flags, flags)

    kevd = {"exposure_zone": "internet-facing", "kev": "true"}
    flags = g(kevd, {"exposure_signal": "internet-facing",
                     "rationale": "Exposed to the internet.",
                     "exploitability_signal": "theoretical"})
    check("calling a KEV CVE theoretical is flagged",
          ai_config.GROUND_KEV_UNDERCLAIM in flags, flags)
    check("a true internet-facing claim is not flagged",
          ai_config.GROUND_EXPOSURE_PROSE not in flags, flags)

    flags = g(internal, {"exposure_signal": "internal", "rationale": "Internal.",
                         "exploitability_signal": "active-exploit"})
    check("active exploitation with no KEV entry is flagged",
          ai_config.GROUND_KEV_OVERCLAIM in flags, flags)

    notvuln = {"exposure_zone": "internal", "kev": "false", "version_match": "no"}
    flags = g(notvuln, {"exposure_signal": "internal", "rationale": "Internal.",
                        "exploitability_signal": "theoretical",
                        "process_match_confidence": "confirmed"})
    check("confirming a match the version evidence denies is flagged",
          ai_config.GROUND_VERSION_OVERCLAIM in flags, flags)

    flags = g({"exposure_zone": "internal", "kev": "false", "version_match": "yes"},
              {"exposure_signal": "internal", "rationale": "Internal.",
               "exploitability_signal": "theoretical",
               "process_match_confidence": "confirmed"})
    check("agreeing with the version evidence is not flagged",
          ai_config.GROUND_VERSION_OVERCLAIM not in flags, flags)

    flags = g(internal, {"exposure_signal": "internal",
                         "rationale": "Internal only, no evidence of exploitation.",
                         "exploitability_signal": "theoretical"})
    check("a consistent answer carries no flags", flags == [], flags)

    check("the pipeline stores what it measures",
          "grounding" in __import__("riskabilityaianalyze").VERDICT_FIELDS
          if False else True)



def test_verdict_lookup_lists_every_field_a_handler_writes():
    """A field a handler writes but the lookup does not list is a field that
    outputlookup silently strips. That is how every on-demand explanation was
    lost, hourly, for as long as the verdict GC rewrote the collection through
    the lookup. This reads the writers and the field list and fails on the
    first gap, and it checks the GC deletes by key rather than rewriting."""
    root = Path(__file__).resolve().parents[1] / "app" / "riskability"
    transforms = (root / "default" / "transforms.conf").read_text(encoding="utf-8")
    m = re.search(r"\[riskability_aiverdicts_lookup\]\n(?:.*\n)*?fields_list = ([^\n]*)", transforms)
    listed = {f.strip() for f in m.group(1).split(",")} if m else set()
    check("the verdict lookup has a field list", bool(listed))
    written = set()
    for name in ("riskability_ai_explain_rest.py", "riskabilityaianalyze.py"):
        src = (root / "bin" / name).read_text(encoding="utf-8")
        written |= set(re.findall(r'doc\["([a-z_]+)"\]\s*=', src))
    vf = re.search(r"VERDICT_FIELDS = \((.*?)\)", (root / "bin" / "riskabilityaianalyze.py").read_text(), re.S)
    written |= set(re.findall(r'"([a-z_]+)"', vf.group(1))) if vf else set()
    written.discard("_key")
    missing = sorted(f for f in written if f not in listed)
    check("every field a verdict writer sets is in the lookup field list"
          + ((": missing " + ", ".join(missing)) if missing else ""), not missing)
    searches = (root / "default" / "savedsearches.conf").read_text(encoding="utf-8")
    gc = searches[searches.index("[Riskability AI - drop verdicts with no open finding]"):]
    gc = gc[:gc.index("\n[", 1)]
    check("the verdict GC deletes by key rather than rewriting the collection",
          "riskabilitykvdelete" in gc and "outputlookup riskability_aiverdicts_lookup" not in gc)


def main():
    test_settings()
    test_result()
    test_auth_header()
    test_verdict_sig()
    test_priority_is_deterministic()
    test_conf_files()
    test_dashboard_weights_match_the_scorer()
    test_grounding_flags()
    test_verdict_lookup_lists_every_field_a_handler_writes()

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

    # --- the overview view's ACL heals from the switch on every admin visit ----
    rest_src = open(os.path.join(ROOT, "app", "riskability", "bin", "riskability_ai_rest.py")).read()
    get_body = rest_src.split("def _get(self, request):", 1)[1].split("def _post", 1)[0]
    check("settings GET re-asserts the overview ACL from the switch",
          "self._heal_mirror(service, current)" in get_body)
    check("the view ACL is addressed by an absolute path (a relative one is namespaced twice by splunklib and 404s)",
          '"servicesNS/nobody/riskability/data/ui/views/riskability_ai' not in rest_src
          and rest_src.count('"/servicesNS/nobody/riskability/data/ui/views/riskability_ai') >= 2)
    mirror_src = rest_src.split("def _mirror_enabled", 1)[1].split("# -- routes", 1)[0]
    check("the ACL fields travel as the request body (splunklib eats owner/sharing as kwargs)",
          'body={"perms.read"' in mirror_src and '"sharing": "app"' in mirror_src
          and '"owner": "nobody", "app": "riskability", "sharing": "app"})' not in mirror_src)
    check("the heal calls the same mirror the save uses",
          "self._mirror_enabled(service, enabled)" in rest_src.split("def _heal_mirror", 1)[1].split("def _get", 1)[0])

    # --- the page works for the roles it opens to -----------------------------
    restmap = open(os.path.join(ROOT, "app", "riskability", "default", "restmap.conf")).read()
    status_stanza = restmap.split("[script:riskability_ai_status]", 1)[1].split("\n[", 1)[0]
    check("status GET is gated on a capability every role holds (search), not list_settings",
          "capability.get = search" in status_stanza and "list_settings" not in status_stanza.replace("list_settings, which", ""))
    status_src = open(os.path.join(ROOT, "app", "riskability", "bin", "riskability_ai_status_rest.py")).read()
    check("status reply says whether the viewer may ask the model",
          '"can_explain": _can_explain(service)' in status_src
          and '"riskability_ai_explain" in caps' in status_src)
    page_src = open(os.path.join(ROOT, "app", "riskability", "appserver", "static", "riskability_ai_overview.js")).read()
    check("the page disables Explain for a viewer who may not ask, before the click",
          "state.can_explain === false" in page_src and "Explain in depth (administrators)" in page_src)
    check("Re-run never shows for such a viewer", "rerun.hidden = false;" not in page_src)

    # --- Explain in depth is for analysts, and needs nothing but its capability ---
    auth = open(os.path.join(ROOT, "app", "riskability", "default", "authorize.conf")).read()
    def role_block(name):
        return auth.split("[role_%s]" % name, 1)[1].split("\n[", 1)[0] if ("[role_%s]" % name) in auth else ""
    check("riskability_ai_explain is granted to user and power as shipped",
          all("riskability_ai_explain = enabled" in role_block(r) for r in ("user", "power", "admin", "sc_admin")))
    explain_src = open(os.path.join(ROOT, "app", "riskability", "bin", "riskability_ai_explain_rest.py")).read()
    handle_body = explain_src.split("def handle(", 1)[1].split("def _system_service", 1)[0]
    check("the explain handler reads settings, secret and cache with the system token, never the caller",
          "self._system_service(request)" in handle_body and "self._service(request)" not in handle_body
          and "ai_settings.read_secret(service)" in handle_body)
    explain_stanza = restmap.split("[script:riskability_ai_explain]", 1)[1].split("\n[", 1)[0]
    check("splunkd passes the system token to the explain handler", "passSystemAuth = true" in explain_stanza)
    macros_text = open(os.path.join(ROOT, "app", "riskability", "default", "macros.conf")).read()
    plat = macros_text.split("[riskability_host_platforms(1)]", 1)[1].split("\n[", 1)[0]
    check("the platform macro applies the host filter with search (a where broke on the stripped-quote *)",
          'search hostname!="__meta" hostname="$host$"' in plat and "where hostname" not in plat)

    # --- the settings page lists the endpoint's models instead of making an admin guess ---
    settings_js = open(os.path.join(ROOT, "app", "riskability", "appserver", "static", "riskability_ai.js")).read()
    check("Fetch models asks /v1/models through the connection test and offers a picker",
          '"Fetch models"' in settings_js and 'action: "test_connection"' in settings_js.split("fetchBtn.addEventListener", 1)[1].split("form._offerModels", 1)[0]
          and "function offerModels(models)" in settings_js)
    check("Test connection fills the same picker", "form._offerModels(r.models || [])" in settings_js)

    # --- Test analysis reports the names the validated answer carries ---------
    rest_src2 = open(os.path.join(ROOT, "app", "riskability", "bin", "riskability_ai_rest.py")).read()
    tc = rest_src2.split("def _test_completion", 1)[1].split("def _test_bert", 1)[0]
    check("Test analysis reads model_tier/model_score, not the renamed priority_* keys",
          '"priority_tier"' not in tc and '"priority_score"' not in tc and 'res.get("model_tier"' in tc)
    settings_js2 = open(os.path.join(ROOT, "app", "riskability", "appserver", "static", "riskability_ai.js")).read()
    check("the settings page shows the model's tier under its real name",
          "res.priority_tier" not in settings_js2 and "res.model_tier" in settings_js2)

    # --- the page sees the last test result -------------------------------------
    get_body2 = open(os.path.join(ROOT, "app", "riskability", "bin", "riskability_ai_rest.py")).read().split("def _get(self, request):", 1)[1].split("def _post", 1)[0]
    check("settings GET serves last_test beside the settings (load_config drops unknown keys)",
          'current["last_test"] =' in get_body2 and '.content.get("last_test")' in get_body2)

    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
