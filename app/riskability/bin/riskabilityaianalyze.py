#!/usr/bin/env python
"""Riskability AI analysis: the queue consumer and verdict cache writer.

Input: the candidate queue (one row per distinct CVE, budget-selected by the
queue saved search, with T0-decided rows already excluded). Output: one
verdict row per input CVE, PLUS an upsert of every verdict into the
``riskability_aiverdicts`` KV collection — the cache the expansion search
joins against.

Scale contract (why this is CVE-level and cached):

* The unit of analysis is the CVE, never the finding. Findings on 50,000
  hosts collapse to the distinct-CVE set here; per-asset variation
  (exposure, version match, criticality) is applied later by deterministic
  SPL, which scales for free.
* A verdict is keyed by a content signature of its inputs (verdict_sig).
  Same signature on a later run: served from the cache, zero model calls.
  Changed inputs: exactly one re-analysis.
* A per-run budget bounds model calls (candidate_cap); rows beyond the
  budget are left WITHOUT verdicts rather than given fake ones, and the
  next run picks them up first (cache hits are instant, so the backlog
  drains in urgency order).
"""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import Configuration, EventingCommand, dispatch  # noqa: E402

from riskability import ai_config, ai_settings  # noqa: E402

VERDICT_COLLECTION = "riskability_aiverdicts"
VERDICT_FIELDS = ("priority_tier", "priority_score", "confidence", "rationale",
                  "exploitability_signal", "exposure_signal",
                  "process_match_confidence", "recommended_action",
                  "recommended_mitigations", "attck_techniques")


@Configuration()
class RiskabilityAIAnalyzeCommand(EventingCommand):
    def transform(self, records):
        # TEMP crash probe: search-command generator exceptions vanish into
        # "exited unexpectedly" — capture the real traceback.
        import traceback
        try:
            for row in self._transform_impl(records):
                yield row
        except BaseException:
            with open("/tmp/rkai_analyze_error.log", "w") as f:
                f.write(traceback.format_exc())
            raise

    def _transform_impl(self, records):
        cfg = ai_settings.load_config(self.service)
        if str(cfg.get("enabled", "0")).strip().lower() in ("1", "true", "yes", "on"):
            secret = ai_settings.read_secret(self.service)
        else:
            raise RuntimeError(
                "AI analysis is switched off in the Riskability Configuration "
                "app; this command refuses to contact any endpoint")
        url = cfg["endpoint_url"]
        auth_type, username = cfg["auth_type"], cfg["username"]
        model, verify = cfg["model"], cfg["verify_tls"] == "1"
        timeout = int(cfg["request_timeout"])
        workers = max(1, int(cfg["t2_concurrency"]))
        max_tokens = int(cfg["t2_max_tokens"])
        budget = max(1, int(cfg["candidate_cap"]))
        bert_url = (cfg.get("bert_url") or "").strip()

        records = [dict(r) for r in records]
        for rec in records:
            rec.setdefault("rk_sig", ai_config.verdict_sig(rec))

        # Backfill finding context from the findings state KV — the queue
        # index's stash rows can carry stale context, so the command reads
        # the authoritative source directly. One indexed KV lookup per CVE.
        cve_ids_needing_context = [r.get("cve_id") for r in records
                                   if r.get("cve_id") and not r.get("cve_description")]
        if cve_ids_needing_context:
            try:
                fs = self.service.kvstore["riskability_findings_state"].data
                q = json.dumps({"cve_id": {"$in": cve_ids_needing_context}})
                finding_map = {}
                for row in fs.query(**{"query": q}):
                    cid = row.get("cve_id")
                    if cid and cid not in finding_map:
                        finding_map[cid] = row
                for rec in records:
                    f = finding_map.get(rec.get("cve_id"))
                    if f:
                        rec.setdefault("cve_description", f.get("title", ""))
                        rec.setdefault("affected_product", f.get("package", ""))
                        rec.setdefault("severity", f.get("severity", ""))
                        rec.setdefault("epss", f.get("epss", ""))
                        rec.setdefault("kev", "true" if f.get("kev_added") else "false")
            except Exception:
                pass  # context is display-only; analysis proceeds without it

        # ---- cache pass ------------------------------------------------
        # One query for every input CVE; signature matches are served
        # instantly and never reach the model. This is what makes the
        # steady-state cost of the pipeline near zero: an unchanged CVE is
        # analysed exactly once, ever (per signature).
        kv = self.service.kvstore[VERDICT_COLLECTION].data
        cached = {}
        cve_ids = [r.get("cve_id") for r in records if r.get("cve_id")]
        if cve_ids:
            try:
                query = json.dumps({"cve_id": {"$in": cve_ids}})
                # splunklib 3.0: the REST query param goes as a KEYWORD —
                # positionally this raises TypeError, which silently
                # emptied the cache on every run.
                for row in kv.query(**{"query": query}):
                    cached[row.get("cve_id")] = row
            except Exception:
                cached = {}

        # ---- triage: cached / to-analyse --------------------------------
        out, to_analyse = [], []
        now = int(time.time())
        for rec in records:
            cve_id = rec.get("cve_id")
            hit = cached.get(cve_id)
            if hit and hit.get("sig") == rec.get("rk_sig"):
                row = dict(rec)
                for f in VERDICT_FIELDS:
                    row[f] = hit.get(f)
                row["analysis_source"] = hit.get("analysis_source", "cache")
                row["analysed_at"] = hit.get("analysed_at")
                out.append(row)
                # Backfill context on cache hits: old verdicts predate the
                # context fields, so the dashboard had nothing to show. One
                # KV upsert per hit, bounded by the budget, fills them in
                # without calling the model again.
                if not hit.get("title"):
                    hit.update({
                        "title": rec.get("cve_description", ""),
                        "package": rec.get("affected_product", ""),
                        "severity": rec.get("severity", ""),
                        "epss": rec.get("epss", ""),
                        "kev": rec.get("kev", "false"),
                        "exposure_zone": rec.get("exposure_zone", ""),
                        "cwe_id": rec.get("cwe_id", "")})
                    try:
                        kv.delete(json.dumps({"_key": hit.get("_key")}))
                        kv.insert(json.dumps(hit))
                    except Exception:
                        pass
            else:
                to_analyse.append(rec)

        # ---- budget-bounded model calls ---------------------------------
        llm_rows, deferred = to_analyse[:budget], to_analyse[budget:]
        if llm_rows:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                analyses = list(pool.map(
                    lambda rec: ai_config.analyze_finding(
                        url, auth_type, username, secret, model, verify,
                        timeout, rec, max_tokens),
                    llm_rows))
            verdict_docs = []
            for rec, analysis in zip(llm_rows, analyses):
                now_row = int(time.time())
                if analysis.get("ok"):
                    result = analysis["result"]
                    source = analysis["source"]
                else:
                    # Explicit, conservative, visible. Never a silent gap.
                    result = {
                        "priority_tier": "P2", "priority_score": 50,
                        "confidence": 0.0,
                        "rationale": "Analysis failed (%s). Conservative "
                                     "placeholder - review manually."
                                     % analysis.get("error", "unknown"),
                        "exploitability_signal": "theoretical",
                        "exposure_signal": rec.get("exposure_zone", "internal"),
                        "process_match_confidence": "unknown",
                        "recommended_action": "monitor",
                        "recommended_mitigations": [],
                        "attck_techniques": [],
                    }
                    source = "fallback"
                row = dict(rec)
                row.update({f: result.get(f) for f in VERDICT_FIELDS})
                row["analysis_source"] = source
                row["analysed_at"] = now_row
                row["analysis_latency_ms"] = analysis.get("latency_ms", 0)
                out.append(row)
                doc = {"_key": "cve:" + str(rec.get("cve_id")),
                       "cve_id": rec.get("cve_id"), "sig": rec.get("rk_sig"),
                       "analysed_at": now_row, "analysis_source": source,
                       "latency_ms": analysis.get("latency_ms", 0),
                       # Finding context, stored so the dashboard can show
                       # what the model actually looked at without needing
                       # to join back to the findings lookup.
                       "title": rec.get("cve_description", ""),
                       "package": rec.get("affected_product", ""),
                       "severity": rec.get("severity", ""),
                       "epss": rec.get("epss", ""),
                       "kev": rec.get("kev", "false"),
                       "exposure_zone": rec.get("exposure_zone", ""),
                       "cwe_id": rec.get("cwe_id", "")}
                doc.update({f: result.get(f) for f in VERDICT_FIELDS})
                verdict_docs.append(doc)
            if verdict_docs:
                # Upsert by primary key: delete the ids we are about to
                # write, then one batch insert. The verdicts collection is
                # the cache; a failed write here must fail the command.
                ids = [d["cve_id"] for d in verdict_docs]
                try:
                    kv.delete(json.dumps({"cve_id": {"$in": ids}}))
                except Exception:
                    pass
                # splunklib 3.0 insert() accepts a single object per call —
                # a JSON array lands as "Expecting an object but got an
                # array". One post per verdict; bounded by the budget.
                for doc in verdict_docs:
                    kv.insert(json.dumps(doc))

        # ---- budget-deferred: reported, never faked ----------------------
        self._deferred = len(deferred)
        for rec in deferred:
            row = dict(rec)
            row["analysis_deferred"] = "1"
            out.append(row)

        yield from out


def main():
    dispatch(RiskabilityAIAnalyzeCommand)


if __name__ == "__main__":
    main()
