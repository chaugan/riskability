#!/usr/bin/env python
"""Riskability AI analysis: the queue consumer and verdict cache writer.

Input: the candidate queue (one row per distinct CVE, budget-selected by the
queue saved search, with T0-decided rows already excluded). Output: one
verdict row per distinct input CVE, PLUS an upsert of every SUCCESSFUL
verdict into the ``riskability_aiverdicts`` KV collection, the cache the
expansion search joins against. A failed analysis is returned as a row and
deliberately not cached, so the next run retries it: cached, it would match
its own signature forever and the CVE would drop out of the prioritised view
on the strength of one HTTP 500.

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
import traceback
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import Configuration, EventingCommand, dispatch  # noqa: E402

from riskability import ai_config, ai_settings  # noqa: E402

VERDICT_COLLECTION = "riskability_aiverdicts"
VERDICT_FIELDS = ("priority_tier", "priority_score", "confidence", "rationale",
                  "exploitability_signal", "exposure_signal",
                  "process_match_confidence", "recommended_action",
                  "recommended_mitigations", "attck_techniques")

# Documents per batch_save call. The KV Store caps both the document count and
# the payload size of one batch_save, and candidate_cap lets a single run
# produce enough verdicts to reach either. Chunking also bounds what a rejected
# write costs: the CVEs in a failed chunk are re-analysed on the next run and
# every other chunk stays written.
UPSERT_CHUNK = 200


def _log(message: str) -> None:
    """Append one diagnostic line to the app's log under var/log/splunk.

    A search command's failures otherwise reach the operator as "exited
    unexpectedly" and nothing else. splunkd indexes its own log directory into
    _internal, so a line written here is searchable from the search head and
    can be alerted on, which is the only way anyone learns about a command that
    runs on a schedule and is never watched. It replaces a probe that wrote to
    a fixed path in /tmp, which any local user could pre-create as a symlink
    onto a file the splunk account owns.

    Best effort on purpose: a logging failure must never replace the problem it
    was trying to describe.
    """
    try:
        splunk_home = os.environ.get("SPLUNK_HOME", "")
        if not os.path.isabs(splunk_home):
            return
        path = os.path.join(splunk_home, "var", "log", "splunk",
                            "riskability_ai_analyze.log")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("%s riskabilityaianalyze %s\n"
                         % (time.strftime("%Y-%m-%d %H:%M:%S"), message))
    except Exception:
        pass


def _upsert(kv, docs):
    """Upsert verdict documents through the KV Store's batch_save.

    batch_save keys on _key and replaces whatever is there, so there is no
    delete half to lose. The delete-then-insert this replaces could destroy a
    good verdict outright: the delete succeeded, the insert hit a 409 on a
    duplicate _key elsewhere in the batch, and the CVE then left the
    prioritised view completely, because the expansion search drops a finding
    whose CVE has no verdict.

    Returns (documents that failed, first error), so the caller can report a
    write failure without throwing away the verdicts it already paid for.
    """
    if not hasattr(kv, "batch_save"):
        raise RuntimeError(
            "the bundled Splunk SDK exposes no KVStoreCollectionData."
            "batch_save; the verdict cache needs an upsert, and the "
            "delete-then-insert it replaces destroys a live verdict whenever "
            "the insert half fails")
    failed, first_error = 0, None
    for start in range(0, len(docs), UPSERT_CHUNK):
        # _key is the one internal field the KV Store accepts back; _user and
        # friends arrive on a queried document and are the server's to set.
        batch = [{k: v for k, v in doc.items()
                  if k == "_key" or not k.startswith("_")}
                 for doc in docs[start:start + UPSERT_CHUNK]]
        try:
            kv.batch_save(*batch)
        except Exception as exc:
            failed += len(batch)
            if first_error is None:
                first_error = str(exc)
    return failed, first_error


# required_fields = ["*"], and it is the difference between this feature
# working and this feature being a CVE-metadata guesser.
#
# splunkd prunes fields a search does not appear to need. The scheduled
# analyse search ends in a stats over analysis_source, so nothing downstream
# references exposure_zone, version_match, process_name, process_path,
# listening_ports, affected_version, asset_criticality, cvss_vector or cwe_id,
# and splunkd therefore never sent them to this command. Everything the queue
# search measured about reachability and running processes, which is the whole
# reason to prefer this app's verdicts over a CVSS sort, was being dropped one
# pipe before the prompt was built.
#
# It hid well. The fields the dashboard shows (package, severity, epss, kev,
# title) survive because this command backfills those from the findings KV, so
# a stored verdict looked complete while the model had been shown almost none
# of the evidence. Measured: exposure_zone arrived empty in the scheduled
# shape and populated when an ad hoc "| table exposure_zone" made splunkd keep
# it, which is why an interactive test never reproduced it.
#
# The SDK documents the default (None) as implicitly selecting all fields.
# That is not what splunkd did here, so the selection is explicit.
@Configuration(required_fields=["*"])
class RiskabilityAIAnalyzeCommand(EventingCommand):
    def transform(self, records):
        try:
            for row in self._transform_impl(records):
                yield row
        except BaseException:
            _log("unhandled exception\n" + traceback.format_exc())
            raise

    def _report(self, message: str) -> None:
        """Surface an operational problem in both places it can be seen.

        A search message reaches whoever opens the job; the log reaches an
        alert, which is what a scheduled run actually needs. Neither is allowed
        to break the run, and the braces are doubled because write_warning
        passes the text through str.format and a KV Store error body is full
        of them.
        """
        _log(message)
        try:
            self.write_warning(message.replace("{", "{{").replace("}", "}}"))
        except Exception:
            pass

    def _sig_salt(self) -> str:
        """The verdict signature salt, read from the macro the SPL half uses.

        Read, never reconstructed. The salt is "<schema version>:<model name>",
        and the same string has to reach both writers of the signature: the
        md5() in savedsearches.conf, which expands this macro directly, and
        verdict_sig() here. Rebuilding it in Python from the configured model
        name would give the salt two sources of truth, and the day they
        disagree the cache splits in half in complete silence.

        A read failure is fatal on purpose. An empty salt would still produce
        perfectly valid signatures, they would simply match nothing that has
        ever been stored, so the entire fleet would be re-analysed on every run
        and the only symptom would be a GPU that never goes idle.

        The macro definition carries its own quotes, the app convention for a
        string-valued macro (riskability_ai_asset_criticality, and see the
        comment above riskability_ai_sig_salt itself). SPL drops them when it
        expands the macro into the concatenation, so they are dropped here too.
        """
        try:
            definition = self.service.confs["macros"][
                "riskability_ai_sig_salt"].content["definition"]
        except Exception as exc:
            raise RuntimeError(
                "cannot read the riskability_ai_sig_salt macro (%s); refusing "
                "to sign verdicts with an unknown salt, because an empty salt "
                "matches no cached verdict and re-analyses the whole fleet"
                % exc)
        salt = str(definition).strip()
        if len(salt) >= 2 and salt[0] == '"' and salt[-1] == '"':
            salt = salt[1:-1]
        if not salt:
            raise RuntimeError(
                "the riskability_ai_sig_salt macro is empty; refusing to sign "
                "verdicts with an empty salt, which would match no cached "
                "verdict and re-analyse the whole fleet")
        return salt

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

        salt = self._sig_salt()
        # _bert_url is stripped on the way in and re-attached from the
        # configuration at call time. analyze_finding takes the classifier URL
        # off the record it is handed, so a record that keeps its own value
        # lets anyone who can write an event into the candidate index aim the
        # search head's POST, carrying the advisory text and process chain, at
        # a host of their choosing. Nothing in the app ever set the field, so
        # nothing legitimate loses anything by its removal.
        records = [{k: v for k, v in r.items() if k != "_bert_url"}
                   for r in records]

        # One row per distinct CVE, enforced here instead of assumed. The
        # saved search does "dedup cve_id" upstream and the cache write below
        # keys on the CVE id, so a duplicate that gets through is not a wasted
        # model call, it is a rejected write that loses a whole batch of
        # verdicts already paid for. A row with no cve_id cannot be keyed,
        # cached or joined back to a finding, so it is passed through rather
        # than spending a model call on a verdict nothing can ever read.
        deduped, unkeyed, seen = [], [], set()
        for rec in records:
            cve_id = rec.get("cve_id")
            if not cve_id:
                unkeyed.append(rec)
            elif cve_id not in seen:
                seen.add(cve_id)
                deduped.append(rec)
        records = deduped

        # Backfill finding context from the findings state KV. The queue
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

        # The queue search stamps rk_sig on every row and this recomputation is
        # the fallback for a row that arrived without one. It runs AFTER the
        # backfill above, because the fields it hashes are the fields the
        # backfill fills: signing first would sign a half-empty record and
        # store a verdict under a signature the SPL half will never produce.
        for rec in records:
            rec.setdefault("rk_sig", ai_config.verdict_sig(rec, salt))

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
                # splunklib 3.0: the REST query param goes as a KEYWORD.
                # Positionally this raises TypeError, which silently
                # emptied the cache on every run.
                for row in kv.query(**{"query": query}):
                    cached[row.get("cve_id")] = row
            except Exception:
                cached = {}

        # ---- triage: cached / to-analyse --------------------------------
        out, to_analyse, backfill_docs = [], [], []
        for rec in records:
            cve_id = rec.get("cve_id")
            hit = cached.get(cve_id)
            if hit and hit.get("sig") == rec.get("rk_sig"):
                row = dict(rec)
                for f in VERDICT_FIELDS:
                    row[f] = hit.get(f)
                # "cache", not the stored verdict's own source. Every stored
                # document carries analysis_source "T2", so reading it back
                # here labelled every cache hit a model call: the analyze
                # search's cache_hits counted approximately nothing and its
                # model_calls counted the whole run, which is precisely
                # backwards for the number that says what the GPU was asked to
                # do. The verdict's provenance is not lost, it stays on the
                # cached document and reaches the expansion search as rk_src.
                row["analysis_source"] = "cache"
                row["analysed_at"] = hit.get("analysed_at")
                out.append(row)
                # Backfill context on cache hits: old verdicts predate the
                # context fields, so the dashboard had nothing to show. The
                # verdict itself is already correct, so this is cosmetic, and
                # cosmetic work is never allowed to cost a verdict. It used to
                # delete the row and insert it again with both halves inside a
                # bare except: a delete that succeeded ahead of an insert that
                # failed destroyed a live verdict, and the finding then
                # vanished from the prioritised view, which drops findings
                # whose CVE has no verdict. Collected instead and upserted in
                # one batch below, where nothing is deleted at any point.
                # Skipped without a _key, because a keyless save would add a
                # second row for the same CVE and the lookup would then pick
                # between them at random.
                if hit.get("_key") and not hit.get("title"):
                    doc = dict(hit)
                    doc.update({
                        "title": rec.get("cve_description", ""),
                        "package": rec.get("affected_product", ""),
                       "vendor": rec.get("vendor", ""),
                       "installed_version": rec.get("process_version", ""),
                        "severity": rec.get("severity", ""),
                        "epss": rec.get("epss", ""),
                        "kev": rec.get("kev", "false"),
                        "exposure_zone": rec.get("exposure_zone", ""),
                        "cwe_id": rec.get("cwe_id", "")})
                    backfill_docs.append(doc)
            else:
                to_analyse.append(rec)

        # ---- budget-bounded model calls ---------------------------------
        llm_rows, deferred = to_analyse[:budget], to_analyse[budget:]
        if llm_rows:
            def analyse(rec):
                # The classifier URL is the configured one, attached to a
                # throwaway copy so it never reaches the emitted row or the
                # cache. Taking it from the record is what let an event decide
                # where the search head posts finding data; the scheme itself
                # is asserted in ai_config._http.
                call = dict(rec, _bert_url=bert_url) if bert_url else rec
                return ai_config.analyze_finding(
                    url, auth_type, username, secret, model, verify,
                    timeout, call, max_tokens)

            with ThreadPoolExecutor(max_workers=workers) as pool:
                analyses = list(pool.map(analyse, llm_rows))
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
                                     "placeholder. Review manually."
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
                if source == "fallback":
                    # Reported, never cached. Stored under the current
                    # signature a fallback becomes a cache hit on the next
                    # run, so the queue search stops selecting the CVE and the
                    # expansion search drops it as stale a week later: one
                    # HTTP 500 and the CVE is gone from the prioritised view
                    # until its advisory text changes, with the daily "no
                    # results" alert quiet throughout because every other CVE
                    # succeeded. An endpoint that failed only for chosen CVE
                    # ids could delete exactly those from the risk view.
                    # Leaving no cache entry means the next run simply tries
                    # again, which is what a transient failure deserves.
                    continue
                doc = {"_key": "cve:" + str(rec.get("cve_id")),
                       "cve_id": rec.get("cve_id"), "sig": rec.get("rk_sig"),
                       "analysed_at": now_row, "analysis_source": source,
                       "latency_ms": analysis.get("latency_ms", 0),
                       # Finding context, stored so the dashboard can show
                       # what the model actually looked at without needing
                       # to join back to the findings lookup.
                       "title": rec.get("cve_description", ""),
                       "package": rec.get("affected_product", ""),
                       "vendor": rec.get("vendor", ""),
                       "installed_version": rec.get("process_version", ""),
                       "severity": rec.get("severity", ""),
                       "epss": rec.get("epss", ""),
                       "kev": rec.get("kev", "false"),
                       "exposure_zone": rec.get("exposure_zone", ""),
                       "cwe_id": rec.get("cwe_id", "")}
                doc.update({f: result.get(f) for f in VERDICT_FIELDS})
                verdict_docs.append(doc)
            if verdict_docs:
                # One upsert keyed on "cve:<id>", no delete anywhere. A write
                # that fails is loud but not fatal: the verdicts are already
                # in the rows being returned, and a CVE missing from the cache
                # is picked up again by the next run, so failing the command
                # here would throw away model calls that have been paid for
                # and fix nothing.
                failed, error = _upsert(kv, verdict_docs)
                if failed:
                    self._report(
                        "could not cache %d of %d verdict(s); they will be "
                        "re-analysed on the next run: %s"
                        % (failed, len(verdict_docs), error))

        if backfill_docs:
            failed, error = _upsert(kv, backfill_docs)
            if failed:
                self._report(
                    "could not backfill display context on %d cached "
                    "verdict(s); the verdicts themselves are untouched: %s"
                    % (failed, error))

        # ---- budget-deferred and unkeyed: reported, never faked -----------
        # Both carry a source like every other emitted row. Without one they
        # were counted into the analyze search's "verdicts" total while
        # matching none of its breakdowns, so the total reported work that had
        # not been done. Neither writes to the cache, so a deferred CVE is
        # picked up by the next run.
        for rec in deferred:
            row = dict(rec)
            row["analysis_source"] = "deferred"
            out.append(row)
        for rec in unkeyed:
            row = dict(rec)
            row["analysis_source"] = "skipped"
            out.append(row)

        yield from out


def main():
    dispatch(RiskabilityAIAnalyzeCommand)


if __name__ == "__main__":
    main()
