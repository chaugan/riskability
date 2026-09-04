#!/usr/bin/env python3
"""The three guards against a fresh install reporting an empty fleet.

All three came out of one clean-install run, on an instance that had never held
the app: 45 scheduled searches all succeeded, no alert fired, the watchdog
reported nothing wrong, and the fleet showed zero findings while an identical
fleet with the identical feed held 13,330. The cause was one field stamped from
the wrong clock, and nothing in the app could see it.

  1. The matcher records the feed generation IN FORCE WHEN IT RAN, and the
     checkpoint stamps that value rather than whatever generation exists when
     the checkpoint itself runs thirteen minutes later.
  2. The app ships configured, because Splunk's setup gate stood in front of the
     only page that could clear it.
  3. The watchdog notices a host checkpointed against a feed imported after that
     host's last match, which is arithmetically impossible and means the host
     will never be re-matched.

No Splunk here. These are conf-level invariants, so they are checked against the
shipped files, plus a truth table for the checkpoint's decision so the SPL and
the intent cannot drift apart silently.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app", "riskability")

FAILURES = []


def check(name, ok, detail=""):
    print("  %s %s%s" % ("ok  " if ok else "FAIL", name, (" " + str(detail)) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def stanza(text, name):
    """One savedsearches stanza, continuations joined, as a single string."""
    m = re.search(r"^\[%s\]\n(.*?)(?=^\[)" % re.escape(name), text, re.S | re.M)
    if not m:
        return ""
    return m.group(1).replace("\\\n", " ")


def norm(s):
    return " ".join(s.split())


# --------------------------------------------------------------------------
# The checkpoint's decision, restated. If the SPL below changes shape, this
# table is what says whether the new shape still means the right thing.
#
#   was_dirty  the host needs matching (digest, generation or matcher changed)
#   matched    a receipt exists from a run newer than the last recorded one
#   receipt_gen  the generation the receipt says the match ran against;
#                None for a receipt written before the field existed
# --------------------------------------------------------------------------
def checkpoint_feed_gen(was_dirty, matched, receipt_gen, prev_gen, current_gen):
    if was_dirty and not matched:
        return prev_gen
    if was_dirty and matched and receipt_gen is not None:
        return None if receipt_gen == "none" else receipt_gen
    return current_gen


CASES = [
    # (was_dirty, matched, receipt_gen, prev_gen, current_gen, expected, why)
    (True, True, "none", None, "1", None,
     "matched before any feed existed: must NOT be credited with the feed that arrived afterwards"),
    (True, True, "1", None, "1", "1",
     "matched against generation 1 and generation 1 is current: record it"),
    (True, True, "1", "1", "2", "1",
     "matched against 1 while 2 is now current: record 1, so the host stays dirty for 2"),
    (True, False, None, "1", "2", "1",
     "dirty but the matcher never got to it: keep what it had, do not claim progress"),
    (True, True, None, None, "1", "1",
     "receipt predates the field: fall back to the old behaviour rather than re-matching the fleet"),
    (False, False, None, "1", "1", "1",
     "nothing to do: leave the record alone"),
]


def main():
    print("Checkpoint attribution, truth table")
    for was_dirty, matched, rgen, prev, cur, expected, why in CASES:
        got = checkpoint_feed_gen(was_dirty, matched, rgen, prev, cur)
        check(why, got == expected, "expected %r got %r" % (expected, got))

    saved = open(os.path.join(APP, "default", "savedsearches.conf"), encoding="utf-8").read()

    # --- 1. the matcher records the generation it actually used --------------
    print("\nFix 1: the receipt records the generation in force at match time")
    mat = norm(stanza(saved, "Riskability - materialise findings"))
    check("the matcher reads the current feed generation",
          "lookup riskability_feedstate_lookup _key AS rk_fs OUTPUT generation AS rk_feed_gen" in mat)
    check("it stamps match_feed_gen on receipts only",
          'eval match_feed_gen = if(record_type == "match_receipt", coalesce(rk_feed_gen, "none"), null())' in mat)
    check('a run with no feed records "none" rather than nothing',
          'coalesce(rk_feed_gen, "none")' in mat)
    check("match_feed_gen survives into the findings index",
          re.search(r"fields [^|]*\bmatch_feed_gen\b", mat) is not None)
    check("the lookup happens after the match, not before",
          mat.index("riskabilitymatch") < mat.index("riskability_feedstate_lookup"))

    # --- 2. the checkpoint uses it ------------------------------------------
    print("\nFix 1: the checkpoint stamps the receipt's generation, not the clock's")
    chk = norm(stanza(saved, "Riskability - checkpoint matched hosts"))
    check("the receipt's generation is read back",
          "latest(match_feed_gen) AS receipt_gen BY hostname" in chk)
    check("feed_gen is decided by a case, not an unconditional current value",
          "eval feed_gen = case(" in chk)
    check("a host the matcher skipped keeps its previous generation",
          "was_dirty == 1 AND rk_matched == 0, prev_gen" in chk)
    check("a matched host is credited with what its receipt names",
          "was_dirty == 1 AND rk_matched == 1 AND isnotnull(receipt_gen)" in chk)
    check('a receipt of "none" stores a null generation, keeping the host dirty',
          'if(receipt_gen == "none", null(), receipt_gen)' in chk)
    check("the old unconditional stamp is gone",
          "eval feed_gen = if(was_dirty == 1 AND rk_matched == 0, prev_gen, feed_gen)" not in chk)
    check("the helper field is not written to the collection",
          "fields - receipt_run, receipt_gen" in chk)

    # --- 3. the watchdog can see the impossible state -----------------------
    print("\nFix 3: the watchdog notices a match that predates its own feed")
    dog = norm(stanza(saved, "Riskability - pipeline did not complete"))
    check("it still checks the original condition (findings produced, never folded)",
          "where findings_produced > 0" in dog and "acknowledged == 0" in dog)
    check("it also reads the checkpoint and the feed's import time",
          "inputlookup riskability_matchstate_lookup" in dog
          and "OUTPUT generation AS current_gen, imported_at AS feed_imported_at" in dog)
    check("it only judges hosts claiming the current generation",
          'where coalesce(feed_gen, "none") == current_gen' in dog)
    check("it fires when the recorded match predates that feed",
          "where tonumber(matched_at) < tonumber(feed_imported_at) - 300" in dog)
    check("it tolerates clock jitter rather than a real gap", "- 300" in dog)
    check("both conditions reach the same alert",
          dog.count("table hostname, match_run, findings_produced, folded_run, problem") == 2)

    # --- 4. the setup gate has an exit --------------------------------------
    print("\nFix 2: a first run is not locked out of its own configuration page")
    app_conf = open(os.path.join(APP, "default", "app.conf"), encoding="utf-8").read()
    check("the app ships configured",
          re.search(r"^is_configured\s*=\s*1\s*$", app_conf, re.M) is not None)
    check("the setup view is still declared, as a way in rather than a wall",
          re.search(r"^setup_view\s*=\s*riskability_setup\s*$", app_conf, re.M) is not None)
    start = open(os.path.join(APP, "default", "data", "ui", "views", "riskability_start.xml"),
                 encoding="utf-8").read()
    check("the landing page decides for itself whether a feed exists",
          "inputlookup riskability_feedstate_lookup" in start and 'set token="no_feed"' in start)
    check("it says so, in a row that only appears when there is none",
          'depends="$no_feed$"' in start
          and "No vulnerability feed has been imported yet" in start)
    check("and it names the page that fixes it",
          "Feed administration" in start)

    print("\nFix 2: the landing page shows numbers on a first run, not token names")
    # stats returns its one row carrying only count when the input is empty:
    # sum() over nothing produces no field, so a token set from it renders as
    # the literal "$result.late$" until some host reports.
    fleet = start.split('<search id="fleetstate">', 1)[1].split("</search>", 1)[0]
    check("the fleet-state counters default to zero when no host has reported",
          "fillnull value=0 late on_schedule unlearned total" in fleet)
    check("the fillnull happens before anything reads those fields",
          fleet.index("fillnull") < fleet.index("eval state = case"))
    off = start.split('<search id="offhour">', 1)[1].split("</search>", 1)[0]
    check("the off-hour line survives having nothing to list",
          "stats count AS n, values(one) AS parts" in off and "if(n = 0," in off)
    # Every field a done handler turns into a token must be one the search
    # guarantees on EVERY input, including none at all. That is the whole bug:
    # the fields were listed, but sum() had not produced them.
    guaranteed = set(re.findall(r"[|] fillnull value=0 ([a-z_ ]+)", fleet)[0].split()) \
        | set(re.findall(r"[|] eval (\w+) =", fleet)) \
        | {"total"}
    wanted = set(re.findall(r"<set token=\"\w+\">\$result\.(\w+)\$</set>",
                            start.split('<search id="fleetstate">', 1)[1].split("</search>", 1)[0]))
    check("every fleet-state token is fed by a field the search always produces",
          wanted <= guaranteed, "unguaranteed: %s" % sorted(wanted - guaranteed))

    # The same defect on two other pages, found by walking every view on an
    # install with no feed, no forwarder and no host: ten tokens reached the
    # page as their own names. stats returns NO row at all when it carries only
    # aggregates and its input is empty, so the done handler never fires.
    views = os.path.join(APP, "default", "data", "ui", "views")
    overview = open(os.path.join(views, "riskability_overview.xml"), encoding="utf-8").read()
    check("the roll-up age survives having never rolled up",
          "| stats count AS rk_rows, max(rolled_at) AS rolled" in overview)
    mitre = open(os.path.join(views, "riskability_mitre.xml"), encoding="utf-8").read()
    check("the ATT&CK legend counters survive an empty ledger",
          "| stats count AS rk_rows, sum(total_open_cves) AS t" in mitre
          and "fillnull value=0 t p c i v o n u" in mitre)
    macros = open(os.path.join(APP, "default", "macros.conf"), encoding="utf-8").read()
    check("the platform macro returns a row before any host has reported",
          "| stats count AS rk_hosts, values(rk_fam) AS rk_fams" in macros)

    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
