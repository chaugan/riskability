#!/usr/bin/env python3
"""Tests for the escalation rule language, runnable on a laptop with no Splunk.

  python3 tools/test_escalations.py

Three things are being defended here, and only the first is obvious.

1. The validator, which is the security control. "when" is a string in a conf
   file that gets expanded into a scheduled search running as the app on the
   search head, so whatever the validator accepts, the search head runs. Every
   rejected token class gets its own case below: a validator with an untested
   reject clause is a validator with an untested reject clause, and the one
   nobody wrote a case for is the one that stopped working.

2. The bump cap. Rules compose, and the failure is not a crash, it is a queue
   that slowly becomes the flat distribution this app was built to replace,
   one reasonable acceptance at a time.

3. The mutation test, which is the most valuable check in here. A rule that
   goes on firing after the fact it was written about has been destroyed is
   matching something other than what its author believed. That rule is not
   wrong in a way any other test can see: it fires on the right rows in the
   sample, for the wrong reason, and it keeps firing on the wrong rows in the
   estate. assert_decisive is written to be reused by every rule added later,
   which is the only version of this test that survives contact with a second
   author.
"""

from __future__ import annotations

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "app", "riskability", "bin"))

from riskability import escalate  # noqa: E402

SHIPPED_CONF = os.path.join(ROOT, "app", "riskability", "default",
                            "riskability_escalations.conf")

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print("  ok   %s" % name)
    else:
        FAILURES.append(name)
        print("  FAIL %s %s" % (name, detail))


def rules_from(text):
    return escalate.load_rules(text)


def stanza(name, when, enabled="0", bump="1", description="Worked example."):
    return ("[%s]\ndescription = %s\nwhen = %s\nbump = %s\nenabled = %s\n\n"
            % (name, description, when, bump, enabled))


# ---------------------------------------------------------------------------
# The allowlist table itself
# ---------------------------------------------------------------------------

def test_allowlist():
    print("field allowlist:")
    bad_prefix = [n for n in escalate.FIELD_ALLOWLIST if not n.startswith(escalate.PREFIX)]
    check("every field carries the rk_esc_ prefix", not bad_prefix, bad_prefix)
    incomplete = [n for n, spec in escalate.FIELD_ALLOWLIST.items()
                  if not spec.get("note") or not spec.get("source")
                  or spec.get("type") not in (escalate.NUMBER, escalate.STRING, escalate.BOOL)
                  or spec.get("status") not in (escalate.PRODUCED, escalate.UNPRODUCED)]
    # A field with no note is a field whose author could not say where it came
    # from, which is how a field nothing computes gets onto an allowlist.
    check("every field declares a type, a status, a note and a source",
          not incomplete, incomplete)
    check("the unproduced fields are marked, not quietly present",
          set(escalate.FIELD_ALLOWLIST) - escalate.PRODUCED_FIELDS
          == {"rk_esc_sole_listener", "rk_esc_root_autorun_writable"})
    modelish = [n for n in escalate.FIELD_ALLOWLIST
                if "priority" in n or "verdict" in n or "rationale" in n or "tier" in n]
    # Nothing a model says can move an ordering. If that ever stops being true
    # it must not be by a field appearing on this table unnoticed.
    check("no model written value is on the allowlist", not modelish, modelish)


# ---------------------------------------------------------------------------
# The validator: what it must accept
# ---------------------------------------------------------------------------

def test_accepts():
    print("validate_when accepts realistic rules:")
    good = [
        'rk_esc_impact_a != "N" AND rk_esc_sole_listener = 1',
        'rk_esc_load_rank = 3 AND rk_esc_reach_rank < 1',
        'rk_esc_eol_support = "no supported release" AND rk_esc_has_fix = 0',
        'rk_esc_attack_vector = "L" AND (rk_esc_impact_c != "N" OR rk_esc_impact_i != "N")'
        ' AND rk_esc_root_autorun_writable = 1',
        'rk_esc_reach_rank == -1',
        'NOT rk_esc_has_fix = 1',
        'rk_esc_load_rank >= 2 AND NOT (rk_esc_eol_support = "supported")',
        'rk_esc_impact_a = "H" or rk_esc_impact_i = "H"',
        'rk_esc_eol_support != ""',
    ]
    for expr in good:
        ok, err = escalate.validate_when(expr)
        check("accepts: %s" % expr, ok, err)


# ---------------------------------------------------------------------------
# The validator: one case per rejected token class
# ---------------------------------------------------------------------------

def test_rejects():
    print("validate_when rejects, one case per class:")
    # Each of these is a real way out of an eval expression and into the
    # search head, written the way somebody would actually write it.
    cases = [
        ("backtick, which reaches every macro in the app",
         'rk_esc_has_fix = 1 AND `riskability_index_meta`', "`"),
        ("pipe, which reaches the next command",
         'rk_esc_has_fix = 1 | delete', "|"),
        ("subsearch bracket",
         'rk_esc_has_fix = 1 [ search index=_internal ]', "["),
        ("comma outside a string, an argument separator",
         'rk_esc_has_fix = 1, rk_esc_load_rank = 3', ","),
        ("semicolon, which separates searches",
         'rk_esc_has_fix = 1 ; | outputlookup x', ";"),
        ("single quote, the way out of a quoted context",
         "rk_esc_eol_support = 'supported'", "'"),
        ("dollar, which is token substitution",
         'rk_esc_eol_support = "$job$"', "$"),
        ("backslash, an SPL escape and a conf continuation at once",
         'rk_esc_eol_support = "a\\"b"', "\\"),
        ("function call on a non field identifier",
         'match(rk_esc_eol_support, "supported")', "function"),
        ("function call on an allowlisted field name",
         'rk_esc_has_fix(1)', "function"),
        ("asterisk",
         'rk_esc_load_rank = 3 AND *', "*"),
        ("brace",
         'rk_esc_load_rank = {3}', "{"),
        ("arithmetic",
         'rk_esc_load_rank - 1 = 2', "-"),
        ("unbalanced parentheses",
         'rk_esc_load_rank = 3 AND (rk_esc_has_fix = 0', "parenthes"),
        ("two operands and no operator",
         'rk_esc_load_rank rk_esc_has_fix', "comparison operator"),
        ("unterminated string",
         'rk_esc_eol_support = "supported', "unterminated"),
        ("empty expression",
         '   ', "empty"),
        # The bounds exist because this string is written into a conf file,
        # where a runaway value takes the rest of the stanza with it, and
        # because a rule nobody can read is a rule nobody can review.
        ("an expression over the length limit",
         'rk_esc_has_fix = 0 OR ' * 40 + 'rk_esc_has_fix = 1', "over the"),
        ("an expression over the token limit",
         '(' * 150 + 'rk_esc_has_fix = 0' + ')' * 150, "more than"),
        ("a string literal over the length limit",
         'rk_esc_eol_support = "%s"' % ("a" * 97), "over 96"),
    ]
    for label, expr, expect in cases:
        ok, err = escalate.validate_when(expr)
        check("rejects %s" % label, (not ok) and expect in err,
              "accepted!" if ok else "message was: %s" % err)

    print("validate_when rejects rules that could never fire:")
    unfireable = [
        ("unknown field", 'rk_esc_nonesuch = 1', "not an allowlisted field"),
        ("misspelt allowlisted field", 'rk_esc_load_rnak = 3', "not an allowlisted field"),
        ("unprefixed field", 'load_rank = 3', "prefixed rk_esc_"),
        ("number against a string field", 'rk_esc_eol_support = 3', "cannot compare"),
        ("string against a numeric field", 'rk_esc_load_rank = "3"', "cannot compare"),
        ("ordering on a string field", 'rk_esc_eol_support > "supported"', "lexicographic"),
        ("always true", '1 = 1', "at least one"),
        ("always true, quoted", '"a" = "a"', "at least one"),
    ]
    for label, expr, expect in unfireable:
        ok, err = escalate.validate_when(expr)
        check("rejects %s" % label, (not ok) and expect in err,
              "accepted!" if ok else "message was: %s" % err)

    # A misspelt field must be refused rather than evaluated, because in SPL an
    # unknown field is null and the rule would simply never fire: no error, no
    # log line, no result, for ever.
    ok, err = escalate.validate_when('rk_esc_load_rnak = 3')
    check("a misspelt field is offered the right one", "rk_esc_load_rank" in err, err)


def test_suspect_values():
    print("values outside a measured vocabulary:")
    rules, problems = rules_from(stanza("typo_value", 'rk_esc_impact_a = "Y"'))
    suspects = [p for p in problems if p.kind == escalate.SUSPECT]
    check("an impossible value is reported", len(suspects) == 1, problems)
    # Reported and not refused: the vocabularies come from feed data, and code
    # that refuses them becomes the thing deciding what the feed may say.
    check("but the rule still loads", len(rules) == 1, rules)


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def test_loading():
    print("load_rules:")
    conf = (stanza("good_one", 'rk_esc_load_rank = 3 AND rk_esc_reach_rank < 1')
            + stanza("injected", 'rk_esc_has_fix = 1 | delete')
            + stanza("good_two", 'rk_esc_eol_support = "no supported release"')
            + "[no_when]\ndescription = Nothing here.\nbump = 1\nenabled = 0\n\n"
            + stanza("bumps_two", 'rk_esc_has_fix = 0', bump="2")
            + stanza("no_description", 'rk_esc_has_fix = 0', description="")
            + stanza("Bad Name", 'rk_esc_has_fix = 0')
            + "[strange_key]\ndescription = x\nwhen = rk_esc_has_fix = 0\n"
              "tiers = 2\nenabled = 0\n\n"
            + stanza("good_three", 'rk_esc_impact_a != "N"'))
    rules, problems = rules_from(conf)
    names = [r.name for r in rules]
    # One malformed stanza must never disable the set. The alternative is that
    # a typo silently changes the priority of every finding in the estate,
    # which is a bigger ordering change than any rule in the file could make.
    check("the sound rules survive the malformed ones",
          names == ["good_one", "good_two", "good_three"], names)
    kinds = {p.rule: p.kind for p in problems}
    check("the injection is named and refused",
          kinds.get("injected") == escalate.REJECT, problems)
    long_name = "x" * 80
    rules_long, problems_long = rules_from(stanza(long_name, 'rk_esc_has_fix = 0'))
    check("an over-long rule name is refused",
          not rules_long and problems_long[0].kind == escalate.REJECT, problems_long)
    for name in ("no_when", "bumps_two", "no_description", "Bad Name", "strange_key"):
        check("refused and named: %s" % name, kinds.get(name) == escalate.REJECT, problems)
    check("a rejected rule says why",
          all(len(p.reason) > 20 for p in problems), problems)
    check("bump = 2 is refused, P0 stays the scorer's to give",
          "P0" in [p.reason for p in problems if p.rule == "bumps_two"][0])

    dupes = rules_from(stanza("twice", 'rk_esc_has_fix = 0')
                       + stanza("twice", 'rk_esc_has_fix = 1'))
    check("a duplicate stanza is refused rather than silently merged",
          len(dupes[0]) == 1 and dupes[1][0].kind == escalate.REJECT, dupes[1])

    default_stanza = rules_from("[default]\nenabled = 1\n\n"
                                + stanza("plain", 'rk_esc_has_fix = 0'))
    check("[default] is refused rather than half applied",
          len(default_stanza[0]) == 1 and not default_stanza[0][0].enabled,
          default_stanza)

    # Ships disabled, as every rule must: an escalation that arrives switched
    # on with the app is an ordering change nobody asked for.
    off = rules_from(stanza("implicit", 'rk_esc_has_fix = 0'))[0]
    check("enabled defaults to 0 when the key is absent",
          not rules_from("[implicit]\ndescription = x\nwhen = rk_esc_has_fix = 0\n")[0][0].enabled)
    check("enabled = 0 parses as off", not off[0].enabled)
    on = rules_from(stanza("switched", 'rk_esc_has_fix = 0', enabled="1"))[0]
    check("enabled = 1 parses as on", on[0].enabled)


def test_unproduced_fields():
    print("fields nothing computes yet:")
    conf = stanza("needs_sole_listener",
                  'rk_esc_impact_a != "N" AND rk_esc_sole_listener = 1')
    rules, problems = rules_from(conf)
    check("a rule naming an unproduced field does not load", not rules, rules)
    check("and it is reported as unproduced, not as malformed",
          [p.kind for p in problems] == [escalate.UNPRODUCED], problems)
    check("the reason says what is missing",
          "sole_listener" in problems[0].reason and "NOT MEASURED" in problems[0].reason,
          problems[0].reason)


def test_continuations():
    print("conf continuation lines:")
    conf = ("[wrapped]\n"
            "description = A description that runs over \\\n"
            "  several lines, the way every rule in the shipped file does, \\\n"
            "  because the reasoning is the point.\n"
            "when = rk_esc_load_rank = 3 AND rk_esc_reach_rank < 1\n"
            "bump = 1\nenabled = 1\n")
    rules, problems = rules_from(conf)
    check("a wrapped description loads as one rule", len(rules) == 1 and not problems,
          problems)
    check("and the continuation is joined, not truncated",
          rules and "because the reasoning is the point." in rules[0].description,
          rules[0].description if rules else "")


# ---------------------------------------------------------------------------
# The cap
# ---------------------------------------------------------------------------

def test_bump_is_capped():
    print("three matching rules bump by one:")
    conf = (stanza("a_listener_loads_it", 'rk_esc_load_rank = 3', enabled="1")
            + stanza("nothing_left_to_patch",
                     'rk_esc_eol_support = "no supported release"', enabled="1")
            + stanza("no_known_fix", 'rk_esc_has_fix = 0', enabled="1"))
    rules, problems = rules_from(conf)
    check("all three load", len(rules) == 3 and not problems, problems)
    row = {"rk_esc_load_rank": 3, "rk_esc_eol_support": "no supported release",
           "rk_esc_has_fix": 0}
    bump, matched = escalate.apply_rules(rules, row)
    check("three rules match", len(matched) == 3, matched)
    # The cap is the whole reason a rule set cannot rebuild the flat
    # distribution the deterministic scorer replaced.
    check("the bump is 1, not 3", bump == 1, bump)
    check("but all three reasons are kept", set(matched) == {r.name for r in rules}, matched)

    spl = escalate.to_spl(rules)
    check("the compiled SPL has no addition in it",
          "+" not in spl and "sum" not in spl, spl)
    check("the compiled bump is a boolean over the matched list",
          'rk_esc_bump = if(mvcount(rk_esc_hits) > 0, 1, 0)' in spl, spl)
    check("every matched rule name reaches rk_esc_hits",
          all('"%s"' % r.name in spl for r in rules), spl)

    one = escalate.apply_rules(rules, {"rk_esc_load_rank": 3})
    check("one rule also bumps by 1", one == (1, ["a_listener_loads_it"]), one)
    none = escalate.apply_rules(rules, {"rk_esc_load_rank": 0, "rk_esc_has_fix": 1})
    check("no rule bumps by 0", none == (0, []), none)
    # No evidence is not evidence: a null field must not escalate anything.
    unknown = escalate.apply_rules(rules, {})
    check("an empty evidence row escalates nothing", unknown == (0, []), unknown)


def test_disabled_contributes_nothing():
    print("a disabled rule:")
    conf = (stanza("switched_on", 'rk_esc_load_rank = 3', enabled="1")
            + stanza("switched_off", 'rk_esc_has_fix = 0', enabled="0"))
    rules, _ = rules_from(conf)
    row = {"rk_esc_load_rank": 3, "rk_esc_has_fix": 0}
    bump, matched = escalate.apply_rules(rules, row)
    check("the disabled rule is not in the match list", matched == ["switched_on"], matched)
    check("and the bump is still 1", bump == 1, bump)
    spl = escalate.to_spl(rules)
    check("the disabled rule is not compiled into the SPL at all",
          "switched_off" not in spl, spl)
    check("the enabled one is", "switched_on" in spl, spl)

    off_only, _ = rules_from(stanza("all_off", 'rk_esc_has_fix = 0'))
    spl = escalate.to_spl(off_only)
    # Both fields are still assigned. A field named downstream and evalled
    # nowhere is the defect this codebase has found five times, and a rule set
    # with nothing switched on is exactly when nobody would notice it.
    check("with no rules enabled both fields are still assigned",
          "rk_esc_bump = 0" in spl and "rk_esc_hits = null()" in spl, spl)
    check("and nothing else is emitted", spl.count("\n") == 0, spl)


def test_compiled_spl_shape():
    print("compiled SPL:")
    rules, _ = rules_from(stanza(
        "shape", 'rk_esc_attack_vector = "L" AND (rk_esc_impact_c != "N" OR '
                 'rk_esc_impact_i != "N") AND rk_esc_reach_rank >= -1', enabled="1"))
    spl = escalate.to_spl(rules)
    for ch in "`[];'$\\":
        check("no %r survives into the compiled SPL" % ch, ch not in spl, spl)
    check("= is canonicalised to ==", ' = "L"' not in spl and '== "L"' in spl, spl)
    check("groupings are parenthesised rather than left to precedence",
          "((" in spl, spl)
    check("negative literals survive", "-1" in spl, spl)
    check("no line carries a conf continuation, the caller owns that",
          not any(line.rstrip().endswith("\\") for line in spl.splitlines()), spl)
    check("no line carries a # comment, which would end the conf value",
          "#" not in spl, spl)
    check("every stage is an eval",
          all(line.startswith("| eval ") for line in spl.splitlines()), spl)


# ---------------------------------------------------------------------------
# The mutation test
# ---------------------------------------------------------------------------

def assert_decisive(rule, evidence, decisive, disjunctive=()):
    """Reusable mutation check. Any rule added later should get one of these.

    "decisive" names the facts the rule cannot do without: destroy any one and
    the rule must stop firing. "disjunctive" names facts on either side of an
    OR, where no single one is decisive but the group is: destroy all of them
    together and the rule must stop firing.

    Every field the rule names must appear in one list or the other. That is
    not bookkeeping. A rule naming a field neither list mentions is a rule
    with a condition nobody thought about, and the whole point of this check
    is to catch a rule that fires for a reason its author did not intend.
    """
    named = set(rule.fields)
    covered = set(decisive) | set(disjunctive)
    check("%s: every field it names is accounted for" % rule.name,
          named == covered, "names %s, covered %s" % (sorted(named), sorted(covered)))
    # A mutation test on a row the rule does not fire on proves nothing at
    # all, and would pass every assertion below.
    check("%s: fires on its own evidence" % rule.name,
          escalate.fires(rule, evidence), evidence)
    for field in decisive:
        row = escalate.mutate(evidence, field)
        check("%s: stops firing when %s is destroyed" % (rule.name, field),
              not escalate.fires(rule, row), row)
    if disjunctive:
        row = evidence
        for field in disjunctive:
            row = escalate.mutate(row, field)
        check("%s: stops firing when all of %s are destroyed"
              % (rule.name, ", ".join(disjunctive)),
              not escalate.fires(rule, row), row)


def test_mutation():
    print("mutation:")
    conf = (stanza("listener_loads_the_library",
                   'rk_esc_load_rank = 3 AND rk_esc_reach_rank < 1', enabled="1")
            + stanza("no_supported_release_no_fix",
                     'rk_esc_eol_support = "no supported release" AND rk_esc_has_fix = 0',
                     enabled="1")
            + stanza("local_flaw_with_impact",
                     'rk_esc_attack_vector = "L" AND (rk_esc_impact_c != "N" '
                     'OR rk_esc_impact_i != "N")', enabled="1"))
    rules, problems = rules_from(conf)
    check("the mutation subjects load", len(rules) == 3 and not problems, problems)
    by_name = {r.name: r for r in rules}

    assert_decisive(
        by_name["listener_loads_the_library"],
        {"rk_esc_load_rank": 3, "rk_esc_reach_rank": 0},
        decisive=["rk_esc_load_rank", "rk_esc_reach_rank"])

    assert_decisive(
        by_name["no_supported_release_no_fix"],
        {"rk_esc_eol_support": "no supported release", "rk_esc_has_fix": 0},
        decisive=["rk_esc_eol_support", "rk_esc_has_fix"])

    assert_decisive(
        by_name["local_flaw_with_impact"],
        {"rk_esc_attack_vector": "L", "rk_esc_impact_c": "H", "rk_esc_impact_i": "N"},
        decisive=["rk_esc_attack_vector"],
        disjunctive=["rk_esc_impact_c", "rk_esc_impact_i"])

    # The counterfactual the sole listener rule was written for, done on the
    # facts that do exist: the same finding on a package the exposure rollup
    # already scores as reachable is covered by the five signals, and the rule
    # must decline to escalate it rather than scoring exposure twice.
    rule = by_name["listener_loads_the_library"]
    reachable = escalate.mutate(
        {"rk_esc_load_rank": 3, "rk_esc_reach_rank": 0}, "rk_esc_reach_rank", to=3)
    check("a package the scorer already calls exposed is not escalated again",
          not escalate.fires(rule, reachable), reachable)

    # Mutating a field the rule does not name must not stop it firing. This is
    # the other half of the check: a rule that stops firing when an unrelated
    # fact changes is reading something it did not declare.
    unrelated = escalate.mutate(
        {"rk_esc_load_rank": 3, "rk_esc_reach_rank": 0, "rk_esc_has_fix": 1},
        "rk_esc_has_fix")
    check("destroying an unnamed fact does not change the rule",
          escalate.fires(rule, unrelated), unrelated)

    err = None
    try:
        escalate.mutate({"rk_esc_load_rank": 3}, "rk_esc_load_rnak")
    except escalate.RuleError as exc:
        err = str(exc)
    # A mutation test that mutates a misspelt field mutates nothing and proves
    # nothing, so the typo has to be an error rather than a quiet pass.
    check("mutating a field that is not on the allowlist is an error",
          err is not None and "rk_esc_load_rank" in err, err)


def test_three_valued_logic():
    print("null handling:")
    rules, _ = rules_from(stanza("not_supported",
                                 'NOT rk_esc_eol_support = "supported"', enabled="1"))
    rule = rules[0]
    check("a known non match fires",
          escalate.fires(rule, {"rk_esc_eol_support": "no supported release"}))
    # This is the trap a NOT rule sets. In SPL, NOT null is null and if() takes
    # the else branch, so a component with no lifecycle row does NOT escalate.
    # A Python evaluator that treated a missing key as falsy would say the
    # opposite and would quietly bless every rule written this way.
    check("an unknown value does not fire, because no evidence is not evidence",
          not escalate.fires(rule, {}))
    check("an empty string is a value for a string field, not an absence",
          escalate.fires(rule, {"rk_esc_eol_support": ""}))
    numeric, _ = rules_from(stanza("ranked", 'rk_esc_load_rank >= 2', enabled="1"))
    check("an unparseable number is unknown, the way tonumber() returns null",
          not escalate.fires(numeric[0], {"rk_esc_load_rank": "n/a"}))
    check("a numeric field arriving as a string still compares",
          escalate.fires(numeric[0], {"rk_esc_load_rank": "3"}))


# ---------------------------------------------------------------------------
# The file that actually ships
# ---------------------------------------------------------------------------

def test_shipped_conf():
    print("default/riskability_escalations.conf:")
    if not os.path.isfile(SHIPPED_CONF):
        check("the shipped rule file exists", False, SHIPPED_CONF)
        return
    with open(SHIPPED_CONF, encoding="utf-8") as fh:
        rules, problems = rules_from(fh.read())
    rejected = [p for p in problems if p.kind == escalate.REJECT]
    check("no shipped rule is malformed or unsafe", not rejected,
          [str(p) for p in rejected])
    check("every shipped rule ships switched off",
          all(not r.enabled for r in rules), [r.name for r in rules if r.enabled])
    check("so the shipped file compiles to no escalation at all",
          escalate.to_spl(rules) == '| eval rk_esc_hits = null(), rk_esc_bump = 0',
          escalate.to_spl(rules))
    unproduced = sorted(p.rule for p in problems if p.kind == escalate.UNPRODUCED)
    # Two of the four worked examples depend on a fleet wide rollup that does
    # not exist yet. They are refused with the reason said out loud, which is
    # the only honest state for a rule that would otherwise be switched on and
    # evaluate null for ever.
    check("the two rules waiting on an unmeasured fact are named",
          unproduced == ["sole_listener_availability",
                         "writable_root_autorun_local_flaw"], unproduced)
    check("the rules whose facts are all measured do load",
          sorted(r.name for r in rules) == ["listener_loads_the_library",
                                            "no_supported_release_no_fix"],
          [r.name for r in rules])
    check("every shipped rule says why the five signals cannot catch it",
          all(len(r.description) > 200 for r in rules),
          [(r.name, len(r.description)) for r in rules])


def test_no_silent_drift():
    """The three places that must agree, and the test that makes them.

    This suite passed with 80-odd green checks while the engine was
    UNREACHABLE: the saved search called a macro nobody had defined and read a
    field nobody evalled, so every finding would have carried escalated = 0 for
    ever and no test would have said a word. That is the sixth time on this
    branch that a field named in one place and produced in none got through.

    So the contracts are asserted here rather than assumed:
      1. the compiled macro in macros.conf matches what the rule file compiles
         to, because the macro is generated and a stale one silently evaluates
         yesterday's rules
      2. every field the validator allows as PRODUCED is actually assigned by
         the facts macro, because an allowlisted field nothing evals is null on
         every row and its rule fires never
      3. the saved search reads the field names the compiler writes
    """
    print("no silent drift:")
    import re as _re
    root = ROOT
    macros = open(os.path.join(root, "app", "riskability", "default",
                               "macros.conf"), encoding="utf-8").read()
    searches = open(os.path.join(root, "app", "riskability", "default",
                                 "savedsearches.conf"), encoding="utf-8").read()

    # 1. macro matches the rules it was generated from
    import subprocess
    rc = subprocess.run([sys.executable,
                         os.path.join(root, "tools", "build_escalation_macro.py"),
                         "--check"], capture_output=True, text=True)
    check("the compiled macro matches the rule file", rc.returncode == 0,
          rc.stdout.strip()[:200])

    # 2. every PRODUCED field is assigned by the facts macro
    i = macros.index("[riskability_escalation_facts]")
    facts = macros[i:macros.index("iseval", i)]
    assigned = set(_re.findall(r"(rk_esc_[a-z0-9_]+)\s*=", facts))
    produced = {name for name, spec in escalate.FIELD_ALLOWLIST.items()
                if spec.get("status") == "produced"}
    missing = sorted(produced - assigned)
    check("every produced field is evalled by the facts macro",
          not missing, "not assigned: %s" % missing)
    stray = sorted(a for a in assigned
                   if a not in escalate.FIELD_ALLOWLIST)
    check("the facts macro evals nothing the allowlist does not know",
          not stray, "unknown: %s" % stray)
    unproduced = {name for name, spec in escalate.FIELD_ALLOWLIST.items()
                  if spec.get("status") != "produced"}
    lying = sorted(unproduced & assigned)
    check("no field marked unproduced is secretly produced",
          not lying, "actually assigned: %s" % lying)

    # 3. the saved search reads what the compiler writes
    emitted = set(_re.findall(r"(rk_esc_[a-z0-9_]+)\s*=", escalate.to_spl([])))
    for field in sorted(emitted):
        check("the expansion search reads %s" % field, field in searches)
    # The replay search compiles the FULL rule set into its own field, so
    # that field must be written too, by the other generated macro.
    every = set(_re.findall(r"(rk_esc_[a-z0-9_]+)\s*=",
                            escalate.to_spl([], field="rk_esc_hits_all", every=True)))
    for field in sorted(every):
        check("the replay search reads %s" % field, field in searches)
    check("the replay macro is defined",
          "[riskability_escalation_rules_all]" in macros)


def main():
    test_allowlist()
    test_accepts()
    test_rejects()
    test_suspect_values()
    test_loading()
    test_unproduced_fields()
    test_continuations()
    test_bump_is_capped()
    test_disabled_contributes_nothing()
    test_compiled_spl_shape()
    test_mutation()
    test_three_valued_logic()
    test_shipped_conf()
    test_no_silent_drift()

    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
