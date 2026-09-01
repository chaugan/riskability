"""The escalation rule language: its field allowlist, its validator, and the
SPL a rule set compiles to.

Stdlib only and Splunk free, for the same reason ``ai_config`` is: a validator
that can only be run on a search head against a live KV store is a validator
nobody runs. Everything here is exercised by ``tools/test_escalations.py`` on a
laptop, and the one thing it guards is the one thing that must never be got
wrong in this app.

WHAT THIS IS FOR

The priority score is computed from five measured signals. The app measures
far more than five things, and none of the rest can move an ordering because
nothing combines them with the flaw. A rule in
``default/riskability_escalations.conf`` is that combination: a boolean
predicate over measured fields whose only power is to raise one finding by one
tier. The rules are read by an operator, live in a conf file, and are ordinary
SPL. There is no new interpreter here, and that is deliberate: SPL already has
one, it is already what every other calculation in this app is written in, and
a rule an operator cannot paste into a search bar is a rule nobody can check.

WHY THE VALIDATOR IS THE SECURITY CONTROL AND NOT A TIDINESS CHECK

"when" is a string read out of a conf file and expanded into a scheduled
search that runs on the search head with the app's own privileges. An
unvalidated one is SPL injection into this app's own pipeline: a backtick
reaches every macro, a pipe reaches every command including ``delete`` and
``outputlookup``, a bracket opens a subsearch, and a dollar sign reaches token
substitution in anything dashboard driven. So the validator accepts by
allowlist and refuses everything else, because a blocklist is a list of the
attacks somebody happened to think of. See ``validate_when``.

WHY THE ALLOWLIST IS ALSO A CORRECTNESS CONTROL

In SPL an unknown field is null and a comparison against null is false, so a
rule naming a field nothing computes never fires: no error, no log line, no
result, and an operator who believes an escalation is running when nothing is.
That failure is silent for ever, and this codebase has found the same shape of
defect five separate times, always as a field named in an output list and
evalled nowhere. So a field is not on the allowlist because it would be nice
to have. It is on the allowlist because something computes it, and the two
fields nothing computes yet are marked, and rules that name them are refused
rather than shipped to fire never.

WHAT IS DELIBERATELY NOT ON THE ALLOWLIST

* Anything a model wrote. The verdict cache carries a tier, a score, a
  confidence and a list of techniques, and not one of them may reach a rule.
  Nothing a model says can move an ordering, and an escalation engine that
  could read model output would be exactly that with extra steps.
* The five scoring signals themselves: KEV, EPSS, CVSS, exposure zone and
  version match confidence. A rule over those is a sixth scoring weight
  wearing a rule's clothes, and it belongs in the scorer where it can be
  reasoned about against the other five rather than here, where it fires on a
  subset and reads as an exception. ``rk_esc_reach_rank`` is the one that
  looks like a counterexample and is not: it appears so a rule can say WHERE
  the score already covers the finding and decline to escalate there.
* The accepted risk register. Findings reach this pipeline through the
  riskability_open_findings macro, which excludes accepted="1" at source, so
  an accepted finding is not escalated because it is not present. A rule that
  could reach past an acceptance would make the register advisory.
"""

from __future__ import annotations

import re
from collections import namedtuple

# ---------------------------------------------------------------------------
# The field allowlist
# ---------------------------------------------------------------------------
# Every entry is a value the escalation stage computes on the finding, under
# an rk_esc_ name, BEFORE any rule is evaluated. The prefix is not decoration.
# It means a rule can never accidentally name an internal field of the
# expansion search (rk_adjust, rk_t0_tier, rk_base and the rest are one
# misspelling away from each other), and it means the prefix itself is the
# signal in the compiled SPL that says which identifiers came out of a conf
# file and through this validator.
#
# The prefix also draws the line between a measured fact and the shape a rule
# gets to see it in. world_writable is the case that proves the point: it
# arrives from swinv as the string "true" on some hosts, as 1 on others and
# blank on every Windows host, and two dashboard panels already test all three
# spellings. A rule must never be the fourth place that has to know that.
#
# "status" is the honest half of this table:
#
#   PRODUCED     something computes it today, and the escalation stage puts it
#                on the row. A rule may name it.
#   UNPRODUCED   the vocabulary is decided and the underlying facts are
#                measured, but nothing reduces them to this field yet. A rule
#                may name it and will be refused by load_rules, with the
#                reason said out loud, rather than shipped to evaluate null on
#                every run for ever.
#
# "values" is the closed vocabulary where one is known. It is used only to
# warn: an equality test against a value outside it is a rule that cannot
# fire, which is the same silent nothing as a misspelt field and deserves the
# same treatment, but the vocabularies come from feed data rather than from
# code, so a warning is as far as it should go.

PRODUCED = "produced"
UNPRODUCED = "unproduced"

NUMBER = "number"
STRING = "string"
BOOL = "bool"

PREFIX = "rk_esc_"

FIELD_ALLOWLIST = {
    "rk_esc_attack_vector": {
        "type": STRING,
        "status": PRODUCED,
        "values": ("N", "A", "L", "P", ""),
        "note": "How the flaw is reached, from the advisory's CVSS v3 vector.",
        "source": "cvss_vector on riskability_advisory_lookup, mvindex guarded",
    },
    "rk_esc_impact_c": {
        "type": STRING,
        "status": PRODUCED,
        "values": ("N", "L", "H", ""),
        "note": "Confidentiality impact letter from the same vector.",
        "source": "cvss_vector on riskability_advisory_lookup, mvindex guarded",
    },
    "rk_esc_impact_i": {
        "type": STRING,
        "status": PRODUCED,
        "values": ("N", "L", "H", ""),
        "note": "Integrity impact letter from the same vector.",
        "source": "cvss_vector on riskability_advisory_lookup, mvindex guarded",
    },
    "rk_esc_impact_a": {
        "type": STRING,
        "status": PRODUCED,
        "values": ("N", "L", "H", ""),
        "note": "Availability impact letter from the same vector.",
        "source": "cvss_vector on riskability_advisory_lookup, mvindex guarded",
    },
    "rk_esc_reach_rank": {
        "type": NUMBER,
        "status": PRODUCED,
        "values": (3, 2, 1, 0, -1),
        "note": "Measured network exposure of the finding's own package on its host.",
        "source": "reach_rank on riskability_reach_lookup, keyed hostname and rk_key",
    },
    "rk_esc_load_rank": {
        "type": NUMBER,
        "status": PRODUCED,
        "values": (3, 2, 1, 0),
        "note": "3 a listener loads it, 2 loaded not listening, 1 not in the load list, 0 not assessed.",
        "source": "load_rank from the riskability_load_evidence macro",
    },
    "rk_esc_eol_support": {
        "type": STRING,
        "status": PRODUCED,
        "values": ("supported", "vendor extended support",
                   "supported by the distribution",
                   "distribution lifecycle unknown", "no supported release", ""),
        "note": 'Vendor support state of the product. "" means no lifecycle row, never good news.',
        "source": "support on riskability_eolstate",
    },
    "rk_esc_has_fix": {
        "type": BOOL,
        "status": PRODUCED,
        "values": (0, 1),
        "note": "1 when the finding carries a fixed version, 0 when it does not.",
        "source": "fixed_version on the finding itself",
    },
    "rk_esc_sole_listener": {
        "type": BOOL,
        "status": UNPRODUCED,
        "values": (0, 1),
        "note": "1 when this package is the only thing answering its port in the assessed fleet.",
        "source": "NOT MEASURED: nothing groups riskability_exposure by port, and there is "
                  "no join path from a port keyed row back to a finding",
    },
    "rk_esc_root_autorun_writable": {
        "type": BOOL,
        "status": UNPRODUCED,
        "values": (0, 1),
        "note": "1 when the host runs a world writable target as root or SYSTEM on a timer.",
        "source": "NOT MEASURED: the mechanism, its user and its world_writable flag are in "
                  "riskability_config, but no per host rollup reduces them to one flag",
    },
}

PRODUCED_FIELDS = frozenset(
    name for name, spec in FIELD_ALLOWLIST.items() if spec["status"] == PRODUCED)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
# Bounded because the output of this module is written into a scheduled search
# in a conf file, where a line is continued with a backslash and a value that
# runs away takes the rest of the stanza with it. A rule nobody can read is
# also a rule nobody can review, and review is the only thing standing between
# an escalation and an ordering change nobody asked for.

MAX_EXPRESSION = 512
MAX_TOKENS = 200
MAX_STRING = 96
MAX_RULE_NAME = 64
MAX_RULES = 64

# Rule names land inside a double quoted SPL string literal in the compiled
# fragment, so the charset here is what makes that quoting safe by
# construction rather than by escaping.
RULE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,%d}$" % (MAX_RULE_NAME - 1))

RULE_KEYS = ("description", "when", "bump", "enabled")


class RuleError(ValueError):
    """A rule that must not be shipped. The message names the offending token
    and its offset, because the operator fixing it is reading a conf file and
    has nothing else to go on."""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
# The string literal charset allows a comma and a colon because measured
# vocabularies contain them ("loaded, not listening"), and it is safe to allow
# them THERE while refusing them as bare tokens: a quoted literal is scanned
# atomically, and the only way out of one is a closing quote or a backslash
# escape, both of which the charset refuses. A comma as a token is an argument
# separator and reaches a function call; a comma inside a literal is a comma.

_WS = re.compile(r"\s+")
_NUM = re.compile(r"\d+(?:\.\d+)?")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STRING = re.compile(r'"([A-Za-z0-9 _.,:/@+-]*)"')
_STRING_OPEN = re.compile(r'"([^"\n]*)"')
_OPERATORS = ("==", "!=", "<=", ">=", "=", "<", ">")
_KEYWORDS = ("AND", "OR", "NOT")

# A leading minus is part of a numeric literal and nothing else. reach_rank is
# -1 when a host was assessed and nothing listened, so negative literals have
# to exist; arithmetic does not, and letting "-" be an infix operator would be
# the first crack in a grammar whose whole value is that it has no expressions
# in it, only comparisons.
_MINUS_MAY_START_NUMBER = (None, "CMP", "AND", "OR", "NOT", "LPAREN")

Token = namedtuple("Token", "kind value pos")


def _scan(text):
    if len(text) > MAX_EXPRESSION:
        raise RuleError("expression is %d characters, over the %d limit"
                        % (len(text), MAX_EXPRESSION))
    tokens = []
    pos = 0
    end = len(text)
    while pos < end:
        m = _WS.match(text, pos)
        if m:
            pos = m.end()
            continue
        prev = tokens[-1].kind if tokens else None
        ch = text[pos]

        if ch == '"':
            m = _STRING.match(text, pos)
            if not m:
                loose = _STRING_OPEN.match(text, pos)
                if not loose:
                    raise RuleError("unterminated string literal at offset %d" % pos)
                bad = _first_bad_string_char(loose.group(1))
                raise RuleError("character %r is not allowed inside a string literal "
                                "at offset %d" % (bad, pos))
            if len(m.group(1)) > MAX_STRING:
                raise RuleError("string literal at offset %d is over %d characters"
                                % (pos, MAX_STRING))
            tokens.append(Token("STRING", m.group(1), pos))
            pos = m.end()
            continue

        if ch.isdigit() or (ch == "-" and prev in _MINUS_MAY_START_NUMBER
                            and _NUM.match(text, pos + 1)):
            start = pos
            if ch == "-":
                pos += 1
            m = _NUM.match(text, pos)
            if not m:
                raise RuleError("expected a number at offset %d" % start)
            raw = text[start:m.end()]
            value = float(raw) if "." in raw else int(raw)
            tokens.append(Token("NUMBER", value, start))
            pos = m.end()
            continue

        m = _IDENT.match(text, pos)
        if m:
            word = m.group(0)
            upper = word.upper()
            if upper in _KEYWORDS:
                # Accepted in any case and emitted uppercase. An operator
                # writing "and" in a conf file has not written a different
                # rule, and the compiled SPL should read the same whoever
                # typed it.
                tokens.append(Token(upper, upper, pos))
                pos = m.end()
                continue
            after = _WS.match(text, m.end())
            nxt = after.end() if after else m.end()
            if nxt < end and text[nxt] == "(":
                # Checked before the allowlist so the message names the real
                # problem. Every SPL function reachable from an eval is here:
                # match(), searchmatch(), commands(), lookup(), and the one
                # that matters most, printf() into a field somebody else
                # expands. There is no function this language needs.
                raise RuleError("function calls are not permitted: %s( at offset %d"
                                % (word, pos))
            if word not in FIELD_ALLOWLIST:
                raise RuleError("%r is not an allowlisted field (offset %d)%s"
                                % (word, pos, _did_you_mean(word)))
            tokens.append(Token("FIELD", word, pos))
            pos = m.end()
            continue

        if ch == "(":
            tokens.append(Token("LPAREN", ch, pos))
            pos += 1
            continue
        if ch == ")":
            tokens.append(Token("RPAREN", ch, pos))
            pos += 1
            continue

        for op in _OPERATORS:
            if text.startswith(op, pos):
                tokens.append(Token("CMP", op, pos))
                pos += len(op)
                break
        else:
            raise RuleError("character %r is not allowed in a rule (offset %d)"
                            % (ch, pos))

    if len(tokens) > MAX_TOKENS:
        raise RuleError("expression has more than %d tokens" % MAX_TOKENS)
    if not tokens:
        raise RuleError("expression is empty")
    return tokens


def _first_bad_string_char(body):
    for ch in body:
        if not re.match(r"[A-Za-z0-9 _.,:/@+-]", ch):
            return ch
    return body[:1] or ""


def _did_you_mean(word):
    """A misspelt field is the failure this whole module exists to make loud,
    so the loud version should also be useful."""
    if not word.startswith(PREFIX):
        return ". Every field a rule may name is prefixed %s" % PREFIX
    letters = set(word)
    near = [name for name in FIELD_ALLOWLIST
            if len(set(name) ^ letters) <= 2 and abs(len(name) - len(word)) <= 3]
    if near:
        return ". Did you mean %s?" % ", ".join(sorted(near))
    return ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
# Tokenising alone would accept "rk_esc_has_fix rk_esc_load_rank", which is not
# an injection but is a scheduled search that fails to parse every hour, which
# for an operator is the same outage with a different cause. So the grammar is
# checked as well, and it is small enough to state in full:
#
#   expression  := or
#   or          := and (OR and)*
#   and         := not (AND not)*
#   not         := NOT not | primary
#   primary     := "(" expression ")" | comparison
#   comparison  := operand CMP operand
#   operand     := field | number | string
#
# There is no arithmetic, no function application, no field list and no
# concatenation, so there is nothing in a rule that can produce a value: only
# things that can compare two.

_ORDERING = ("<", "<=", ">", ">=")
_EQUALITY = ("=", "==", "!=")


class _Parser(object):
    def __init__(self, tokens):
        self.toks = tokens
        self.i = 0
        self.suspects = []

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self):
        tok = self.peek()
        if tok is None:
            raise RuleError("expression ends early, after %s"
                            % (self.toks[-1].value if self.toks else "nothing"))
        self.i += 1
        return tok

    def parse(self):
        node = self.parse_or()
        left = self.peek()
        if left is not None:
            raise RuleError("unexpected %r at offset %d" % (left.value, left.pos))
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() is not None and self.peek().kind == "OR":
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek() is not None and self.peek().kind == "AND":
            self.take()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.peek() is not None and self.peek().kind == "NOT":
            self.take()
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        tok = self.peek()
        if tok is not None and tok.kind == "LPAREN":
            self.take()
            node = self.parse_or()
            closing = self.peek()
            if closing is None or closing.kind != "RPAREN":
                raise RuleError("unbalanced parentheses, no ')' for the '(' at offset %d"
                                % tok.pos)
            self.take()
            return node
        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_operand()
        op = self.peek()
        if op is None or op.kind != "CMP":
            where = op.pos if op is not None else -1
            raise RuleError("expected a comparison operator after %r (offset %d)"
                            % (left[1], where))
        self.take()
        right = self.parse_operand()
        self._check_types(op, left, right)
        return ("cmp", "==" if op.value == "=" else op.value, left, right)

    def parse_operand(self):
        tok = self.take()
        if tok.kind == "FIELD":
            return ("field", tok.value)
        if tok.kind == "NUMBER":
            return ("num", tok.value)
        if tok.kind == "STRING":
            return ("str", tok.value)
        raise RuleError("expected a field, a number or a string, got %r at offset %d"
                        % (tok.value, tok.pos))

    # Type checking is not pedantry here. A numeric field compared to a quoted
    # string, or a string field compared with "<", is a rule that parses, ships
    # and never fires, which is the exact silent nothing the allowlist exists
    # to prevent one line further up.
    def _check_types(self, op, left, right):
        lt = _operand_type(left)
        rt = _operand_type(right)
        if left[0] != "field" and right[0] != "field":
            raise RuleError("a comparison must name a measured field on at least one "
                            "side, so 1=1 and \"a\"=\"a\" are refused: a rule that is "
                            "true for every finding is not an escalation")
        if _family(lt) != _family(rt):
            raise RuleError("cannot compare %s with %s: %s is %s and %s is %s"
                            % (_show(left), _show(right), _show(left), lt,
                               _show(right), rt))
        if _family(lt) == STRING and op.value in _ORDERING:
            raise RuleError("%r orders strings lexicographically, which is never what "
                            "a rule about a measured vocabulary means" % op.value)
        if op.value in _EQUALITY:
            for field_side, literal_side in ((left, right), (right, left)):
                if field_side[0] != "field" or literal_side[0] == "field":
                    continue
                values = FIELD_ALLOWLIST[field_side[1]].get("values")
                if values and literal_side[1] not in values:
                    self.suspects.append(
                        "%s is never %s: the measured values are %s"
                        % (field_side[1], _show(literal_side),
                           ", ".join(_show(("lit", v)) for v in values)))


def _operand_type(node):
    if node[0] == "field":
        return FIELD_ALLOWLIST[node[1]]["type"]
    return NUMBER if node[0] == "num" else STRING


def _family(kind):
    return NUMBER if kind in (NUMBER, BOOL) else STRING


def _show(node):
    value = node[1]
    if isinstance(value, str) and node[0] != "field":
        return '"%s"' % value
    return str(value)


# ---------------------------------------------------------------------------
# The public validator
# ---------------------------------------------------------------------------

def compile_when(expression):
    """Parse and check one "when", returning (ast, suspects) or raising
    RuleError. Callers wanting a boolean want validate_when."""
    parser = _Parser(_scan(expression))
    return parser.parse(), parser.suspects


def validate_when(expression):
    """Return (ok, error) for one "when" expression.

    This is the security control of the escalation engine, and it is worth
    saying plainly why. "when" is read out of a conf file that any admin with
    write access to the app directory can edit, and it is expanded into a
    scheduled search that runs on the search head as the app. Whatever this
    function lets through, the search head runs. A permissive validator here
    is not a lax setting, it is SPL injection into the app's own pipeline,
    with the app's own privileges, on a cron.

    So it accepts an allowlist and refuses the rest. What is accepted:

    * identifiers that appear in FIELD_ALLOWLIST, and nothing else that looks
      like a name;
    * integer and decimal literals, with a leading minus permitted only where
      a number may start, because reach_rank is -1 and arithmetic is not a
      thing a rule needs;
    * double quoted string literals over a fixed charset, with no escapes at
      all, so a literal cannot close itself early;
    * the operators = == != < <= > >= and the keywords AND OR NOT;
    * matched parentheses, checked by parsing rather than by counting.

    What is refused, and what each one would otherwise reach:

    * backtick, which is macro expansion, and therefore every macro in the
      app including the index macros;
    * pipe, which is the next command, and therefore delete, outputlookup,
      collect, sendemail and the rest of them;
    * square bracket, which opens a subsearch and takes the pipe restriction
      with it;
    * comma outside a string, which is an argument separator and only useful
      next to a function call;
    * semicolon, which separates searches;
    * single quote, which quotes a field name containing anything at all and
      is the standard way out of a double quoted context;
    * dollar sign, which is token substitution anywhere this string is ever
      rendered into a dashboard or an alert action;
    * backslash, which is both an SPL escape and a conf line continuation, so
      one character can end the setting and start the next;
    * any identifier followed by an opening parenthesis, which is a function
      call, refused whether or not the identifier is an allowlisted field,
      because there is no function this language needs and every function is
      an argument list, and an argument list is a comma away from somewhere
      else.

    The refusals above are the ones that matter today. They are not the
    control. The control is that anything not named as accepted is refused,
    including whatever nobody here thought of.
    """
    try:
        compile_when(expression)
    except RuleError as exc:
        return False, str(exc)
    return True, ""


# ---------------------------------------------------------------------------
# Rules and their problems
# ---------------------------------------------------------------------------

Rule = namedtuple("Rule", "name description when bump enabled ast fields")

# Three kinds, because "the operator must be told" and "the rule must not run"
# are different questions and collapsing them loses one of the answers.
#
#   REJECT       malformed, unsafe, or naming something that is not a field.
#                Never shipped.
#   UNPRODUCED   well formed and allowlisted, but names a field nothing
#                computes yet. Not shipped, because shipping it means an
#                operator switches on a rule that evaluates null for ever and
#                nothing anywhere says so.
#   SUSPECT      shipped, and reported. An equality against a value outside a
#                measured vocabulary. The vocabularies come from feed data
#                rather than from code, so this cannot be a refusal without
#                the code becoming the thing that decides what the feed is
#                allowed to say.
REJECT = "reject"
SUSPECT = "suspect"

Problem = namedtuple("Problem", "rule kind reason")


def _problem_str(self):
    return "%s [%s] %s" % (self.rule, self.kind, self.reason)


Problem.__str__ = _problem_str


_STANZA_RE = re.compile(r"^\[(?P<name>[^\]]*)\]\s*$")


def _continues(line):
    """True when this line continues onto the next. Only an ODD number of
    trailing backslashes continues, matching tools/conf_lint.py, which matches
    the Splunk Packaging Toolkit. Getting this wrong here would mean reading a
    different rule than the one the search head runs."""
    m = re.search(r"(\\+)$", line)
    return bool(m) and len(m.group(1)) % 2 == 1


def parse_conf(conf_text):
    """Stanzas to a dict of dicts, in file order, with continuations joined.

    Deliberately not splunklib and deliberately not configparser. splunklib
    would need a search head, and configparser's interpolation would eat the
    dollar signs and percent signs this validator exists to refuse.
    """
    stanzas = []
    current = None
    pending_key = None
    for raw in conf_text.splitlines():
        line = raw.rstrip("\r")
        if pending_key is not None:
            body = line[:-1] if _continues(line) else line
            current[1][pending_key] += " " + body.strip()
            if not _continues(line):
                pending_key = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _STANZA_RE.match(stripped)
        if m:
            current = (m.group("name").strip(), {})
            stanzas.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if _continues(value):
            current[1][key] = value[:-1].strip()
            pending_key = key
        else:
            current[1][key] = value.strip()
    return stanzas


def load_rules(conf_text):
    """Parse riskability_escalations.conf and return (rules, problems).

    A malformed rule must never disable the whole set. The engine degrades to
    the rules that are sound, because the alternative is that one typo in one
    stanza silently changes the priority of every finding in the estate, which
    is a bigger ordering change than any rule in the file could make.
    """
    rules = []
    problems = []
    seen = set()

    for name, settings in parse_conf(conf_text):
        if name == "default":
            # Splunk's own parser merges [default] into every stanza. This one
            # does not, and saying so is the point: a default that silently
            # applied here and nowhere else would be a rule set that behaves
            # differently depending on which parser read it.
            problems.append(Problem(name, REJECT,
                                    "a [default] stanza is not merged into rules by this "
                                    "validator, so its settings would apply on the search "
                                    "head and not here. Put the settings in each rule."))
            continue
        if not RULE_NAME_RE.match(name):
            problems.append(Problem(name or "(unnamed)", REJECT,
                                    "rule name must be lowercase letters, digits and "
                                    "underscores, starting with a letter, at most %d "
                                    "characters" % MAX_RULE_NAME))
            continue
        if name in seen:
            problems.append(Problem(name, REJECT, "duplicate stanza name"))
            continue
        seen.add(name)

        unknown = [key for key in settings if key not in RULE_KEYS]
        if unknown:
            # An unknown key is an author expecting behaviour that does not
            # exist. "severity = high" or "bump = 2" spelt as "tiers = 2" must
            # not load as a rule that quietly does something else.
            problems.append(Problem(name, REJECT,
                                    "unknown setting(s): %s. A rule has exactly %s"
                                    % (", ".join(sorted(unknown)), ", ".join(RULE_KEYS))))
            continue

        when = settings.get("when", "").strip()
        if not when:
            problems.append(Problem(name, REJECT,
                                    "no 'when' expression, so the rule has no predicate "
                                    "and nothing it could ever match"))
            continue

        description = settings.get("description", "").strip()
        if not description:
            problems.append(Problem(name, REJECT,
                                    "no description. A rule whose author could not say "
                                    "what it catches and why the five scoring signals "
                                    "cannot catch it is a scoring weight in disguise."))
            continue

        bump_raw = settings.get("bump", "1").strip()
        if bump_raw != "1":
            problems.append(Problem(name, REJECT,
                                    "bump is %r. A rule raises a finding by exactly one "
                                    "tier and can never reach P0, which stays the "
                                    "deterministic rules' to give." % bump_raw))
            continue

        enabled_raw = settings.get("enabled", "0").strip().lower()
        if enabled_raw not in ("0", "1", "true", "false"):
            problems.append(Problem(name, REJECT,
                                    "enabled is %r, expected 0 or 1" % enabled_raw))
            continue
        enabled = enabled_raw in ("1", "true")

        try:
            ast, suspects = compile_when(when)
        except RuleError as exc:
            problems.append(Problem(name, REJECT, str(exc)))
            continue

        fields = sorted(_fields_of(ast))
        unproduced = [f for f in fields if f not in PRODUCED_FIELDS]
        if unproduced:
            problems.append(Problem(
                name, UNPRODUCED,
                "names %s, which nothing computes today, so the rule would evaluate "
                "null on every row for ever and fire never. %s"
                % (", ".join(unproduced),
                   " ".join(FIELD_ALLOWLIST[f]["source"] for f in unproduced))))
            continue

        for suspect in suspects:
            problems.append(Problem(name, SUSPECT, suspect))

        rules.append(Rule(name=name, description=description, when=when, bump=1,
                          enabled=enabled, ast=ast, fields=fields))

        if len(rules) > MAX_RULES:
            problems.append(Problem(name, REJECT,
                                    "more than %d rules. Past that a rule set is a "
                                    "scoring model nobody agreed to." % MAX_RULES))
            rules.pop()
            break

    return rules, problems


def _fields_of(node):
    kind = node[0]
    if kind == "field":
        return {node[1]}
    if kind in ("num", "str"):
        return set()
    if kind == "not":
        return _fields_of(node[1])
    if kind == "cmp":
        return _fields_of(node[2]) | _fields_of(node[3])
    return _fields_of(node[1]) | _fields_of(node[2])


# ---------------------------------------------------------------------------
# Compilation to SPL
# ---------------------------------------------------------------------------

def render(node):
    """One AST back to SPL. Every binary node is parenthesised, so the SPL
    parser cannot reach a different reading of the rule than the validator
    did. Two parsers agreeing by luck of precedence is not agreement."""
    kind = node[0]
    if kind == "field":
        return node[1]
    if kind == "num":
        value = node[1]
        return str(int(value)) if isinstance(value, int) else repr(value)
    if kind == "str":
        return '"%s"' % node[1]
    if kind == "not":
        return "NOT (%s)" % render(node[1])
    if kind == "cmp":
        return "%s %s %s" % (render(node[2]), node[1], render(node[3]))
    return "(%s %s %s)" % (render(node[1]), kind.upper(), render(node[2]))


def to_spl(rules, field="rk_esc_hits", every=False):
    """Compile the ENABLED rules into one SPL eval fragment computing
    rk_esc_bump and rk_esc_rules.

    WHY THE BUMP IS CAPPED AT ONE, AND WHY THAT IS NOT OPTIONAL

    Rules compose. Each one is written on its own, justified on its own, and
    switched on by somebody who has thought about that one case, and every one
    of them is defensible in isolation. A finding on an end of life product,
    in a library a listener loads, on a host with a writable root autorun,
    matches three rules that three different people each thought was rare.
    Sum them and it moves three tiers, from a considered position near the
    bottom of the queue to the top, on the strength of nobody's decision.

    That is precisely how the thing this app replaced failed. The model
    assigned priorities produced seven distinct scores across 1,020 findings,
    663 of them the value 85, and 82% above the waterline: a flat queue that
    told an analyst nothing, arrived at one reasonable sounding judgement at a
    time. A rule set that can add is a rule set that can rebuild that
    distribution, and ten sensible acceptances is all it takes. So the cap is
    structural rather than arithmetic: rk_esc_bump is a boolean over whether
    ANY rule matched, not a sum with a min() over it, so there is no
    expression anywhere in the compiled fragment that can produce a 2.

    rk_esc_rules carries every rule that matched, comma separated, so an
    operator looking at an escalated finding can see all three reasons even
    though only one tier was given. Losing the other two would make the same
    finding unexplainable.

    On the shape of the emitted SPL: it accumulates a plain string rather than
    a multivalue field. String concatenation with a multivalue field yields
    NULL in SPL, which has silently emptied a field in this app before, and
    every fix for it costs an mvdedup and an mvindex on a value that was never
    multivalue in the first place. A single valued string cannot fail that
    way. Each term is an if(), so a "when" that evaluates to null (a lookup
    miss upstream, a field the escalation stage failed to compute) takes the
    else branch and contributes nothing: the fragment fails closed, which for
    an escalation means the finding keeps the tier the five signals gave it.

    The caller writes this into savedsearches.conf and owns the line
    continuations there; what comes back is plain SPL, one stage per line,
    with no trailing backslashes and no comments, because SPL has no comment
    syntax and a "#" inside a continued conf value silently ends the search.
    """
    # field: which multivalue the hits land in. The enabled set writes
    # rk_esc_hits, which the expansion search joins and acts on. The full set
    # writes rk_esc_hits_all, which the replay search mvexpands to attribute a
    # would-be bump to the rule that caused it. Two consumers, two needs, one
    # representation: MULTIVALUE, because mvexpand can attribute and a joined
    # string cannot, while joining a multivalue is one function call.
    #
    # An earlier version emitted a comma-joined string and the replay search
    # could not use it. The mismatch was invisible because nothing checked that
    # what this writes is what anything reads, which is the same defect this
    # codebase has now found six times.
    selected = rules if every else [rule for rule in rules if rule.enabled]
    if not selected:
        # Assigned even with no rules, because downstream names them. A field
        # named in an output list and evalled nowhere is the defect this
        # codebase has found six times, and "there were no rules today" is
        # exactly the condition under which nobody would notice it.
        return '| eval %s = null(), rk_esc_bump = 0' % field

    lines = ['| eval %s = null()' % field]
    for rule in selected:
        lines.append('| eval %s = if(%s, mvappend(%s, "%s"), %s)'
                     % (field, render(rule.ast), field, rule.name, field))
    # ltrim rather than replace(): a regex here would need an end anchor, and
    # the fragment this returns is written into savedsearches.conf where a
    # dollar sign is token substitution in every context that renders a saved
    # search. The validator refuses a dollar sign in a rule, so the compiler
    # emitting one would be the one place the control did not reach. ltrim is
    # exact because a rule name is required to start with a lowercase letter,
    # so a leading comma or space can never be part of one.
    # The bump is a boolean over whether ANY rule matched, never a count.
    # Rules compose: ten reasonable acceptances would otherwise rebuild the
    # flat distribution the deterministic scoring replaced, one defensible
    # decision at a time. A finding matched by three rules moves one tier.
    lines.append('| eval rk_esc_bump = if(mvcount(%s) > 0, 1, 0)' % field)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evaluation, for tests and for counterfactual replay
# ---------------------------------------------------------------------------
# A reference evaluator in Python, so a rule can be tested without a search
# head. It mirrors SPL's three valued logic on purpose: an unknown field is
# null, a comparison involving null is null, and if() treats null as false.
#
# Said plainly, because it matters: this is a MODEL of SPL, not SPL. It has
# not been run against a Splunk instance as part of this work. It is trusted
# for what a rule's shape is and which facts it depends on, and it is not
# evidence of what a search head will return.

UNKNOWN = object()


def evaluate(node, evidence):
    """Three valued: True, False, or None for unknown."""
    kind = node[0]
    if kind == "cmp":
        left = _value(node[2], evidence)
        right = _value(node[3], evidence)
        if left is None or right is None:
            return None
        return _compare(node[1], left, right)
    if kind == "not":
        inner = evaluate(node[1], evidence)
        return None if inner is None else not inner
    if kind == "and":
        left = evaluate(node[1], evidence)
        right = evaluate(node[2], evidence)
        if left is False or right is False:
            return False
        if left is None or right is None:
            return None
        return True
    if kind == "or":
        left = evaluate(node[1], evidence)
        right = evaluate(node[2], evidence)
        if left is True or right is True:
            return True
        if left is None or right is None:
            return None
        return False
    raise RuleError("cannot evaluate node %r" % (node,))


def _value(node, evidence):
    if node[0] == "field":
        raw = evidence.get(node[1])
        if raw is None or raw is UNKNOWN or raw == "":
            # An empty string is a real value for eol_support and for the
            # impact letters, and a real absence for a number. Only the
            # numeric families treat it as unknown, which is what tonumber("")
            # does in SPL.
            if FIELD_ALLOWLIST[node[1]]["type"] in (NUMBER, BOOL):
                return None
            if raw is None or raw is UNKNOWN:
                return None
            return ""
        if FIELD_ALLOWLIST[node[1]]["type"] in (NUMBER, BOOL):
            try:
                return float(raw)
            except (TypeError, ValueError):
                return None
        return str(raw)
    if node[0] == "num":
        return float(node[1])
    return node[1]


def _compare(op, left, right):
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    return left >= right


def fires(rule, evidence):
    """True only when the rule is definitely true for this row. Null is not a
    match, which is the same way the compiled SPL behaves and the same way an
    escalation should behave: no evidence is not evidence."""
    return evaluate(rule.ast, evidence) is True


def apply_rules(rules, evidence):
    """(bump, matched names) for one evidence row. The bump is capped at 1 in
    the same place and for the same reason as in the compiled SPL: here it is
    a boolean over a list, there it is a boolean over a string, and neither
    has an addition in it."""
    matched = [rule.name for rule in rules if rule.enabled and fires(rule, evidence)]
    return (1 if matched else 0), matched


def mutate(evidence, field, to=UNKNOWN):
    """Return a copy of an evidence row with one fact destroyed.

    This is the whole of the mutation test, and the mutation test is the most
    valuable check the engine has. Take a row a rule fires on, destroy the
    fact the rule was written about, and the rule must stop firing. One that
    keeps firing is matching something other than what its author believed:
    usually a second condition that happens to be true of every row in the
    sample, sometimes a comparison whose sides are the wrong way round.

    Destroying a fact means setting it to unknown rather than to some other
    value, because unknown is the state a lookup miss actually produces and
    because "some other value" quietly chooses one, which for an ordering
    comparison decides the answer. Pass "to" for the cases where a specific
    counterfactual is the point (reach_rank 0 to 3, say).

    The field is checked against the allowlist, and that check is not
    defensive tidiness. A mutation test that mutates a misspelt field mutates
    nothing, the rule goes on firing, the assertion that it stopped is the one
    that fails, and the next person deletes the assertion. Worse: assert the
    rule STILL fires and a typo makes the test pass while proving nothing.
    """
    if field not in FIELD_ALLOWLIST:
        raise RuleError("%r is not an allowlisted field, so mutating it would "
                        "change nothing and prove nothing%s" % (field, _did_you_mean(field)))
    out = dict(evidence)
    out[field] = None if to is UNKNOWN else to
    return out


def field_reference():
    """The allowlist as text, for a validation tool or a doc build."""
    lines = []
    width = max(len(name) for name in FIELD_ALLOWLIST)
    for name, spec in FIELD_ALLOWLIST.items():
        lines.append("%-*s  %-6s  %-10s  %s" % (width, name, spec["type"],
                                                spec["status"], spec["note"]))
        lines.append("%-*s  %s" % (width, "", spec["source"]))
    return "\n".join(lines)
