"""Address to host resolution, and the grade of a piece of network evidence.

Stdlib only and Splunk free, for the same reason ``escalate`` and ``ai_config``
are: this ships to an air-gapped search head, the app vendors nothing it does
not need, and a guard that can only be exercised on a live search head against
a live KV store is a guard nobody exercises. Everything here runs under
``tools/test_route.py`` on a laptop.

WHAT THIS IS FOR

Riskability derives exposure from local socket binding. A collector running ON
a host can see what the host bound, and it cannot see NAT, a firewall, a
security group, a reverse proxy or a load balancer. Firewall logs record
exactly the layer the collector cannot. Joining the two narrows the gap.

It does not close it, and the vocabulary here is chosen so that nothing in
this module can be read as saying it does. A permitted edge in a firewall log
proves that at some time T a flow from one address to another address and port
traversed an enforcement point that logs to that index. It does not prove the
rule is still in place, that the path is bidirectional, that anything answered
at L7, or that the host still holds the address. The term is OBSERVED
PERMITTED TRAFFIC EVIDENCE. It is never "reachability", and no function here
returns a boolean that a caller could mistake for one.

WHY THE TIME ARGUMENT IS MANDATORY AND NOT A CONVENIENCE

This is the whole point of the module. A firewall log records dest 10.2.3.4 at
time T1. The inventory says host A holds 10.2.3.4 at time T2. Join those on the
address alone and the product asserts that host A's vulnerable service was
exposed, when at T1 that address may have belonged to a different host, a NAT
mapping, a container, a virtual address, a load balancer or an expired DHCP
lease. Each half is correct on its own. The join manufactures an entity
equivalence that neither half claims, and it does it silently, at scale, with a
confident label on the front.

So ``resolve_address`` takes the observation time as a mandatory positional
argument. A caller cannot ask who held an address without saying when, because
the version of that question without a time has no true answer, only a
plausible one.

WHY A REFUSAL IS A RESULT AND NOT AN ERROR

Five outcomes, and only one of them is a host. "We cannot say which host this
was" is a better product than a confident wrong join, so refusals are returned
in the same shape as successes, carry their reason in words an operator can
read, and are counted rather than logged and dropped. ``OUTCOME_OUTSIDE_ESTATE``
is the case that shows the shape is right: an address nothing in the estate
ever claimed is not a failure at all, it is the expected and useful answer for
an internet entry point.

WHY ABSENCE IS GRADED AND NEVER INVERTED

The old exposure label over-claimed: a wildcard bind was reported as
internet-facing on the strength of a socket. Evidence from observed edges
errs the other way, because a permitted but unused rule generates no edge, so
the graph says nothing about paths that are merely untried. Under-claiming a
risk produces false reassurance, which is worse here than over-claiming, so
``grade_evidence`` treats the absence of an edge as informative only where the
firewall data is present, fresh and complete, and grades it UNKNOWN in every
other case. Unknown never collapses to not exposed. A site that has not
onboarded firewall logs gets a lower confidence and never a lower finding.

The decay with hop count encodes the one asymmetry that is real. Internet scan
pressure is constant, so a permitted edge at the boundary shows sessions within
hours of the rule existing, and its absence therefore means something. East to
west, "nobody has tried yet" is the ordinary case, so absence there means
almost nothing and a route found there is worth less per hop.

WHAT THIS MODULE DELIBERATELY DOES NOT DO

* It does not build attack paths. Permitted network edges are not
  exploitability edges. The next hop after a compromise needs a privilege, a
  credential or a trust relationship, and a firewall log records none of the
  three. What is produced here is per host and port evidence to hang off a
  finding, a ledger and not a narrative.
* It does not price risk. The confidence numbers grade evidence strength.
  None of them is a scoring weight, none of them is wired to the priority
  score, and the decision to let any of this move an ordering belongs in a
  later change that the owner approves.
"""

from __future__ import annotations

import ipaddress
from collections import namedtuple

# ---------------------------------------------------------------------------
# Address normalisation
# ---------------------------------------------------------------------------
# Two systems write the same address in different spellings and neither is
# wrong. A firewall may log ::ffff:10.0.0.7 where swinv reports 10.0.0.7;
# ECMP kit logs 2001:DB8::1 where an operator typed 2001:db8:0:0:0:0:0:1.
# Every address that enters this module goes through normalise_address first,
# so that the comparison further down is between canonical forms and never
# between two strings that happen to have been typed the same way.

_MAPPED_V4_PREFIX = ipaddress.ip_network("::ffff:0:0/96")


def normalise_address(text):
    """Canonical text form of a single address, or None if it is not one.

    None rather than an exception because the inputs are firewall log fields
    and KV store columns, which contain hostnames, ranges, empty strings and
    the occasional "-" on a perfectly healthy day. A parse failure here is
    ordinary data, not a bug, and the caller decides what to do about it.

    An IPv4-mapped IPv6 address collapses to its IPv4 form. It is the same
    address, and keeping both spellings alive would mean an edge logged by a
    dual stack device never matching the host that owns it.
    """
    if not isinstance(text, str):
        return None
    raw = text.strip()
    if not raw:
        return None
    # A scope id is meaningful only on the machine that wrote it, so it cannot
    # be part of a key two machines are compared on. Cut it before parsing
    # rather than relying on the interpreter version to accept it.
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    # Bracketed literals arrive from anything that also has to write a port.
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if not raw:
        return None
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if addr.version == 6 and addr in _MAPPED_V4_PREFIX:
        return str(ipaddress.ip_address(addr.packed[-4:]))
    return str(addr)


def normalise_network(text):
    """Canonical CIDR form of a network, or None if it is not one.

    Strict about host bits, because 10.0.0.7/24 written where 10.0.0.0/24 was
    meant is a different question being answered, and the app should say so
    rather than quietly widen the range under the operator.
    """
    if not isinstance(text, str):
        return None
    raw = text.strip()
    if not raw or "/" not in raw:
        return None
    if "%" in raw:
        return None
    try:
        net = ipaddress.ip_network(raw, strict=True)
    except ValueError:
        return None
    return str(net)


def address_of(text):
    """The address part of either a bare address or a CIDR form of one.

    swinv writes host.ipv4 and host.ipv6 bare, and the --all-interfaces
    inventory writes every address in CIDR form. This is the one place that
    difference is absorbed, so that no caller has to remember which output it
    is holding.
    """
    if not isinstance(text, str):
        return None
    raw = text.strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    return normalise_address(raw)


def address_in_network(address, network):
    """Is this address inside this network. False, never an exception.

    A v4 address tested against a v6 network is a question with a perfectly
    good answer, and raising there would mean every caller writing the same
    try block around a membership test.
    """
    addr = normalise_address(address) if isinstance(address, str) else None
    net = normalise_network(network) if isinstance(network, str) else None
    if addr is None or net is None:
        return False
    parsed_addr = ipaddress.ip_address(addr)
    parsed_net = ipaddress.ip_network(net)
    if parsed_addr.version != parsed_net.version:
        return False
    return parsed_addr in parsed_net


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------
# An entry point described as "the internet" and one described as "the admin
# network" are different claims about the same graph, and the difference is
# visible in the address. A public address found on a host is also evidence in
# its own right, which is why this returns a named scope rather than a boolean.
#
# The ranges are spelled out here rather than taken from ipaddress.is_private,
# because that property has been redefined between interpreter versions and
# the app runs on whatever Splunk ships. A table that changes underneath a
# security control is worse than a longer table.

SCOPE_PUBLIC = "public"
SCOPE_PRIVATE = "private"
SCOPE_CGNAT = "cgnat"
SCOPE_LOOPBACK = "loopback"
SCOPE_LINK_LOCAL = "link-local"
SCOPE_UNIQUE_LOCAL = "unique-local"
SCOPE_MULTICAST = "multicast"
SCOPE_UNSPECIFIED = "unspecified"
SCOPE_RESERVED = "reserved"
SCOPE_UNKNOWN = "unknown"

# Order matters: the first network that contains the address names it, so the
# narrow ranges come before the wide ones.
_SCOPE_TABLE = (
    ("0.0.0.0/32", SCOPE_UNSPECIFIED),
    ("127.0.0.0/8", SCOPE_LOOPBACK),
    ("169.254.0.0/16", SCOPE_LINK_LOCAL),
    ("100.64.0.0/10", SCOPE_CGNAT),
    ("10.0.0.0/8", SCOPE_PRIVATE),
    ("172.16.0.0/12", SCOPE_PRIVATE),
    ("192.168.0.0/16", SCOPE_PRIVATE),
    ("192.0.0.0/24", SCOPE_RESERVED),
    ("192.0.2.0/24", SCOPE_RESERVED),
    ("198.18.0.0/15", SCOPE_RESERVED),
    ("198.51.100.0/24", SCOPE_RESERVED),
    ("203.0.113.0/24", SCOPE_RESERVED),
    ("224.0.0.0/4", SCOPE_MULTICAST),
    ("240.0.0.0/4", SCOPE_RESERVED),
    ("::/128", SCOPE_UNSPECIFIED),
    ("::1/128", SCOPE_LOOPBACK),
    ("fe80::/10", SCOPE_LINK_LOCAL),
    ("fc00::/7", SCOPE_UNIQUE_LOCAL),
    ("2001:db8::/32", SCOPE_RESERVED),
    ("ff00::/8", SCOPE_MULTICAST),
)

_SCOPE_NETWORKS = tuple(
    (ipaddress.ip_network(cidr), scope) for cidr, scope in _SCOPE_TABLE)

# Everything that is not the public internet, named once so no caller has to
# assemble the list and get it half right.
NON_PUBLIC_SCOPES = frozenset((
    SCOPE_PRIVATE, SCOPE_CGNAT, SCOPE_LOOPBACK, SCOPE_LINK_LOCAL,
    SCOPE_UNIQUE_LOCAL, SCOPE_MULTICAST, SCOPE_UNSPECIFIED, SCOPE_RESERVED,
    SCOPE_UNKNOWN,
))


def classify_address(text):
    """Name the scope an address sits in. SCOPE_UNKNOWN if it is not one.

    An unparseable value classifies as unknown rather than as public. Guessing
    public would turn a malformed log field into evidence of internet
    exposure, which is the exact over-claim this work exists to stop making.
    """
    addr = normalise_address(text)
    if addr is None:
        return SCOPE_UNKNOWN
    parsed = ipaddress.ip_address(addr)
    for net, scope in _SCOPE_NETWORKS:
        if parsed.version == net.version and parsed in net:
            return scope
    return SCOPE_PUBLIC


def is_public_address(text):
    """True only for an address that is routable on the public internet."""
    return classify_address(text) == SCOPE_PUBLIC


# ---------------------------------------------------------------------------
# Resolution with a time window
# ---------------------------------------------------------------------------

# A claim is one host saying it held one address over one interval. first_seen
# and last_seen are epoch seconds. last_seen may be None, which asserts that
# the host still held the address at the most recent scan, and that assertion
# costs confidence below because it is an extrapolation past the last thing
# anybody observed.
AddressClaim = namedtuple("AddressClaim", "hostname address first_seen last_seen")

OUTCOME_RESOLVED = "resolved"
OUTCOME_STALE = "stale"
OUTCOME_REASSIGNED = "reassigned"
OUTCOME_SHARED = "shared"
OUTCOME_OUTSIDE_ESTATE = "outside estate"
OUTCOME_MALFORMED = "malformed address"

# Every outcome, so a caller can assert it has handled the lot and a new one
# added later fails a test rather than falling through somebody's else branch.
ALL_OUTCOMES = (
    OUTCOME_RESOLVED, OUTCOME_STALE, OUTCOME_REASSIGNED, OUTCOME_SHARED,
    OUTCOME_OUTSIDE_ESTATE, OUTCOME_MALFORMED,
)

# hostname is None on every outcome except OUTCOME_RESOLVED. claimants lists
# every host that ever claimed the address, present on the refusals too,
# because "one of these four, and we cannot say which" is the sentence an
# operator needs and a bare refusal is not.
Resolution = namedtuple(
    "Resolution", "hostname outcome reason confidence claimants address observed_at")

# A resolution is never certain. The address was held by the host at a time
# either side of the observation and the handover moments in between were not
# watched, so the ceiling sits below one and the penalties come off it.
CONFIDENCE_CLEAN = 0.95
# Reached only by widening a window, extrapolating past a last scan, or
# resolving an address that is known to move between hosts.
CONFIDENCE_TOLERANCE_PENALTY = 0.7
CONFIDENCE_OPEN_WINDOW_PENALTY = 0.7
CONFIDENCE_CHURN_PENALTY = 0.6
# The ceiling once any claim for this address could not be read at all.
CONFIDENCE_DEGRADED = 0.5


def _epoch(value):
    """Epoch seconds out of whatever a KV store or a log field handed us.

    KV store columns arrive as strings, so an int check alone would reject
    every real row. None passes through as None, since None is a meaningful
    value on last_seen. Anything else unreadable returns False, which is
    distinguishable from None and is what marks a claim malformed.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return False
    return False


def _claim_field(claim, *names):
    """Read a field from a claim, whether it arrived as a mapping or an object.

    Claims reach this module from two places that disagree about shape. The
    KV Store lookup yields DICTS, which is what the searches actually pass, and
    the tests find it natural to pass small objects. An earlier version read
    only attributes, so every real dict claim was counted unreadable and every
    join refused. That failed closed, which was right, and was still useless:
    the feature would have resolved nothing for ever while looking like it was
    working, because a refusal is a legitimate answer here and nothing would
    have looked wrong.

    Several names are accepted because the collection prefixes its columns
    (addr_first_seen) while the natural attribute does not (first_seen).
    """
    for name in names:
        if isinstance(claim, dict):
            if name in claim:
                return claim[name]
        else:
            value = getattr(claim, name, None)
            if value is not None:
                return value
    return None


def resolve_address(address, observed_at, claims, tolerance=0.0):
    """Which host held this address at this time, or why we will not say.

    ``observed_at`` is positional and mandatory. See the module docstring: the
    question without a time has no true answer.

    ``tolerance`` widens every claim window by that many seconds at both ends.
    It defaults to zero, which is the honest default, because a widened window
    is the caller asserting that an address did not move between two scans and
    that assertion is not in the data. Widening buys coverage with exactly the
    guard this module exists to provide, so it is a number the caller has to
    type rather than one it inherits.
    """
    if observed_at is None:
        raise ValueError("resolve_address needs the time the flow was observed")
    when = _epoch(observed_at)
    if when is False or when is None:
        raise ValueError("observed_at must be epoch seconds")
    try:
        slack = float(tolerance)
    except (TypeError, ValueError):
        raise ValueError("tolerance must be a number of seconds")
    if slack < 0:
        raise ValueError("tolerance must not be negative")

    wanted = normalise_address(address)
    if wanted is None:
        return Resolution(None, OUTCOME_MALFORMED,
                          "not an address, so no host can be held to it",
                          0.0, (), None, when)

    claimants = set()
    holders = set()
    unreadable = 0
    widened = False
    open_window = False

    for claim in claims or ():
        claimed = normalise_address(_claim_field(claim, "address"))
        if claimed is None or claimed != wanted:
            continue
        host = (_claim_field(claim, "hostname") or "").strip()
        if not host:
            # A claim with no host cannot resolve anything and must not be
            # discarded either: it is evidence that somebody held the address.
            unreadable += 1
            continue
        claimants.add(host)

        start = _epoch(_claim_field(claim, "first_seen", "addr_first_seen"))
        end = _epoch(_claim_field(claim, "last_seen", "addr_last_seen"))
        if start is False or end is False or start is None:
            # An unreadable bound counts the host as a claimant and never as a
            # holder. That direction is deliberate: it can only ever push the
            # answer towards a refusal, and a refusal is the safe wrong answer.
            unreadable += 1
            continue
        if end is not None and end < start:
            unreadable += 1
            continue

        low = start - slack
        high = (end + slack) if end is not None else None
        if when < low:
            continue
        if high is not None and when > high:
            continue
        holders.add(host)
        if when < start or (end is not None and when > end):
            widened = True
        if end is None:
            open_window = True

    ordered = tuple(sorted(claimants))

    # A PUBLIC address claimed by more than one inventory host is a NAT egress
    # identity, not a host identity, and that is true whether or not the
    # observation windows happen to overlap. This is not hypothetical: the
    # first real rollup on a live fleet produced two hosts claiming one public
    # address, one of them from a single scan, so their windows did not
    # overlap and the window test alone called it a clean resolve.
    #
    # Non-overlapping OBSERVATION does not establish non-overlapping
    # POSSESSION. A single scan is one instant, not a window, and hosts behind
    # one NAT are all holding that address the whole time while each is seen
    # at a different moment. Resolving it would attribute an inbound internet
    # flow to whichever host a timestamp happened to land nearest, which is
    # the false attack path this module exists to refuse. A public address
    # that legitimately moves between hosts exists (a reassigned elastic IP),
    # and it is still not attributable from bind observations, so refusing
    # costs a true edge we could not have trusted anyway.
    if len(claimants) > 1 and is_public_address(wanted):
        return Resolution(
            None, OUTCOME_SHARED,
            "%d hosts claim this public address, so it identifies a NAT "
            "egress or a shared front end rather than one host, and a flow "
            "to it cannot be attributed to any of them" % len(claimants),
            0.0, ordered, wanted, when)

    if len(holders) > 1:
        return Resolution(
            None, OUTCOME_SHARED,
            "%d hosts held this address at the same time, so it is shared, "
            "a virtual address or a NAT mapping rather than one host"
            % len(holders),
            0.0, ordered, wanted, when)

    if len(holders) == 1:
        host = sorted(holders)[0]
        confidence = CONFIDENCE_CLEAN
        reasons = ["one host held this address across the observation"]
        if widened:
            confidence *= CONFIDENCE_TOLERANCE_PENALTY
            reasons.append("the observation falls outside the observed window "
                           "and inside the tolerance the caller allowed")
        if open_window:
            confidence *= CONFIDENCE_OPEN_WINDOW_PENALTY
            reasons.append("the claim is open at the end, so holding it at the "
                           "observation is an extrapolation past the last scan")
        if len(ordered) > 1:
            confidence *= CONFIDENCE_CHURN_PENALTY
            reasons.append("this address has been held by %d hosts over time, "
                           "so it moves and the windows are all the app has "
                           "to tell them apart" % len(ordered))
        if unreadable:
            confidence = min(confidence, CONFIDENCE_DEGRADED)
            reasons.append("%d claim(s) on this address could not be read, so "
                           "another host may have held it unseen" % unreadable)
        return Resolution(host, OUTCOME_RESOLVED, ". ".join(reasons),
                          round(confidence, 3), ordered, wanted, when)

    # Nobody held it at that moment. What that means depends entirely on how
    # many hosts have ever held it, which is the difference between an address
    # outside the estate, a host that has since given it up, and a pool.
    if not ordered and not unreadable:
        return Resolution(
            None, OUTCOME_OUTSIDE_ESTATE,
            "no host in the inventory ever claimed this address, which is the "
            "expected answer for an internet entry point and not a failure",
            0.0, (), wanted, when)

    if len(ordered) > 1:
        return Resolution(
            None, OUTCOME_REASSIGNED,
            "%d hosts have held this address at different times and none of "
            "them held it at the observation, so the flow cannot be attributed"
            % len(ordered),
            0.0, ordered, wanted, when)

    return Resolution(
        None, OUTCOME_STALE,
        "the only host that ever claimed this address did not hold it at the "
        "observation, so the inventory is too old or too young to say",
        0.0, ordered, wanted, when)


def is_resolved(result):
    """True only for a resolution that names a host. One place, one spelling.

    Written because ``if result.hostname:`` and ``if result.outcome ==
    "resolved":`` are the two ways a caller gets this subtly wrong later, and
    a helper is cheaper than finding out which one was used.
    """
    return bool(result) and result.outcome == OUTCOME_RESOLVED and bool(result.hostname)


# ---------------------------------------------------------------------------
# The evidence grade
# ---------------------------------------------------------------------------

GRADE_CONFIRMED = "confirmed observed"
GRADE_HISTORIC = "historically observed"
GRADE_UNKNOWN = "unknown"
GRADE_NOT_OBSERVED = "not observed"

ALL_GRADES = (GRADE_CONFIRMED, GRADE_HISTORIC, GRADE_UNKNOWN, GRADE_NOT_OBSERVED)

COVERAGE_NONE = "none"
COVERAGE_PARTIAL = "partial"
COVERAGE_FULL = "full"

ALL_COVERAGE = (COVERAGE_NONE, COVERAGE_PARTIAL, COVERAGE_FULL)

Grade = namedtuple("Grade", "grade confidence reason hops")

# An edge seen inside this window is present tense. Beyond it the rule may
# still exist and nothing has exercised it lately, which is a different
# sentence and gets a different word.
FRESH_SECONDS = 7 * 86400
# Firewall logging is continuous by nature, so silence from the whole feed for
# this long means the feed broke, not that the network went quiet. Absence of
# edges proves nothing across a gap like that.
FEED_STALE_SECONDS = 86400

CONFIRMED_BASE = 0.9
HISTORIC_BASE = 0.55
# Confidence in a route decays per hop away from the entry point. At the
# boundary, constant internet scan pressure means a permitted edge shows
# sessions quickly, so its presence and its absence both mean something. Each
# hop inward, "nobody has tried this yet" becomes the ordinary case and the
# same observation carries less.
HOP_DECAY = 0.75
# The same asymmetry, on the negative. Absence at an internet boundary is
# worth stating. Absence east to west is close to worthless and must never be
# reported as though the path were shut.
NOT_OBSERVED_PUBLIC = 0.7
NOT_OBSERVED_INTERNAL = 0.3
# A positive is never worth nothing, however many hops away it was seen.
CONFIDENCE_FLOOR = 0.05

# Sessions separate one flow that happened once from a path in daily use. The
# steps are coarse on purpose: the count is a property of the log retention
# window as much as of the network, so reading more into it than three bands
# would be reading noise.
SESSIONS_ESTABLISHED = 100
SESSIONS_REPEATED = 10
SESSIONS_FACTOR_ESTABLISHED = 1.0
SESSIONS_FACTOR_REPEATED = 0.95
SESSIONS_FACTOR_SINGLE = 0.85


def _sessions_factor(sessions):
    try:
        count = float(sessions or 0)
    except (TypeError, ValueError):
        count = 0.0
    if count >= SESSIONS_ESTABLISHED:
        return SESSIONS_FACTOR_ESTABLISHED
    if count >= SESSIONS_REPEATED:
        return SESSIONS_FACTOR_REPEATED
    return SESSIONS_FACTOR_SINGLE


# How much traffic an entry point attracts, which decides whether silence
# means anything at all. Constant pressure is the internet, where scanning is
# ceaseless and an open path shows sessions quickly. Occasional is an admin
# network or a jump host, where nobody having tried is the ordinary state and
# an absence of edges is not evidence of a closed path.
PRESSURE_CONSTANT = "constant"
PRESSURE_OCCASIONAL = "occasional"
ALL_PRESSURE = (PRESSURE_CONSTANT, PRESSURE_OCCASIONAL)


def grade_evidence(now, coverage, entry_pressure, hops=None, sessions=0,
                   route_last_seen=None, feed_last_seen=None,
                   fresh_seconds=FRESH_SECONDS,
                   feed_stale_seconds=FEED_STALE_SECONDS):
    """Grade what the firewall data says about one host and port.

    ``now`` is mandatory for the same reason ``observed_at`` is: freshness is
    the whole difference between the first two grades, and a function that
    reads its own clock cannot be tested or replayed.

    A route is present when ``hops`` and ``route_last_seen`` are both given.
    Everything else is the absence of a route, and the absence only means
    anything when the data is there, fresh and complete. Otherwise it is
    UNKNOWN, which is not a polite way of saying not exposed.
    """
    when = _epoch(now)
    if when is False or when is None:
        raise ValueError("grade_evidence needs the time to grade against")
    if coverage not in ALL_COVERAGE:
        # Loudly, because an unrecognised coverage token defaulting to full
        # would turn a config typo into a fleet reported as unexposed.
        raise ValueError("coverage must be one of %s" % (ALL_COVERAGE,))

    # Three states, kept apart, and the reason is the whole point of this
    # module. _epoch returns None for a value that was absent and False for one
    # that was present and unreadable. Collapsing them made an unreadable KV
    # column indistinguishable from no edge at all, so the grader positively
    # asserted "no permitted flow to this host and port has been logged" about
    # a row it had failed to parse. That is manufacturing reassurance from a
    # parse error, which is the one thing this feature must never do. The same
    # file already applies the opposite rule to claims, where an unreadable
    # bound can only ever push the answer towards a refusal.
    seen = _epoch(route_last_seen)
    if seen is False:
        return Grade(GRADE_UNKNOWN, 0.0,
                     "the last seen time on this route could not be read, so "
                     "whether a permitted flow was observed cannot be said",
                     None)
    feed = _epoch(feed_last_seen)
    if feed is False:
        return Grade(GRADE_UNKNOWN, 0.0,
                     "the age of the firewall feed could not be read, so "
                     "whether an absence of edges means anything cannot be said",
                     None)
    if seen is None and hops is not None:
        # The mirror of the check below, which raises when a time arrives
        # without a hop count. A hop count without a time is a half read row,
        # not an absence, and it grades unknown rather than falling through to
        # the branch that speaks about absence.
        return Grade(GRADE_UNKNOWN, 0.0,
                     "a hop count arrived with no last seen time, so this row "
                     "cannot be graded", None)

    if seen is not None:
        if hops is None:
            raise ValueError("a route with a last seen time needs a hop count")
        try:
            hop_count = int(hops)
        except (TypeError, ValueError):
            raise ValueError("hops must be a whole number of hops")
        if hop_count < 1:
            raise ValueError("a route from the entry point is at least one hop")

        # Coverage gaps are asymmetric and this is the line that says so. An
        # incomplete feed cannot invent an edge, so it does not weaken an edge
        # that was seen. It destroys the ability to say an edge was not seen,
        # which is handled in the branch below.
        age = when - seen
        if age <= fresh_seconds:
            grade = GRADE_CONFIRMED
            confidence = CONFIRMED_BASE
            reason = ("a permitted flow to this host and port was logged "
                      "within the freshness window, %d hop(s) from the "
                      "declared entry point" % hop_count)
        else:
            grade = GRADE_HISTORIC
            confidence = HISTORIC_BASE
            reason = ("a permitted flow to this host and port was logged, but "
                      "not since the freshness window, so the rule may have "
                      "gone and nothing here can tell")
        confidence *= HOP_DECAY ** max(0, hop_count - 1)
        confidence *= _sessions_factor(sessions)
        if hop_count > 1:
            reason += (". Confidence decays per hop because untried is the "
                       "ordinary state of an east to west path")
        return Grade(grade, max(CONFIDENCE_FLOOR, round(confidence, 3)),
                     reason, hop_count)

    if coverage == COVERAGE_NONE:
        return Grade(GRADE_UNKNOWN, 0.0,
                     "no firewall data covers this host, so nothing is known "
                     "about permitted traffic to it. This is not evidence that "
                     "nothing can reach it", None)

    if coverage == COVERAGE_PARTIAL:
        return Grade(GRADE_UNKNOWN, 0.0,
                     "firewall coverage of this segment is incomplete, so a "
                     "permitted path could exist through an enforcement point "
                     "that does not log here", None)

    if feed is None:
        return Grade(GRADE_UNKNOWN, 0.0,
                     "the segment is covered but the feed has produced no "
                     "events at all, so its silence cannot be read as quiet",
                     None)

    if (when - feed) > feed_stale_seconds:
        return Grade(GRADE_UNKNOWN, 0.0,
                     "the firewall feed has produced nothing recent, so the "
                     "absence of an edge is a broken feed until proven "
                     "otherwise", None)

    # Only a constant pressure entry point can produce a negative claim, and
    # this is where that contract is enforced rather than merely documented.
    # macros.conf and docs/ROUTE-EVIDENCE.md both state the rule; an earlier
    # version of this function defaulted the flag to the unsafe value, so a
    # caller who simply omitted the argument was handed "not observed" about an
    # internal entry point where untried is the ordinary state.
    #
    # The argument is required and its vocabulary is closed, for the same
    # reason coverage is: an unrecognised token that fell through to the
    # permissive branch would turn a configuration typo into a fleet reported
    # as unexposed.
    if entry_pressure not in ALL_PRESSURE:
        raise ValueError("entry_pressure must be one of %s" % (ALL_PRESSURE,))
    if entry_pressure != PRESSURE_CONSTANT:
        return Grade(GRADE_UNKNOWN, 0.0,
                     "the segment is covered and the feed is current, but this "
                     "entry point is not one traffic constantly arrives from, "
                     "so nothing having been logged says nothing: untried is "
                     "the ordinary state there", None)

    return Grade(GRADE_NOT_OBSERVED, NOT_OBSERVED_PUBLIC,
                 "the segment is covered, the feed is current, and no permitted "
                 "flow to this host and port has been logged from the declared "
                 "entry point. Traffic arrives there constantly, so an open "
                 "path usually shows sessions quickly and the silence carries "
                 "some weight. It is still not proof the path is shut", None)
