#!/usr/bin/env python3
"""Tests for address to host resolution and the evidence grade.

  python3 tools/test_route.py

Three things are defended here.

1. That missing firewall data grades UNKNOWN and never "not observed". It is
   the first test in the file and the first one run, because it is the only
   defect in this module that would be invisible in a demo and wrong in every
   estate that has not onboarded firewall logs, which is most of them. A host
   reported as unexposed because the customer sent no data is the product
   telling a comfortable lie.

2. That the join refuses. Every refusal case gets its own test with a worked
   example, because the failure mode this module exists to stop is not a
   crash, it is a confident sentence about the wrong host, produced by code
   that had every input it needed to know better. A DHCP address is the case
   that proves it: two laptops, one address, a firewall edge overnight in the
   gap between the leases, and no honest answer available.

3. That evidence gets weaker the further it is from the entry point, and that
   the absence of evidence is weakest of all in exactly the place people are
   most tempted to read it as safety.
"""

from __future__ import annotations

import calendar
import inspect
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app" / "riskability" / "bin"))

from riskability import route  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print("  ok   %s" % name)
    else:
        print("  FAIL %s%s" % (name, (" :: %s" % (detail,)) if detail else ""))
        FAILURES.append(name)


def raises(kind, fn, *args, **kwargs):
    """Did this call refuse in exactly this way.

    The exception type is part of the assertion. A guard that moved from the
    signature into the body still refuses, and is still a different contract
    from the one the test was written to protect.
    """
    try:
        fn(*args, **kwargs)
    except kind:
        return True
    except Exception as exc:  # noqa: BLE001
        print("       (refused with %s, not %s)" % (type(exc).__name__, kind.__name__))
        return False
    return False


def at(text):
    """Epoch seconds for a UTC "YYYY-MM-DD HH:MM", so a lease reads as a lease."""
    return float(calendar.timegm(time.strptime(text, "%Y-%m-%d %H:%M")))


def claim(hostname, address, first_seen, last_seen):
    return route.AddressClaim(hostname, address, first_seen, last_seen)


# ---------------------------------------------------------------------------
# 1. The one that matters most
# ---------------------------------------------------------------------------

def test_absent_firewall_data_grades_unknown_and_never_not_observed():
    print("missing firewall data is unknown, not an all clear:")
    now = at("2026-08-25 12:00")

    no_data = route.grade_evidence(now, route.COVERAGE_NONE, route.PRESSURE_CONSTANT)
    check("no firewall data grades unknown",
          no_data.grade == route.GRADE_UNKNOWN, no_data.grade)
    check("no firewall data does NOT grade not observed",
          no_data.grade != route.GRADE_NOT_OBSERVED, no_data.grade)
    check("the reason says out loud that this is not evidence of safety",
          "not evidence" in no_data.reason, no_data.reason)

    partial = route.grade_evidence(now, route.COVERAGE_PARTIAL, route.PRESSURE_CONSTANT,
                                   feed_last_seen=at("2026-08-25 11:55"))
    check("incomplete coverage grades unknown, not not observed",
          partial.grade == route.GRADE_UNKNOWN, partial.grade)

    stale_feed = route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT,
                                      feed_last_seen=at("2026-08-01 09:00"))
    check("a covered segment whose feed died grades unknown",
          stale_feed.grade == route.GRADE_UNKNOWN, stale_feed.grade)

    silent_feed = route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT,
                                       feed_last_seen=None)
    check("a covered segment that has never produced an event grades unknown",
          silent_feed.grade == route.GRADE_UNKNOWN, silent_feed.grade)

    # The invariant, swept rather than argued. Nothing a caller can pass with
    # no firewall data may ever come back as "not observed".
    bad = []
    for hops in (None, 1, 4):
        for sessions in (0, 1, 5000):
            for seen in (None, at("2026-08-25 11:00"), at("2025-01-01 00:00")):
                for pressure in route.ALL_PRESSURE:
                    if seen is not None and hops is None:
                        continue
                    got = route.grade_evidence(
                        now, route.COVERAGE_NONE, pressure, hops=hops,
                        sessions=sessions, route_last_seen=seen,
                        feed_last_seen=at("2026-08-25 11:59"))
                    if got.grade == route.GRADE_NOT_OBSERVED:
                        bad.append((hops, sessions, seen, pressure))
    check("no input at all turns absent coverage into not observed", not bad, bad)

    # And the same statement from the other end: not observed is reachable
    # only when the data is present, complete and current.
    only = route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT,
                                feed_last_seen=at("2026-08-25 11:00"))
    check("not observed needs full coverage and a live feed",
          only.grade == route.GRADE_NOT_OBSERVED, only.grade)
    check("and even then it is not certainty", only.confidence < 1.0, only.confidence)

    # An unreadable value is not an absent one, and the difference is the whole
    # feature. Both of these graded "not observed" at 0.7 confidence once, which
    # is the module asserting that no flow was logged about a row it had failed
    # to parse. Reassurance manufactured from a parse error.
    unreadable = route.grade_evidence(now, route.COVERAGE_FULL,
                                      route.PRESSURE_CONSTANT, hops=1,
                                      sessions=5000, route_last_seen="-",
                                      feed_last_seen=at("2026-08-25 11:59"))
    check("an unreadable route time grades unknown, never not observed",
          unreadable.grade == route.GRADE_UNKNOWN, unreadable.grade)
    halfrow = route.grade_evidence(now, route.COVERAGE_FULL,
                                   route.PRESSURE_CONSTANT, hops=1,
                                   feed_last_seen=at("2026-08-25 11:59"))
    check("a hop count with no time grades unknown, never not observed",
          halfrow.grade == route.GRADE_UNKNOWN, halfrow.grade)
    unreadable_feed = route.grade_evidence(now, route.COVERAGE_FULL,
                                           route.PRESSURE_CONSTANT,
                                           feed_last_seen="not a time")
    check("an unreadable feed age grades unknown, never not observed",
          unreadable_feed.grade == route.GRADE_UNKNOWN, unreadable_feed.grade)

    # Only an entry point traffic constantly arrives from can support a
    # negative claim. Internally, untried is the ordinary state.
    internal = route.grade_evidence(now, route.COVERAGE_FULL,
                                    route.PRESSURE_OCCASIONAL,
                                    feed_last_seen=at("2026-08-25 11:00"))
    check("an occasional entry point cannot produce not observed",
          internal.grade == route.GRADE_UNKNOWN, internal.grade)
    try:
        route.grade_evidence(now, route.COVERAGE_FULL, "wobble",
                             feed_last_seen=at("2026-08-25 11:00"))
        typo_refused = False
    except ValueError:
        typo_refused = True
    check("an unrecognised entry pressure is refused, not defaulted",
          typo_refused)


# ---------------------------------------------------------------------------
# 2. Address normalisation
# ---------------------------------------------------------------------------

def test_normalisation():
    print("address normalisation:")
    check("a plain IPv4 address survives",
          route.normalise_address("10.0.0.7") == "10.0.0.7")
    check("surrounding whitespace is not an address change",
          route.normalise_address("  10.0.0.7 ") == "10.0.0.7")
    check("a compressed IPv6 form and its long form agree",
          route.normalise_address("2001:db8::7")
          == route.normalise_address("2001:0db8:0000:0000:0000:0000:0000:0007"),
          route.normalise_address("2001:0db8:0000:0000:0000:0000:0000:0007"))
    check("IPv6 case is not an address change",
          route.normalise_address("2001:DB8::7") == "2001:db8::7",
          route.normalise_address("2001:DB8::7"))
    check("an IPv4-mapped IPv6 address collapses to its IPv4 form",
          route.normalise_address("::ffff:192.168.5.10") == "192.168.5.10",
          route.normalise_address("::ffff:192.168.5.10"))
    check("the mapped form and the bare form are the same address",
          route.normalise_address("::ffff:10.0.0.7")
          == route.normalise_address("10.0.0.7"))
    check("a zone id is dropped, since it means nothing off its own host",
          route.normalise_address("fe80::1%eth0") == "fe80::1",
          route.normalise_address("fe80::1%eth0"))
    check("a bracketed literal is still an address",
          route.normalise_address("[2001:db8::7]") == "2001:db8::7")

    for junk in ("", "   ", "web-01", "10.0.0.256", "10.0.0", "not an address",
                 "-", "10.0.0.1:443", None, 3232235777, "10.0.0.0/24"):
        check("rejected: %r" % (junk,), route.normalise_address(junk) is None,
              route.normalise_address(junk))

    check("a CIDR value from the interface inventory yields its address",
          route.address_of("10.0.0.7/24") == "10.0.0.7")
    check("a bare value from host.ipv4 yields the same",
          route.address_of("10.0.0.7") == "10.0.0.7")
    check("an IPv6 CIDR from the inventory yields its address",
          route.address_of("2001:db8::7/64") == "2001:db8::7")


def test_cidr_membership():
    print("CIDR membership:")
    check("a network containing the address",
          route.address_in_network("10.2.3.4", "10.2.0.0/16"))
    check("a network not containing the address",
          not route.address_in_network("10.3.3.4", "10.2.0.0/16"))
    check("the boundary address is inside",
          route.address_in_network("10.2.0.0", "10.2.0.0/16"))
    check("the address one past the end is outside",
          not route.address_in_network("10.3.0.0", "10.2.0.0/16"))
    check("an IPv6 network containing the address",
          route.address_in_network("2001:db8::7", "2001:db8::/32"))
    check("an IPv6 network not containing the address",
          not route.address_in_network("2001:db9::7", "2001:db8::/32"))
    check("a mapped IPv4 is tested as the IPv4 it is",
          route.address_in_network("::ffff:10.2.3.4", "10.2.0.0/16"))
    check("mismatched families answer false rather than raising",
          not route.address_in_network("10.2.3.4", "2001:db8::/32"))
    check("a network with host bits set is refused rather than widened",
          route.normalise_network("10.0.0.7/24") is None)
    check("and membership against it is false, not accidentally true",
          not route.address_in_network("10.0.0.99", "10.0.0.7/24"))
    check("junk is not a network", route.normalise_network("web-01") is None)
    check("a bare address is not a network",
          route.normalise_network("10.0.0.7") is None)


def test_classification():
    print("address classification:")
    cases = (
        ("10.0.0.7", route.SCOPE_PRIVATE),
        ("172.16.4.4", route.SCOPE_PRIVATE),
        ("172.32.4.4", route.SCOPE_PUBLIC),
        ("192.168.86.223", route.SCOPE_PRIVATE),
        ("100.64.0.1", route.SCOPE_CGNAT),
        ("127.0.0.53", route.SCOPE_LOOPBACK),
        ("169.254.10.10", route.SCOPE_LINK_LOCAL),
        ("0.0.0.0", route.SCOPE_UNSPECIFIED),
        ("224.0.0.251", route.SCOPE_MULTICAST),
        ("62.238.42.61", route.SCOPE_PUBLIC),
        ("8.8.8.8", route.SCOPE_PUBLIC),
        ("::1", route.SCOPE_LOOPBACK),
        ("fe80::1", route.SCOPE_LINK_LOCAL),
        ("fd00:1234::5", route.SCOPE_UNIQUE_LOCAL),
        ("2606:4700:4700::1111", route.SCOPE_PUBLIC),
        ("ff02::1", route.SCOPE_MULTICAST),
        ("::ffff:10.0.0.7", route.SCOPE_PRIVATE),
        ("web-01", route.SCOPE_UNKNOWN),
        ("", route.SCOPE_UNKNOWN),
    )
    for text, want in cases:
        got = route.classify_address(text)
        check("%r classifies as %s" % (text, want), got == want, got)

    check("only a public address is public", route.is_public_address("62.238.42.61"))
    check("CGNAT is not public", not route.is_public_address("100.64.0.1"))
    # An unreadable value must not become evidence of internet exposure, which
    # is the over-claim this whole change set exists to stop making.
    check("an unparseable value is not public", not route.is_public_address("-"))
    check("every non public scope is listed in one place",
          route.SCOPE_PUBLIC not in route.NON_PUBLIC_SCOPES)


# ---------------------------------------------------------------------------
# 3. Resolution, and above all its refusals
# ---------------------------------------------------------------------------

def test_time_is_mandatory():
    print("a caller cannot resolve an address without saying when:")
    claims = [claim("web-01", "10.0.0.7", at("2026-08-01 00:00"), None)]
    # TypeError specifically, not any refusal: the guard has to be the
    # signature itself, so that a later author who gives observed_at a default
    # breaks a test rather than quietly making the time optional again.
    check("resolving without a time is refused by the signature",
          raises(TypeError, route.resolve_address, "10.0.0.7"))
    check("an explicit null time is refused too",
          raises(ValueError, route.resolve_address, "10.0.0.7", None, claims))
    check("an unreadable time is refused too",
          raises(ValueError, route.resolve_address, "10.0.0.7", "yesterday", claims))
    check("grading without a time is refused by the signature",
          raises(TypeError, route.grade_evidence, coverage=route.COVERAGE_FULL))


def test_resolution_inside_the_window():
    print("one host, one window, an observation inside it:")
    claims = [claim("web-01", "10.0.0.7", at("2026-08-01 00:00"), at("2026-08-25 06:00"))]
    got = route.resolve_address("10.0.0.7", at("2026-08-10 13:37"), claims)
    check("it resolves", route.is_resolved(got), got)
    check("to the host that held it", got.hostname == "web-01", got.hostname)
    check("with a confidence the caller can act on",
          0.9 <= got.confidence <= 0.95, got.confidence)
    check("and never with certainty", got.confidence < 1.0, got.confidence)
    check("the address comes back canonical", got.address == "10.0.0.7")
    check("the claimant list holds the one host", got.claimants == ("web-01",))

    # The same host scanned many times is one host, not a shared address.
    rescans = [
        claim("web-01", "10.0.0.7", at("2026-08-01 00:00"), at("2026-08-10 00:00")),
        claim("web-01", "10.0.0.7", at("2026-08-10 00:00"), at("2026-08-20 00:00")),
    ]
    again = route.resolve_address("10.0.0.7", at("2026-08-05 00:00"), rescans)
    check("two scan rows from one host are not a shared address",
          route.is_resolved(again) and again.hostname == "web-01", again)


def test_observation_outside_the_window():
    print("one host, one window, an observation outside it:")
    claims = [claim("web-01", "10.0.0.7", at("2026-08-10 00:00"), at("2026-08-20 00:00"))]

    before = route.resolve_address("10.0.0.7", at("2026-08-09 23:00"), claims)
    check("an observation before first_seen does not resolve",
          before.outcome == route.OUTCOME_STALE, before.outcome)
    check("and names no host", before.hostname is None, before.hostname)
    check("and carries no confidence", before.confidence == 0.0, before.confidence)

    after = route.resolve_address("10.0.0.7", at("2026-08-21 00:00"), claims)
    check("an observation after last_seen does not resolve",
          after.outcome == route.OUTCOME_STALE, after.outcome)
    check("and names no host", after.hostname is None, after.hostname)
    check("but it still says which host to go and look at",
          after.claimants == ("web-01",), after.claimants)
    check("is_resolved is false for a refusal", not route.is_resolved(after))

    # The tolerance exists, it is off by default, and using it is visible in
    # the confidence rather than free.
    widened = route.resolve_address("10.0.0.7", at("2026-08-21 00:00"), claims,
                                    tolerance=2 * 86400)
    check("a caller who widens the window can resolve",
          route.is_resolved(widened), widened)
    check("and pays for it in confidence",
          widened.confidence < 0.7, widened.confidence)
    check("and the reason says the window was widened",
          "tolerance" in widened.reason, widened.reason)


def test_reassigned_dhcp_address():
    print("the DHCP case, worked:")
    # 10.20.30.40 is in a DHCP pool on the office subnet. Two laptops held it
    # on consecutive days, and neither held it overnight in between.
    claims = [
        claim("laptop-anna", "10.20.30.40", at("2026-08-20 09:00"), at("2026-08-20 17:00")),
        claim("laptop-bob", "10.20.30.40", at("2026-08-21 08:00"), at("2026-08-21 18:00")),
    ]

    # The firewall logged a permitted flow to that address at half past ten at
    # night. Nobody in the inventory held it then. This is the join that would
    # otherwise attribute a finding to whichever laptop the lookup returned
    # first.
    overnight = route.resolve_address("10.20.30.40", at("2026-08-20 22:30"), claims)
    check("an edge in the gap between two leases refuses",
          overnight.outcome == route.OUTCOME_REASSIGNED, overnight.outcome)
    check("and names no host at all", overnight.hostname is None, overnight.hostname)
    check("and lists both candidates for a human to judge",
          overnight.claimants == ("laptop-anna", "laptop-bob"), overnight.claimants)
    check("and the reason says the address moved",
          "different times" in overnight.reason, overnight.reason)

    # Inside a lease the time window does its job and the answer is available,
    # at a confidence that remembers the address moves.
    daytime = route.resolve_address("10.20.30.40", at("2026-08-20 12:00"), claims)
    check("an edge inside the first lease resolves to that laptop",
          route.is_resolved(daytime) and daytime.hostname == "laptop-anna", daytime)
    check("a churning address resolves at reduced confidence",
          daytime.confidence < 0.7, daytime.confidence)
    check("and says why it was reduced", "held by 2 hosts" in daytime.reason,
          daytime.reason)

    next_day = route.resolve_address("10.20.30.40", at("2026-08-21 09:00"), claims)
    check("an edge inside the second lease resolves to the other laptop",
          route.is_resolved(next_day) and next_day.hostname == "laptop-bob", next_day)

    # Before either lease existed. One address, two known holders, and the
    # observation predates both.
    earlier = route.resolve_address("10.20.30.40", at("2026-08-19 12:00"), claims)
    check("an edge before both leases refuses as reassigned",
          earlier.outcome == route.OUTCOME_REASSIGNED, earlier.outcome)


def test_concurrent_holders():
    print("the shared address case:")
    # A virtual address on a load balancer pair, or a NAT egress address, or a
    # cluster VIP. Every one of those is two hosts holding one address at once,
    # and every one of them is a finding attributed to the wrong machine.
    claims = [
        claim("lb-a", "10.9.9.9", at("2026-01-01 00:00"), None),
        claim("lb-b", "10.9.9.9", at("2026-01-01 00:00"), None),
    ]
    got = route.resolve_address("10.9.9.9", at("2026-08-20 12:00"), claims)
    check("two concurrent holders refuse",
          got.outcome == route.OUTCOME_SHARED, got.outcome)
    check("and name no host", got.hostname is None, got.hostname)
    check("and carry no confidence", got.confidence == 0.0, got.confidence)
    check("and list both holders", got.claimants == ("lb-a", "lb-b"), got.claimants)
    check("and the reason offers the operator the explanations",
          "NAT" in got.reason and "virtual" in got.reason, got.reason)

    # Overlap by one second is still overlap.
    brief = [
        claim("node-1", "10.9.9.10", at("2026-08-01 00:00"), at("2026-08-20 12:00")),
        claim("node-2", "10.9.9.10", at("2026-08-20 12:00"), at("2026-09-01 00:00")),
    ]
    edge = route.resolve_address("10.9.9.10", at("2026-08-20 12:00"), brief)
    check("a handover instant claimed by both hosts refuses",
          edge.outcome == route.OUTCOME_SHARED, edge.outcome)


def test_outside_the_estate():
    print("an address nothing in the estate ever claimed:")
    claims = [claim("web-01", "10.0.0.7", at("2026-08-01 00:00"), None)]
    got = route.resolve_address("203.0.113.9", at("2026-08-20 12:00"), claims)
    check("it is its own outcome, not a failure",
          got.outcome == route.OUTCOME_OUTSIDE_ESTATE, got.outcome)
    check("it names no host", got.hostname is None, got.hostname)
    check("it lists no claimants", got.claimants == (), got.claimants)
    check("and it is not confused with a stale claim",
          got.outcome != route.OUTCOME_STALE)
    check("an empty claim set behaves the same",
          route.resolve_address("203.0.113.9", at("2026-08-20 12:00"), []).outcome
          == route.OUTCOME_OUTSIDE_ESTATE)
    check("so does a null claim set",
          route.resolve_address("203.0.113.9", at("2026-08-20 12:00"), None).outcome
          == route.OUTCOME_OUTSIDE_ESTATE)


def test_ipv6_resolution():
    print("IPv6 and mapped IPv4 resolve across spellings:")
    claims = [
        claim("db-01", "2001:0db8:0000:0000:0000:0000:0000:0007",
              at("2026-08-01 00:00"), at("2026-08-25 00:00")),
        claim("app-01", "192.168.5.10", at("2026-08-01 00:00"), at("2026-08-25 00:00")),
    ]
    compressed = route.resolve_address("2001:db8::7", at("2026-08-10 00:00"), claims)
    check("a compressed query matches an expanded claim",
          route.is_resolved(compressed) and compressed.hostname == "db-01", compressed)

    mapped = route.resolve_address("::ffff:192.168.5.10", at("2026-08-10 00:00"), claims)
    check("a firewall logging the mapped form matches the bare inventory form",
          route.is_resolved(mapped) and mapped.hostname == "app-01", mapped)

    zoned = route.resolve_address("2001:db8::7%eth0", at("2026-08-10 00:00"), claims)
    check("a zone id on the query does not break the match",
          route.is_resolved(zoned) and zoned.hostname == "db-01", zoned)


def test_open_and_malformed_claims():
    print("open windows and claims that cannot be read:")
    still_held = [claim("web-01", "10.0.0.7", at("2026-08-01 00:00"), None)]
    got = route.resolve_address("10.0.0.7", at("2026-08-20 00:00"), still_held)
    check("an open ended claim resolves",
          route.is_resolved(got) and got.hostname == "web-01", got)
    check("but at less than a closed window is worth",
          got.confidence < 0.95 * 0.75, got.confidence)
    check("and says it is extrapolating", "extrapolation" in got.reason, got.reason)

    unreadable = [
        claim("web-01", "10.0.0.7", at("2026-08-01 00:00"), at("2026-08-25 00:00")),
        claim("web-02", "10.0.0.7", "n/a", "n/a"),
    ]
    degraded = route.resolve_address("10.0.0.7", at("2026-08-10 00:00"), unreadable)
    check("an unreadable claim does not stop the resolution",
          route.is_resolved(degraded) and degraded.hostname == "web-01", degraded)
    check("but it caps the confidence",
          degraded.confidence <= route.CONFIDENCE_DEGRADED, degraded.confidence)
    check("and says another host may have held it unseen",
          "could not be read" in degraded.reason, degraded.reason)

    inverted = [claim("web-01", "10.0.0.7", at("2026-08-25 00:00"), at("2026-08-01 00:00"))]
    backwards = route.resolve_address("10.0.0.7", at("2026-08-10 00:00"), inverted)
    check("a window that ends before it starts never resolves",
          not route.is_resolved(backwards), backwards)

    nameless = [claim("", "10.0.0.7", at("2026-08-01 00:00"), None)]
    anonymous = route.resolve_address("10.0.0.7", at("2026-08-10 00:00"), nameless)
    check("a claim with no host resolves nothing",
          not route.is_resolved(anonymous), anonymous)

    junk = route.resolve_address("web-01", at("2026-08-10 00:00"), still_held)
    check("a query that is not an address is refused by name",
          junk.outcome == route.OUTCOME_MALFORMED, junk.outcome)

    # Claims for other addresses are not evidence about this one.
    elsewhere = [claim("web-09", "10.0.0.99", at("2026-08-01 00:00"), None)]
    unrelated = route.resolve_address("10.0.0.7", at("2026-08-10 00:00"), elsewhere)
    check("claims on other addresses do not leak in",
          unrelated.outcome == route.OUTCOME_OUTSIDE_ESTATE, unrelated.outcome)


def test_tolerance_is_guarded():
    print("the tolerance knob:")
    claims = [claim("web-01", "10.0.0.7", at("2026-08-10 00:00"), at("2026-08-20 00:00"))]
    for bad in (-1, "wide", None):
        check("tolerance %r is refused" % (bad,),
              raises(ValueError, route.resolve_address, "10.0.0.7",
                     at("2026-08-15 00:00"), claims, bad))
    check("the default tolerance is zero, so no window is widened for free",
          route.resolve_address("10.0.0.7", at("2026-08-20 00:01"), claims).outcome
          == route.OUTCOME_STALE)


# ---------------------------------------------------------------------------
# 4. The evidence grade
# ---------------------------------------------------------------------------

def test_grade_of_an_observed_route():
    print("an observed route:")
    now = at("2026-08-25 12:00")
    fresh = route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT, hops=1, sessions=4000,
                                 route_last_seen=at("2026-08-25 09:00"),
                                 feed_last_seen=at("2026-08-25 11:59"))
    check("a recent edge grades confirmed observed",
          fresh.grade == route.GRADE_CONFIRMED, fresh.grade)
    check("at one hop it is the strongest evidence available",
          fresh.confidence == 0.9, fresh.confidence)
    check("and never certainty", fresh.confidence < 1.0, fresh.confidence)
    check("the hop count comes back with it", fresh.hops == 1, fresh.hops)

    old = route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT, hops=1, sessions=4000,
                               route_last_seen=at("2026-06-01 09:00"),
                               feed_last_seen=at("2026-08-25 11:59"))
    check("an old edge grades historically observed",
          old.grade == route.GRADE_HISTORIC, old.grade)
    check("and is worth less than a recent one",
          old.confidence < fresh.confidence, (old.confidence, fresh.confidence))
    check("but is still evidence, not an absence",
          old.grade != route.GRADE_NOT_OBSERVED and old.confidence > 0.0)

    # A single session is one flow that happened once. Thousands is a path in
    # daily use. The grade is the same, the confidence is not.
    thin = route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT, hops=1, sessions=1,
                                route_last_seen=at("2026-08-25 09:00"),
                                feed_last_seen=at("2026-08-25 11:59"))
    check("one session is worth less than four thousand",
          thin.confidence < fresh.confidence, (thin.confidence, fresh.confidence))
    check("but it is still a confirmed observation",
          thin.grade == route.GRADE_CONFIRMED, thin.grade)


def test_grade_decays_with_every_hop():
    print("confidence decays with distance from the entry point:")
    now = at("2026-08-25 12:00")
    seen = at("2026-08-25 09:00")
    got = [route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT, hops=h, sessions=4000,
                                route_last_seen=seen,
                                feed_last_seen=at("2026-08-25 11:59"))
           for h in (1, 2, 3, 6)]
    check("every hop is still a confirmed observation",
          all(g.grade == route.GRADE_CONFIRMED for g in got),
          [g.grade for g in got])
    confidences = [g.confidence for g in got]
    check("and each hop inward is worth strictly less than the last",
          all(a > b for a, b in zip(confidences, confidences[1:])), confidences)
    check("a distant observation is still worth more than nothing",
          confidences[-1] > 0.0, confidences[-1])
    check("the reason names the reason for the decay",
          "east to west" in got[1].reason, got[1].reason)

    for bad in (0, -2):
        check("a hop count of %d is refused" % bad,
              raises(ValueError, route.grade_evidence, now, route.COVERAGE_FULL,
                     route.PRESSURE_CONSTANT, bad, 1, seen))
    check("an edge with no hop count is refused",
          raises(ValueError, route.grade_evidence, now, route.COVERAGE_FULL,
                 route.PRESSURE_CONSTANT, None, 1, seen))


def test_absence_is_weakest_where_it_is_most_tempting():
    print("the absence of an edge, graded by where it is absent:")
    now = at("2026-08-25 12:00")
    fresh_feed = at("2026-08-25 11:30")

    boundary = route.grade_evidence(now, route.COVERAGE_FULL,
                                    route.PRESSURE_CONSTANT,
                                    feed_last_seen=fresh_feed)
    inside = route.grade_evidence(now, route.COVERAGE_FULL,
                                  route.PRESSURE_OCCASIONAL,
                                  feed_last_seen=fresh_feed)
    # The asymmetry is now structural rather than a confidence number. An
    # entry point traffic constantly arrives from can support a negative
    # claim, because an open path there shows sessions quickly. Anywhere else,
    # nobody having tried is the ordinary state, and the honest grade is that
    # we do not know. An earlier version answered "not observed" at low
    # confidence for both, which is a negative claim in a quiet voice.
    check("absence at a constant pressure entry point is a claim",
          boundary.grade == route.GRADE_NOT_OBSERVED, boundary.grade)
    check("absence east to west is not a claim at all",
          inside.grade == route.GRADE_UNKNOWN, inside.grade)
    check("and even the claim it does support is not certainty",
          boundary.confidence < 1.0, boundary.confidence)
    check("the boundary reason says it is still not proof",
          "not proof" in boundary.reason, boundary.reason)
    check("the inside reason says untried is ordinary there",
          "untried" in inside.reason, inside.reason)


def test_incomplete_coverage_weakens_only_the_negative():
    print("coverage gaps are asymmetric:")
    now = at("2026-08-25 12:00")
    # An enforcement point that does not log here cannot manufacture an edge,
    # so a gap in coverage cannot weaken an edge that was seen. It destroys
    # only the ability to say an edge was not seen.
    seen_anyway = route.grade_evidence(now, route.COVERAGE_PARTIAL, route.PRESSURE_CONSTANT, hops=1,
                                       sessions=4000,
                                       route_last_seen=at("2026-08-25 09:00"),
                                       feed_last_seen=at("2026-08-25 11:59"))
    full = route.grade_evidence(now, route.COVERAGE_FULL, route.PRESSURE_CONSTANT, hops=1, sessions=4000,
                                route_last_seen=at("2026-08-25 09:00"),
                                feed_last_seen=at("2026-08-25 11:59"))
    check("a positive under partial coverage is still confirmed observed",
          seen_anyway.grade == route.GRADE_CONFIRMED, seen_anyway.grade)
    check("and is worth exactly what it is worth under full coverage",
          seen_anyway.confidence == full.confidence,
          (seen_anyway.confidence, full.confidence))
    check("while the same gap makes a negative unknown",
          route.grade_evidence(now, route.COVERAGE_PARTIAL, route.PRESSURE_CONSTANT,
                               feed_last_seen=at("2026-08-25 11:59")).grade
          == route.GRADE_UNKNOWN)


def test_grade_vocabulary_is_closed():
    print("the vocabulary:")
    check("there are exactly four grades", len(route.ALL_GRADES) == 4, route.ALL_GRADES)
    check("unknown is one of them", route.GRADE_UNKNOWN in route.ALL_GRADES)
    check("not observed is a different one from unknown",
          route.GRADE_UNKNOWN != route.GRADE_NOT_OBSERVED)
    check("there are exactly six resolution outcomes",
          len(route.ALL_OUTCOMES) == 6, route.ALL_OUTCOMES)
    check("outcomes are unique", len(set(route.ALL_OUTCOMES)) == 6)
    # A word nobody can misread as a claim about reachability. If any of these
    # ever changes, the dashboards and the docs have to change with it, which
    # is the point of asserting the strings themselves.
    check("the grades read as evidence and not as reachability",
          route.ALL_GRADES == ("confirmed observed", "historically observed",
                               "unknown", "not observed"), route.ALL_GRADES)
    for bad in ("full ", "FULL", "yes", None, 1):
        check("coverage %r is refused rather than assumed" % (bad,),
              raises(ValueError, route.grade_evidence,
                     at("2026-08-25 12:00"), bad, route.PRESSURE_CONSTANT))



def test_claims_may_be_dicts():
    """The searches pass KV Store rows, which are dicts, not objects.

    An earlier version read claims with getattr only, so every real dict claim
    counted as unreadable and every join was refused. It failed closed, which
    was right, and was useless, because a refusal is a legitimate answer here
    and so nothing would ever have looked wrong.
    """
    claims = [{"hostname": "h1", "address": "10.0.0.5",
               "addr_first_seen": 100, "addr_last_seen": 400}]
    r = route.resolve_address("10.0.0.5", 200, claims)
    check(r.outcome == route.OUTCOME_RESOLVED and r.hostname == "h1",
          "a dict claim resolves", r.outcome)

    class Claim:
        hostname, address = "h1", "10.0.0.5"
        first_seen, last_seen = 100, 400
    r = route.resolve_address("10.0.0.5", 200, [Claim()])
    check(r.outcome == route.OUTCOME_RESOLVED and r.hostname == "h1",
          "an object claim still resolves", r.outcome)


def test_public_address_with_two_claimants_is_never_attributed():
    """Two hosts on one public address is NAT, whatever the windows say.

    Taken from the first real rollup on a live fleet: two hosts claimed one
    public address, one of them from a single scan, so the windows did not
    overlap and the overlap test alone called it a clean resolve. Attributing
    an inbound internet flow on that basis is the false attack path this
    module exists to refuse.
    """
    claims = [{"hostname": "a", "address": "62.238.42.61",
               "addr_first_seen": 1787908528, "addr_last_seen": 1787908528},
              {"hostname": "b", "address": "62.238.42.61",
               "addr_first_seen": 1787467219, "addr_last_seen": 1787755910}]
    for when in (1787500000, 1787908528, 1799999999):
        r = route.resolve_address("62.238.42.61", when, claims)
        check(r.outcome == route.OUTCOME_SHARED and r.hostname is None,
              "public address with 2 claimants refuses at t=%s" % when,
              r.outcome)
        check(r.confidence == 0.0,
              "a refused NAT address carries no confidence", r.confidence)

    # The guard must stay narrow. Private churn is ordinary DHCP and still
    # resolves; a public address only one host ever claimed still resolves.
    priv = [{"hostname": "a", "address": "10.0.0.5",
             "addr_first_seen": 100, "addr_last_seen": 200},
            {"hostname": "b", "address": "10.0.0.5",
             "addr_first_seen": 300, "addr_last_seen": 400}]
    check(route.resolve_address("10.0.0.5", 150, priv).hostname == "a",
          "private DHCP churn still resolves")
    sole = [{"hostname": "edge", "address": "203.0.113.9",
             "addr_first_seen": 100, "addr_last_seen": 400}]
    check(route.resolve_address("203.0.113.9", 200, sole).hostname == "edge",
          "a public address only one host claims still resolves")



def main():
    test_absent_firewall_data_grades_unknown_and_never_not_observed()
    test_normalisation()
    test_cidr_membership()
    test_classification()
    test_time_is_mandatory()
    test_resolution_inside_the_window()
    test_observation_outside_the_window()
    test_reassigned_dhcp_address()
    test_concurrent_holders()
    test_outside_the_estate()
    test_ipv6_resolution()
    test_open_and_malformed_claims()
    test_tolerance_is_guarded()
    test_grade_of_an_observed_route()
    test_grade_decays_with_every_hop()
    test_absence_is_weakest_where_it_is_most_tempting()
    test_incomplete_coverage_weakens_only_the_negative()
    test_grade_vocabulary_is_closed()
    test_claims_may_be_dicts()
    test_public_address_with_two_claimants_is_never_attributed()

    # A test that is written but never called is worse than no test: it reads
    # as coverage and asserts nothing. That has already happened twice on this
    # branch, so the roll call is checked mechanically rather than by whoever
    # remembers to add a line here.
    declared = {n for n, v in sorted(globals().items())
                if n.startswith("test_") and callable(v)}
    called = set(re.findall(r"^    (test_\w+)\(\)$",
                            inspect.getsource(main), re.M))
    missed = declared - called
    if missed:
        FAILURES.append("tests defined but never run: %s"
                        % ", ".join(sorted(missed)))
        print("FAIL  tests defined but never run: %s"
              % ", ".join(sorted(missed)))

    print()
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
