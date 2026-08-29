"""Importing a feed bundle into the KV Store.

Three constraints shape this, and the third was learned the hard way.

* **KV Store has hard batch limits.** ``max_documents_per_batch_save`` is 1000
  and ``max_size_per_batch_save_mb`` is 50 by default, so a naive "save
  everything" call fails on any real feed. Batches are sized to both limits.

* **Nothing may observe a half-imported feed.** A search running during an
  import must see either the whole old feed or the whole new one.

* **An import can be interrupted, and usually will be.** A full bundle takes
  around five minutes to load. In that window an admin closes the tab, a proxy
  times out, or splunkd restarts. The obvious implementation -- delete the
  collection, then repopulate it -- turns every one of those into silent data
  loss: the collection is left truncated while the feed-state row still
  describes the previous, complete feed, so dashboards report a healthy feed
  and every search quietly under-reports. That is worse than a failed import,
  because nothing looks wrong.

So rows are tagged with a **generation**. An import writes generation N+1
alongside the existing generation N, flips the feed-state pointer in a single
write once every row has landed, and only then deletes the old generation.
Readers filter on the live generation, so an interrupted import leaves the
previous feed intact and merely wastes space until the next successful import
cleans it up.
"""

from __future__ import annotations

import json
import time
from typing import Callable, Dict, Iterable, Iterator, List, Optional

from . import feed as feedlib

# Splunk's limits.conf [kvstore] defaults. Staying under both is required; the
# error Splunk returns when you exceed them is not obviously about batch size.
MAX_DOCS_PER_BATCH = 1000
MAX_BATCH_BYTES = 40 * 1024 * 1024   # 50 MB limit, with headroom for framing

# How often to publish progress, in rows.
PROGRESS_EVERY = 25000

# And in seconds, whatever the row count is doing. A row threshold alone
# measures the wrong thing: the watchdog that decides whether a worker is still
# alive reads a timestamp, so a run whose throughput drops can go quiet for
# minutes between two perfectly ordinary progress writes and be declared dead
# while it is still working. KV Store insert rates are not constant, and they
# fall off exactly where it hurts, near the end of the largest collection.
PROGRESS_EVERY_SECONDS = 30

COLLECTIONS = {
    "ranges": "riskability_ranges",
    "advisories": "riskability_advisories",
    "notaffected": "riskability_notaffected",
    "attack": "riskability_attack",
    "tactics": "riskability_tactics",
    # The CVE encyclopaedia. Kept here rather than in a local file so that a
    # search head cluster distributes it the way it distributes everything else
    # in this feed: one import, replicated by the KV Store, no per-member
    # command and no member quietly serving a stale copy. It is the largest
    # collection by bytes and the smallest by rows read, since a page renders
    # exactly one of them.
    "cvedetail": "riskability_cvedetail",
    "kevmap": "riskability_kevmap",
    "capec": "riskability_capec",
    "mitigations": "riskability_mitigations",
    "winpatch": "riskability_winpatch",
    "lifecycle": "riskability_lifecycle",
}

MEMBER_FOR = {
    "ranges": feedlib.RANGES_NAME,
    "advisories": feedlib.ADVISORIES_NAME,
    "notaffected": feedlib.NOTAFFECTED_NAME,
    "attack": feedlib.ATTACK_MEMBER,
    "tactics": feedlib.TACTICS_MEMBER,
    "cvedetail": feedlib.CVEDETAIL_MEMBER,
    "kevmap": feedlib.KEVMAP_MEMBER,
    "capec": feedlib.CAPEC_MEMBER,
    "mitigations": feedlib.MITIGATIONS_MEMBER,
    "winpatch": feedlib.WINPATCH_MEMBER,
    "lifecycle": feedlib.LIFECYCLE_MEMBER,
}

# Per-ecosystem package counts, derived while streaming ranges rather than
# recomputed later. Not in COLLECTIONS because no bundle member produces it.
ECO_COLLECTION = "riskability_feedeco"

# Above this many distinct (ecosystem, package) pairs the exact set is
# abandoned. A feed that large makes the set itself a memory problem on a
# search head, and this figure exists to answer "is this ecosystem covered at
# all", which does not need the last digit. The row says so when it happens
# rather than quietly reporting a number that stopped counting.
ECO_DISTINCT_CAP = 8_000_000

STATE_COLLECTION = "riskability_feedstate"
STATE_KEY = "current"
STATUS_KEY = "import_status"


class ImportError_(Exception):
    """The bundle could not be imported."""


# A batch_save that fails is usually a moment, not a verdict.
BATCH_RETRIES = 5
BATCH_BACKOFF = 2.0


def _save_batch(data, batch: List[dict]) -> None:
    """batch_save with bounded retries.

    An import is 4.2 million rows in ~4,200 requests, over minutes, against a
    KV Store that is also serving dashboards and the hourly pipeline. One of
    those requests coming back with a closed socket or an empty body is a
    normal event at that volume -- splunklib surfaces the empty body as
    "Expecting value: line 1 column 1", which reads like corrupt data and is
    not. Aborting the whole import for it means somebody carries a 59MB bundle
    across the air gap a second time to work around a hiccup that lasted a
    second. Observed on a clean install: failed at exactly 1,000,000 rows with
    the KV Store healthy before and after.

    Retrying is safe because writes are keyed and idempotent: the same batch
    written twice produces the same documents, and the whole generation is
    invisible to readers until the pointer flips at the end.
    """
    last = None
    for attempt in range(BATCH_RETRIES):
        try:
            data.batch_save(*batch)
            return
        except Exception as exc:
            last = exc
            if attempt < BATCH_RETRIES - 1:
                time.sleep(BATCH_BACKOFF * (2 ** attempt))
    raise ImportError_(
        f"a batch of {len(batch)} rows could not be written after {BATCH_RETRIES} "
        f"attempts: {last}") from last


def _batches(records: Iterable[dict], generation: int) -> Iterator[List[dict]]:
    """Group records into batches within both the count and byte limits."""
    batch: List[dict] = []
    size = 0
    for rec in records:
        rec["gen"] = generation
        encoded = len(json.dumps(rec, separators=(",", ":")))
        if batch and (len(batch) >= MAX_DOCS_PER_BATCH or size + encoded > MAX_BATCH_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(rec)
        size += encoded
    if batch:
        yield batch


def current_state(kvstore) -> Optional[dict]:
    """The live feed-state row, or None if nothing has been imported."""
    try:
        rows = kvstore[STATE_COLLECTION].data.query(
            query=json.dumps({"_key": STATE_KEY}))
    except Exception:
        return None
    return rows[0] if rows else None


def live_generation(kvstore) -> int:
    """Which generation of rows readers should be looking at.

    Returns 0 when no feed has been imported, which matches nothing -- the
    correct answer for "no data", rather than accidentally exposing a partially
    written generation.
    """
    state = current_state(kvstore) or {}
    try:
        return int(state.get("generation") or 0)
    except (TypeError, ValueError):
        return 0


def import_status(kvstore) -> Optional[dict]:
    try:
        rows = kvstore[STATE_COLLECTION].data.query(
            query=json.dumps({"_key": STATUS_KEY}))
    except Exception:
        return None
    return rows[0] if rows else None


def _write_status(kvstore, **fields) -> None:
    """Record progress so a long import is observable while it runs.

    Merges into the existing row rather than replacing it. A periodic progress
    update only carries the loaded count, so a straight replace would drop
    ``expected_ranges`` and ``bundle_version`` and leave the UI showing 0% for
    the whole import.

    Best effort: a failure to write status must never abort an import that is
    otherwise succeeding.
    """
    row = {"_key": STATUS_KEY, "updated_at": int(time.time())}
    existing = import_status(kvstore) or {}
    for k, v in existing.items():
        if k not in ("_key", "_user", "updated_at"):
            row[k] = v
    # Starting a new operation clears the previous one's failure text, which
    # would otherwise be merged forward and shown against a healthy import.
    if fields.get("state") in ("importing", "fetching", "queued"):
        row.pop("error", None)
    row.update(fields)
    try:
        data = kvstore[STATE_COLLECTION].data
        try:
            data.delete(json.dumps({"_key": STATUS_KEY}))
        except Exception:
            pass
        data.insert(json.dumps(row))
    except Exception:
        pass


def import_bundle(
    path: str,
    kvstore,
    imported_by: str = "",
    progress: Optional[Callable[[str, int], None]] = None,
) -> dict:
    """Validate and import a bundle. Returns the feed-state row that was written.

    The keepalive is started and stopped here rather than inside the work, so
    that no failure path can leave the thread running. A leaked keepalive would
    be worse than the problem it solves: it would touch the status row forever
    and a genuinely stuck import would never be recognised as stuck.
    """
    keepalive = _KeepAlive(kvstore).start()
    try:
        return _import_bundle(path, kvstore, imported_by=imported_by,
                              progress=progress)
    finally:
        keepalive.stop()


def _import_bundle(
    path: str,
    kvstore,
    imported_by: str = "",
    progress: Optional[Callable[[str, int], None]] = None,
) -> dict:
    """Validate and import a bundle. Returns the feed-state row that was written.

    ``kvstore`` is ``splunklib``'s ``service.kvstore``; passing it in keeps this
    module importable and testable without a running Splunk.
    """
    # Validate before touching anything. read_manifest also enforces the archive
    # safety checks, so a hostile tar is rejected before extraction, and
    # verify_members checks each member against the digest recorded when the
    # bundle was built -- the cheapest possible moment to discover that what
    # crossed the air gap is not what was built on the far side.
    manifest = feedlib.read_manifest(path)
    feedlib.verify_members(path, manifest)

    previous = current_state(kvstore) or {}
    old_gen = live_generation(kvstore)
    new_gen = old_gen + 1

    # A previous import that died before flipping leaves rows at exactly this
    # generation number, and the next attempt reuses that number -- so without
    # clearing first, the orphans merge into the new feed and every duplicated
    # advisory is reported twice. Those rows are unreachable (nothing points at
    # this generation yet), so removing them is safe at any time.
    _delete_generation(kvstore, new_gen)

    expected = manifest.get("counts", {})
    _write_status(kvstore, state="importing", generation=new_gen,
                  bundle_version=manifest.get("bundle_version", ""),
                  started_at=int(time.time()),
                  expected_ranges=expected.get("ranges", 0),
                  expected_advisories=expected.get("advisories", 0),
                  loaded_ranges=0, loaded_advisories=0, loaded_notaffected=0)

    counts: Dict[str, int] = {}
    # ecosystem -> set of package names, and ecosystem -> row count. Built from
    # the rows already in hand; the alternative is a dc(package) over the whole
    # range table on every Coverage load, which is measured in tens of seconds
    # and grows with the feed.
    eco_packages: Dict[str, set] = {}
    eco_ranges: Dict[str, int] = {}
    eco_exact = True
    eco_seen = 0
    # How many ATT&CK rows actually say which tactic their technique belongs to.
    # A bundle whose STIX fetch failed still carries a full set of attack rows;
    # they simply have no tactics, and the matrix has nothing to plot. Counting
    # it here is the difference between noticing at import and noticing when
    # somebody opens the page and finds it blank.
    attack_with_tactics = 0
    try:
        for kind, collection in COLLECTIONS.items():
            member = MEMBER_FOR[kind]
            data = kvstore[collection].data
            n = 0
            next_report = PROGRESS_EVERY
            last_report = time.time()
            # Note: no delete first. The previous generation stays readable for
            # the whole of this loop, which is what makes an interruption
            # harmless rather than destructive.
            for batch in _batches(feedlib.iter_member(path, member), new_gen):
                _save_batch(data, batch)
                n += len(batch)
                if kind == "attack":
                    for rec in batch:
                        if rec.get("tactics"):
                            attack_with_tactics += 1
                if kind == "ranges":
                    for rec in batch:
                        eco = rec.get("ecosystem") or ""
                        eco_ranges[eco] = eco_ranges.get(eco, 0) + 1
                        if eco_exact:
                            bucket = eco_packages.setdefault(eco, set())
                            bucket.add(rec.get("package") or "")
                            eco_seen += 1
                            if eco_seen > ECO_DISTINCT_CAP:
                                eco_exact = False
                                eco_packages.clear()
                if progress:
                    progress(kind, n)
                # A threshold, not "n % PROGRESS_EVERY == 0": batches are sized
                # by bytes as well as count, so n steps by varying amounts and
                # sails straight past exact multiples. That is why an earlier
                # run appeared frozen at 800,000 rows for twenty minutes while
                # it was in fact still importing.
                now = time.time()
                if n >= next_report or (now - last_report) >= PROGRESS_EVERY_SECONDS:
                    _write_status(kvstore, state="importing", generation=new_gen,
                                  **{f"loaded_{kind}": n})
                    next_report = n + PROGRESS_EVERY
                    last_report = now
            counts[kind] = n
    except Exception as exc:
        _write_status(kvstore, state="failed", generation=new_gen, error=str(exc))
        # Best effort: drop what this run wrote so it cannot accumulate. The
        # live generation is untouched either way, so failing here is safe.
        _delete_generation(kvstore, new_gen)
        raise ImportError_(f"failed importing {path!r}: {exc}") from exc

    # Never flip to an empty generation.
    #
    # The builder now refuses to write an empty bundle, but the import side
    # cannot depend on that: bundles arrive by hand, across an air gap, from a
    # build host this code has never seen, possibly built by an older version.
    # Since the flip below is atomic and irreversible, and the search head has
    # no way to re-fetch a feed it just discarded, an empty import must be
    # rejected here rather than trusted to have been rejected earlier.
    if not any(counts.get(k, 0) for k in ("advisories", "ranges", "attack")):
        _delete_generation(kvstore, new_gen)
        msg = ("the bundle contains no advisories, no version ranges and no "
               "ATT&CK mappings, so it was not imported. The existing feed is "
               "unchanged. This usually means the build host could not reach "
               "the upstream feeds; rebuild the bundle and check its output.")
        _write_status(kvstore, state="failed", generation=old_gen, error=msg)
        raise ImportError_(msg)

    _write_eco_summary(kvstore, new_gen, eco_packages, eco_ranges, eco_exact)

    state = {
        "_key": STATE_KEY,
        "generation": new_gen,
        "bundle_id": manifest.get("bundle_id", ""),
        "bundle_version": manifest.get("bundle_version", ""),
        "created_at": manifest.get("created_at", 0),
        "imported_at": int(time.time()),
        "imported_by": imported_by,
        "sources": manifest.get("sources", []),
        # Sources the build host could not reach. Kept with the feed so the
        # search head can say the feed is incomplete; otherwise this is known
        # only to whoever watched the build scroll past on the other side.
        "warnings": manifest.get("warnings", []),
        "advisory_count": counts.get("advisories", 0),
        "range_count": counts.get("ranges", 0),
        "notaffected_count": counts.get("notaffected", 0),
        "attack_count": counts.get("attack", 0),
        "attack_with_tactics": attack_with_tactics,
        "tactic_count": counts.get("tactics", 0),
        "schema": manifest.get("schema", ""),
        "previous_bundle_version": previous.get("bundle_version", ""),
    }

    # The atomic flip. Until this single write lands, every reader is still on
    # the old generation; after it, every reader is on the new one.
    feedstate = kvstore[STATE_COLLECTION].data
    try:
        feedstate.delete(json.dumps({"_key": STATE_KEY}))
    except Exception:
        pass
    feedstate.insert(json.dumps(state))

    # Reclaiming space is the longest silent stretch of an import, and it comes
    # after the feed is already live, which is why it used to look like a hang
    # at 99% and then get reported as an interrupted worker. Status is written
    # before it starts and again per collection, so the row keeps moving.
    done_counts = {
        "loaded_ranges": counts.get("ranges", 0),
        "loaded_advisories": counts.get("advisories", 0),
    }
    _write_status(kvstore, state="cleaning", generation=new_gen,
                  message="the new feed is live; reclaiming space from the "
                          "previous one", **done_counts)

    def beat(collection: str) -> None:
        _write_status(kvstore, state="cleaning", generation=new_gen,
                      message=f"reclaiming space from the previous feed "
                              f"({collection})", **done_counts)

    sweep_ungenerationed(kvstore, heartbeat=beat)

    # Only now is the old generation unreachable, so removing it is safe. If
    # this is interrupted the leftovers are invisible to readers and will be
    # cleaned up by the next import.
    for gen in range(0, new_gen):
        _delete_generation(kvstore, gen, heartbeat=beat)

    _write_status(kvstore, state="done", generation=new_gen,
                  bundle_version=state["bundle_version"],
                  finished_at=int(time.time()),
                  loaded_ranges=counts.get("ranges", 0),
                  loaded_advisories=counts.get("advisories", 0),
                  loaded_notaffected=counts.get("notaffected", 0))
    return state


def _write_eco_summary(kvstore, generation: int, eco_packages: Dict[str, set],
                       eco_ranges: Dict[str, int], exact: bool) -> None:
    """Store one row per ecosystem describing what the feed knows about it.

    Best effort. A feed that imported correctly but whose summary failed to
    write is still a usable feed, and Coverage saying "unknown" about an
    ecosystem is a far smaller problem than an import that refuses to flip.
    """
    rows = []
    for eco in sorted(set(eco_ranges) | set(eco_packages)):
        rows.append({
            "_key": f"{generation}|{eco}",
            "gen": generation,
            "ecosystem": eco,
            "feed_packages": len(eco_packages.get(eco, ())) if exact else -1,
            "feed_ranges": eco_ranges.get(eco, 0),
            "exact": "1" if exact else "0",
        })
    if not rows:
        return
    try:
        data = kvstore[ECO_COLLECTION].data
        for i in range(0, len(rows), MAX_DOCS_PER_BATCH):
            data.batch_save(*rows[i:i + MAX_DOCS_PER_BATCH])
    except Exception:
        pass


class _KeepAlive:
    """Touch the status row on a clock while a blocking call runs.

    Progress writes happen between units of work, which is fine until one unit
    is itself long. Deleting a generation from a single collection is one
    KV Store call that can take minutes, and nothing can report from inside it.
    The watchdog reads a timestamp, so a healthy import that is simply busy
    looks identical to a dead worker and gets reaped, which is reported to the
    operator as an interruption that never happened.

    Only updated_at moves. State, message and counts are left to the code doing
    the actual work, so this cannot invent progress that is not happening.
    """

    def __init__(self, kvstore, every: int = 30):
        self.kvstore, self.every = kvstore, every
        self._stop = None
        self._thread = None

    def start(self):
        import threading
        self._stop = threading.Event()

        def beat():
            while not self._stop.wait(self.every):
                _write_status(self.kvstore)

        self._thread = threading.Thread(target=beat, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._stop:
            self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


def _delete_generation(kvstore, generation: int, heartbeat=None) -> None:
    """Remove every row of one generation. Safe to interrupt and re-run.

    heartbeat is called per collection. Deleting a generation of a large feed
    takes minutes, and without a sign of life the watchdog that looks for dead
    workers cannot tell this from a crash.
    """
    for collection in list(COLLECTIONS.values()) + [ECO_COLLECTION]:
        if heartbeat:
            heartbeat(collection)
        try:
            kvstore[collection].data.delete(json.dumps({"gen": generation}))
        except Exception:
            pass


def sweep_ungenerationed(kvstore, heartbeat=None) -> None:
    """Remove rows that carry no generation at all.

    These predate generations, or were left by a version that could not delete
    them. Readers all filter on the live generation -- the matcher queries
    {"gen": <live>} explicitly -- so these rows are unreachable and cannot
    affect a result. They can, however, never be reclaimed, and they are not
    small: a development instance was carrying 962,000 orphaned version ranges
    and 323,387 orphaned advisories, 18.6% of the range table, against Splunk's
    25GB-per-collection guidance for search-head stability.

    They accumulated because the delete used {"$exists": False}. Splunk's KV
    Store accepts only a subset of MongoDB's query operators and rejects
    $exists outright as an invalid query, and the exception was swallowed -- so
    nothing was ever deleted and nothing was ever said. {"gen": None} is the
    selector that works, which the feed worker already knew and this module was
    never told. It also ran only when generation == 0, a condition that stops
    being true after the first successful import and never becomes true again.
    """
    for collection in list(COLLECTIONS.values()) + [ECO_COLLECTION]:
        if heartbeat:
            heartbeat(collection)
        try:
            kvstore[collection].data.delete(json.dumps({"gen": None}))
        except Exception:
            # Best effort: reclaiming space must never be the reason an import
            # fails. But it no longer fails silently for a reason nobody can
            # see -- the selector above is the tested one.
            pass


def verify(kvstore) -> dict:
    """Cheap sanity check that the live feed is actually readable.

    Deliberately does not count rows. With generations the stored count matches
    the claimed count by construction -- the feed-state pointer is only written
    after every row has landed -- so an exact count would cost millions of KV
    Store reads on every page load to confirm something already guaranteed.

    What it does catch is the case that guarantee does not cover: a feed
    imported by an older build, or left behind by an aborted clear-then-reload
    import, where the state row promises data that is no longer reachable at
    the live generation. That is the dangerous state, because a truncated
    collection otherwise looks exactly like a healthy one.
    """
    state = current_state(kvstore) or {}
    gen = live_generation(kvstore)
    # One key per entry in COLLECTIONS, and .get rather than [] on the way out.
    # This dict was missing "tactics" while COLLECTIONS has had it, so the loop
    # below raised KeyError('tactics') on every call. The REST handler catches
    # Exception and drops the key from its reply, and the admin page only warns
    # when it reads consistent === false, so the one check that catches a
    # truncated collection masquerading as a healthy feed had never once run.
    # A guard that fails silently is worse than no guard: it is a guard the
    # reader believes in.
    claimed = {
        "ranges": int(state.get("range_count") or 0),
        "advisories": int(state.get("advisory_count") or 0),
        "notaffected": int(state.get("notaffected_count") or 0),
        "attack": int(state.get("attack_count") or 0),
        "tactics": int(state.get("tactic_count") or 0),
    }
    out = {"generation": gen, "claimed": claimed, "readable": {}, "consistent": True}

    if not state:
        return out

    for kind, collection in COLLECTIONS.items():
        if claimed.get(kind, 0) <= 0:
            out["readable"][kind] = True
            continue
        try:
            rows = kvstore[collection].data.query(
                query=json.dumps({"gen": gen}), limit=1)
            readable = bool(rows)
        except Exception:
            readable = False
        out["readable"][kind] = readable
        if not readable:
            out["consistent"] = False
            out["reason"] = (
                f"the feed state promises {claimed[kind]:,} {kind} at generation "
                f"{gen}, but none are readable there. This usually means an "
                f"import was interrupted by an older build. Re-import the bundle."
            )
    return out


def member_id(service) -> str:
    """Which search head this is, stable across restarts.

    Staged bundles live in var/run/riskability/incoming/, and var/ replicates
    nowhere. On a search head cluster the browser reaches whichever member the
    load balancer picked, so an upload can land on one member and the import
    request arrive at another. The queue itself is a KV Store row and does
    replicate, so without this every member's worker sees a job for a file only
    one of them has.

    Computed here rather than at each call site so the endpoint that stamps a
    request and the worker that decides whether to claim it can never disagree
    about what this member is called.
    """
    try:
        info = service.info or {}
    except Exception:
        return ""
    for key in ("guid", "serverName", "host"):
        value = (info.get(key) or "").strip()
        if value:
            return value
    return ""
