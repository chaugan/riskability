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

COLLECTIONS = {
    "ranges": "riskability_ranges",
    "advisories": "riskability_advisories",
    "notaffected": "riskability_notaffected",
    "attack": "riskability_attack",
}

MEMBER_FOR = {
    "ranges": feedlib.RANGES_NAME,
    "advisories": feedlib.ADVISORIES_NAME,
    "notaffected": feedlib.NOTAFFECTED_NAME,
    "attack": feedlib.ATTACK_MEMBER,
}

STATE_COLLECTION = "riskability_feedstate"
STATE_KEY = "current"
STATUS_KEY = "import_status"


class ImportError_(Exception):
    """The bundle could not be imported."""


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

    ``kvstore`` is ``splunklib``'s ``service.kvstore``; passing it in keeps this
    module importable and testable without a running Splunk.
    """
    # Validate before touching anything. read_manifest also enforces the archive
    # safety checks, so a hostile tar is rejected before extraction.
    manifest = feedlib.read_manifest(path)

    previous = current_state(kvstore) or {}
    old_gen = live_generation(kvstore)
    new_gen = old_gen + 1

    expected = manifest.get("counts", {})
    _write_status(kvstore, state="importing", generation=new_gen,
                  bundle_version=manifest.get("bundle_version", ""),
                  started_at=int(time.time()),
                  expected_ranges=expected.get("ranges", 0),
                  expected_advisories=expected.get("advisories", 0),
                  loaded_ranges=0, loaded_advisories=0, loaded_notaffected=0)

    counts: Dict[str, int] = {}
    try:
        for kind, collection in COLLECTIONS.items():
            member = MEMBER_FOR[kind]
            data = kvstore[collection].data
            n = 0
            # Note: no delete first. The previous generation stays readable for
            # the whole of this loop, which is what makes an interruption
            # harmless rather than destructive.
            for batch in _batches(feedlib.iter_member(path, member), new_gen):
                data.batch_save(*batch)
                n += len(batch)
                if progress:
                    progress(kind, n)
                if n % 50000 == 0:
                    _write_status(kvstore, state="importing", generation=new_gen,
                                  **{f"loaded_{kind}": n})
            counts[kind] = n
    except Exception as exc:
        _write_status(kvstore, state="failed", generation=new_gen, error=str(exc))
        # Best effort: drop what this run wrote so it cannot accumulate. The
        # live generation is untouched either way, so failing here is safe.
        _delete_generation(kvstore, new_gen)
        raise ImportError_(f"failed importing {path!r}: {exc}") from exc

    state = {
        "_key": STATE_KEY,
        "generation": new_gen,
        "bundle_id": manifest.get("bundle_id", ""),
        "bundle_version": manifest.get("bundle_version", ""),
        "created_at": manifest.get("created_at", 0),
        "imported_at": int(time.time()),
        "imported_by": imported_by,
        "sources": manifest.get("sources", []),
        "advisory_count": counts.get("advisories", 0),
        "range_count": counts.get("ranges", 0),
        "notaffected_count": counts.get("notaffected", 0),
        "attack_count": counts.get("attack", 0),
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

    # Only now is the old generation unreachable, so removing it is safe. If
    # this is interrupted the leftovers are invisible to readers and will be
    # cleaned up by the next import.
    _write_status(kvstore, state="cleaning", generation=new_gen, **{
        "loaded_ranges": counts.get("ranges", 0),
        "loaded_advisories": counts.get("advisories", 0),
    })
    for gen in range(0, new_gen):
        _delete_generation(kvstore, gen)

    _write_status(kvstore, state="done", generation=new_gen,
                  bundle_version=state["bundle_version"],
                  finished_at=int(time.time()),
                  loaded_ranges=counts.get("ranges", 0),
                  loaded_advisories=counts.get("advisories", 0),
                  loaded_notaffected=counts.get("notaffected", 0))
    return state


def _delete_generation(kvstore, generation: int) -> None:
    """Remove every row of one generation. Safe to interrupt and re-run."""
    for collection in COLLECTIONS.values():
        try:
            kvstore[collection].data.delete(json.dumps({"gen": generation}))
        except Exception:
            pass
        # Rows written before generations existed carry no gen field at all.
        if generation == 0:
            try:
                kvstore[collection].data.delete(
                    json.dumps({"gen": {"$exists": False}}))
            except Exception:
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
    claimed = {
        "ranges": int(state.get("range_count") or 0),
        "advisories": int(state.get("advisory_count") or 0),
        "notaffected": int(state.get("notaffected_count") or 0),
        "attack": int(state.get("attack_count") or 0),
    }
    out = {"generation": gen, "claimed": claimed, "readable": {}, "consistent": True}

    if not state:
        return out

    for kind, collection in COLLECTIONS.items():
        if claimed[kind] <= 0:
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
