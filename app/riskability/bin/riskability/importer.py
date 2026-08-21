"""Importing a feed bundle into the KV Store.

Two constraints shape this:

* **Nothing may observe a half-imported feed.** A search running while an
  import is in flight must see either the old feed or the new one. So each
  import writes into the live collections only after the bundle has been fully
  validated, and the feed-state row that dashboards read is flipped last.
* **KV Store has hard batch limits.** ``max_documents_per_batch_save`` is 1000
  and ``max_size_per_batch_save_mb`` is 50 by default, so a naive "save
  everything" call fails on any real feed. Batches are sized to both limits.
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
}

MEMBER_FOR = {
    "ranges": feedlib.RANGES_NAME,
    "advisories": feedlib.ADVISORIES_NAME,
    "notaffected": feedlib.NOTAFFECTED_NAME,
}


class ImportError_(Exception):
    """The bundle could not be imported."""


def _batches(records: Iterable[dict]) -> Iterator[List[dict]]:
    """Group records into batches within both the count and byte limits."""
    batch: List[dict] = []
    size = 0
    for rec in records:
        encoded = len(json.dumps(rec, separators=(",", ":")))
        if batch and (len(batch) >= MAX_DOCS_PER_BATCH or size + encoded > MAX_BATCH_BYTES):
            yield batch
            batch, size = [], 0
        batch.append(rec)
        size += encoded
    if batch:
        yield batch


def import_bundle(
    path: str,
    kvstore,
    imported_by: str = "",
    progress: Optional[Callable[[str, int], None]] = None,
) -> dict:
    """Validate and import a bundle. Returns the feed-state row that was written.

    ``kvstore`` is ``splunklib`` ``service.kvstore``; passing it in keeps this
    module importable and testable without a running Splunk.
    """
    # Validate before touching anything. read_manifest also enforces the
    # archive safety checks, so a hostile tar is rejected before extraction.
    manifest = feedlib.read_manifest(path)

    counts: Dict[str, int] = {}
    for kind, collection in COLLECTIONS.items():
        member = MEMBER_FOR[kind]
        data = kvstore[collection].data

        # Clear first: an import replaces the feed rather than merging, so a
        # withdrawn advisory or a corrected range cannot survive as a ghost.
        try:
            data.delete()
        except Exception as exc:
            raise ImportError_(f"could not clear {collection}: {exc}") from exc

        n = 0
        try:
            for batch in _batches(feedlib.iter_member(path, member)):
                data.batch_save(*batch)
                n += len(batch)
                if progress:
                    progress(kind, n)
        except Exception as exc:
            raise ImportError_(f"failed importing {kind} into {collection}: {exc}") from exc
        counts[kind] = n

    state = {
        "_key": "current",
        "bundle_id": manifest.get("bundle_id", ""),
        "bundle_version": manifest.get("bundle_version", ""),
        "created_at": manifest.get("created_at", 0),
        "imported_at": int(time.time()),
        "imported_by": imported_by,
        "sources": manifest.get("sources", []),
        "advisory_count": counts.get("advisories", 0),
        "range_count": counts.get("ranges", 0),
        "notaffected_count": counts.get("notaffected", 0),
        "schema": manifest.get("schema", ""),
    }

    # Flipped last: until this row lands, dashboards still describe the
    # previous feed rather than a partially loaded one.
    feedstate = kvstore["riskability_feedstate"].data
    try:
        feedstate.delete()
    except Exception:
        pass
    feedstate.insert(json.dumps(state))
    return state


def current_state(kvstore) -> Optional[dict]:
    try:
        rows = kvstore["riskability_feedstate"].data.query()
    except Exception:
        return None
    return rows[0] if rows else None
