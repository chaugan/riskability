#!/usr/bin/env python
"""``riskabilitymatch`` - match inventory rows against the imported feed.

Usage in SPL::

    `riskability_latest_inventory`
    | riskabilitymatch
    | where confidence="high"

The command deliberately does **not** stream over raw inventory. Splunk cannot
express dpkg or RPM version ordering in SPL, so the comparison has to happen in
Python -- but running Python over ten million raw inventory events would be
hopeless. Instead the caller reduces to latest state first (the
``riskability_latest_inventory`` macro), and this command batches each chunk
into a handful of KV Store queries keyed on (ecosystem, package), so the work
is proportional to distinct packages rather than to hosts times packages.

Configured ``local = true`` in commands.conf: the feed lives in the search
head's KV Store, and shipping it to indexers would put a large collection into
the knowledge bundle on every search.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, Iterable, List, Sequence, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch  # noqa: E402
from splunklib.searchcommands.validators import Boolean  # noqa: E402

from riskability import importer as importerlib  # noqa: E402
from riskability import match as matchlib  # noqa: E402

RANGES_COLLECTION = "riskability_ranges"
NOTAFFECTED_COLLECTION = "riskability_notaffected"
ADVISORIES_COLLECTION = "riskability_advisories"

# Pseudo-ecosystem for CPE-keyed rows; see riskability.feed.CPE_ECOSYSTEM.
CPE_ECOSYSTEM = "cpe"

# KV Store refuses to return more than this per query (limits.conf
# [kvstore] max_rows_per_query, default 50000), so paginate rather than
# silently truncating a package with many advisories. Paging AT the cap rather
# than well under it: at 5,000 a hot package cost ten round trips to fetch what
# one could carry, and every round trip is HTTP to Mongo.
KV_PAGE = 50000


@Configuration()
class RiskabilityMatchCommand(EventingCommand):
    """Turn inventory rows into vulnerability findings."""

    include_informational = Option(
        doc="Also emit upstream claims about distro packages that a backport may "
            "already have fixed. Default false.",
        require=False, default=False, validate=Boolean(),
    )

    enrich = Option(
        doc="Join advisory metadata (severity, CVSS, KEV, EPSS). Default true.",
        require=False, default=True, validate=Boolean(),
    )

    def __init__(self):
        super().__init__()
        self._advisory_cache: Dict[str, dict] = {}
        self._generation = None
        # Caches that live for the whole command invocation rather than for one
        # protocol chunk. Splunk hands a chunked command 50,000 rows at a time,
        # so on a large fleet transform() is called many times -- and every one
        # of those calls used to re-fetch openssl's ranges from KV Store.
        self._range_cache: Dict[Tuple[str, str], List[dict]] = {}
        self._na_cache: Dict[Tuple[str, str], List[dict]] = {}
        self._fetched: set = set()
        # Deliberately NOT caching verdicts by component identity, though a
        # gold-image fleet would benefit enormously. match_component bakes the
        # hostname into finding_key, and applies host-scoped suppressions, so a
        # shared verdict carries the first host's identity to every other host
        # -- silently, and worst on exactly the homogeneous fleets the sharing
        # is meant to help. Doing it safely means separating the host-
        # independent verdict from the host-stamped identity inside match.py,
        # which is a change to the matching contract, not a cache.
        self._stats = {"kv_queries": 0}

    # -- KV Store access ---------------------------------------------------

    def _kv(self, collection: str):
        return self.service.kvstore[collection].data

    def _gen(self) -> int:
        """The feed generation to read, resolved once per search.

        Filtering on this is what keeps a search off a feed that is still being
        imported: a partially written generation is simply not the live one.
        """
        if self._generation is None:
            self._generation = importerlib.live_generation(self.service.kvstore)
        return self._generation

    def _query_all(self, collection: str, query: dict) -> List[dict]:
        """Page through a KV Store query so a hot package is never truncated."""
        out: List[dict] = []
        skip = 0
        while True:
            page = self._kv(collection).query(
                query=json.dumps(query), limit=KV_PAGE, skip=skip
            )
            if not page:
                break
            out.extend(page)
            if len(page) < KV_PAGE:
                break
            skip += KV_PAGE
        return out

    def _candidates(self, wanted: Dict[str, set]) -> None:
        """Fetch ranges and not-affected rows for identities not already held.

        One query per ecosystem with an ``$in`` on the package names, rather
        than one query per inventory row -- and only for names this command has
        not already asked about. A name that returned nothing is remembered too:
        most installed packages have no advisory at all, and re-asking for them
        on every chunk was the bulk of the KV traffic.
        """
        for ecosystem, packages in wanted.items():
            names = sorted(n for n in packages if (ecosystem, n) not in self._fetched)
            if not names:
                continue
            for i in range(0, len(names), 1000):
                batch = names[i:i + 1000]
                q = {"gen": self._gen(), "ecosystem": ecosystem,
                     "package": {"$in": batch}}
                self._stats["kv_queries"] += 2
                for row in self._query_all(RANGES_COLLECTION, q):
                    self._range_cache.setdefault(
                        (ecosystem, row.get("package", "")), []).append(row)
                for row in self._query_all(NOTAFFECTED_COLLECTION, q):
                    self._na_cache.setdefault(
                        (ecosystem, row.get("package", "")), []).append(row)
            self._fetched.update((ecosystem, n) for n in names)

    def _advisories(self, advisory_ids: Sequence[str]) -> Dict[str, dict]:
        missing = [a for a in set(advisory_ids) if a not in self._advisory_cache]
        for i in range(0, len(missing), 1000):
            batch = missing[i:i + 1000]
            q = {"gen": self._gen(), "advisory_id": {"$in": batch}}
            for row in self._query_all(ADVISORIES_COLLECTION, q):
                self._advisory_cache[row.get("advisory_id", "")] = row
        for a in missing:
            self._advisory_cache.setdefault(a, {})
        return self._advisory_cache

    # -- main --------------------------------------------------------------

    def transform(self, records):
        records = list(records)
        if not records:
            return

        # Resolve every row before doing anything else: recover the source
        # package from the PURL, and work out which filesystem root the
        # component lives in. Skipping this is not a partial result, it is a
        # wrong one -- packages inside a snap base get matched against the
        # host's distro release, and binary packages never find the advisories
        # filed against their source package.
        prepared = [matchlib.prepare_component(r) for r in records]

        # Collect the distinct package identities in this chunk. Both the
        # binary name and any source package are candidates, because distro
        # advisories are keyed on the source package.
        wanted: Dict[str, set] = {}
        for r in prepared:
            eco = (r.get("type") or "").strip().lower()
            if not eco:
                continue
            for name in matchlib._candidate_names(r):
                wanted.setdefault(eco, set()).add(name)
            # Software no package manager installed -- most of a Windows estate
            # -- has no PURL, only generated CPEs. Those are looked up under a
            # pseudo-ecosystem keyed on vendor:product.
            for key in matchlib.cpe_candidate_keys(r):
                wanted.setdefault(CPE_ECOSYSTEM, set()).add(key)

        try:
            self._candidates(wanted)
        except Exception as exc:
            # A KV Store failure must be visible, not an empty result set that
            # reads as "no vulnerabilities".
            self.error_exit(exc, f"could not read the vulnerability feed: {exc}")
            return

        all_findings = []
        for r in prepared:
            eco = (r.get("type") or "").strip().lower()
            if not eco:
                continue
            cand_ranges: List[dict] = []
            cand_notaffected: List[dict] = []
            for name in matchlib._candidate_names(r):
                cand_ranges.extend(self._range_cache.get((eco, name), ()))
                cand_notaffected.extend(self._na_cache.get((eco, name), ()))
            for key in matchlib.cpe_candidate_keys(r):
                cand_ranges.extend(self._range_cache.get((CPE_ECOSYSTEM, key), ()))
            if not cand_ranges:
                continue
            for finding in matchlib.match_component(r, cand_ranges, cand_notaffected):
                if finding["confidence"] == "informational" and not self.include_informational:
                    continue
                finding["hostname"] = r.get("hostname", "")
                # Carry the scan timestamp onto the finding. The command emits
                # a fresh record per finding, so anything not copied here is
                # lost -- and without the scan time the lifecycle cannot tell
                # "still present in the latest scan" from "never seen again",
                # which is the whole basis of mitigation detection.
                finding["scanned_at"] = r.get("scanned_at", "")
                # The resolved root, not the host's: an operator needs to see
                # that a finding is about /snap/core18 rather than the machine.
                finding["scope"] = r.get("scope", "host")
                finding["scope_id"] = r.get("scope_id", "")
                finding["source_package"] = r.get("source_package", "")
                finding["os_id"] = r.get("os_id", "")
                finding["os_version_id"] = r.get("os_version_id", "")
                finding["purl"] = r.get("purl", "")
                all_findings.append(finding)

        if self.enrich and all_findings:
            try:
                meta = self._advisories([f["advisory_id"] for f in all_findings])
            except Exception:
                meta = {}
            for f in all_findings:
                a = meta.get(f["advisory_id"]) or {}
                f["title"] = a.get("title", "")
                f["severity"] = a.get("severity", "")
                f["cvss_vector"] = a.get("cvss_vector", "")
                f["published"] = a.get("published", "")
                f["url"] = a.get("url", "")
                f["epss"] = a.get("epss", "")
                f["epss_percentile"] = a.get("epss_percentile", "")
                f["kev_added"] = a.get("kev_added", "")
                f["kev_due"] = a.get("kev_due", "")
                f["kev_ransomware"] = a.get("kev_ransomware", "")

        for f in all_findings:
            yield f


dispatch(RiskabilityMatchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
