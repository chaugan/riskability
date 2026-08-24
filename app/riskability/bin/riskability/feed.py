"""The Riskability feed bundle: schema, normalisers, and safe extraction.

The app never fetches anything. An operator runs ``riskability-feed build`` on
an Internet-connected machine, carries the resulting bundle across the air gap,
and uploads it. This module defines that bundle and the normalisers that turn
upstream feeds into it, so the same code produces and consumes it.

Why a normalised bundle rather than "upload the raw feeds":

* Upstream formats disagree wildly (OSV JSON, OVAL XML, CSAF, updateinfo.xml,
  CSV). Parsing all of them inside Splunk's Python at upload time is slow and
  fragile, and every new format would need an app upgrade.
* Redistribution terms differ per source. A bundle the operator built from
  sources they chose sidesteps the question of what this app may ship.
* The matcher wants one shape: (ecosystem, package, advisory, range, status).

Bundle layout (a gzipped tar):

    manifest.json      bundle identity, source list, counts, member digests
    advisories.jsonl   one compact record per advisory
    ranges.jsonl       one record per affected (ecosystem, package, range)
    notaffected.jsonl  explicit vendor "not affected" / "will not fix" claims
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
import zipfile
import time
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

SCHEMA_VERSION = "1.0"

MANIFEST_NAME = "manifest.json"
ADVISORIES_NAME = "advisories.jsonl"
RANGES_NAME = "ranges.jsonl"
NOTAFFECTED_NAME = "notaffected.jsonl"

# attack.jsonl arrived after schema 1.0 and is optional: a bundle built before
# MITRE mapping existed must still import, so readers treat it as "no mapping"
# rather than as a malformed bundle.
ATTACK_MEMBER = "attack.jsonl"

# tactics.jsonl is likewise optional, and for the same reason: it arrived with
# the ATT&CK matrix, and every bundle built before it must keep importing. The
# schema version deliberately does NOT change -- bumping it would reject the
# feed an air-gapped site already has, forcing a rebuild to install an upgrade.
# A missing member means "no tactic data", which the matrix panel says plainly
# rather than drawing an empty grid.
TACTICS_MEMBER = "tactics.jsonl"

# The CVE Program catalogue: descriptions and product names for the
# encyclopaedia. Optional for the same reason as the two above, and more
# strongly: it is the largest member by far, an operator may reasonably decline
# to carry it across an air gap, and a bundle without it must still import and
# still match. Its absence means the encyclopaedia shows what the advisories
# already say, which is a poorer page rather than a broken one.
CVEDETAIL_MEMBER = "cvedetail.jsonl"
MEMBERS = (MANIFEST_NAME, ADVISORIES_NAME, RANGES_NAME, NOTAFFECTED_NAME,
           ATTACK_MEMBER, TACTICS_MEMBER, CVEDETAIL_MEMBER)
OPTIONAL_MEMBERS = (ATTACK_MEMBER, TACTICS_MEMBER, CVEDETAIL_MEMBER)

# An uploaded archive is attacker-controlled input parsed by a privileged
# process. These caps bound the damage a hostile bundle can do.
MAX_MEMBER_BYTES = 4 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBERS = 32


class FeedError(Exception):
    """A bundle is malformed, unsafe, or of an unsupported schema version."""


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cve(advisory_id: str, aliases: Optional[List[str]] = None) -> str:
    """Recover the plain CVE id for an advisory, or "" if there is none.

    An alias is the reliable source, but several feeds embed the CVE in their
    own identifier and carry no aliases at all -- Alpine publishes
    ``ALPINE-CVE-2006-20001``. Without recovering it, the KEV and EPSS overlays
    (which key strictly on ``CVE-...``) silently fail to join for that whole
    ecosystem, and every Alpine finding loses its exploitation context.
    """
    for alias in aliases or []:
        m = _CVE_RE.search(alias or "")
        if m:
            return m.group(0).upper()
    m = _CVE_RE.search(advisory_id or "")
    return m.group(0).upper() if m else ""


# ---------------------------------------------------------------------------
# OSV normalisation
# ---------------------------------------------------------------------------

# OSV ecosystem names -> the package types swinv emits, so the matcher can join
# on one vocabulary. OSV qualifies distro ecosystems with a release
# ("Ubuntu:24.04"), which is exactly the information that makes backport
# matching correct, so it is preserved separately rather than flattened away.
_OSV_ECOSYSTEM_TO_TYPE = {
    "debian": "deb",
    "ubuntu": "deb",
    "alpine": "apk",
    "red hat": "rpm",
    "rocky linux": "rpm",
    "almalinux": "rpm",
    "suse": "rpm",
    "opensuse": "rpm",
    "amazon linux": "rpm",
    "npm": "npm",
    "pypi": "python",
    "go": "go-module",
    "maven": "java-archive",
    "nuget": "nuget",
    "rubygems": "gem",
    "crates.io": "rust-crate",
    "packagist": "composer",
    "hex": "hex",
    "pub": "dart-pub",
    "conan": "conan",
    "swifturl": "swift",
}

# Statuses that mean "this package is not vulnerable here", which must beat a
# version-range hit from a less specific source.
_NOT_AFFECTED_STATUSES = {
    "not-affected",
    "not affected",
    "notaffected",
    "unaffected",
    "wontfix",
    "will-not-fix",
    "won't fix",
    "ignored",
    "no-dsa",
    "unimportant",
    "out-of-support-scope",
}


_RELEASE_TOKEN_RE = re.compile(r"^v?\d+(?:\.\d+)*$")

# Tokens that qualify a release without being part of it. "LTS" is pure noise;
# the rest name genuinely different product lines whose advisories do not apply
# to a plain installation.
_RELEASE_NOISE = {"lts", "kernel"}


def split_release(raw_release: str) -> Tuple[str, str]:
    """Split an OSV distro release into (release, variant).

    OSV does not spell a release the way ``/etc/os-release`` does, and it uses
    the same field to distinguish separate product lines::

        "24.04:LTS"                 -> ("24.04", "")
        "Pro:18.04:LTS"             -> ("18.04", "pro")
        "Pro:FIPS-updates:20.04:LTS"-> ("20.04", "pro:fips-updates")
        "Nvidia-BlueField:22.04:LTS"-> ("22.04", "nvidia-bluefield")
        "25.10"                     -> ("25.10", "")

    Splitting these matters twice over. Without stripping ``:LTS`` a release
    never compares equal to the host's, so either nothing matches or -- worse --
    a major-version fallback rescues it and quietly matches 24.04 against 24.10.
    And the variants are not the same product: Ubuntu Pro, FIPS and Realtime
    advisories describe package sets a plain host does not have.
    """
    tokens = [t for t in (raw_release or "").split(":") if t.strip()]
    release = ""
    variant_parts = []
    for token in tokens:
        t = token.strip()
        if not release and _RELEASE_TOKEN_RE.match(t):
            release = t.lstrip("vV")
            continue
        if t.lower() in _RELEASE_NOISE:
            continue
        variant_parts.append(t.lower())
    return release, ":".join(variant_parts)


def split_osv_ecosystem(ecosystem: str) -> Tuple[str, str, str, str]:
    """Split an OSV ecosystem into (package_type, distro, release, variant).

    ``"Ubuntu:24.04:LTS"``  -> ``("deb", "ubuntu", "24.04", "")``
    ``"Ubuntu:Pro:18.04:LTS"`` -> ``("deb", "ubuntu", "18.04", "pro")``
    ``"npm"``               -> ``("npm", "", "", "")``
    """
    raw = (ecosystem or "").strip()
    base, _, rest = raw.partition(":")
    base_l = base.strip().lower()
    pkg_type = _OSV_ECOSYSTEM_TO_TYPE.get(base_l, base_l)
    is_distro = base_l in {
        "debian", "ubuntu", "alpine", "red hat", "rocky linux", "almalinux",
        "suse", "opensuse", "amazon linux",
    }
    distro = base_l if is_distro else ""
    release, variant = split_release(rest)
    return pkg_type, distro, release, variant


def normalize_osv(record: dict, feed_source: str = "osv") -> Tuple[dict, List[dict], List[dict]]:
    """Turn one OSV record into (advisory, ranges, notaffected).

    OSV is the common denominator: OSV.dev exports Debian, Ubuntu, Alpine, Red
    Hat, Rocky, Alma and SUSE alongside every major language ecosystem, so one
    parser covers most of what a Linux fleet needs.
    """
    advisory_id = record.get("id") or ""
    if not advisory_id:
        raise FeedError("OSV record has no id")

    aliases = [a for a in (record.get("aliases") or []) if a]
    severity = ""
    cvss_score = None
    cvss_vector = ""
    for sev in record.get("severity") or []:
        if sev.get("type", "").upper().startswith("CVSS"):
            cvss_vector = sev.get("score") or ""
            break

    db = record.get("database_specific") or {}
    if isinstance(db.get("severity"), str):
        severity = db["severity"].lower()

    advisory = {
        "advisory_id": advisory_id,
        "aliases": aliases,
        # Operators think in CVEs, and KEV and EPSS key on them, so a CVE is the
        # display id wherever one can be recovered.
        "cve_id": extract_cve(advisory_id, aliases) or advisory_id,
        "title": (record.get("summary") or "").strip()[:500],
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published": record.get("published") or "",
        "modified": record.get("modified") or "",
        "withdrawn": record.get("withdrawn") or "",
        "feed_source": feed_source,
        "url": next(
            (r.get("url") for r in (record.get("references") or []) if r.get("type") == "ADVISORY"),
            "",
        ),
    }

    ranges: List[dict] = []
    notaffected: List[dict] = []

    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        pkg_type, distro, distro_release, distro_variant = split_osv_ecosystem(
            pkg.get("ecosystem", "")
        )

        eco_specific = affected.get("ecosystem_specific") or {}
        db_specific = affected.get("database_specific") or {}
        status = str(
            eco_specific.get("status") or db_specific.get("status") or ""
        ).strip().lower()

        base = {
            "ecosystem": pkg_type,
            "package": name.lower(),
            "package_display": name,
            "advisory_id": advisory_id,
            "cve_id": advisory["cve_id"],
            "distro": distro,
            "distro_release": distro_release,
            "distro_variant": distro_variant,
            # OSV keys distro records on the SOURCE package. Keeping it explicit
            # lets the matcher map a binary package to it rather than guessing.
            "source_package": name.lower() if distro else "",
            "feed_source": feed_source,
        }

        if status in _NOT_AFFECTED_STATUSES:
            notaffected.append(dict(base, status=status, reason=status))
            continue

        emitted = False
        for rng in affected.get("ranges") or []:
            introduced = ""
            fixed = ""
            last_affected = ""
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev:
                    fixed = ev["fixed"]
                elif "last_affected" in ev:
                    last_affected = ev["last_affected"]
            # A GIT range without an ecosystem range is not usable against an
            # installed package version; skip rather than mis-flag.
            if (rng.get("type") or "").upper() == "GIT" and not (fixed or last_affected):
                continue
            if not (introduced or fixed or last_affected):
                continue
            ranges.append(dict(
                base,
                introduced=introduced if introduced != "0" else "",
                fixed=fixed,
                last_affected=last_affected,
                status="affected",
                range_type=(rng.get("type") or "ECOSYSTEM").upper(),
            ))
            emitted = True

        # Some records enumerate exact versions instead of ranges.
        if not emitted:
            for v in affected.get("versions") or []:
                ranges.append(dict(
                    base,
                    introduced=v,
                    fixed="",
                    last_affected=v,
                    status="affected",
                    range_type="EXACT",
                ))

    return advisory, ranges, notaffected


# ---------------------------------------------------------------------------
# Overlay feeds
# ---------------------------------------------------------------------------

def normalize_kev(catalog: dict) -> Dict[str, dict]:
    """CISA KEV catalog -> {cve_id: {kev_added, kev_due, kev_ransomware}}."""
    out: Dict[str, dict] = {}
    for item in catalog.get("vulnerabilities") or []:
        cve = (item.get("cveID") or "").upper()
        if not cve:
            continue
        # The catalogue carries far more than the three date fields this used
        # to keep, and it is the only source in the whole feed that names a
        # product in the words a human would use. "TrueConf Server", not
        # "pkg:deb/ubuntu/trueconf-server". It also says what the vulnerability
        # actually does and what CISA requires be done about it. All of it is
        # in a file already downloaded, and the catalogue is only a couple of
        # thousand entries, so keeping it costs almost nothing and applies to
        # exactly the vulnerabilities an operator most needs to understand.
        vendor = (item.get("vendorProject") or "").strip()
        product = (item.get("product") or "").strip()
        out[cve] = {
            "kev_added": item.get("dateAdded", ""),
            "kev_due": item.get("dueDate", ""),
            "kev_ransomware": item.get("knownRansomwareCampaignUse", ""),
            "kev_vendor": vendor,
            "kev_product": product,
            # Pre-joined, because every consumer wants them together and a
            # lookup cannot concatenate two fields without an eval per panel.
            "kev_name": (vendor + " " + product).strip(),
            "kev_title": (item.get("vulnerabilityName") or "").strip(),
            "kev_description": (item.get("shortDescription") or "").strip(),
            "kev_action": (item.get("requiredAction") or "").strip(),
            # Semicolon separated in the source; kept verbatim so a dashboard
            # can split it without guessing at the delimiter.
            "kev_notes": (item.get("notes") or "").strip(),
        }
    return out


def iter_cvelist_archive(path: str) -> Iterable[dict]:
    """Stream CVE records out of the cvelistV5 release archive.

    Streamed from the file rather than read into memory: the archive is about
    600 MB compressed and several GB expanded, and a build host is not
    necessarily a large machine. The release asset is a zip whose entries are
    themselves sometimes a nested zip, which is why the inner PK check exists;
    the published name really is "...zip.zip".
    """
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.endswith(".zip"):
                with z.open(info) as fh:
                    inner = fh.read()
                if inner[:2] == b"PK":
                    with zipfile.ZipFile(io.BytesIO(inner)) as z2:
                        for i2 in z2.infolist():
                            if i2.is_dir() or not i2.filename.endswith(".json"):
                                continue
                            # Same guard as the outer branch below. Without it
                            # cves/deltaLog.json comes through, and it is a
                            # top-level array rather than a CVE record.
                            if not os.path.basename(
                                    i2.filename).upper().startswith("CVE-"):
                                continue
                            with z2.open(i2) as f2:
                                try:
                                    doc = json.loads(f2.read().decode("utf-8"))
                                except (json.JSONDecodeError, UnicodeDecodeError):
                                    continue
                            if isinstance(doc, dict):
                                yield doc
                continue
            if not name.endswith(".json"):
                continue
            # delta and metadata files sit alongside the records and are not
            # CVE records; they have no cveMetadata and are skipped by the
            # normaliser, but skipping them here avoids the parse entirely.
            base = os.path.basename(name)
            if not base.upper().startswith("CVE-"):
                continue
            with z.open(info) as fh:
                try:
                    doc = json.loads(fh.read().decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
            # A CVE record is an object. Anything else in here is a catalogue
            # file that happens to be named like one.
            if isinstance(doc, dict):
                yield doc


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_FIRST_YEAR = 2002
NVD_LATEST_YEAR = 2026

# This module deliberately does not import build.py: build.py imports this one,
# and a cycle between them would be a worse problem than a four line opener.
_UA = "riskability-feed/1.0 (+https://github.com/chaugan/riskability)"


def _http_get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 300):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": _UA, **(headers or {})})
    return urllib.request.urlopen(req, timeout=timeout)

# NIST retired the bulk JSON feeds at nvd.nist.gov/feeds/json/cve/2.0/. They
# return 404 now, which is what the admin page's connectivity check reports as
# "the feed URL has moved". The 2.0 API replaces them and serves the same record
# shape, so normalize_nvd() is unchanged; only the transport differs.
#
# The API is paged and rate limited: 5 requests per rolling 30 seconds without a
# key, 50 with one. At 2000 records a page and roughly 382,000 CVEs that is 191
# requests, so an unkeyed run is bounded by the rate limit rather than by
# bandwidth. Set NVD_API_KEY to make it quick; the key is free from NIST.
# 2000 is NIST's hard maximum for resultsPerPage; asking for more is refused
# with a 404. What actually costs time is the server's think time per request,
# measured at roughly 20 seconds for a full page and unaffected by payload size
# (gzip cuts 8.2 MB to 0.9 MB and saves nothing on the clock). Bandwidth is not
# the constraint, so the only lever is asking for several pages at once.
#
# The rate limits leave ample room for that. At 20 seconds a request, 10 in
# flight is 0.5 requests a second against an allowance of 1.67 with a key, and
# 3 in flight is 0.15 against 0.167 without one.
NVD_PAGE = 2000
NVD_RATE_UNKEYED = (5, 30.0)
NVD_RATE_KEYED = (50, 30.0)
NVD_WORKERS_UNKEYED = 3
NVD_WORKERS_KEYED = 10


def _nvd_windows(years):
    """120 day (pubStartDate, pubEndDate) pairs covering the requested years.

    The API caps a published-date range at 120 days per request, so a year
    becomes three or four windows.
    """
    import datetime as _dt
    out = []
    for year in sorted(years):
        cur = _dt.datetime(year, 1, 1)
        stop = _dt.datetime(year + 1, 1, 1)
        while cur < stop:
            nxt = min(cur + _dt.timedelta(days=119), stop)
            out.append((cur.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        nxt.strftime("%Y-%m-%dT%H:%M:%S.000")))
            cur = nxt
    return out


# The retired bulk feeds are regenerated daily by Fraunhofer FKIE from the same
# NVD API, one file per CVE ID year, xz compressed. A year is about 2 MB and
# arrives in under a second, against roughly 20 seconds a page from the API, so
# a full fetch is a minute or two rather than an hour.
#
# It also restores the original meaning of --nvd. The bulk feeds grouped by CVE
# ID year; the API can only filter on published date, and a CVE numbered 2015
# may be published in 2016. Those files are what --nvd year ranges always meant.
NVD_MIRROR_URL = ("https://github.com/fkie-cad/nvd-json-data-feeds/releases/"
                  "latest/download/CVE-{year}.json.xz")


def iter_nvd_mirror(years=None, log=None, url: str = NVD_MIRROR_URL):
    """Yield NVD records from the regenerated bulk feeds, API record shape.

    The mirror stores each CVE unwrapped, where the API nests it under "cve".
    Re-wrapping here means normalize_nvd never has to know which source it is
    looking at.
    """
    import lzma as _lzma
    say = log or (lambda m: None)
    wanted = sorted(years or range(NVD_FIRST_YEAR, NVD_LATEST_YEAR + 1))
    say(f"  {len(wanted)} year file(s) from the regenerated bulk feeds")
    total = 0
    for year in wanted:
        try:
            with _http_get(url.format(year=year)) as r:
                doc = json.loads(_lzma.decompress(r.read()).decode("utf-8"))
        except Exception as exc:
            # A missing year should not lose the other twenty-four.
            say(f"  {year}: skipped, {str(exc)[:70]}")
            continue
        items = doc.get("cve_items") or []
        total += len(items)
        say(f"  {year}: {len(items)} CVEs")
        for item in items:
            yield {"cve": item}
    say(f"  {total} CVEs fetched")


class _RateLimiter:
    """At most `count` acquisitions in any rolling `per` seconds, across threads."""

    def __init__(self, count: int, per: float):
        import collections, threading
        self.count, self.per = count, per
        self._times = collections.deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        import time as _time
        while True:
            with self._lock:
                now = _time.monotonic()
                while self._times and now - self._times[0] > self.per:
                    self._times.popleft()
                if len(self._times) < self.count:
                    self._times.append(now)
                    return
                wait = self.per - (now - self._times[0])
            _time.sleep(max(wait, 0.05))


def _nvd_page(url: str, headers, limiter) -> dict:
    """One API request, retrying the rate-limit and overload responses.

    403 and 429 both mean "too fast" here and NIST returns 503 under load, so
    all three are worth backing off on rather than failing the build. gzip is
    requested because it cuts 8 MB to under 1; it does not make the request
    quicker, but it is a great deal kinder to a metered or slow link.
    """
    import gzip as _gzip, time as _time
    hdrs = dict(headers or {})
    hdrs["Accept-Encoding"] = "gzip"
    for attempt in range(5):
        limiter.acquire()
        try:
            with _http_get(url, headers=hdrs) as r:
                raw = r.read()
                if (r.headers.get("Content-Encoding") or "").lower() == "gzip":
                    raw = _gzip.decompress(raw)
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            if attempt == 4:
                raise FeedError(f"NVD API request failed: {exc}")
            _time.sleep(2.0 * (attempt + 1))


def _nvd_pages(base: str, headers, limiter, workers: int, say):
    """Yield every page of one query, in order, `workers` requests in flight.

    Pages are fetched ahead but handed back in order and never more than
    `workers` are held at once, so peak memory stays bounded no matter how many
    pages the query turns out to have.
    """
    import collections, itertools
    from concurrent.futures import ThreadPoolExecutor

    first = _nvd_page(f"{base}&startIndex=0", headers, limiter)
    total = int(first.get("totalResults") or 0)
    yield first, total
    starts = range(NVD_PAGE, total, NVD_PAGE)
    if not starts:
        return
    with ThreadPoolExecutor(max_workers=workers) as pool:
        remaining = iter(starts)
        inflight = collections.deque(
            pool.submit(_nvd_page, f"{base}&startIndex={s}", headers, limiter)
            for s in itertools.islice(remaining, workers))
        while inflight:
            doc = inflight.popleft().result()
            nxt = next(remaining, None)
            if nxt is not None:
                inflight.append(pool.submit(
                    _nvd_page, f"{base}&startIndex={nxt}", headers, limiter))
            yield doc, total


def iter_nvd_api(years=None, api_key: str = "", log=None,
                 url: str = NVD_API_URL):
    """Page the NVD 2.0 API, yielding the items the old feed files held.

    Two strategies, because the cost differs by an order of magnitude. Asking
    for everything is 191 requests whatever you then discard, so a narrow year
    selection is fetched as published-date windows instead and only pays for
    the years it wants. A full-span request pages straight through, since
    windowing that would just add a request per window for no saving.
    """
    say = log or (lambda m: None)
    count, per = NVD_RATE_KEYED if api_key else NVD_RATE_UNKEYED
    workers = NVD_WORKERS_KEYED if api_key else NVD_WORKERS_UNKEYED
    limiter = _RateLimiter(count, per)
    headers = {"apiKey": api_key} if api_key else {}

    wanted = sorted(years or [])
    full_span = not wanted or (min(wanted) <= NVD_FIRST_YEAR
                               and len(wanted) >= (max(wanted) - min(wanted) + 1))
    windows = [None] if full_span else _nvd_windows(wanted)
    if not full_span:
        say(f"  {len(wanted)} year(s) as {len(windows)} date windows")

    seen = 0
    for win in windows:
        base = f"{url}?resultsPerPage={NVD_PAGE}"
        if win:
            base += f"&pubStartDate={win[0]}&pubEndDate={win[1]}"
        announced = False
        for doc, total in _nvd_pages(base, headers, limiter, workers, say):
            if not announced:
                announced = True
                if win is None:
                    pages = (total + NVD_PAGE - 1) // NVD_PAGE
                    say(f"  {total} CVEs, {pages} pages, {workers} requests at a time")
            for item in doc.get("vulnerabilities") or []:
                yield item
            seen += len(doc.get("vulnerabilities") or [])
            if win is None and seen % (NVD_PAGE * 10) < NVD_PAGE:
                say(f"  {seen} of {total}")
    say(f"  {seen} CVEs fetched")


def nvd_mirror_timestamp(url: str = NVD_MIRROR_URL) -> str:
    """When the mirror was last regenerated, from any one of its year files."""
    import lzma as _lzma
    with _http_get(url.format(year=NVD_LATEST_YEAR)) as r:
        doc = json.loads(_lzma.decompress(r.read()).decode("utf-8"))
    return doc.get("timestamp") or ""


def _iso_windows(start, end, days: int = 119):
    """(from, to) pairs no longer than the API's 120 day maximum."""
    import datetime as _dt
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out = []
    cur = start
    while cur < end:
        nxt = min(cur + _dt.timedelta(days=days), end)
        out.append((cur.strftime(fmt), nxt.strftime(fmt)))
        cur = nxt
    return out


def iter_nvd_modified(since: str, api_key: str = "", log=None,
                      url: str = NVD_API_URL):
    """Every CVE the API has touched since `since`, an ISO 8601 timestamp."""
    import datetime as _dt
    say = log or (lambda m: None)
    count, per = NVD_RATE_KEYED if api_key else NVD_RATE_UNKEYED
    workers = NVD_WORKERS_KEYED if api_key else NVD_WORKERS_UNKEYED
    limiter = _RateLimiter(count, per)
    headers = {"apiKey": api_key} if api_key else {}

    start = _dt.datetime.fromisoformat(since).astimezone(
        _dt.timezone.utc).replace(tzinfo=None)
    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    for a, b in _iso_windows(start, now):
        base = (f"{url}?resultsPerPage={NVD_PAGE}"
                f"&lastModStartDate={a}&lastModEndDate={b}")
        for doc, _total in _nvd_pages(base, headers, limiter, workers, say):
            for item in doc.get("vulnerabilities") or []:
                yield item


def _cve_year(item: dict):
    """The year in a CVE id, which is how the bulk feeds were always grouped."""
    cid = ((item.get("cve") or {}).get("id") or "")
    parts = cid.split("-")
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def iter_nvd(years=None, api_key: str = "", log=None, source: str = "auto"):
    """NVD records for the requested years, freshest available copy of each.

    The mirror is a day's regeneration of the whole corpus and arrives in about
    a minute; the API is authoritative but takes roughly an hour to page. Taking
    the bulk from the mirror and then asking the API only what changed since the
    mirror was built gives the API's freshness at the mirror's speed, because a
    day of changes is a single page.

    Updated records are yielded before the mirror's copies and the mirror's are
    then suppressed, so a caller that keeps the first record it sees for a given
    CVE keeps the newer one.
    """
    say = log or (lambda m: None)
    wanted = sorted(years or range(NVD_FIRST_YEAR, NVD_LATEST_YEAR + 1))

    if source == "api":
        yield from iter_nvd_api(years=wanted, api_key=api_key, log=say)
        return

    try:
        stamp = nvd_mirror_timestamp()
    except Exception as exc:
        if source == "mirror":
            raise FeedError(f"NVD mirror unreachable: {exc}")
        say(f"  mirror unreachable ({str(exc)[:60]}), using the API instead")
        yield from iter_nvd_api(years=wanted, api_key=api_key, log=say)
        return

    fresh = {}
    if source != "mirror" and stamp:
        say(f"  mirror was built {stamp}, asking the API what changed since")
        try:
            for item in iter_nvd_modified(stamp, api_key=api_key, log=say):
                year = _cve_year(item)
                if year is not None and year not in wanted:
                    continue
                cid = (item.get("cve") or {}).get("id")
                if cid:
                    fresh[cid] = item
        except Exception as exc:
            # The mirror alone is at most a day behind, which is far better
            # than failing the whole build over the top-up.
            say(f"  could not fetch updates ({str(exc)[:60]}), "
                f"using the mirror as built")
        say(f"  {len(fresh)} CVEs changed since then")

    for item in fresh.values():
        yield item
    for item in iter_nvd_mirror(years=wanted, log=say):
        if ((item.get("cve") or {}).get("id")) not in fresh:
            yield item


def normalize_cvelist(record: dict) -> Optional[dict]:
    """One CVE Program record (JSON 5.0) -> the fields worth carrying offline.

    This is the only source in the feed that names a product the way a person
    would: "Red Hat OpenShift Virtualization 4.17", not a purl. Distribution
    advisories describe their own packaging and frequently carry no prose at
    all, so without this the encyclopaedia has an id, a score and little else.

    References are deliberately capped rather than kept whole. They are URLs,
    and on a search head with no route to the internet nobody can follow one;
    keeping every reference costs 52 MB across the catalogue to store links
    that cannot be clicked. Three is enough to write down and look up later
    from a machine that does have a connection.
    """
    meta = record.get("cveMetadata") or {}
    cve_id = (meta.get("cveId") or "").upper()
    if not cve_id:
        return None
    cna = (record.get("containers") or {}).get("cna") or {}

    description = ""
    for d in cna.get("descriptions") or []:
        if (d.get("lang") or "").lower().startswith("en"):
            description = (d.get("value") or "").strip()
            break

    products = []
    for a in cna.get("affected") or []:
        product = (a.get("product") or "").strip()
        if not product or product == "n/a":
            continue
        vendor = (a.get("vendor") or "").strip()
        if vendor and vendor != "n/a" and not product.lower().startswith(vendor.lower()):
            product = vendor + " " + product
        if product not in products:
            products.append(product)

    cwes = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = (d.get("cweId") or "").strip()
            if cwe and cwe not in cwes:
                cwes.append(cwe)


    # A record with nothing to say is not worth a row. "state" is REJECTED for
    # withdrawn CVE ids, which should not appear in an encyclopaedia as though
    # they were real.
    if (meta.get("state") or "").upper() == "REJECTED":
        return None
    if not description and not products:
        return None

    # Shaped for the KV Store here rather than at import time, because the
    # decisions are about what is worth carrying across an air gap and that is
    # a build question. _key is the CVE id, so re-importing cannot produce two
    # rows for one CVE and a lookup is a primary key hit.
    #
    # References are deliberately absent. Measured across the catalogue they
    # cost 52 MB to store URLs that cannot be followed from a search head with
    # no route to the internet, which is the only kind this app is built for.
    # Product names cost 10 MB and are the thing no other source in the feed
    # provides, so they stay.
    return {
        "_key": cve_id,
        "cve_id": cve_id,
        "description": description,
        "products": "\n".join(products[:12]),
        "cwes": ",".join(cwes),
        "assigner": (meta.get("assignerShortName") or "").strip(),
        "published": (meta.get("datePublished") or "")[:10],
    }


def normalize_epss(lines: Iterable[str]) -> Dict[str, dict]:
    """FIRST EPSS CSV -> {cve_id: {epss, epss_percentile}}.

    The file begins with a ``#model_version`` comment line and then a header.
    """
    out: Dict[str, dict] = {}
    header: Optional[List[str]] = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if header is None:
            header = [p.strip().lower() for p in parts]
            continue
        row = dict(zip(header, parts))
        cve = (row.get("cve") or "").upper()
        if not cve:
            continue
        out[cve] = {
            "epss": _to_float(row.get("epss")),
            "epss_percentile": _to_float(row.get("percentile")),
        }
    return out


def _to_float(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Bundle writing
# ---------------------------------------------------------------------------

class BundleWriter:
    """Streams a bundle to disk without holding the whole feed in memory."""

    def __init__(self, path: str, sources: List[dict]):
        self.path = path
        self.sources = sources
        self._tmp = path + ".partial"
        self._dir = os.path.dirname(os.path.abspath(path)) or "."
        os.makedirs(self._dir, exist_ok=True)
        self._files: Dict[str, io.TextIOWrapper] = {}
        self._counts = {ADVISORIES_NAME: 0, RANGES_NAME: 0, NOTAFFECTED_NAME: 0,
                        ATTACK_MEMBER: 0, TACTICS_MEMBER: 0, CVEDETAIL_MEMBER: 0}
        self._staging = self._tmp + ".d"
        os.makedirs(self._staging, exist_ok=True)
        for name in (ADVISORIES_NAME, RANGES_NAME, NOTAFFECTED_NAME, ATTACK_MEMBER,
                     CVEDETAIL_MEMBER,
                     TACTICS_MEMBER):
            self._files[name] = open(os.path.join(self._staging, name), "w", encoding="utf-8")

    def write(self, name: str, record: dict) -> None:
        self._files[name].write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
        self._counts[name] += 1

    def add_advisory(self, rec: dict) -> None:
        self.write(ADVISORIES_NAME, rec)

    def add_range(self, rec: dict) -> None:
        self.write(RANGES_NAME, rec)

    def add_notaffected(self, rec: dict) -> None:
        self.write(NOTAFFECTED_NAME, rec)

    def add_attack(self, rec: dict) -> None:
        self.write(ATTACK_MEMBER, rec)

    def add_tactic(self, rec: dict) -> None:
        self.write(TACTICS_MEMBER, rec)

    def close(self, bundle_version: str = "", warnings=None) -> dict:
        for f in self._files.values():
            f.close()

        digests = {}
        for name in (ADVISORIES_NAME, RANGES_NAME, NOTAFFECTED_NAME, ATTACK_MEMBER,
                     CVEDETAIL_MEMBER,
                     TACTICS_MEMBER):
            digests[name] = _sha256_file(os.path.join(self._staging, name))

        manifest = {
            "schema": SCHEMA_VERSION,
            "bundle_id": hashlib.sha256(
                "".join(digests[n] for n in sorted(digests)).encode()
            ).hexdigest()[:16],
            "bundle_version": bundle_version or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
            "created_at": int(time.time()),
            "sources": self.sources,
            # Sources that could not be fetched. Carried in the bundle so the
            # person importing it on the far side of the air gap can see that
            # it is incomplete without access to the build host's console.
            "warnings": list(warnings or []),
            "counts": {
                "advisories": self._counts[ADVISORIES_NAME],
                "ranges": self._counts[RANGES_NAME],
                "notaffected": self._counts[NOTAFFECTED_NAME],
                "attack": self._counts[ATTACK_MEMBER],
                "tactics": self._counts[TACTICS_MEMBER],
            },
            "digests": digests,
        }
        manifest_path = os.path.join(self._staging, MANIFEST_NAME)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)

        with tarfile.open(self._tmp, "w:gz") as tar:
            for name in MEMBERS:
                tar.add(os.path.join(self._staging, name), arcname=name)

        for name in MEMBERS:
            os.unlink(os.path.join(self._staging, name))
        os.rmdir(self._staging)
        # Atomic publish: a consumer never sees a half-written bundle.
        os.replace(self._tmp, self.path)
        manifest["sha256"] = _sha256_file(self.path)
        manifest["size_bytes"] = os.path.getsize(self.path)
        return manifest


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Bundle reading
# ---------------------------------------------------------------------------

def _safe_members(tar: tarfile.TarFile) -> Iterator[tarfile.TarInfo]:
    """Yield only the expected regular files, refusing anything hostile.

    An uploaded tar is untrusted. Reject absolute paths, traversal, symlinks,
    devices, hardlinks, unexpected names, oversized members and member floods,
    which between them cover path-traversal writes and decompression bombs.
    """
    seen = 0
    total = 0
    for member in tar:
        seen += 1
        if seen > MAX_MEMBERS:
            raise FeedError("bundle contains too many members")
        name = member.name
        if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
            raise FeedError(f"unsafe path in bundle: {name!r}")
        if name not in MEMBERS:
            raise FeedError(f"unexpected member in bundle: {name!r}")
        if not member.isfile():
            raise FeedError(f"bundle member is not a regular file: {name!r}")
        if member.size > MAX_MEMBER_BYTES:
            raise FeedError(f"bundle member too large: {name!r}")
        total += member.size
        if total > MAX_TOTAL_BYTES:
            raise FeedError("bundle expands beyond the allowed total size")
        yield member


def read_manifest(path: str) -> dict:
    with tarfile.open(path, "r:gz") as tar:
        for member in _safe_members(tar):
            if member.name == MANIFEST_NAME:
                fh = tar.extractfile(member)
                if fh is None:
                    raise FeedError("manifest is unreadable")
                manifest = json.loads(fh.read().decode("utf-8"))
                break
        else:
            raise FeedError("bundle has no manifest.json")
    if manifest.get("schema") != SCHEMA_VERSION:
        raise FeedError(
            f"bundle schema {manifest.get('schema')!r} is not supported "
            f"(this app reads {SCHEMA_VERSION})"
        )
    return manifest


def verify_members(path: str, manifest: dict) -> None:
    """Check every member against the digest the manifest recorded for it.

    The manifest has carried per-member SHA-256 digests since the format was
    written, and nothing ever checked them. That matters more here than in most
    software: a bundle's whole delivery model is that somebody copies a 59MB
    file onto removable media, walks it to an air-gapped search head, and
    imports it. Truncated copies, bad media and interrupted transfers are the
    ordinary failure modes of that journey, and the import had no way to tell
    one from a good bundle.

    What it did instead was fail partway through. A corrupt bundle got as far
    as writing a million rows before a malformed line surfaced as
    "Expecting value: line 1 column 1 (char 0)" -- a message that names neither
    the file nor the line nor the fact that the bundle is damaged, after
    minutes of work, leaving a half-written generation to clean up. Reading the
    archive once up front costs seconds and turns that into an immediate
    refusal that says which member is wrong.

    Bundles built before digests were recorded verify trivially: a member with
    no recorded digest is not checked.
    """
    digests = manifest.get("digests") or {}
    if not digests:
        return
    seen = {}
    with tarfile.open(path, "r:gz") as tar:
        for member in _safe_members(tar):
            want = digests.get(member.name)
            if not want:
                continue
            fh = tar.extractfile(member)
            if fh is None:
                raise FeedError(f"member {member.name!r} is unreadable")
            h = hashlib.sha256()
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
            seen[member.name] = h.hexdigest()
    for name, want in digests.items():
        got = seen.get(name)
        if got is None:
            raise FeedError(
                f"the bundle's manifest lists {name!r} but the archive does not "
                "contain it. The bundle is incomplete; rebuild or re-copy it.")
        if got != want:
            raise FeedError(
                f"{name} does not match the digest recorded when the bundle was "
                f"built (expected {want[:16]}..., got {got[:16]}...). The bundle "
                "was damaged after it was built -- most likely an interrupted or "
                "truncated copy. Nothing has been imported; the existing feed is "
                "unchanged. Copy the bundle across again.")


def has_member(path: str, member_name: str) -> bool:
    """Whether a bundle carries an optional member, without reading it."""
    with tarfile.open(path, "r:gz") as tar:
        return any(m.name == member_name for m in _safe_members(tar))


def read_cvedetail_member(path: str) -> Iterator[dict]:
    """The CVE catalogue out of a bundle, or FileNotFoundError if absent.

    Distinguished from an empty member on purpose. "This bundle was built
    without the CVE Program source" and "this bundle's catalogue is empty" are
    different problems with different fixes, and a caller that cannot tell them
    apart will report the wrong one.
    """
    if not has_member(path, CVEDETAIL_MEMBER):
        raise FileNotFoundError(CVEDETAIL_MEMBER)
    return iter_member(path, CVEDETAIL_MEMBER)


def iter_member(path: str, member_name: str) -> Iterator[dict]:
    """Stream one JSONL member without materialising it in memory.

    Yields nothing for an optional member a older bundle does not carry.
    """
    with tarfile.open(path, "r:gz") as tar:
        for member in _safe_members(tar):
            if member.name != member_name:
                continue
            fh = tar.extractfile(member)
            if fh is None:
                raise FeedError(f"member {member_name!r} is unreadable")
            for lineno, line in enumerate(io.TextIOWrapper(fh, encoding="utf-8"), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError as exc:
                    # Name the member and the line. Without this the failure is
                    # a bare "Expecting value: line 1 column 1" from json, which
                    # says nothing about which of five members is damaged or how
                    # far in -- and json's own "line 1" refers to the fragment it
                    # was handed, not to the file, so it actively misleads.
                    raise FeedError(
                        f"{member_name} line {lineno} is not valid JSON ({exc}). "
                        "The bundle is damaged; copy it across again."
                    ) from exc
            return


# ---------------------------------------------------------------------------
# NVD normalisation (CPE ranges, and the CWE that MITRE mapping depends on)
# ---------------------------------------------------------------------------

# Feed rows for CPE-matched software use this pseudo-ecosystem, keyed on
# "vendor:product" so they slot into the same (ecosystem, package) index the
# PURL-based rows use. Nothing else changes in the matcher's data path.
CPE_ECOSYSTEM = "cpe"


def parse_cpe(cpe: str) -> Dict[str, str]:
    """Split a CPE 2.3 formatted string into its fields.

    Returns {} for anything that is not a well-formed cpe:2.3 string. Escaped
    colons (``\\:``) inside a component are respected, because vendor and
    product names legitimately contain them.
    """
    s = (cpe or "").strip()
    if not s.lower().startswith("cpe:2.3:"):
        return {}
    parts, cur, esc = [], [], False
    for ch in s[len("cpe:2.3:"):]:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    if len(parts) < 5:
        return {}
    names = ["part", "vendor", "product", "version", "update", "edition",
             "language", "sw_edition", "target_sw", "target_hw", "other"]
    out = {}
    for i, name in enumerate(names):
        out[name] = parts[i] if i < len(parts) else "*"
    return out


def cpe_key(cpe: str) -> str:
    """The (vendor, product) join key for a CPE, or "" if unusable.

    Version is deliberately excluded: the key selects candidate advisories, and
    the version comparison happens afterwards against the advisory's range.
    """
    p = parse_cpe(cpe)
    vendor, product = p.get("vendor", ""), p.get("product", "")
    if not vendor or not product or vendor == "*" or product == "*":
        return ""
    return f"{vendor.lower()}:{product.lower()}"


def normalize_nvd(record: dict, feed_source: str = "nvd") -> Tuple[dict, List[dict], List[dict]]:
    """Turn one NVD 2.0 vulnerability record into (advisory, ranges, notaffected).

    NVD earns its place for two things OSV cannot provide: CPE-keyed ranges,
    which are the only way to assess software that no package manager installed
    (most of a Windows estate), and the CWE classification that the MITRE
    ATT&CK mapping is derived from.
    """
    cve = record.get("cve") or record
    cve_id = cve.get("id") or ""
    if not cve_id:
        raise FeedError("NVD record has no CVE id")

    title = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            title = (d.get("value") or "").strip()[:500]
            break

    severity, score, vector = "", None, ""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            vector = data.get("vectorString") or ""
            score = data.get("baseScore")
            severity = (data.get("baseSeverity")
                        or entries[0].get("baseSeverity") or "").lower()
            break

    cwes = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = (d.get("value") or "").strip()
            if v.upper().startswith("CWE-") and v not in cwes:
                cwes.append(v.upper())

    advisory = {
        "advisory_id": cve_id,
        "cve_id": cve_id,
        "aliases": [],
        "title": title,
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "cwes": cwes,
        "published": cve.get("published") or "",
        "modified": cve.get("lastModified") or "",
        "withdrawn": "",
        "feed_source": feed_source,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }

    ranges: List[dict] = []
    seen = set()
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                criteria = m.get("criteria") or ""
                key = cpe_key(criteria)
                if not key:
                    continue
                parsed = parse_cpe(criteria)
                # An exact version in the CPE itself is a single-version range.
                exact = parsed.get("version", "*")
                introduced = m.get("versionStartIncluding") or ""
                fixed = m.get("versionEndExcluding") or ""
                last = m.get("versionEndIncluding") or ""
                start_excl = m.get("versionStartExcluding") or ""
                if not (introduced or fixed or last or start_excl):
                    if exact in ("*", "-", ""):
                        # "all versions of this product" carries no bound we can
                        # compare; recording it would flag every install.
                        continue
                    introduced = last = exact
                dedup = (key, introduced, fixed, last, start_excl)
                if dedup in seen:
                    continue
                seen.add(dedup)
                ranges.append({
                    "ecosystem": CPE_ECOSYSTEM,
                    "package": key,
                    "package_display": f"{parsed.get('vendor')} {parsed.get('product')}",
                    "advisory_id": cve_id,
                    "cve_id": cve_id,
                    "distro": "",
                    "distro_release": "",
                    "distro_variant": "",
                    "source_package": "",
                    "introduced": introduced,
                    "fixed": fixed,
                    "last_affected": last,
                    "introduced_excluding": start_excl,
                    "status": "affected",
                    "range_type": "CPE",
                    "target_sw": parsed.get("target_sw", "*"),
                    "feed_source": feed_source,
                })

    return advisory, ranges, []


# ---------------------------------------------------------------------------
# MITRE: CWE -> CAPEC -> ATT&CK
# ---------------------------------------------------------------------------

ATTACK_NAME = "attack.jsonl"


def parse_cwe_capec(csv_text: str) -> Dict[str, List[str]]:
    """CWE id -> CAPEC ids, from MITRE's CWE catalogue CSV.

    The catalogue writes related attack patterns as ``::21::59::``.
    """
    import csv as _csv
    out: Dict[str, List[str]] = {}
    reader = _csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        cwe = (row.get("CWE-ID") or "").strip()
        if not cwe:
            continue
        raw = row.get("Related Attack Patterns") or ""
        capecs = [c for c in raw.split("::") if c.strip().isdigit()]
        if capecs:
            out[f"CWE-{cwe}"] = capecs
    return out


# The entry name runs to the "::" field terminator, NOT to the next colon:
# MITRE writes names like "Hijack Execution Flow: Services File Permissions
# Weakness", and stopping at the first colon silently truncates them. Worse,
# the truncated forms collide, so one technique ends up displayed under several
# different names -- T1027 appeared as "Hijack Execution Flow" in a dashboard
# before this was fixed.
_ATTACK_ENTRY_RE = re.compile(
    r"TAXONOMY NAME:ATTACK:ENTRY ID:([^:]+):ENTRY NAME:(.*?)(?:::|$)",
    re.IGNORECASE | re.DOTALL)


def parse_capec_attack(csv_text: str) -> Dict[str, List[dict]]:
    """CAPEC id -> ATT&CK techniques, from MITRE's CAPEC catalogue CSV.

    Taxonomy mappings are a flat string listing several taxonomies; only the
    ATTACK ones are of interest here. Sub-technique ids arrive as ``1574.010``
    and are normalised to ``T1574.010``.
    """
    import csv as _csv
    out: Dict[str, List[dict]] = {}
    reader = _csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        # MITRE exports the id column with a leading apostrophe.
        capec = (row.get("'ID") or row.get("ID") or "").strip().lstrip("'")
        if not capec:
            continue
        techniques = []
        for tid, tname in _ATTACK_ENTRY_RE.findall(row.get("Taxonomy Mappings") or ""):
            tid = tid.strip()
            if not tid:
                continue
            technique = tid if tid.upper().startswith("T") else f"T{tid}"
            techniques.append({"technique": technique, "name": tname.strip()})
        if techniques:
            out[capec] = techniques
    return out


def _canonical_technique_names(capec_attack: Dict[str, List[dict]]) -> Dict[str, str]:
    """One name per ATT&CK technique.

    CAPEC records disagree with each other about what a technique is called.
    Real examples from one catalogue: "Unsecure Credentials: Private Keys" vs
    "Unsecured Credentials: Private Keys" (a typo), "Man in the Browser" vs
    "Browser Session Hijacking" (MITRE renamed it), and
    "Masquerading:Space after Filename" vs the same with a space. Left alone,
    a dashboard grouping by (technique, name) splits one technique across
    several rows and it reads as several different problems.

    Whitespace around the sub-technique colon is normalised first, then the
    most frequent spelling wins, ties broken by the longer name -- which
    favours the fuller "Supply Chain Compromise: Compromise Software
    Dependencies..." over a truncated variant.
    """
    counts: Dict[str, Dict[str, int]] = {}
    for entries in capec_attack.values():
        for e in entries:
            name = re.sub(r"\s*:\s*", ": ", (e.get("name") or "").strip())
            if not name:
                continue
            counts.setdefault(e["technique"], {})
            counts[e["technique"]][name] = counts[e["technique"]].get(name, 0) + 1
    canonical = {}
    for technique, names in counts.items():
        canonical[technique] = max(names.items(), key=lambda kv: (kv[1], len(kv[0])))[0]
    return canonical


def parse_attack_stix(raw: str):
    """MITRE's ATT&CK STIX bundle -> technique metadata and the tactic order.

    Two things come from here that CAPEC cannot provide.

    The tactic each technique belongs to, which is what makes an ATT&CK matrix
    a matrix: without it the app can say a technique is reachable but not where
    it sits in an attack. A technique can belong to several tactics.

    Authoritative technique names. CAPEC's taxonomy strings are hand-entered
    and disagree with themselves -- "Services File Permissions Weakness" and
    "ServicesFile Permissions Weakness" for one id -- which previously had to
    be resolved by majority vote. STIX is the source of record, so where it
    knows a name, that name wins outright.

    Tactic order is read from the matrix object rather than hardcoded: ATT&CK
    reorders and renames tactics between versions (Defense Evasion recently
    became Stealth and Defense Impairment), and a hardcoded list would quietly
    render last year's matrix.
    """
    doc = json.loads(raw)
    objects = doc.get("objects") or []

    tactic_by_ref = {o.get("id"): o for o in objects
                     if o.get("type") == "x-mitre-tactic"}
    tactic_rows: List[dict] = []
    order_by_shortname: Dict[str, int] = {}
    for matrix in objects:
        if matrix.get("type") != "x-mitre-matrix":
            continue
        for position, ref in enumerate(matrix.get("tactic_refs") or []):
            tactic = tactic_by_ref.get(ref)
            if not tactic:
                continue
            shortname = tactic.get("x_mitre_shortname") or ""
            if not shortname or shortname in order_by_shortname:
                continue
            order_by_shortname[shortname] = position
            tactic_rows.append({
                "tactic": shortname,
                "tactic_name": tactic.get("name") or shortname,
                "tactic_order": position,
            })
        break

    technique_meta: Dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        # Revoked and deprecated techniques still resolve from old CAPEC
        # mappings. Carrying them would put retired ids on the matrix.
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = ""
        for ref in obj.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack":
                tid = (ref.get("external_id") or "").strip()
                break
        if not tid:
            continue
        tactics = []
        for phase in obj.get("kill_chain_phases") or []:
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            name = phase.get("phase_name")
            if name and name not in tactics:
                tactics.append(name)
        tactics.sort(key=lambda t: order_by_shortname.get(t, 999))
        technique_meta[tid] = {
            "name": (obj.get("name") or "").strip(),
            "tactics": tactics,
        }
    return technique_meta, tactic_rows


def build_attack_rows(cwe_capec: Dict[str, List[str]],
                      capec_attack: Dict[str, List[dict]],
                      technique_meta: Optional[Dict[str, dict]] = None) -> List[dict]:
    """Flatten CWE -> ATT&CK, keeping the CAPEC that justified each hop.

    Each hop is a published MITRE mapping, but the chain is many-to-many and
    lossy: a weakness class does not imply an adversary used that technique.
    The justification is carried through so a finding can show its reasoning
    rather than asserting an attack path.
    """
    canonical = _canonical_technique_names(capec_attack)
    meta = technique_meta or {}
    rows = []
    for cwe, capecs in cwe_capec.items():
        seen = {}
        for capec in capecs:
            for t in capec_attack.get(capec, ()):
                tid = t["technique"]
                info = meta.get(tid) or {}
                # STIX first, majority-vote second, whatever CAPEC said last.
                name = info.get("name") or canonical.get(tid) or t["name"]
                entry = seen.setdefault(tid, {
                    "cwe": cwe,
                    "technique": tid,
                    "technique_name": name,
                    # Comma-joined rather than a list: the KV Store lookup path
                    # already flattens multivalue fields, and the macro that
                    # reads this splits on comma exactly as it does for cwes.
                    "tactics": ",".join(info.get("tactics") or []),
                    "via_capec": [],
                })
                if capec not in entry["via_capec"]:
                    entry["via_capec"].append(capec)
        rows.extend(seen.values())
    return rows
