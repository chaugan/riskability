"""Fetching upstream feeds and assembling a bundle.

Lives in the app rather than only in the CLI so that both entry points share
one implementation:

* ``tools/riskability-feed`` -- run on a connected machine, bundle carried
  across an air gap by hand. This is the design case.
* the **Fetch now** button on the admin page -- for the deployments that do
  have outbound access and would rather not carry files around.

The app never reaches the network on its own. The online path exists only when
an operator presses the button, and every request it makes is listed in
:data:`SOURCES` so what it would contact is auditable before it is used.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Callable, Dict, Iterable, List, Optional

from . import feed as feedlib

USER_AGENT = "riskability-feed/0.1 (+https://github.com/chaugan/riskability)"

OSV_BASE = "https://storage.googleapis.com/osv-vulnerabilities"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_YEAR_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
NVD_FIRST_YEAR = 2002
NVD_LATEST_YEAR = 2026
CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CAPEC_URL = "https://capec.mitre.org/data/csv/1000.csv"

# Every host this tool will ever contact, so an operator can allow exactly
# these and nothing else.
NETWORK_HOSTS = [
    "storage.googleapis.com",   # OSV ecosystem archives
    "nvd.nist.gov",             # NVD CVE 2.0 feeds
    "cwe.mitre.org",            # MITRE CWE catalogue
    "capec.mitre.org",          # MITRE CAPEC catalogue
    "www.cisa.gov",             # CISA KEV
    "epss.empiricalsecurity.com",  # FIRST EPSS scores
]

# OSV ecosystems worth offering, with what each covers.
ECOSYSTEMS: Dict[str, str] = {
    "Debian": "deb packages on Debian hosts",
    "Ubuntu": "deb packages on Ubuntu hosts",
    "Alpine": "apk packages",
    "Red Hat": "rpm packages on RHEL",
    "Rocky Linux": "rpm packages on Rocky",
    "AlmaLinux": "rpm packages on Alma",
    "SUSE": "rpm packages on SLES",
    "openSUSE": "rpm packages on openSUSE",
    "npm": "JavaScript packages",
    "PyPI": "Python packages",
    "Go": "Go modules",
    "Maven": "Java archives",
    "NuGet": ".NET packages",
    "RubyGems": "Ruby gems",
    "crates.io": "Rust crates",
    "Packagist": "PHP packages",
}


def osv_url(ecosystem: str) -> str:
    return f"{OSV_BASE}/{urllib.parse.quote(ecosystem)}/all.zip"


def _open(url: str, timeout: int = 300):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def head_size(url: str) -> Optional[int]:
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as r:
            v = r.headers.get("Content-Length")
            return int(v) if v else None
    except Exception:
        return None


def online() -> Dict[str, bool]:
    """Which upstream hosts are reachable right now.

    Used by the admin page to say whether the online path is even available,
    rather than offering a button that fails minutes later.
    """
    checks = {
        "osv": osv_url("Go"),
        "nvd": NVD_YEAR_URL.format(year=NVD_LATEST_YEAR),
        "mitre": CWE_URL,
        "kev": KEV_URL,
        "epss": EPSS_URL,
    }
    return {name: head_size(url) is not None for name, url in checks.items()}


def nvd_years(spec: str) -> List[int]:
    """Expand an NVD year spec ('all', '2024', '2020-2026', '2019,2024')."""
    spec = (spec or "").strip().lower()
    if spec in ("all", "*"):
        return list(range(NVD_FIRST_YEAR, NVD_LATEST_YEAR + 1))
    years = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                years.update(range(int(a), int(b) + 1))
            except ValueError:
                continue
        elif part.isdigit():
            years.add(int(part))
    return sorted(y for y in years if NVD_FIRST_YEAR <= y <= NVD_LATEST_YEAR)


def _read_single_csv_from_zip(raw: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for info in z.infolist():
            if info.filename.lower().endswith(".csv"):
                with z.open(info) as fh:
                    return fh.read().decode("utf-8", errors="replace")
    raise ValueError("no CSV inside the archive")


def _fetch_csv(url: str) -> str:
    """Fetch a CSV that may actually be a zip.

    MITRE serves CAPEC at a ``.csv`` URL that is really a zip archive, so the
    magic bytes decide rather than the extension.
    """
    with _open(url) as r:
        raw = r.read()
    if raw[:2] == b"PK":
        return _read_single_csv_from_zip(raw)
    return raw.decode("utf-8", errors="replace")


def _iter_osv_zip(raw: bytes) -> Iterable[dict]:
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for info in z.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            with z.open(info) as fh:
                try:
                    yield json.loads(fh.read().decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue


def build_bundle(
    out_path: str,
    ecosystems: Optional[List[str]] = None,
    nvd: str = "",
    mitre: bool = False,
    kev: bool = False,
    epss: bool = False,
    version: str = "",
    include_withdrawn: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> dict:
    """Download the requested sources and write a bundle. Returns the manifest."""
    say = log or (lambda msg: None)
    ecosystems = list(ecosystems or [])
    sources: List[dict] = []
    writer = feedlib.BundleWriter(out_path, sources)

    seen_advisories: Dict[str, dict] = {}
    cwe_by_cve: Dict[str, List[str]] = {}

    for eco in ecosystems:
        url = osv_url(eco)
        say(f"fetching OSV {eco}")
        try:
            with _open(url) as r:
                raw = r.read()
        except Exception as exc:
            say(f"  ERROR {exc} - skipping {eco}")
            continue
        count = 0
        for record in _iter_osv_zip(raw):
            if record.get("withdrawn") and not include_withdrawn:
                continue
            try:
                advisory, ranges, notaffected = feedlib.normalize_osv(
                    record, feed_source=f"osv:{eco}")
            except feedlib.FeedError:
                continue
            seen_advisories.setdefault(advisory["advisory_id"], advisory)
            for row in ranges:
                writer.add_range(row)
            for row in notaffected:
                writer.add_notaffected(row)
            count += 1
        say(f"  {eco}: {count} advisories")
        sources.append({"name": f"osv:{eco}", "url": url,
                        "fetched_at": int(time.time()), "records": count,
                        "licence": "per-record; see OSV source attribution"})

    if nvd:
        years = nvd_years(nvd)
        say(f"fetching NVD {len(years)} year file(s)")
        n_cve = 0
        for year in years:
            try:
                with _open(NVD_YEAR_URL.format(year=year)) as r:
                    doc = json.loads(gzip.decompress(r.read()).decode("utf-8"))
            except Exception as exc:
                say(f"  ERROR {exc} - skipping {year}")
                continue
            for item in doc.get("vulnerabilities") or []:
                try:
                    advisory, ranges, _ = feedlib.normalize_nvd(item, feed_source="nvd")
                except feedlib.FeedError:
                    continue
                if advisory.get("cwes"):
                    cwe_by_cve[advisory["cve_id"]] = advisory["cwes"]
                seen_advisories.setdefault(advisory["advisory_id"], advisory)
                for row in ranges:
                    writer.add_range(row)
                n_cve += 1
            say(f"  NVD {year} done ({n_cve} CVEs so far)")
        sources.append({"name": "nvd", "url": NVD_YEAR_URL.format(year="YYYY"),
                        "fetched_at": int(time.time()), "records": n_cve,
                        "licence": "NIST/NVD; US Government work. Not endorsed by NVD."})

    if mitre:
        say("fetching MITRE CWE and CAPEC catalogues")
        try:
            cwe_capec = feedlib.parse_cwe_capec(_fetch_csv(CWE_URL))
            capec_attack = feedlib.parse_capec_attack(_fetch_csv(CAPEC_URL))
            rows = feedlib.build_attack_rows(cwe_capec, capec_attack)
            for row in rows:
                writer.add_attack(row)
            say(f"  {len(rows)} CWE -> ATT&CK technique mappings")
            sources.append({"name": "mitre-attack", "url": CAPEC_URL,
                            "fetched_at": int(time.time()), "records": len(rows),
                            "licence": "MITRE CWE/CAPEC; see MITRE terms of use"})
        except Exception as exc:
            say(f"  ERROR {exc} - continuing without MITRE mapping")

    kev_map: Dict[str, dict] = {}
    if kev:
        say("fetching CISA KEV")
        try:
            with _open(KEV_URL) as r:
                kev_map = feedlib.normalize_kev(json.loads(r.read().decode("utf-8")))
            say(f"  {len(kev_map)} known-exploited CVEs")
            sources.append({"name": "cisa-kev", "url": KEV_URL,
                            "fetched_at": int(time.time()), "records": len(kev_map),
                            "licence": "US Government work, public domain"})
        except Exception as exc:
            say(f"  ERROR {exc} - continuing without KEV")

    epss_map: Dict[str, dict] = {}
    if epss:
        say("fetching EPSS")
        try:
            with _open(EPSS_URL) as r:
                data = gzip.decompress(r.read()).decode("utf-8")
            epss_map = feedlib.normalize_epss(data.splitlines())
            say(f"  {len(epss_map)} scored CVEs")
            sources.append({"name": "first-epss", "url": EPSS_URL,
                            "fetched_at": int(time.time()), "records": len(epss_map),
                            "licence": "FIRST.org EPSS; attribution expected"})
        except Exception as exc:
            say(f"  ERROR {exc} - continuing without EPSS")

    for advisory in seen_advisories.values():
        cve = (advisory.get("cve_id") or "").upper()
        if cve in cwe_by_cve and not advisory.get("cwes"):
            advisory["cwes"] = cwe_by_cve[cve]
        if cve in kev_map:
            advisory.update(kev_map[cve])
        if cve in epss_map:
            advisory.update(epss_map[cve])
        writer.add_advisory(advisory)

    return writer.close(bundle_version=version or "")
