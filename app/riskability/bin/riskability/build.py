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
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Callable, Dict, Iterable, List, Optional

from . import feed as feedlib

USER_AGENT = "riskability-feed/0.1 (+https://github.com/chaugan/riskability)"

OSV_BASE = "https://storage.googleapis.com/osv-vulnerabilities"
# MITRE publishes ATT&CK as STIX here rather than on attack.mitre.org. It is
# the only source for which tactic a technique belongs to, and so the only way
# to draw a matrix rather than a list.
ATTACK_STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
                   "/master/enterprise-attack/enterprise-attack.json")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
# The bulk JSON feeds that used to live under nvd.nist.gov/feeds are retired
# and return 404. feedlib.iter_nvd_api pages the 2.0 API in their place.
# Defined in feed.py so the year window helper there can use them too.
NVD_FIRST_YEAR = feedlib.NVD_FIRST_YEAR
NVD_LATEST_YEAR = feedlib.NVD_LATEST_YEAR
# The CVE Program's own records, which are the only source in the feed that
# names a product the way a person says it. Published as a dated release asset
# rather than a stable path, so the tag is resolved at fetch time. Large: about
# 600 MB, which is why it is opt in.
CVELIST_LATEST_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CAPEC_URL = "https://capec.mitre.org/data/csv/1000.csv"

# Every host this tool will ever contact, so an operator can allow exactly
# these and nothing else.
NETWORK_HOSTS = [
    "storage.googleapis.com",   # OSV ecosystem archives
    "nvd.nist.gov",             # NVD CVE 2.0 feeds
    "cwe.mitre.org",            # MITRE CWE catalogue
    "capec.mitre.org",          # MITRE CAPEC catalogue
    "raw.githubusercontent.com", # MITRE ATT&CK STIX bundle
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


class BuildError(Exception):
    """A build that produced nothing usable."""


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


def probe(url: str) -> Dict[str, str]:
    """Reachability plus the reason, because "no" alone is not actionable.

    An operator needs to tell a firewall or proxy problem they can fix from a
    CDN edge-block they cannot. CISA in particular serves the KEV catalogue
    behind Akamai, which 403s whole datacenter IP ranges -- the site is up, the
    URL is right, and this host will never reach it.
    """
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"ok": True, "detail": f"HTTP {r.status}"}
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 401):
            return {"ok": False, "detail": (
                f"HTTP {exc.code}: the server refused this host. Usually a CDN "
                f"blocking datacenter IP ranges rather than anything to fix "
                f"locally -- the same request normally succeeds from a "
                f"corporate or home network.")}
        if exc.code == 404:
            return {"ok": False, "detail": f"HTTP 404: the feed URL has moved."}
        return {"ok": False, "detail": f"HTTP {exc.code}"}
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return {"ok": False, "detail": (
            f"no route: {reason}. If this host is meant to have access, check "
            f"the firewall or proxy allowlist.")}
    except Exception as exc:
        return {"ok": False, "detail": str(exc)[:120]}


def online() -> Dict[str, bool]:
    """Which upstream hosts are reachable right now.

    Used by the admin page to say whether the online path is even available,
    rather than offering a button that fails minutes later.
    """
    checks = {
        "osv": osv_url("Go"),
        "nvd bulk feeds": feedlib.NVD_MIRROR_URL.format(
            year=feedlib.NVD_LATEST_YEAR),
        "nvd api": feedlib.NVD_API_URL + "?resultsPerPage=1",
        "mitre": CWE_URL,
        "kev": KEV_URL,
        "epss": EPSS_URL,
    }
    return {name: probe(url) for name, url in checks.items()}


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
    nvd_source: str = "auto",
    mitre: bool = False,
    cve_list: bool = False,
    cve_list_file: str = "",
    kev: bool = False,
    epss: bool = False,
    kev_file: str = "",
    epss_file: str = "",
    version: str = "",
    include_withdrawn: bool = False,
    log: Optional[Callable[[str], None]] = None,
) -> dict:
    """Download the requested sources and write a bundle. Returns the manifest."""
    say = log or (lambda msg: None)
    ecosystems = list(ecosystems or [])
    sources: List[dict] = []
    # Every source failure is recorded, not just narrated. A source that could
    # not be fetched changes what the bundle means, and the person importing it
    # on the air-gapped side never sees this side's console output.
    warnings: List[str] = []

    def failed(source: str, exc) -> None:
        warnings.append(f"{source}: {exc}")
        say(f"  ERROR {exc} - continuing without {source}")

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
            failed(f"OSV {eco}", exc)
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
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if nvd_source == "api":
            say("fetching NVD from the NIST API"
                + (" with an API key" if api_key else ", with no API key")
                + ". Expect this to take an hour or more: the API serves 2000 "
                  "CVEs a request and takes about 20 seconds over each one")
        else:
            say("fetching NVD from the regenerated bulk feeds, then topping up "
                "from the NIST API with whatever changed since they were built")
        n_cve = 0
        try:
            for item in feedlib.iter_nvd(years=years, api_key=api_key,
                                         log=say, source=nvd_source):
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
        except Exception as exc:
            failed("NVD", exc)
        say(f"  NVD done ({n_cve} CVEs)")
        sources.append({"name": "nvd", "url": feedlib.NVD_API_URL,
                        "fetched_at": int(time.time()), "records": n_cve,
                        "licence": "NIST/NVD; US Government work. Not endorsed by NVD."})

    if mitre:
        say("fetching MITRE CWE and CAPEC catalogues")
        try:
            cwe_capec = feedlib.parse_cwe_capec(_fetch_csv(CWE_URL))
            capec_attack = feedlib.parse_capec_attack(_fetch_csv(CAPEC_URL))

            # Tactic data is fetched separately and tolerated missing: the
            # CWE -> technique mapping is still useful without it, and losing
            # the whole MITRE section because one host is unreachable would be
            # a poor trade. The matrix panel says when it has no tactics.
            technique_meta, tactic_rows = {}, []
            try:
                with _open(ATTACK_STIX_URL) as r:
                    technique_meta, tactic_rows = feedlib.parse_attack_stix(
                        r.read().decode("utf-8"))
                for row in tactic_rows:
                    writer.add_tactic(row)
                say(f"  {len(technique_meta)} techniques, "
                    f"{len(tactic_rows)} tactics from ATT&CK")
            except Exception as exc:
                # Not fatal, but say what it costs. The build still emits a full
                # set of CWE -> technique rows, so the bundle looks complete and
                # imports cleanly; what it silently lacks is which tactic each
                # technique belongs to, and the only symptom is that the ATT&CK
                # matrix is blank while every other MITRE panel works.
                failed("MITRE ATT&CK tactics", exc)
                say("  WARNING: no tactic mapping. The ATT&CK matrix will be "
                    "empty in this bundle; every other MITRE panel still works.")

            rows = feedlib.build_attack_rows(cwe_capec, capec_attack, technique_meta)
            for row in rows:
                writer.add_attack(row)
            say(f"  {len(rows)} CWE -> ATT&CK technique mappings")
            sources.append({"name": "mitre-attack", "url": CAPEC_URL,
                            "fetched_at": int(time.time()), "records": len(rows),
                            "licence": "MITRE CWE/CAPEC; see MITRE terms of use"})
            if tactic_rows:
                sources.append({"name": "mitre-attack-tactics",
                                "url": ATTACK_STIX_URL,
                                "fetched_at": int(time.time()),
                                "records": len(tactic_rows),
                                "licence": "MITRE ATT&CK; see MITRE terms of use"})
        except Exception as exc:
            failed("MITRE CWE/CAPEC", exc)

    kev_map: Dict[str, dict] = {}
    if kev or kev_file:
        # A local file wins over the download.
        #
        # CISA serves the KEV catalogue behind a CDN that refuses whole
        # datacentre ranges, so a build host can be perfectly well connected,
        # have the URL exactly right, and still never fetch it. Downloading the
        # file by hand on a workstation and passing it in is the difference
        # between a bundle with known-exploited flags and one without, and KEV
        # is the strongest prioritisation signal available offline.
        origin = kev_file or KEV_URL
        say("reading CISA KEV from a file" if kev_file else "fetching CISA KEV")
        try:
            if kev_file:
                with open(kev_file, "rb") as fh:
                    raw = fh.read()
            else:
                with _open(KEV_URL) as r:
                    raw = r.read()
            kev_map = feedlib.normalize_kev(json.loads(raw.decode("utf-8")))
            say(f"  {len(kev_map)} known-exploited CVEs")
            sources.append({"name": "cisa-kev", "url": origin,
                            "fetched_at": int(time.time()), "records": len(kev_map),
                            "licence": "US Government work, public domain"})
        except Exception as exc:
            failed("CISA KEV", exc)

    epss_map: Dict[str, dict] = {}
    if epss or epss_file:
        origin = epss_file or EPSS_URL
        say("reading EPSS from a file" if epss_file else "fetching EPSS")
        try:
            if epss_file:
                with open(epss_file, "rb") as fh:
                    blob = fh.read()
            else:
                with _open(EPSS_URL) as r:
                    blob = r.read()
            # Accepts the published .csv.gz or a file somebody already
            # decompressed, because both are what actually turns up.
            if blob[:2] == b"\x1f\x8b":
                data = gzip.decompress(blob).decode("utf-8")
            else:
                data = blob.decode("utf-8")
            epss_map = feedlib.normalize_epss(data.splitlines())
            say(f"  {len(epss_map)} scored CVEs")
            sources.append({"name": "first-epss", "url": origin,
                            "fetched_at": int(time.time()), "records": len(epss_map),
                            "licence": "FIRST.org EPSS; attribution expected"})
        except Exception as exc:
            failed("FIRST EPSS", exc)

    for advisory in seen_advisories.values():
        cve = (advisory.get("cve_id") or "").upper()
        if cve in cwe_by_cve and not advisory.get("cwes"):
            advisory["cwes"] = cwe_by_cve[cve]
        if cve in kev_map:
            advisory.update(kev_map[cve])
        if cve in epss_map:
            advisory.update(epss_map[cve])
        writer.add_advisory(advisory)

    # The CVE Program catalogue, last because it is by far the largest fetch and
    # everything above should already be safely written if it fails.
    if cve_list or cve_list_file:
        say("fetching the CVE Program catalogue (about 600 MB, this takes a while)")
        try:
            if cve_list_file:
                blob_path = cve_list_file
                origin = cve_list_file
            else:
                with _open(CVELIST_LATEST_API) as r:
                    rel = json.loads(r.read().decode("utf-8"))
                asset = next((a for a in rel.get("assets", [])
                              if "all_CVEs" in a.get("name", "")), None)
                if asset is None:
                    raise feedlib.FeedError("no all_CVEs asset in the latest cvelistV5 release")
                origin = asset["browser_download_url"]
                say(f"  {rel.get('tag_name','')}, {asset['size']/1e6:.0f} MB")
                blob_path = os.path.join(tempfile.gettempdir(),
                                         "riskability-cvelist.zip")
                with _open(origin) as r, open(blob_path, "wb") as fh:
                    shutil.copyfileobj(r, fh, 1024 * 1024)

            kept = 0
            for record in feedlib.iter_cvelist_archive(blob_path):
                row = feedlib.normalize_cvelist(record)
                if row is None:
                    continue
                writer.write(feedlib.CVEDETAIL_MEMBER, row)
                kept += 1
                if kept % 25000 == 0:
                    say(f"  {kept} CVEs")
            say(f"  {kept} CVEs with a description or a named product")
            sources.append({"name": "cve-program", "url": origin,
                            "fetched_at": int(time.time()), "records": kept,
                            "licence": "CVE Program terms of use, redistribution permitted"})
            if not cve_list_file and os.path.exists(blob_path):
                os.unlink(blob_path)
        except Exception as exc:
            failed("CVE Program catalogue", exc)

    manifest = writer.close(bundle_version=version or "", warnings=warnings)

    # An empty bundle is a failed build, not a small one.
    #
    # Every fetch above is best-effort so that one unreachable source does not
    # throw away the others. Taken to its conclusion that meant a run in which
    # *everything* failed still wrote a valid 512-byte bundle and exited 0.
    # Carried across the air gap and imported, that would atomically replace a
    # working feed with nothing -- on the one host that cannot simply rebuild
    # it. Fail here instead, and leave no file to carry.
    counts = manifest.get("counts", {})
    if not any(counts.get(k, 0) for k in ("advisories", "ranges", "attack")):
        try:
            os.unlink(out_path)
        except OSError:
            pass
        detail = "; ".join(warnings) if warnings else "no sources were requested"
        raise BuildError(
            "no data could be collected, so no bundle was written (" + detail + ")")

    return manifest
