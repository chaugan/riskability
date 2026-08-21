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
MEMBERS = (MANIFEST_NAME, ADVISORIES_NAME, RANGES_NAME, NOTAFFECTED_NAME, ATTACK_MEMBER)
OPTIONAL_MEMBERS = (ATTACK_MEMBER,)

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
        out[cve] = {
            "kev_added": item.get("dateAdded", ""),
            "kev_due": item.get("dueDate", ""),
            "kev_ransomware": item.get("knownRansomwareCampaignUse", ""),
        }
    return out


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
                        ATTACK_MEMBER: 0}
        self._staging = self._tmp + ".d"
        os.makedirs(self._staging, exist_ok=True)
        for name in (ADVISORIES_NAME, RANGES_NAME, NOTAFFECTED_NAME, ATTACK_MEMBER):
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

    def close(self, bundle_version: str = "") -> dict:
        for f in self._files.values():
            f.close()

        digests = {}
        for name in (ADVISORIES_NAME, RANGES_NAME, NOTAFFECTED_NAME, ATTACK_MEMBER):
            digests[name] = _sha256_file(os.path.join(self._staging, name))

        manifest = {
            "schema": SCHEMA_VERSION,
            "bundle_id": hashlib.sha256(
                "".join(digests[n] for n in sorted(digests)).encode()
            ).hexdigest()[:16],
            "bundle_version": bundle_version or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
            "created_at": int(time.time()),
            "sources": self.sources,
            "counts": {
                "advisories": self._counts[ADVISORIES_NAME],
                "ranges": self._counts[RANGES_NAME],
                "notaffected": self._counts[NOTAFFECTED_NAME],
                "attack": self._counts[ATTACK_MEMBER],
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
            for line in io.TextIOWrapper(fh, encoding="utf-8"):
                line = line.strip()
                if line:
                    yield json.loads(line)
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


_ATTACK_ENTRY_RE = re.compile(
    r"TAXONOMY NAME:ATTACK:ENTRY ID:([^:]+):ENTRY NAME:([^:]*)", re.IGNORECASE)


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


def build_attack_rows(cwe_capec: Dict[str, List[str]],
                      capec_attack: Dict[str, List[dict]]) -> List[dict]:
    """Flatten CWE -> ATT&CK, keeping the CAPEC that justified each hop.

    Each hop is a published MITRE mapping, but the chain is many-to-many and
    lossy: a weakness class does not imply an adversary used that technique.
    The justification is carried through so a finding can show its reasoning
    rather than asserting an attack path.
    """
    rows = []
    for cwe, capecs in cwe_capec.items():
        seen = {}
        for capec in capecs:
            for t in capec_attack.get(capec, ()):
                entry = seen.setdefault(t["technique"], {
                    "cwe": cwe,
                    "technique": t["technique"],
                    "technique_name": t["name"],
                    "via_capec": [],
                })
                if capec not in entry["via_capec"]:
                    entry["via_capec"].append(capec)
        rows.extend(seen.values())
    return rows
