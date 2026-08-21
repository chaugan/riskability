"""Minimal Package URL parsing, for the parts that change matching outcomes.

This is not a general PURL library. It extracts the three things that decide
whether a component matches an advisory:

* the **source package**, from Syft's ``upstream`` qualifier. Debian and RPM
  advisories are keyed on the source package, while an inventory reports the
  binary one: ``libssl3t64`` is advised as ``openssl``. Without this, every
  binary package whose name differs from its source package silently misses
  its own advisories -- and on a real Ubuntu host that is 40% of them.
* the **distro and release**, from the ``distro`` qualifier, which is more
  reliable than the host-level ``os_id`` for a component found inside a
  nested root.
* the **namespace**, which for language ecosystems is part of the package
  identity (``golang.org/x/crypto``, ``@types/node``).

Written against the PURL spec's encoding rules rather than by splitting on
punctuation, because deb versions routinely contain percent-encoded ``+`` and
``~`` characters that a naive split mangles.
"""

from __future__ import annotations

from typing import Dict, Optional
from urllib.parse import unquote


def parse(purl: str) -> Dict[str, str]:
    """Parse a PURL into its components. Returns {} for anything unparseable.

    Shape: ``pkg:type/namespace/name@version?qualifiers#subpath``
    """
    if not purl or not purl.startswith("pkg:"):
        return {}

    rest = purl[4:]

    # Subpath and qualifiers are stripped from the right, in that order,
    # because both may contain '/' and '@' that would break a left-to-right
    # parse of the name and version.
    subpath = ""
    if "#" in rest:
        rest, _, subpath = rest.partition("#")

    qualifiers: Dict[str, str] = {}
    if "?" in rest:
        rest, _, qs = rest.partition("?")
        for pair in qs.split("&"):
            if not pair:
                continue
            key, _, value = pair.partition("=")
            if key:
                qualifiers[unquote(key).lower()] = unquote(value)

    version = ""
    if "@" in rest:
        rest, _, version = rest.rpartition("@")
        version = unquote(version)

    parts = [p for p in rest.split("/") if p]
    if not parts:
        return {}
    ptype = unquote(parts[0]).lower()
    name = unquote(parts[-1]) if len(parts) > 1 else ""
    namespace = "/".join(unquote(p) for p in parts[1:-1]) if len(parts) > 2 else (
        unquote(parts[1]) if len(parts) == 2 else ""
    )
    if len(parts) == 1:
        name = ""
        namespace = ""
    elif len(parts) == 2:
        name = unquote(parts[1])
        namespace = ""

    out = {
        "type": ptype,
        "namespace": namespace,
        "name": name,
        "version": version,
        "subpath": unquote(subpath) if subpath else "",
    }
    out.update({f"qualifier_{k}": v for k, v in qualifiers.items()})

    # Syft records the source package as "upstream". It is sometimes written
    # as "name@version"; only the name is a join key.
    upstream = qualifiers.get("upstream", "")
    if upstream:
        out["source_package"] = upstream.split("@", 1)[0]

    distro = qualifiers.get("distro", "")
    if distro:
        # "ubuntu-26.04" -> ("ubuntu", "26.04"); "debian-12" -> ("debian", "12")
        base, sep, release = distro.rpartition("-")
        if sep and release and release[0].isdigit():
            out["distro"] = base.lower()
            out["distro_release"] = release
        else:
            out["distro"] = distro.lower()
            out["distro_release"] = ""

    return out


def enrich(component: dict) -> dict:
    """Return a copy of the component with PURL-derived fields filled in.

    Only fills fields that are absent: an explicit field on the component always
    wins over one inferred from its PURL.
    """
    out = dict(component)
    parsed = parse(component.get("purl", ""))
    if not parsed:
        return out

    if parsed.get("source_package") and not out.get("source_package"):
        out["source_package"] = parsed["source_package"]
    if parsed.get("namespace") and not out.get("namespace"):
        out["namespace"] = parsed["namespace"]
    # A distro qualifier describes the package's own root, which is what should
    # be matched against -- more trustworthy than the host's os-release when the
    # component was found inside a nested filesystem.
    if parsed.get("distro") and not out.get("purl_distro"):
        out["purl_distro"] = parsed["distro"]
        out["purl_distro_release"] = parsed.get("distro_release", "")
    return out
