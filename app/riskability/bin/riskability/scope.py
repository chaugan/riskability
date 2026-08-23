"""Working out which root a component actually belongs to.

swinv scans a filesystem, and a modern Linux filesystem contains several
operating systems. A single Ubuntu 26.04 host legitimately reports four
different ``openssl`` packages: the host's own, one inside ``/snap/core18``
(Ubuntu 18.04), one inside ``/snap/core20`` (Ubuntu 20.04), and one inside an
unpacked container rootfs sitting in a source tree.

Every one of those inherits the *host's* ``os_id`` and ``os_version_id``,
because the inventory record repeats host identity on every component. Matching
them against the host's distro advisories is wrong twice over: the advisory is
for the wrong release, and the fix arrives by a completely different mechanism
(``snap refresh`` or a rebuilt image, not ``apt upgrade``).

So each component is assigned a scope before matching. Host packages match host
advisories. A snap base gets the release its name encodes, so it can still be
matched correctly rather than merely excluded. Anything else is reported
against a scope the operator can see, instead of being quietly folded into the
host's numbers.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Dict, List, Optional, Sequence, Tuple

SCOPE_HOST = "host"
SCOPE_SNAP = "snap"
SCOPE_CONTAINER = "container"
SCOPE_NESTED = "nested-root"

# /snap/<name>/<revision>/...
_SNAP_RE = re.compile(r"^/snap/([^/]+)/([^/]+)/")
# /var/lib/snapd/snap/<name>/<revision>/... on some distributions
_SNAPD_RE = re.compile(r"^/var/lib/snapd/snap/([^/]+)/([^/]+)/")

_CONTAINER_PREFIXES = (
    "/var/lib/docker/",
    "/var/lib/containerd/",
    "/var/lib/containers/",
    "/var/lib/lxd/",
    "/var/lib/lxc/",
    "/run/containerd/",
)

# A second dpkg/rpm database anywhere other than the real one means we are
# looking at an unpacked root filesystem, not the host.
_NESTED_MARKERS = (
    "/rootfs/",
    "/var/lib/dpkg/status",
    "/var/lib/rpm/",
    "/lib/apk/db/",
)

# Ubuntu's base snaps encode the release they are built from. Knowing this
# turns "cannot assess" into a correct assessment against the right release.
_SNAP_BASE_RELEASE = {
    "core": "16.04",
    "core16": "16.04",
    "core18": "18.04",
    "core20": "20.04",
    "core22": "22.04",
    "core24": "24.04",
    "core26": "26.04",
}

_SNAP_NAME_RELEASE_RE = re.compile(r"(\d{2})(?:04|10)$")


def _snap_release(snap_name: str) -> str:
    """The Ubuntu release a snap base is built on, or "" if not derivable."""
    name = (snap_name or "").lower()
    if name in _SNAP_BASE_RELEASE:
        return _SNAP_BASE_RELEASE[name]
    # Names like "gnome-3-28-1804" carry the release as a trailing 1804.
    m = re.search(r"(\d{2})(\d{2})$", name)
    if m and m.group(2) in ("04", "10"):
        return f"{m.group(1)}.{m.group(2)}"
    return ""


def classify(location: str) -> Tuple[str, str, str]:
    """Classify one path into (scope_kind, scope_id, inferred_release)."""
    path = location or ""
    if not path.startswith("/"):
        return SCOPE_HOST, "", ""

    for regex in (_SNAP_RE, _SNAPD_RE):
        m = regex.match(path)
        if m:
            name = m.group(1)
            return SCOPE_SNAP, f"snap:{name}", _snap_release(name)

    for prefix in _CONTAINER_PREFIXES:
        if path.startswith(prefix):
            return SCOPE_CONTAINER, prefix.rstrip("/"), ""

    # A package database that is not the host's own is a separate root.
    for marker in _NESTED_MARKERS:
        idx = path.find(marker)
        if idx > 0:
            # idx > 0 means something precedes the marker, i.e. it is nested.
            return SCOPE_NESTED, path[:idx], ""

    return SCOPE_HOST, "", ""


def component_scope(component: dict) -> Dict[str, str]:
    """Assign a scope to a component from where it was found on disk.

    Prefers an explicit scalar ``path``, falling back to the first entry of
    ``locations``. The distinction matters inside Splunk: a JSON array becomes a
    multivalue field, and a multivalue field does not survive the search-command
    protocol as a Python list, so reading ``locations`` there yields nothing and
    every component silently looks like a host package. The caller therefore
    passes a pre-flattened ``path``.

    swinv sorts locations, so the first entry is stable across scans, and a
    component backed by several files inside one root has all of them in it.
    """
    # swinv 0.2.3 reports the filesystem root it scanned. Where it names one
    # other than "/", that is authoritative and needs no inference. It does not
    # currently treat a snap base as a separate root, so path classification
    # still does the work for those.
    root = (component.get("root") or "").strip()
    # swinv names a container root as "container:<id>". That is not merely a
    # nested filesystem: a container has a lifecycle, an image behind it and
    # possibly a published port, and calling it "nested-root" throws all of that
    # away at the one point the app could still keep it.
    if root.startswith("container:"):
        return {"scope": SCOPE_CONTAINER, "scope_id": root, "scope_release": ""}
    if root and root not in ("/", ""):
        return {"scope": SCOPE_NESTED, "scope_id": root.rstrip("/"),
                "scope_release": ""}

    path = component.get("path")
    if not path:
        locations = component.get("locations") or ()
        if isinstance(locations, str):
            locations = [locations]
        path = locations[0] if locations else ""
    if not path:
        return {"scope": SCOPE_HOST, "scope_id": "", "scope_release": ""}

    kind, scope_id, release = classify(path)
    return {"scope": kind, "scope_id": scope_id, "scope_release": release}


def purl_distro(purl: str) -> Tuple[str, str]:
    """Split a purl's distro qualifier into (id, release).

    Syft writes it as "distro=<id>-<versionID>", and the id itself can contain a
    hyphen -- "opensuse-leap-15.5". Splitting on the first hyphen would call that
    release "leap-15.5" and splitting on the last would call it "15.5" only by
    luck. The boundary is the first hyphen followed by a digit, which is the one
    place a version can start.

    Returns ("", "") for a purl with no distro qualifier, which is most of them:
    a Go module or an npm package has no distribution and must not be given one.
    """
    if "?" not in purl:
        return "", ""
    for part in purl.split("?", 1)[1].split("&"):
        if not part.startswith("distro="):
            continue
        value = urllib.parse.unquote(part[len("distro="):]).strip()
        m = re.search(r"-(?=\d)", value)
        if not m:
            return value.lower(), ""
        return value[:m.start()].lower(), value[m.start() + 1:]
    return "", ""


def apply_scope(component: dict) -> dict:
    """Return a copy of the component with scope fields resolved.

    For a scope whose release is known (an Ubuntu base snap), the distro
    release is rewritten to that root's release so the component is matched
    against the advisories that actually apply to it. For a scope whose release
    is unknown, the release is cleared rather than left as the host's, because
    matching against the host's release would be a confident wrong answer.
    """
    out = dict(component)
    info = component_scope(component)
    out.update(info)

    if info["scope"] == SCOPE_HOST:
        return out

    # A container's own OS, as the collector read it from inside that container.
    # This is not an inference from a path: swinv opened the container's
    # os-release and its package database. Refusing to use it would leave every
    # container unassessed -- which is the state this app was in until now, and
    # which draws as a container with no vulnerabilities rather than as one
    # nobody looked at.
    if info["scope"] == SCOPE_CONTAINER:
        root_os = (component.get("root_os_id") or "").strip()
        if root_os:
            out["os_id"] = root_os
            out["os_version_id"] = (component.get("root_os_version_id") or "").strip()
            return out
        # No root_os_id: read the distro out of the purl instead, but only for
        # a root the collector NAMED as a container. A path-classified one --
        # a dpkg status file spotted under /var/lib/docker/overlay2 -- is an
        # inference, and the case directly below this one exists because a
        # component whose evidence spans two roots can arrive carrying the
        # HOST's distro qualifier on a foreign package. Trusting the qualifier
        # there would match a Debian package against Ubuntu advisories, which
        # is the confident wrong answer this whole function is built to avoid.
        #
        #
        # Where the collector did name it, the package's own purl is not an
        # inference: an apk inside an Alpine container carries
        # distro=alpine-3.21.3 because that is the distribution that built it.
        # No collector this app has seen has ever sent root_os_id -- checked
        # against every event ever ingested -- so without this every container
        # package falls through to "refuse to assert a release" and can only be
        # matched on ecosystem, never against a distro security tracker.
        named = str(info.get("scope_id") or "").startswith("container:")
        distro_id, distro_release = purl_distro(component.get("purl") or "") if named \
            else ("", "")
        if distro_id:
            out["os_id"] = distro_id
            out["os_version_id"] = distro_release
            return out

    if info["scope_release"]:
        out["os_version_id"] = info["scope_release"]
        # A base snap is Ubuntu regardless of what the host runs.
        out["os_id"] = "ubuntu"
    else:
        # Unknown root: refuse to assert a distro release for it.
        out["os_version_id"] = ""
        out["os_id"] = ""
    return out
