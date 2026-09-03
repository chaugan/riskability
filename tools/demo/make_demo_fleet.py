#!/usr/bin/env python3
"""Demo inventory for the sample firewall topology, so routes have depth.

    python3 tools/demo/make_demo_fleet.py --end EPOCH > exposure.json
    python3 tools/demo/make_demo_fleet.py --end EPOCH --findings > findings.json

The sample edge table (sample_firewall_edges.csv) is a genuine three-hop
topology: 10.0.45.0/24 (jump hosts) -> 10.20.30.0/24 (app tier) ->
192.168.10.0/24 (database tier) -> 192.168.50.0/24 (core services). None of
its addresses is held by an inventory host, so the routes page can draw at
most one jump before the identity guard, correctly, stops attributing. This
gives the sample's hosts an inventory of their own: an exposure record per
listening port, bound to a SPECIFIC address, across several scans, which is
exactly the evidence the address snapshot derives a claim window from. Two
hosts in the same tier deliberately share one address across scans so the
guard's refusal shows up in the demo too.

Findings are seeded on the packages behind those ports so the last two
columns of the chain have something to draw. Every record carries
demo=true so the batch can be removed with one search.
"""
import json, random, sys, time

random.seed(11)
# host, tier address, listening ports -> (package, purl)
HOSTS = [
    ("demo-jump-01",  "10.0.45.10",     {22: ("openssh-server", "pkg:deb/ubuntu/openssh-server@1:9.6p1"), 3389: ("xrdp", "pkg:deb/ubuntu/xrdp@0.9.24")}),
    ("demo-jump-02",  "10.0.45.11",     {22: ("openssh-server", "pkg:deb/ubuntu/openssh-server@1:9.6p1")}),
    ("demo-app-01",   "10.20.30.10",    {443: ("nginx", "pkg:deb/ubuntu/nginx@1.24.0"), 8080: ("tomcat9", "pkg:deb/ubuntu/tomcat9@9.0.70")}),
    ("demo-app-02",   "10.20.30.11",    {443: ("nginx", "pkg:deb/ubuntu/nginx@1.24.0"), 22: ("openssh-server", "pkg:deb/ubuntu/openssh-server@1:9.6p1")}),
    ("demo-app-03",   "10.20.30.12",    {22: ("openssh-server", "pkg:deb/ubuntu/openssh-server@1:9.6p1"), 8080: ("tomcat9", "pkg:deb/ubuntu/tomcat9@9.0.70")}),
    ("demo-db-01",    "192.168.10.10",  {5432: ("postgresql-15", "pkg:deb/ubuntu/postgresql-15@15.6")}),
    ("demo-db-02",    "192.168.10.11",  {3306: ("mysql-server", "pkg:deb/ubuntu/mysql-server@8.0.36")}),
    ("demo-core-dns", "192.168.50.10",  {53: ("bind9", "pkg:deb/ubuntu/bind9@1:9.18.18")}),
    ("demo-core-ad",  "192.168.50.12",  {389: ("samba", "pkg:deb/ubuntu/samba@2:4.19.5"), 88: ("krb5-kdc", "pkg:deb/ubuntu/krb5-kdc@1.20.1"), 445: ("samba", "pkg:deb/ubuntu/samba@2:4.19.5")}),
    # The shared-address case, on purpose: two hosts claim 192.168.50.11 so a
    # flow to it is refused rather than attributed. That is the guard working
    # and the demo should show it.
    ("demo-core-ntp-a", "192.168.50.11", {123: ("chrony", "pkg:deb/ubuntu/chrony@4.5")}),
    ("demo-core-ntp-b", "192.168.50.11", {123: ("chrony", "pkg:deb/ubuntu/chrony@4.5")}),
]
# Findings per package: (cve, severity, epss, kev, fixed_version)
FINDINGS = {
    "openssh-server": [("CVE-2024-6387", "high", "0.91", "1", "1:9.8p1"), ("CVE-2023-51385", "medium", "0.12", "", "1:9.6p1-2")],
    "xrdp":           [("CVE-2023-42822", "critical", "0.44", "", "0.9.24")],
    "nginx":          [("CVE-2024-7347", "medium", "0.03", "", "1.26.2"), ("CVE-2023-44487", "high", "0.97", "1", "1.25.3")],
    "tomcat9":        [("CVE-2024-50379", "critical", "0.78", "", "9.0.98"), ("CVE-2024-56337", "critical", "0.61", "", "9.0.98"), ("CVE-2025-24813", "critical", "0.95", "1", "9.0.99")],
    "postgresql-15":  [("CVE-2024-10979", "high", "0.09", "", "15.9"), ("CVE-2025-1094", "high", "0.83", "1", "15.11")],
    "mysql-server":   [("CVE-2024-21096", "medium", "0.02", "", "8.0.37")],
    "bind9":          [("CVE-2024-1737", "high", "0.05", "", "1:9.18.24"), ("CVE-2024-0760", "high", "0.06", "", "1:9.18.24")],
    "samba":          [("CVE-2024-3596", "medium", "0.01", "", "2:4.19.7"), ("CVE-2025-37778", "high", "0.04", "", "2:4.20.5")],
    "krb5-kdc":       [("CVE-2024-37371", "critical", "0.15", "", "1.21.3")],
    "chrony":         [("CVE-2024-22212", "low", "0.01", "", "4.5-1")],
}


def main():
    end = int(sys.argv[sys.argv.index("--end") + 1]) if "--end" in sys.argv else int(time.time())
    scans = [end - 86400 * d - 3600 * 2 for d in (6, 4, 2, 0)]      # four scans over a week
    if "--findings" in sys.argv:
        n = 0
        for host, addr, ports in HOSTS:
            seen = set()
            for port, (pkg, purl) in ports.items():
                if pkg in seen:
                    continue
                seen.add(pkg)
                for cve, sev, epss, kev, fix in FINDINGS.get(pkg, []):
                    key = "demo%08x" % (hash((host, pkg, cve)) & 0xffffffff)
                    row = {"_key": key, "finding_key": key, "hostname": host, "package": pkg,
                           "path": "/var/lib/dpkg/info/%s.list" % pkg, "cve_id": cve, "severity": sev,
                           "epss": epss, "kev_added": ("2024-07-01" if kev else ""), "fixed_version": fix,
                           "first_version": purl.split("@")[-1], "last_version": purl.split("@")[-1],
                           "current_version": purl.split("@")[-1], "first_seen": str(scans[0]),
                           "last_seen": str(scans[-1]), "last_match_run": str(scans[-1]), "times_seen": "4",
                           "status": "open", "accepted": "0", "confidence": "high", "ecosystem": "deb",
                           "scope": "host", "match_authority": "ecosystem", "age_days": "6", "demo": "true"}
                    sys.stdout.write(json.dumps(row) + "\n"); n += 1
        sys.stderr.write("%d demo findings\n" % n)
        return
    n = 0
    for host, addr, ports in HOSTS:
        for t in scans:
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
            for port, (pkg, purl) in ports.items():
                ev = {"record_type": "exposure", "hostname": host, "scanned_at": stamp, "address": addr,
                      "port": port, "protocol": "udp" if port in (53, 123) else "tcp", "family": "ipv4",
                      "bind_scope": "specific", "purl": purl, "executable": "/usr/sbin/%s" % pkg.split("-")[0],
                      "confidence": "high", "root": "/", "demo": True, "time": t}
                sys.stdout.write(json.dumps(ev) + "\n"); n += 1
        # a heartbeat per scan so the host is "seen" and not aged out
        for t in scans:
            hb = {"record_type": "heartbeat", "hostname": host, "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)),
                  "swinv_version": "v0.9.6", "schema_version": 2, "scan_profile": "standard", "demo": True, "time": t}
            sys.stdout.write(json.dumps(hb) + "\n"); n += 1
    sys.stderr.write("%d demo exposure/heartbeat events for %d hosts\n" % (n, len(HOSTS)))


if __name__ == "__main__":
    main()
