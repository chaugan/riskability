#!/usr/bin/env python3
"""Turn the FW Route Explorer sample edges into firewall events for a demo index.

    python3 tools/demo/make_firewall_events.py [--days 7 | --minutes 45] [--end EPOCH] [--chain-only] > events.json

--chain-only emits only the worst-case chain (CHAIN below), for topping up a
demo index that already holds the sample.

--end pins the newest event to a moment rather than to now. It exists because
the identity guard is strict on purpose: a flow is attributed to a host only
if a scan saw the host holding the destination address in a window around
the flow, and a demo generated "now" against an inventory last scanned days
ago resolves nothing. Point --end at the hosts' last scan and the demo
resolves; that is the guard working, not a limitation to route around.

The sample (tools/demo/sample_firewall_edges.csv, from
github.com/chaugan/Find-Route) is a topology: unique src, dest, port edges
with a session count. It lives in 10.0.45.x and 192.168.50.x, addresses no
host in this app's inventory has ever held, so loaded as-is it would draw a
graph that touches no host and every Network evidence row would stay unknown.

Two things are done to it. The session counts become that many CIM-shaped
events (src_ip, dest_ip, dest_port, transport, action=allowed) spread over
the last N days, so the generated edge macro has real events to reduce; and
a small number of edges are ADDED that land on addresses the inventory hosts
hold, from the two entry points the demo declares, so the routes page has a
host to resolve. The additions are marked in a comment column so nobody
mistakes them for the upstream sample. Nothing in the sample is altered.

Bounded: the sample sums to about 60,000 sessions, which is capped per edge
so a demo index holds a few thousand events, not sixty thousand.
"""
import csv, json, random, sys, time, os

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample_firewall_edges.csv")

# Where the demo's routes end up: an address a real inventory host holds.
# fnaskZenbook holds 192.168.86.223 (measured). 62.238.42.61 is held by two
# hosts and is refused by the identity guard on purpose, so flows to it show
# the refusal panel rather than a host.
LANDING = [
    ("203.0.113.7",  "192.168.86.223", 4002,  "internet edge -> fnaskZenbook:4002"),
    ("203.0.113.9",  "192.168.86.223", 4002,  "internet edge -> fnaskZenbook:4002"),
    ("203.0.113.7",  "192.168.86.223", 42050, "internet edge -> fnaskZenbook:42050"),
    ("10.0.45.10",   "192.168.86.223", 42050, "sample jump host -> fnaskZenbook:42050"),
    ("203.0.113.22", "62.238.42.61",   8443,  "internet edge -> shared address, refused by design"),
    ("10.0.45.5",    "62.238.42.61",   5432,  "sample -> shared address, refused by design"),
]
# A worst case, on purpose: a chain from the internet edge that lands on a
# CVE-enabled listener at every jump, so the routes page has a path that stays
# red for four jumps. The sample's own lateral flows hit ports nothing in the
# demo fleet listens on (1433, 1521, 49152), which is realistic and shows the
# "permitted only" grade, and it also means no sample path stays red past the
# first jump. These land where the demo fleet's vulnerable software listens:
# nginx on demo-app-01, postgres on demo-db-01, bind on demo-core-dns, the KDC
# on demo-core-ad, tomcat on demo-app-03.
CHAIN = [
    ("203.0.113.40", "10.20.30.10",   443,  "internet edge -> demo-app-01:443 (nginx)"),
    ("203.0.113.41", "10.20.30.10",   443,  "internet edge -> demo-app-01:443 (nginx)"),
    ("10.20.30.10",  "192.168.10.10", 5432, "demo-app-01 -> demo-db-01:5432 (postgres)"),
    ("192.168.10.10", "192.168.50.10", 53,  "demo-db-01 -> demo-core-dns:53 (bind)"),
    ("192.168.50.10", "192.168.50.12", 88,  "demo-core-dns -> demo-core-ad:88 (kdc)"),
    ("192.168.50.12", "10.20.30.12",  8080, "demo-core-ad -> demo-app-03:8080 (tomcat)"),
]
CAP = 120          # events per edge at most
DAYS = 7
random.seed(7)

def main():
    days = DAYS
    if "--days" in sys.argv:
        days = int(sys.argv[sys.argv.index("--days") + 1])
    # --minutes spans the events over minutes rather than days. The identity
    # guard attributes a flow to a host only when a scan saw the host holding
    # the address in a window around the flow, and on a fleet scanned once
    # that window is the length of one scan: on the dev fleet, fifty minutes.
    # A demo has to land inside it to resolve at all.
    minutes = None
    if "--minutes" in sys.argv:
        minutes = int(sys.argv[sys.argv.index("--minutes") + 1])
    now = int(time.time())
    if "--end" in sys.argv:
        now = int(sys.argv[sys.argv.index("--end") + 1])
    span = minutes * 60 if minutes else days * 86400
    edges = []
    with open(SAMPLE, newline="") as fh:
        for row in csv.DictReader(fh):
            edges.append((row["src_ip"], row["dest_ip"], int(row["port"]),
                          min(CAP, int(row["sessions"])), "sample"))
    for src, dst, port, note in LANDING:
        edges.append((src, dst, port, 40, note))
    if "--chain-only" in sys.argv:
        edges = []
    for src, dst, port, note in CHAIN:
        edges.append((src, dst, port, 60, note))
    n = 0
    for src, dst, port, count, note in edges:
        for _ in range(count):
            t = now - random.randint(1, span)
            ev = {"time": t, "src_ip": src, "dest_ip": dst, "dest_port": port,
                  "transport": "udp" if port in (53, 123, 514) else "tcp",
                  "action": "allowed", "bytes": random.randint(200, 90000),
                  "dvc": "demo-fw-1", "rule": "permit-%s" % port, "note": note}
            sys.stdout.write(json.dumps(ev) + "\n")
            n += 1
    sys.stderr.write("%d events across %d edges\n" % (n, len(edges)))

if __name__ == "__main__":
    main()
