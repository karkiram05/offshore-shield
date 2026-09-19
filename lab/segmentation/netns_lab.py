#!/usr/bin/env python3
"""Real, OS-level network segmentation using Linux network namespaces,
veth links, and nftables -- an honest substitute for the docker-compose
per-container topology this repo's docs describe, in an environment where
Docker Hub and ghcr.io are both unreachable (see docs/architecture.md for
why, and the "why not Docker here" note in this module's own docs entry).

Everything else in this repo's lab/ (the network tap, the Modbus
simulators) proves the *detection* side of OffshoreShield: it watches
traffic and flags what shouldn't happen. This module proves the
*enforcement* side: it builds a real router namespace with real nftables
forward rules generated directly from lab/network_zones.json's
allowed_cross_zone policy, so a disallowed cross-zone connection doesn't
just get logged after the fact -- the kernel drops the packets before
they arrive. Two separate, real mechanisms, on the same policy source of
truth, is the honest way to demonstrate both detect and prevent without
either one silently standing in for the other.

Topology: one root-namespace router (ns-offshoreshield-rtr) with one
veth link to each zone's own namespace (ns-offshoreshield-<zone>), each
on its own /30 point-to-point subnet. IP forwarding is enabled in the
router namespace; its nftables `forward` chain default-drops and only
explicitly accepts (src_zone -> dst_zone) pairs present in
allowed_cross_zone -- generated, not hand-duplicated, so it can never
drift from the same policy the detection engine reads.

Each zone namespace runs a minimal TCP listener (reusing the
mgmt-banner-sim style: it identifies itself and closes) representing
"the service reachable in that zone," so connectivity tests are real
TCP handshakes through the kernel's actual forwarding/filtering path,
not a simulation of one.

Requires root (or CAP_NET_ADMIN) and the `ip` and `nft` binaries. Not
usable inside an unprivileged container without those capabilities --
this sandbox has them (verified: `ip netns add` and loading an nftables
ruleset both work as root with CAP_NET_ADMIN, even though the Docker
*registries* are unreachable here -- a separate, unrelated restriction).

Usage:
    python3 lab/segmentation/netns_lab.py up
    python3 lab/segmentation/netns_lab.py test
    python3 lab/segmentation/netns_lab.py down
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess  # nosec B404
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ZONES_PATH = REPO_ROOT / "lab" / "network_zones.json"
NS_PREFIX = "offshoreshield"
ROUTER_NS = f"{NS_PREFIX}-rtr"
LISTEN_PORT = 7000

# Short, unique codes for each zone -- interface names are limited to 15
# characters (IFNAMSIZ), so full zone names like "ot-engineering" don't
# fit once prefixed. This mapping only affects interface/namespace
# naming; the policy itself is still read from network_zones.json's own
# zone names.
ZONE_CODES = {
    "scada": "scada",
    "auxiliary": "aux",
    "ot-engineering": "oteng",
    "dmz": "dmz",
    "it-enterprise": "itent",
    "vendor-remote": "vremote",
}


@dataclass
class ZoneNet:
    zone: str
    code: str
    subnet: ipaddress.IPv4Network  # /30
    router_ip: ipaddress.IPv4Address
    host_ip: ipaddress.IPv4Address

    @property
    def netns(self) -> str:
        return f"{NS_PREFIX}-{self.code}"

    @property
    def veth_host(self) -> str:
        return f"vh-{self.code}"

    @property
    def veth_router(self) -> str:
        return f"vr-{self.code}"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)  # nosec B603


def run_ok(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Like run(), but doesn't raise on nonzero exit -- for teardown steps
    that should be idempotent (e.g. deleting a namespace that may already
    be gone)."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)  # nosec B603


def load_zone_policy() -> dict:
    with open(ZONES_PATH) as f:
        return json.load(f)


def build_zone_nets(policy: dict) -> list[ZoneNet]:
    """One /30 per zone that appears anywhere in the policy (as a key or
    an allowed value), carved out of 10.50.200.0/23 -- a block distinct
    from anything else this lab uses (loopback 127.0.0.x for the tap
    lab, 10.0.0.x in unit tests) so the two never collide."""
    zones_seen: list[str] = []
    for dst_zone, allowed_srcs in policy.get("allowed_cross_zone", {}).items():
        if dst_zone not in zones_seen:
            zones_seen.append(dst_zone)
        for src_zone in allowed_srcs:
            if src_zone not in zones_seen:
                zones_seen.append(src_zone)

    nets = []
    base = ipaddress.ip_network("10.50.200.0/23")
    subnets = list(base.subnets(new_prefix=30))
    for i, zone in enumerate(zones_seen):
        if zone not in ZONE_CODES:
            raise ValueError(f"Zone {zone!r} from network_zones.json has no entry in ZONE_CODES -- add one (<=11 chars)")
        subnet = subnets[i]
        hosts = list(subnet.hosts())
        nets.append(ZoneNet(zone=zone, code=ZONE_CODES[zone], subnet=subnet, router_ip=hosts[0], host_ip=hosts[1]))
    return nets


def teardown(nets: list[ZoneNet]) -> None:
    """Idempotent: safe to call even if nothing is up yet."""
    for z in nets:
        run_ok(["pkill", "-f", f"netns_lab_listener.py --zone {z.zone}"])
        run_ok(["ip", "netns", "del", z.netns])
    run_ok(["ip", "netns", "del", ROUTER_NS])


def build(nets: list[ZoneNet]) -> None:
    teardown(nets)  # start clean

    run(["ip", "netns", "add", ROUTER_NS])
    run(["ip", "netns", "exec", ROUTER_NS, "ip", "link", "set", "lo", "up"])
    run(["ip", "netns", "exec", ROUTER_NS, "sysctl", "-qw", "net.ipv4.ip_forward=1"])

    for z in nets:
        run(["ip", "netns", "add", z.netns])
        run(["ip", "link", "add", z.veth_host, "type", "veth", "peer", "name", z.veth_router])
        run(["ip", "link", "set", z.veth_host, "netns", z.netns])
        run(["ip", "link", "set", z.veth_router, "netns", ROUTER_NS])

        run(["ip", "netns", "exec", z.netns, "ip", "addr", "add", f"{z.host_ip}/30", "dev", z.veth_host])
        run(["ip", "netns", "exec", z.netns, "ip", "link", "set", z.veth_host, "up"])
        run(["ip", "netns", "exec", z.netns, "ip", "link", "set", "lo", "up"])
        run(["ip", "netns", "exec", z.netns, "ip", "route", "add", "default", "via", str(z.router_ip)])

        run(["ip", "netns", "exec", ROUTER_NS, "ip", "addr", "add", f"{z.router_ip}/30", "dev", z.veth_router])
        run(["ip", "netns", "exec", ROUTER_NS, "ip", "link", "set", z.veth_router, "up"])

        subprocess.Popen(  # nosec B603 B607 -- "ip" resolved via PATH is intentional, matches the rest of this lab's use of `ip netns exec`
            [
                "ip", "netns", "exec", z.netns,
                sys.executable, str(Path(__file__).parent / "netns_lab_listener.py"),
                "--zone", z.zone, "--host", str(z.host_ip), "--port", str(LISTEN_PORT),
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    time.sleep(0.5)  # let listeners bind


def load_firewall(nets: list[ZoneNet], policy: dict) -> str:
    """Generates and loads an nftables ruleset in the router namespace,
    directly from allowed_cross_zone -- default-drop forward chain, one
    accept rule per (src_zone -> dst_zone) pair the policy allows. Returns
    the ruleset text (also useful for the scenario/docs to show what was
    actually loaded, not just claim it)."""
    by_zone = {z.zone: z for z in nets}
    rules = [
        "table inet segmentation {",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "    ct state established,related accept",
    ]
    for dst_zone, allowed_srcs in policy.get("allowed_cross_zone", {}).items():
        dst = by_zone[dst_zone]
        for src_zone in allowed_srcs:
            src = by_zone[src_zone]
            rules.append(f'    iifname "{src.veth_router}" oifname "{dst.veth_router}" accept')
    rules.append("  }")
    rules.append("}")
    ruleset = "\n".join(rules) + "\n"

    proc = subprocess.run(  # nosec B603 B607 -- "ip"/"nft" resolved via PATH is intentional, matches the rest of this lab's use of `ip netns exec`
        ["ip", "netns", "exec", ROUTER_NS, "nft", "-f", "-"],
        input=ruleset, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nft load failed: {proc.stderr}\nRuleset was:\n{ruleset}")
    return ruleset


def test_connectivity(nets: list[ZoneNet], src_zone: str, dst_zone: str, timeout: float = 2.0) -> bool:
    """Real TCP connect attempt from src_zone's namespace to dst_zone's
    listener, through the router namespace's actual forwarding/filtering
    path. Returns True if the connection succeeded."""
    by_zone = {z.zone: z for z in nets}
    src, dst = by_zone[src_zone], by_zone[dst_zone]
    proc = subprocess.run(  # nosec B603 B607 -- "ip" resolved via PATH is intentional, matches the rest of this lab's use of `ip netns exec`
        [
            "ip", "netns", "exec", src.netns,
            sys.executable, "-c",
            (
                "import socket,sys\n"
                "s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                f"s.settimeout({timeout})\n"
                "try:\n"
                f"    s.connect(('{dst.host_ip}', {LISTEN_PORT}))\n"
                "    s.recv(64)\n"
                "    print('OK')\n"
                "except Exception as e:\n"
                "    print('FAIL', type(e).__name__, e)\n"
            ),
        ],
        capture_output=True, text=True, timeout=timeout + 2,
    )
    return proc.stdout.strip().startswith("OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["up", "down", "test"])
    args = parser.parse_args()

    policy = load_zone_policy()
    nets = build_zone_nets(policy)

    if args.action == "up":
        build(nets)
        ruleset = load_firewall(nets, policy)
        print(f"[netns-lab] {len(nets)} zone namespace(s) + router namespace up, nftables ruleset loaded:")
        print(ruleset)
    elif args.action == "down":
        teardown(nets)
        print("[netns-lab] torn down.")
    elif args.action == "test":
        allowed = policy.get("allowed_cross_zone", {})
        results = []
        for dst_zone, allowed_srcs in allowed.items():
            for src_zone in [z.zone for z in nets]:
                if src_zone == dst_zone:
                    continue
                expected_allowed = src_zone in allowed_srcs
                actual_allowed = test_connectivity(nets, src_zone, dst_zone)
                results.append({
                    "src_zone": src_zone, "dst_zone": dst_zone,
                    "expected_allowed": expected_allowed, "actual_allowed": actual_allowed,
                    "matches_policy": expected_allowed == actual_allowed,
                })
        print(json.dumps(results, indent=2))
        if not all(r["matches_policy"] for r in results):
            sys.exit(1)


if __name__ == "__main__":
    main()
