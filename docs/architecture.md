# Architecture

## Why this isn't 8 Docker containers on a real bridge network (yet)

The original design called for one container per lab host (Kali,
jump-host, historian, HMI, engineering workstation, PLC/turbine
simulator) on a dedicated Docker network, matching a real IT/DMZ/OT
segmentation diagram. That's still the plan (see STATUS.md) -- but two
things are simulated differently today, and it's worth being explicit
about the trade-off rather than letting the docker-compose.yml imply more
than the current code does:

**Loopback-IP host simulation instead of separate containers.** Every
lab "host" (engineering workstation, corp laptop, vendor conduit, etc.) is
represented by a distinct address in `127.0.0.0/8` (`lab/network_zones.json`),
which Linux lets you bind to without any extra network setup. A scan or
Modbus client run with `--src-ip 127.0.0.30` genuinely originates from
that address at the OS level -- the network tap and detection engine see
real, distinguishable source IPs, real connection attempts, and real
timing. What's simulated is the *topology* (which host is "really" a
separate machine on its own subnet), not the *traffic*. Moving to real
containers on a Docker bridge network changes the topology from simulated
to real without changing any detection logic, because the detection rules
already key off IP/zone classification, not "which container this is."

**A custom network tap instead of Zeek.** Zeek isn't a pip package --
it's compiled from source or installed from a distro-specific package that
wasn't available in this project's build environment. Rather than claim
"Zeek" and ship something else, `lab/tap/network_tap.py` is a small,
honestly-scoped asyncio TCP proxy: every lab service sits behind one, so
any connection to it -- from this repo's own scanner, from real Modbus
tooling, eventually from a real nmap -- is necessarily observed and logged
in a conn.log-inspired format. It does one thing Zeek does (connection
metadata + light protocol awareness: it parses the Modbus MBAP header to
extract the function code) and doesn't attempt the rest (deep packet
inspection across arbitrary protocols, passive span-port capture, the full
Zeek scripting language). If you have Zeek available in your own
environment, swapping it in as the log source is a matter of pointing
`detection/engine.py` at whatever produces equivalent JSON records --
the detection rules don't care where conn.log came from.

## Real OS-level segmentation, without Docker (`lab/segmentation/`)

The plan above was to demonstrate zone enforcement -- not just detection
-- using per-host Docker containers on a dedicated bridge network. That
turned out not to be buildable in this project's actual build
environment: `docker pull` against both Docker Hub (`registry-1.docker.io`)
and `ghcr.io` returns `403 Forbidden` here, even though the Docker daemon
itself starts fine and has `CAP_NET_ADMIN`. Rather than drop the
enforcement demonstration entirely, `lab/segmentation/netns_lab.py` builds
it a different, real way: Linux network namespaces (`ip netns`), veth
links, and an nftables ruleset -- all kernel-level primitives, no
container runtime or registry required.

Concretely: one namespace per zone in `network_zones.json`, each
connected by its own point-to-point veth link to a router namespace with
IP forwarding enabled. The router's nftables `forward` chain is
generated directly from `allowed_cross_zone` (default-drop, one explicit
accept rule per allowed src-zone/dst-zone pair) -- not hand-duplicated,
so it cannot silently drift from the policy the detection engine reads.
`scenarios/scenario_network_segmentation.py` then makes a real TCP
connection attempt for every zone pair the policy has an opinion on and
checks whether the *kernel* actually let it through or dropped it -- this
is the one part of this repo that demonstrates prevention rather than
after-the-fact detection.

This is arguably a more honest demonstration of "real segmentation" than
Docker containers would have been: veth + netns + nftables is exactly the
mechanism a Docker bridge network uses under the hood (Docker itself is a
container-lifecycle and image-distribution tool built on these same
primitives), so this substitutes the orchestration layer that was blocked
for the actual enforcement mechanism it wraps, not for something weaker.
The container-per-host topology (separate root filesystems, separate
process trees) remains future work if that isolation boundary specifically
matters for a given use case -- see STATUS.md.

## Data flow

```
 real Kelmarsh SCADA data --> turbine_modbus_server.py (Modbus TCP, :5020)
 synthetic HVAC signal     --> hvac_modbus_server.py    (Modbus TCP, :5021)
                                        |
                                        | (backend connections)
                                        v
                              network_tap.py (per-service proxy)
                                :6502 (scada/turbine-plc)
                                :6521 (auxiliary/hvac-controller)
                                :6501/:6503/:6505/:6510/:6515 (decoy ports)
                                        |
                                        | logs every connection attempt
                                        v
                                  logs/conn.log (JSON lines)
                                        |
                                        v
                              detection/engine.py
                          (rules.py: port-scan, cross-zone,
                           unexpected Modbus write)
                                        |
                                        v
                         risk.py (confidence -> score -> severity,
                                   repeat-offender boost)
                                        |
                                        v
                              logs/alerts.log + terminal output,
                              each mapped to a verified ATT&CK-for-ICS
                              technique (detection/attck_ics.py)
```

`scenarios/scenario_discovery.py` drives a real scan through this whole
pipeline and reports measured before/after numbers -- see STATUS.md for
what's actually been run and `scenarios/results/discovery.json` for the
latest real output.

## Why the detection design borrows from SentinelFlow but doesn't import it

[SentinelFlow](https://github.com/karkiram05/sentinelflow) scores network
anomalies with a blended rule-confidence + repeat-offender-boost design
(`backend/app/detection/risk.py`). `detection/risk.py` here reuses that
exact design, reimplemented standalone rather than imported across repos,
for a boring but real reason: two independent portfolio projects
shouldn't have a runtime dependency on each other's internal package
layout, and a recruiter cloning this repo alone shouldn't have to also
clone a second one for `pip install -e .` to work. What doesn't carry over
is SentinelFlow's actual rule set: those rules operate on NSL-KDD-style
engineered features from a labeled intrusion-detection dataset, which has
no meaning for live Modbus/OT flow data. The rules in `detection/rules.py`
are new, written specifically against what a real OT network tap actually
observes.

## Roadmap

See STATUS.md's "Planned, not yet built" section -- kept there rather than
duplicated here so there's exactly one place this list can go stale.
