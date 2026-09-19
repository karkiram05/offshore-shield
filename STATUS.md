# Status

_Last updated 2026-09-19: all originally-scoped items below are now
implemented and tested; see "Deliberate substitutions" for the two
places the implementation differs honestly from the original plan, and
why._

Honest tracking of what's actually implemented and tested vs. planned.
Read this before docs/results.md or any scenario output -- it tells you
which numbers are real measurements from working code and which parts are
still roadmap. Updated as work happens, not written once and left stale.

## Implemented and tested (real, runnable, has passing tests)

- **Turbine simulator** (`lab/plc_sim/turbine_modbus_server.py`) -- real
  Modbus TCP server serving real Kelmarsh Wind Farm SCADA data (see
  `data/kelmarsh/README.md` for the real-vs-excerpt caveat) as holding
  registers. Verified against a live Modbus client. Also exposes one
  writable holding register (40007, `curtailment_setpoint_pct`) for the
  process-manipulation scenario below -- TelemetryFeeder never overwrites
  it, so a written value persists exactly like a real turbine's control
  setpoint would.
- **HVAC simulator** (`lab/plc_sim/hvac_modbus_server.py`) -- synthetic
  signal, honestly labeled as such (no public HVAC dataset used).
- **Remote-management banner service** (`lab/services/mgmt_banner_service.py`)
  -- a minimal, explicitly-synthetic asyncio service (not a real SSH
  implementation) representing "the management port" on the jump host and
  engineering workstation for the lateral-movement scenario.
- **Network tap** (`lab/tap/network_tap.py`) -- a real asyncio TCP proxy
  that logs every connection (5-tuple, timing, byte counts, parsed Modbus
  function code, and -- for Write Single Register -- the register address
  and value written) to `logs/conn.log`. This is explicitly not Zeek --
  see docs/architecture.md for why and what the difference actually is.
- **Detection engine** (`detection/`) -- seven real rules running against
  real tap output, each mapped to a verified MITRE ATT&CK for ICS
  technique ID (`detection/attck_ics.py`):
  - `port_scan_discovery` (T0846/T0840) -- many distinct services touched
    by one source in a short window.
  - `cross_zone_violation` (T0886) -- a source zone not on the
    destination zone's allow-list.
  - `unexpected_modbus_write` (T0836) -- any write-type Modbus function
    code against a lab asset modeled as read-only.
  - `rogue_master` (T0848) -- a source outside the provisioned-host
    inventory reaching an OT-zone asset directly.
  - `automated_collection` (T0802) -- many requests to the *same*
    destination in a short window, faster than the lab's own telemetry
    feeder polls.
  - `lateral_movement_pivot` (T0859) -- a sequence rule: a host reached
    as a destination that shortly after becomes a source into a new
    zone, catching a two-hop pivot where each individual hop is
    zone-allowed.
  - `unsafe_setpoint_write` (T0836) -- distinguishes an abrupt, large
    Modbus setpoint change from a gradual ramp, with real
    mechanical-safety framing (drivetrain/blade-pitch stress), co-firing
    intentionally alongside `unexpected_modbus_write` as defense-in-depth
    rather than suppressing the overlap.

  26 passing unit tests. Verified end-to-end against live scenarios (see
  below).
- **OT-aware vulnerability prioritizer** (`vuln/ot_prioritizer.py`) -- a
  real, computed rules engine (not a lookup table) taking CVSS + exposure +
  compensating-control context and producing an operational risk score and
  recommended treatment. 5 passing unit tests, including one that proves
  the whole point of the module: a lower-CVSS, internet-exposed finding
  outranks a higher-CVSS isolated one.
- **Discovery scenario** (`scenarios/scenario_discovery.py`) -- runs a
  real port scan against the live lab, replays the captured real
  conn.log records through the detection engine under a deliberately
  loose "before hardening" zone policy and the corrected "after" policy,
  and reports real measured counts and detection latency.
- **Lateral-movement scenario** (`scenarios/scenario_lateral_movement.py`)
  -- a two-hop pivot: an IT-zone host reaches the DMZ jump host's
  management port (individually zone-allowed), then the jump host itself
  reaches the engineering workstation's management port (also
  individually allowed). Neither hop trips `cross_zone_violation` alone;
  `lateral_movement_pivot` catches the two-hop pattern. Verified live:
  0 cross-zone-violation alerts, 1 pivot alert, on the real captured
  records.
- **Process-manipulation scenario**
  (`scenarios/scenario_process_manipulation.py`) -- sends real Modbus
  writes through a real pymodbus client: a ramped five-step sequence
  (0->25%), then one abrupt jump (25->100%). Verified live: every write
  trips the broader `unexpected_modbus_write`, but only the abrupt jump
  trips `unsafe_setpoint_write` -- the ramped steps are each too small to
  read as unsafe.
- **Real OS-level network segmentation**
  (`lab/segmentation/netns_lab.py`, `scenarios/scenario_network_segmentation.py`)
  -- one Linux network namespace per zone, connected via veth to a router
  namespace running an nftables forward chain generated directly from
  `network_zones.json`'s `allowed_cross_zone` policy. A real TCP
  connection attempt is made for every (src_zone, dst_zone) pair the
  policy has an opinion on. Verified live: all 20 cases match the
  declared policy -- 6/6 allowed pairs connected, 14/14 disallowed pairs
  were actually blocked by the kernel. This is the one part of the repo
  that demonstrates prevention, not just detection -- see "Deliberate
  substitutions" below for why namespaces instead of Docker containers.
- **Static dashboard** (`dashboard/generate_dashboard.py` ->
  `dashboard/index.html`) -- a small, read-only, statically-generated
  view built from two real sources on disk: every
  `scenarios/results/*.json` file (rendered generically, so a new
  scenario's results show up automatically) and `detection/rules.py`'s
  own source, parsed for each rule's docstring summary and the ATT&CK
  technique ID(s) it actually uses -- not a hand-maintained table that
  could drift from the rule code. Regenerate with `make dashboard`.
- **CI/CD identity scenario** (`scenarios/scenario_cicd_identity.py`) --
  a small fictional GitHub Actions pipeline (`cicd/vulnerable-workflow/`,
  `cicd/hardened-workflow/`) that publishes turbine firmware/config
  bundles via OIDC-assumed AWS access, scanned with TrustGraph's real
  detection engine (github.com/karkiram05/trustgraph, a genuine
  dependency -- see requirements.txt, not a reimplementation). 5 real
  findings before hardening (wildcard OIDC trust, missing audience
  restriction, an overpermissioned token, two unpinned actions), 0
  after. Also surfaced and fixed a real bug in TrustGraph itself: a
  `resources.json` entry naming a role that doesn't match any
  trust-policy file used to silently corrupt the graph instead of
  erroring -- see trustgraph's `graph/builder.py` and its new
  regression test.

Run `make test` for the unit tests. `make lab-up` starts the live lab,
after which `make demo-discovery`, `make demo-lateral-movement`, or
`make demo-process-manipulation` each run a real scenario against it.
`make demo-network-segmentation` is standalone (builds and tears down its
own namespaces, needs root/CAP_NET_ADMIN) and `make demo-cicd` is
standalone (no live lab needed). `make dashboard` regenerates
`dashboard/index.html` from whatever's currently in `scenarios/results/`.

## Implemented, not yet wired into a full scenario

- `docs/orsted-case-study.md` and `compliance/control-mapping.md` are
  written but reference the scenarios above at a point-in-time; they were
  last extended alongside the CI/CD identity scenario and haven't yet
  been updated for the four scenarios added since (lateral movement,
  process manipulation, network segmentation, and the dashboard).

## Deliberate substitutions (not silent scope-cuts)

Two places where the original plan called for one specific technology
and the actual build uses a different, real one instead -- documented
here and in docs/architecture.md rather than left implicit:

- **Network segmentation via Linux namespaces, not docker-compose.**
  `docker pull` against both Docker Hub and ghcr.io returns 403 Forbidden
  in this project's build environment, confirmed directly, even though
  the Docker daemon itself starts fine with `CAP_NET_ADMIN` available.
  veth + network namespaces + nftables is the same mechanism a Docker
  bridge network uses under the hood, so `lab/segmentation/netns_lab.py`
  substitutes the container-orchestration layer that was blocked for the
  actual kernel-level enforcement primitives it wraps -- not for
  something weaker. The container-per-host topology (separate root
  filesystems/process trees, as opposed to shared-kernel namespaces)
  remains future work if that specific isolation boundary matters for a
  given use case.
- **A custom network tap, not Zeek.** Zeek isn't installable in this
  build environment (see docs/architecture.md). `lab/tap/network_tap.py`
  is a small, honestly-scoped asyncio TCP proxy that captures exactly the
  signal this lab's detections need (connection 5-tuples, timing, and
  Modbus function-code/register parsing) and doesn't claim the rest of
  what Zeek does.

## Explicitly not building

- Any component that requires or resembles a real penetration-testing
  toolkit pointed at anything other than this lab's own simulated,
  fictional hosts.
- A "compliance certified" claim of any kind -- `compliance/control-mapping.md`
  states plainly that this maps to public control frameworks, not that it
  satisfies them for any real organization.
- Separate per-host Docker containers, given the registry restriction
  above -- the network-namespace substitution is the enforcement
  demonstration this repo ships instead, not a placeholder for containers
  still to come.
