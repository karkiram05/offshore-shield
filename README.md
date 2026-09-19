# OffshoreShield

An isolated OT (operational technology) security research lab: a
simulated renewable-energy control network, a real network tap, a
detection engine mapped to MITRE ATT&CK for ICS, and an OT-aware
vulnerability prioritizer that computes operational risk from exposure and
compensating controls instead of ranking purely on CVSS.

Built as an independent portfolio project to study the specific security
problems public job postings and industry frameworks describe for
critical-infrastructure OT security roles -- not a generic pentesting lab.
See [`docs/orsted-case-study.md`](docs/orsted-case-study.md) for a worked
example against one real operator's publicly described requirements.
**Not affiliated with or endorsed by any named company.**

**Read [`STATUS.md`](STATUS.md) before anything else.** It tracks exactly
what's implemented and tested vs. still planned. Nothing below claims more
than STATUS.md backs up.

## What's real right now

- A Modbus TCP server replaying real [Kelmarsh Wind Farm](https://zenodo.org/records/15799719)
  SCADA data (CC-BY-4.0) as turbine telemetry
- A synthetic (honestly labeled, not real-data-backed) HVAC/auxiliary
  simulator on a separate logical zone
- A real network tap (`lab/tap/network_tap.py`) -- not Zeek, and it says
  why in [`docs/architecture.md`](docs/architecture.md) -- that logs every
  connection any tool makes to the lab, including parsed Modbus function
  codes
- Three detection rules (port-scan/discovery, cross-zone violation,
  unexpected Modbus write) each mapped to a verified MITRE ATT&CK for ICS
  technique, with 11 passing unit tests
- An OT-aware vulnerability prioritizer with 5 passing unit tests,
  including one that proves its actual point: a lower-CVSS, exposed
  finding can and does outrank a higher-CVSS isolated one
- A purple-team scenario harness that runs a real scan against the live
  lab and measures real detection latency and before/after counts --
  numbers in [`docs/results.md`](docs/results.md) come from rerunning
  this, not from hand-typing
- A CI/CD identity scenario (`cicd/`, `scenarios/scenario_cicd_identity.py`)
  that scans a fictional turbine-firmware deploy pipeline with
  [TrustGraph](https://github.com/karkiram05/trustgraph) -- a real
  dependency, not a reimplementation -- and measures real findings
  before/after hardening the workflow permissions and OIDC trust policy

## Quickstart

Works in GitHub Codespaces (zero local setup -- open this repo in a
Codespace and the devcontainer installs everything), or locally:

```bash
pip install -r requirements.txt
make fetch-dataset      # full real Kelmarsh dataset (falls back to a
                         # committed 20-row real excerpt if you skip this --
                         # see data/kelmarsh/README.md)
make lab-up              # starts the turbine + HVAC simulators and the tap
make demo-discovery      # runs a real scan and detection scenario end to end
make demo-cicd           # scans the CI/CD identity fixtures with TrustGraph
make test                # unit tests, no live processes required
```

`make demo-discovery` prints real, freshly computed before/after detection
numbers and writes them to `scenarios/results/discovery.json`.

To watch alerts live while you interact with the lab yourself:

```bash
python3 detection/engine.py    # tails logs/conn.log, prints alerts as they fire
```

## Project layout

```
lab/            simulators (turbine, HVAC), the network tap, the scanner
detection/      rules, ATT&CK-for-ICS mapping, risk scoring, the engine
vuln/           the OT-aware vulnerability prioritizer
cicd/           fictional CI/CD fixtures for the TrustGraph identity scenario
scenarios/      scenario scripts + their real generated results
compliance/     public control-framework mapping (not a certification claim)
data/kelmarsh/  real public SCADA data + provenance
docs/           architecture, results, ethics, the Ørsted case study
tests/          unit tests, no live processes required
```

## Why this exists

CVSS scores and generic vulnerability scanners answer "how bad is this in
the abstract." Real OT security work -- the kind described in public job
postings for critical-infrastructure operators -- asks a different
question: given where this asset actually sits, what's actually reachable,
and what breaks if you patch it right now. This project is built to
demonstrate that specific kind of judgment in working code, not just claim
it in a README.

See [`docs/ethics.md`](docs/ethics.md) for scope boundaries -- nothing
here touches, scans, or references any real organization's infrastructure.
