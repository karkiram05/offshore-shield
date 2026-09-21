# Control mapping

This maps what OffshoreShield actually demonstrates to control families
named in IEC 62443, ISO/IEC 27001, and the EU NIS2 directive -- all of
which are public standards, none of which this project is certified
against. **This is a mapping of demonstrated capability to public control
language, not a compliance or certification claim.** No organization can
become IEC 62443- or ISO 27001-compliant by running this repo; those
require a certified assessment of a real organization's real environment,
people, and processes, not a portfolio project's lab.

| Control area | Referenced in | What this repo actually demonstrates | Status |
|---|---|---|---|
| Network segmentation (zones/conduits) | IEC 62443-3-3 SR 5.x, NIS2 Art. 21(2)(a) | Two independent layers: `lab/network_zones.json` defines explicit zones and an allow-list of legitimate cross-zone paths; `detection/rules.py`'s `cross_zone_violation` rule *detects* traffic that violates it, and `lab/segmentation/netns_lab.py`'s real Linux-namespace/nftables router *enforces* the same policy at the kernel level -- verified live, 20/20 (src_zone, dst_zone) cases matching the declared policy, disallowed pairs actually blocked, not just logged | Implemented, tested (both detect and enforce) |
| Asset visibility | IEC 62443-2-1, ISO 27001 A.5.9 | The network tap logs every connection to every lab asset, including register-level detail on Modbus writes; nothing reaches a simulated OT service unobserved | Implemented, tested |
| Security monitoring / detection | ISO 27001 A.8.16, NIS2 Art. 21(2)(b) | `detection/engine.py` runs continuously against live tap output; seven rules (port-scan, cross-zone, unexpected write, rogue master, automated collection, lateral-movement pivot, unsafe setpoint write) each with severity, ATT&CK mapping, and repeat-offender scoring | Implemented, tested |
| Remote/vendor access monitoring | IEC 62443-2-4, NIS2 Art. 21(2)(d) | `lab/network_zones.json` models a `vendor-remote` zone distinct from `it-enterprise`, enforced by the same namespace/nftables layer above; `vuln/ot_prioritizer.py` treats vendor-conduit reachability as a distinct risk factor | Implemented, tested |
| Vulnerability management with operational context | IEC 62443-2-1, ISO 27001 A.8.8 | `vuln/ot_prioritizer.py` computes operational risk from exposure/compensating-controls, not CVSS alone (see docs/results.md for a worked example) | Implemented, tested |
| Safe change/process control | IEC 62443-3-3 SR 3.x, ISO 27001 A.8.32 | `rule_unsafe_setpoint_write` distinguishes a mechanically abrupt control-setpoint change from a gradual ramp on a real Modbus write path, with explicit safety-impact framing rather than treating every write as equally severe | Implemented, tested |
| Incident detection & response evidence | NIS2 Art. 23 (incident reporting), ISO 27001 A.5.24-A.5.28 | `logs/alerts.log` and `scenarios/results/*.json` are timestamped, structured, regenerable evidence of a detection actually firing, across all five purple-team scenarios | Implemented, tested |
| Security testing / validation | IEC 62443-4-1, ISO 27001 A.8.29 | Five purple-team scenarios (`scenarios/scenario_*.py`) are real before/after validations against real (simulated) attack behavior -- discovery, lateral movement, process manipulation, network segmentation, and CI/CD identity | Implemented, tested |
| Supply-chain / CI security | NIS2 Art. 21(2)(d) (supply chain), ISO 27001 A.8.25-A.8.28 | SHA-pinned GitHub Actions, `contents: read` default permissions, hard-failing `pip-audit`, Dependabot -- same pattern as this author's other repos (see `.github/workflows/ci.yml`) | Implemented |

## What's deliberately not claimed here

- No safety-instrumented-system (SIS) or IEC 61511 mapping -- this lab has
  no safety layer to speak of, and claiming one would be actively
  misleading for anything genuinely safety-critical.
- No claim of coverage for physical security, personnel security, or
  organizational governance controls (most of ISO 27001 Annex A, most of
  IEC 62443-2-1) -- a code repository can't demonstrate those.
