# Industry case study: Ørsted

**Disclaimer:** OffshoreShield is an independent portfolio project. It is
not affiliated with, commissioned by, or endorsed by Ørsted or any other
named company. Nothing in this repo touches, scans, or references
Ørsted's actual infrastructure. This document maps the project's design
choices to Ørsted's own public description of its cybersecurity work, as
one example of how this kind of OT security research applies to a real
offshore-wind/critical-infrastructure operator.

## Why Ørsted, specifically

Ørsted describes itself as providing critical energy infrastructure and
states, in its own public careers material, that its cybersecurity team's
work spans "developing strategy, guidance, and supervision to undertaking
penetration testing and security analytics and ensuring compliance"
([Ørsted IT & digital careers page](https://orsted.com/en/careers/areas-of-work/it-and-digital),
verified live as of September 2026). That's a close match to the shape of
this project: detection engineering (SentinelFlow), attack-path/CI-CD
security analysis (TrustGraph), and now OT-specific network security and
operationally-aware vulnerability triage (OffshoreShield) -- three
distinct security-engineering disciplines, not one narrow tool.

Public job postings for OT-focused roles at Ørsted (titles seen in a
September 2026 search: "OT Cyber Security Engineer," "OT Security
Engineer," "OT Network Engineer for Windfarm Networks" -- individual
postings rotate and expire, so specific listing URLs are not cited here
as durably live) consistently describe work spanning SIEM/OT security
monitoring, vulnerability assessment with operational risk judgment rather
than raw CVSS ranking, and IT/OT network segmentation. That pattern --
not any single job ad -- is what this project is built to demonstrate
competence in.

## What in this repo maps to that pattern

| Public pattern | What OffshoreShield demonstrates |
|---|---|
| OT security monitoring / SIEM-adjacent work | `detection/engine.py` + `lab/tap/network_tap.py`: a real, running detection pipeline over live OT network traffic |
| "Not blindly trusting vulnerability scanner results" -- assessing real operational risk | `vuln/ot_prioritizer.py`: computed operational risk from exposure/compensating-controls, not CVSS alone (worked example in docs/results.md) |
| IT/OT network segmentation | `lab/network_zones.json` + the `cross_zone_violation` rule, with a real measured before/after (docs/results.md) |
| Penetration testing / red-team-adjacent skills, cooperating with detection | `lab/scanner/ot_scanner.py` generating real traffic that `detection/rules.py` has to actually catch -- purple-team by construction, not by claim |
| Cloud/DevSecOps (AWS, Terraform, GitHub Actions, CI/CD security) | This author's [TrustGraph](https://github.com/karkiram05/trustgraph) project, and the same SHA-pinned/hardened CI pattern applied to this repo's own `.github/workflows/ci.yml` |
| Compliance awareness (IEC 62443, ISO 27001, NIS2 -- all public frameworks applicable to EU critical-infrastructure operators generally) | `compliance/control-mapping.md`, written as a mapping, explicitly not a certification claim |

## What this is not

This is not a claim to have found anything about Ørsted's actual security
posture, not a request for Ørsted's data or systems, and not a substitute
for the kind of assessment only a real OT security team with real access
could do. It's evidence that the author can design, build, and honestly
document a working OT detection and risk-triage system from public
information about what the job actually requires -- which is the thing a
resume bullet point can't show and a working repository can.
