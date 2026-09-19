# Industry case study: Ørsted

**Disclaimer:** OffshoreShield is an independent portfolio project. It is
not affiliated with, commissioned by, or endorsed by Ørsted or any other
named company. Nothing in this repo touches, scans, or references
Ørsted's actual infrastructure. This document maps the project's design
choices to Ørsted's own public description of its cybersecurity work and
to a specific, currently open OT-security job posting, as one example of
how this kind of research applies to a real offshore-wind operator.

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

## A specific, currently open posting

As of 19 September 2026, Ørsted has an open req for
[**OT Compliance Manager (m/f/d)**](https://orsted.com/en/careers/vacancies-list/2026/04/32212-ot-compliance-manager-m-f-d)
(Gentofte, Skærbæk, Warsaw, Hamburg -- application deadline 20 September
2026 per the listing, so treat the link as likely expired if you're
reading this later; individual postings rotate and expire, which is why
the rest of this project avoids citing specific listing URLs as durably
live). Quoting its stated requirements directly:

> "very good knowledge and understanding about industrial standards like
> ISO27001, -2, -5 and IEC62443"

> "are capable to fully understand and get familiar with national and/or
> energy market specific standards and regulations like NIS2, UK NIS CAF,
> German IT Sicherheitskatalog and KRITIS regulations and US NERC CIP and
> understanding of how it applies to OT environments"

> "have experience with security and compliance in the OT area (e.g. ICS
> & SCADA systems and components, i.e. PLCs, HMIs, RTUs, and auxiliary
> system like HVAC, LV Systems, UPS etc.)"

That last line is a near-exact description of what OffshoreShield's lab
actually simulates: a PLC (`lab/plc_sim/turbine_modbus_server.py`) and an
auxiliary HVAC system (`lab/plc_sim/hvac_modbus_server.py`), on distinct
zones, with the exact standards named above (ISO 27001, IEC 62443, NIS2)
mapped -- not asserted -- in `compliance/control-mapping.md`. This isn't
a coincidence the project was built around after the fact: it's read as
confirmation the OT-plus-compliance-plus-real-standards shape of this
project matches what the role actually asks for, checked against a live
posting rather than assumed.

Public job postings for OT-focused roles at Ørsted more broadly (titles
seen across a September 2026 search: "OT Cyber Security Engineer," "OT
Security Engineer," "OT Compliance Manager," "OT Network Engineer for
Windfarm Networks," "Senior OT Risk Manager," "Lead SCADA U.S.
Specialist") consistently describe work spanning SIEM/OT security
monitoring, vulnerability assessment with operational risk judgment
rather than raw CVSS ranking, IT/OT network segmentation, and — per the
posting above — compliance mapped against named industrial standards.
That sustained pattern, not any single ad, is what this project is built
to demonstrate competence in.

## What in this repo maps to that pattern

| Public pattern | What OffshoreShield demonstrates |
|---|---|
| OT security monitoring / SIEM-adjacent work | `detection/engine.py` + `lab/tap/network_tap.py`: a real, running detection pipeline over live OT network traffic |
| "Not blindly trusting vulnerability scanner results" -- assessing real operational risk | `vuln/ot_prioritizer.py`: computed operational risk from exposure/compensating-controls, not CVSS alone (worked example in docs/results.md) |
| IT/OT network segmentation | `lab/network_zones.json` + the `cross_zone_violation` rule, with a real measured before/after (docs/results.md) |
| Penetration testing / red-team-adjacent skills, cooperating with detection | `lab/scanner/ot_scanner.py` generating real traffic that `detection/rules.py` has to actually catch -- purple-team by construction, not by claim |
| Compliance mapped to named standards (ISO 27001, IEC 62443, NIS2 -- explicitly named in the posting above) | `compliance/control-mapping.md`, written as a mapping, explicitly not a certification claim |
| ICS/SCADA components: PLCs, auxiliary systems like HVAC (explicitly named in the posting above) | `lab/plc_sim/turbine_modbus_server.py` (PLC, real Kelmarsh SCADA data) and `lab/plc_sim/hvac_modbus_server.py` (auxiliary system) |
| Supply-chain / CI-CD identity security (NIS2 Art. 21(2)(d)) | `cicd/` + `scenarios/scenario_cicd_identity.py`: a real before/after scan of an OIDC-federated deploy pipeline using [TrustGraph](https://github.com/karkiram05/trustgraph), this author's own attack-path analysis tool, as a genuine dependency |

## What this is not

This is not a claim to have found anything about Ørsted's actual security
posture, not a request for Ørsted's data or systems, and not a substitute
for the kind of assessment only a real OT security team with real access
could do. It's evidence that the author can design, build, and honestly
document a working OT detection and risk-triage system from public
information about what the job actually requires -- which is the thing a
resume bullet point can't show and a working repository can.
