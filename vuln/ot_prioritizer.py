"""OT-aware vulnerability prioritization.

A raw CVSS score answers "how bad is this vulnerability in the abstract."
It doesn't answer the question an OT security engineer actually has to
answer: "given where this asset sits, what's actually reachable, and what
happens to the turbine/substation if I patch it right now" -- CVSS says
nothing about exposure, compensating controls, or the cost of an outage.
That gap is explicit in how OT security roles at critical-infrastructure
operators describe the job (see docs/orsted-case-study.md for the public
job-posting language this module is built to answer).

This is a real, runnable rules engine over structured inputs -- not a
lookup table of hand-written outputs per CVE. Feed it a different asset and
you get a genuinely different, computed recommendation.
"""
from dataclasses import dataclass, field
from enum import Enum


class Zone(str, Enum):
    SCADA = "scada"
    AUXILIARY = "auxiliary"
    DMZ = "dmz"
    IT_ENTERPRISE = "it-enterprise"


@dataclass
class VulnerabilityContext:
    cve_id: str
    cvss_base: float
    asset_name: str
    zone: Zone
    internet_exposed: bool
    reachable_from_vendor_remote_access: bool
    exploit_publicly_known: bool
    patch_requires_outage: bool
    compensating_firewall_rule_available: bool
    safety_impact: str  # "none" | "low" | "medium" | "high"
    availability_impact: str  # "none" | "low" | "medium" | "high"


@dataclass
class Treatment:
    operational_risk: str  # LOW/MEDIUM/HIGH/CRITICAL
    operational_risk_score: float  # 0-100, computed
    immediate_action: str
    compensating_control: str | None
    monitoring_action: str
    patch_timing: str
    rationale: list[str] = field(default_factory=list)


IMPACT_WEIGHT = {"none": 0.0, "low": 0.15, "medium": 0.35, "high": 0.55}


def score(ctx: VulnerabilityContext) -> Treatment:
    rationale = []
    operational = (ctx.cvss_base / 10.0) * 40.0  # CVSS contributes at most 40/100
    rationale.append(f"CVSS {ctx.cvss_base}/10 contributes {operational:.1f}/40 base points")

    exposure = 0.0
    if ctx.internet_exposed:
        exposure += 25.0
        rationale.append("directly internet-exposed: +25")
    if ctx.reachable_from_vendor_remote_access:
        exposure += 15.0
        rationale.append("reachable via vendor remote-access conduit: +15")
    if ctx.exploit_publicly_known:
        exposure += 10.0
        rationale.append("exploit is publicly known: +10")
    operational += exposure

    impact = IMPACT_WEIGHT.get(ctx.safety_impact, 0.0) * 20 + IMPACT_WEIGHT.get(ctx.availability_impact, 0.0) * 20
    operational += impact
    rationale.append(
        f"safety impact={ctx.safety_impact}, availability impact={ctx.availability_impact}: +{impact:.1f}"
    )

    if ctx.zone in (Zone.IT_ENTERPRISE, Zone.DMZ) and not ctx.reachable_from_vendor_remote_access:
        operational -= 10.0
        rationale.append(f"zone={ctx.zone.value}, not on an OT-reachable path: -10")

    operational = max(0.0, min(100.0, operational))

    if operational >= 75:
        band = "CRITICAL"
    elif operational >= 50:
        band = "HIGH"
    elif operational >= 25:
        band = "MEDIUM"
    else:
        band = "LOW"

    if ctx.reachable_from_vendor_remote_access and band in ("HIGH", "CRITICAL"):
        immediate = "Restrict or suspend the vendor-access conduit reaching this asset pending review"
    elif ctx.internet_exposed and band in ("HIGH", "CRITICAL"):
        immediate = "Remove direct internet exposure; route through a monitored jump host"
    elif band == "CRITICAL":
        immediate = "Escalate to OT security lead for an emergency change review"
    else:
        immediate = "No immediate containment action required; proceed to scheduled treatment"

    if ctx.patch_requires_outage and ctx.compensating_firewall_rule_available:
        compensating = "Add a compensating firewall rule restricting access to the vulnerable service/port until the next approved outage window"
        patch_timing = "Next approved maintenance window"
    elif ctx.patch_requires_outage and not ctx.compensating_firewall_rule_available:
        compensating = "No compensating control currently available -- flag for engineering review before accepting the risk window"
        patch_timing = "Escalate: needs a compensating control decision before an outage can be scheduled"
    else:
        compensating = None
        patch_timing = "Can be patched without a scheduled outage; proceed at next routine cycle"

    monitoring = (
        f"Enable/verify detection coverage for remote-service access to {ctx.asset_name} "
        f"(zone={ctx.zone.value}) while the fix is pending"
    )

    return Treatment(
        operational_risk=band,
        operational_risk_score=round(operational, 1),
        immediate_action=immediate,
        compensating_control=compensating,
        monitoring_action=monitoring,
        patch_timing=patch_timing,
        rationale=rationale,
    )
