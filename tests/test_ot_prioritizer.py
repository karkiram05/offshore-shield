import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vuln.ot_prioritizer import VulnerabilityContext, Zone, score  # noqa: E402


def make_ctx(**overrides):
    base = dict(
        cve_id="CVE-2026-TEST",
        cvss_base=9.8,
        asset_name="engineering-workstation",
        zone=Zone.SCADA,
        internet_exposed=False,
        reachable_from_vendor_remote_access=False,
        exploit_publicly_known=False,
        patch_requires_outage=False,
        compensating_firewall_rule_available=False,
        safety_impact="low",
        availability_impact="low",
    )
    base.update(overrides)
    return VulnerabilityContext(**base)


def test_same_cvss_different_exposure_gives_different_operational_risk():
    isolated = score(make_ctx(cvss_base=9.8, internet_exposed=False, reachable_from_vendor_remote_access=False))
    exposed = score(make_ctx(cvss_base=9.8, internet_exposed=True, reachable_from_vendor_remote_access=True, exploit_publicly_known=True))
    assert exposed.operational_risk_score > isolated.operational_risk_score
    assert isolated.operational_risk in ("LOW", "MEDIUM")
    assert exposed.operational_risk in ("HIGH", "CRITICAL")


def test_low_cvss_high_exposure_can_outrank_high_cvss_isolated():
    """The whole point of this module: CVSS alone is not the operational
    risk ranking. A lower CVSS finding that's internet-exposed and has a
    known exploit can and should score above an isolated 9.8."""
    low_cvss_exposed = score(make_ctx(
        cvss_base=6.0, internet_exposed=True, reachable_from_vendor_remote_access=True,
        exploit_publicly_known=True, safety_impact="high", availability_impact="high",
    ))
    high_cvss_isolated = score(make_ctx(
        cvss_base=9.8, internet_exposed=False, reachable_from_vendor_remote_access=False,
        exploit_publicly_known=False, zone=Zone.IT_ENTERPRISE, safety_impact="none", availability_impact="none",
    ))
    assert low_cvss_exposed.operational_risk_score > high_cvss_isolated.operational_risk_score


def test_outage_required_without_compensating_control_flags_escalation():
    result = score(make_ctx(patch_requires_outage=True, compensating_firewall_rule_available=False))
    assert "escalate" in result.patch_timing.lower() or "review" in result.patch_timing.lower()


def test_outage_required_with_compensating_control_gives_scheduled_treatment():
    result = score(make_ctx(patch_requires_outage=True, compensating_firewall_rule_available=True))
    assert result.compensating_control is not None
    assert "window" in result.patch_timing.lower()


def test_vendor_remote_access_reachability_drives_immediate_containment():
    result = score(make_ctx(
        cvss_base=9.0, reachable_from_vendor_remote_access=True, exploit_publicly_known=True,
        safety_impact="high", availability_impact="high",
    ))
    assert result.operational_risk in ("HIGH", "CRITICAL")
    assert "vendor" in result.immediate_action.lower()
