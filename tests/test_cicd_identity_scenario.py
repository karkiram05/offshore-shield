"""Tests for scenarios/scenario_cicd_identity.py -- runs TrustGraph's real
detection engine against the cicd/ fixtures (no network, no live processes,
so this runs in CI same as the rest of the suite)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

trustgraph = pytest.importorskip(
    "trustgraph",
    reason="trustgraph isn't installed -- see requirements.txt",
)

from scenarios.scenario_cicd_identity import scan, summarize  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN_DIR = REPO_ROOT / "cicd" / "vulnerable-workflow"
HARDENED_DIR = REPO_ROOT / "cicd" / "hardened-workflow"


def test_fixtures_exist():
    assert (VULN_DIR / ".github" / "workflows" / "deploy-turbine-config.yml").exists()
    assert (VULN_DIR / "trust-policies" / "turbine-ota-deploy-role.json").exists()
    assert (HARDENED_DIR / ".github" / "workflows" / "deploy-turbine-config.yml").exists()
    assert (HARDENED_DIR / "trust-policies" / "turbine-ota-deploy-role.json").exists()


def test_vulnerable_fixture_has_real_findings():
    findings = scan(VULN_DIR, repo_name="offshore-wind-ops/turbine-firmware")
    summary = summarize(findings)
    assert summary["findings_total"] > 0
    # The specific rules this fixture is built to trip:
    assert "wildcard-oidc-trust" in summary["rule_ids"]
    assert "unpinned-action" in summary["rule_ids"]
    assert "overpermissioned-token" in summary["rule_ids"]
    assert "missing-audience-restriction" in summary["rule_ids"]


def test_hardened_fixture_has_no_findings():
    findings = scan(HARDENED_DIR, repo_name="offshore-wind-ops/turbine-firmware")
    summary = summarize(findings)
    assert summary["findings_total"] == 0


def test_hardening_actually_reduces_findings():
    vuln_summary = summarize(scan(VULN_DIR, repo_name="offshore-wind-ops/turbine-firmware"))
    hardened_summary = summarize(scan(HARDENED_DIR, repo_name="offshore-wind-ops/turbine-firmware"))
    assert vuln_summary["findings_total"] > hardened_summary["findings_total"]
