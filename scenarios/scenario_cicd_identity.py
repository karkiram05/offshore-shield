#!/usr/bin/env python3
"""CI/CD identity scenario: how a compromised (or just over-permissioned)
GitHub Actions deploy pipeline for turbine firmware/config updates could
reach further than intended, and what fixing it actually removes.

This reuses TrustGraph (github.com/karkiram05/trustgraph) as a real
dependency rather than reimplementing attack-path analysis inside this
repo -- see requirements.txt. It scans the two fixtures in cicd/ with
TrustGraph's actual parser/graph/detection engine and reports the real
findings, before and after hardening. Nothing here is a canned or
hand-written number; rerun this script and you regenerate
scenarios/results/cicd_identity.json from scratch.

Usage:
    python scenarios/scenario_cicd_identity.py --write-results
"""
import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

try:
    from trustgraph.detections.base import Severity
    from trustgraph.detections.engine import run_detections
    from trustgraph.graph.builder import build_graph, load_resource_access
    from trustgraph.parsers.github_actions import parse_workflow
    from trustgraph.parsers.iam_trust import parse_trust_policy
except ImportError as exc:  # pragma: no cover
    print(
        "ERROR: trustgraph isn't installed. This scenario depends on it "
        "for real (see requirements.txt): pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


def _discover_workflows(target: Path) -> list[Path]:
    wf_dir = target / ".github" / "workflows"
    return sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))


def _discover_trust_policies(target: Path) -> list[Path]:
    tp_dir = target / "trust-policies"
    return sorted(tp_dir.glob("*.json")) if tp_dir.exists() else []


def scan(target: Path, repo_name: str) -> list:
    """Run TrustGraph's real parser -> graph -> detection engine pipeline
    against a fixture directory. Returns TrustGraph Finding objects."""
    workflow_paths = _discover_workflows(target)
    policy_paths = _discover_trust_policies(target)
    workflows = [parse_workflow(p) for p in workflow_paths]
    trust_policies = [parse_trust_policy(p) for p in policy_paths]

    resource_path = target / "resources.json"
    resource_access = load_resource_access(resource_path) if resource_path.exists() else []

    graph = build_graph(workflows, trust_policies, resource_access, repo_name=repo_name)
    return run_detections(workflows, trust_policies, graph, repo_name=repo_name)


def summarize(findings: list) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return {
        "findings_total": len(findings),
        "by_severity": counts,
        "rule_ids": sorted({f.rule_id for f in findings}),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-results", action="store_true", help="Also write scenarios/results/cicd_identity.json")
    args = parser.parse_args()

    vuln_dir = REPO_ROOT / "cicd" / "vulnerable-workflow"
    hardened_dir = REPO_ROOT / "cicd" / "hardened-workflow"

    print("[scenario] scanning cicd/vulnerable-workflow with TrustGraph's real detection engine")
    vuln_findings = scan(vuln_dir, repo_name="offshore-wind-ops/turbine-firmware")
    print("[scenario] scanning cicd/hardened-workflow with TrustGraph's real detection engine")
    hardened_findings = scan(hardened_dir, repo_name="offshore-wind-ops/turbine-firmware")

    result = {
        "generated_at": time.time(),
        "scenario": "A GitHub Actions pipeline publishes signed turbine "
                     "controller firmware/config bundles via OIDC-assumed "
                     "AWS access. Same pipeline, scanned before and after "
                     "hardening the workflow permissions and trust policy.",
        "before_hardening": summarize(vuln_findings),
        "after_hardening": summarize(hardened_findings),
    }

    print(json.dumps(result, indent=2))
    print()
    print("Findings before hardening:")
    for f in vuln_findings:
        print(f"  [{f.severity.value}] {f.rule_id}: {f.title}")
    print("Findings after hardening:")
    for f in hardened_findings:
        print(f"  [{f.severity.value}] {f.rule_id}: {f.title}")

    if args.write_results:
        out_path = REPO_ROOT / "scenarios" / "results" / "cicd_identity.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(f"\n[scenario] wrote {out_path}")


if __name__ == "__main__":
    main()
