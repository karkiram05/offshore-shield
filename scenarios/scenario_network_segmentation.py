#!/usr/bin/env python3
"""Purple-team scenario: real OS-level network segmentation, not just
detection.

Every other scenario in this repo proves the detection engine catches a
disallowed pattern *after* it happens (it reads conn.log). This one is
different in kind: it builds real Linux network namespaces connected
through a real router namespace running real nftables forward rules
(lab/segmentation/netns_lab.py), generated directly from
lab/network_zones.json's allowed_cross_zone policy, then makes a genuine
TCP connection attempt for every (src_zone, dst_zone) pair the policy
defines an opinion on and checks whether the *kernel* let it through.

An allowed pair should connect; a disallowed pair should be refused/
dropped by nftables before it ever reaches the destination's listener --
this is prevention, not detection, and it's real: no code here decides
"this would have been blocked," the actual packets take the actual path
and either arrive or don't.

Requires root / CAP_NET_ADMIN (see netns_lab.py's module docstring for
why network namespaces are used here instead of docker-compose).

Usage:
    python3 scenarios/scenario_network_segmentation.py --write-results
"""
import argparse
import json
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
NETNS_LAB = REPO_ROOT / "lab" / "segmentation" / "netns_lab.py"


def run_netns_lab(action: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603
        [sys.executable, str(NETNS_LAB), action],
        capture_output=True, text=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write-results", action="store_true", help="Also write scenarios/results/network_segmentation.json")
    args = parser.parse_args()

    print("[scenario] tearing down any leftover namespaces from a previous run...")
    run_netns_lab("down")

    print("[scenario] building real network namespaces + router + nftables ruleset from lab/network_zones.json...")
    up = run_netns_lab("up")
    if up.returncode != 0:
        print("ERROR: failed to bring up the namespace lab (needs root / CAP_NET_ADMIN):", file=sys.stderr)
        print(up.stderr, file=sys.stderr)
        sys.exit(1)
    print(up.stdout)

    print("[scenario] attempting a real TCP connection for every (src_zone, dst_zone) pair the policy has an opinion on...")
    test_start = time.time()
    test = run_netns_lab("test")
    test_elapsed = time.time() - test_start

    print("[scenario] tearing down...")
    run_netns_lab("down")

    if test.returncode not in (0, 1):
        print("ERROR: connectivity test run itself failed unexpectedly:", file=sys.stderr)
        print(test.stderr, file=sys.stderr)
        sys.exit(1)

    try:
        cases = json.loads(test.stdout)
    except json.JSONDecodeError:
        print("ERROR: could not parse connectivity test output:", file=sys.stderr)
        print(test.stdout, file=sys.stderr)
        print(test.stderr, file=sys.stderr)
        sys.exit(1)

    matched = [c for c in cases if c["matches_policy"]]
    mismatched = [c for c in cases if not c["matches_policy"]]
    allowed_cases = [c for c in cases if c["expected_allowed"]]
    blocked_cases = [c for c in cases if not c["expected_allowed"]]

    result = {
        "generated_at": time.time(),
        "cases_tested": len(cases),
        "cases_matching_policy": len(matched),
        "cases_mismatching_policy": len(mismatched),
        "allowed_pairs_tested": len(allowed_cases),
        "allowed_pairs_actually_connected": sum(1 for c in allowed_cases if c["actual_allowed"]),
        "disallowed_pairs_tested": len(blocked_cases),
        "disallowed_pairs_actually_blocked": sum(1 for c in blocked_cases if not c["actual_allowed"]),
        "enforcement_fully_matches_policy": len(mismatched) == 0,
        "eval_latency_s": round(test_elapsed, 4),
        "cases": cases,
    }

    print(json.dumps({k: v for k, v in result.items() if k != "cases"}, indent=2))
    print()
    if mismatched:
        print("MISMATCHES (kernel behavior didn't match the declared policy):")
        for c in mismatched:
            print(f"  {c['src_zone']} -> {c['dst_zone']}: expected_allowed={c['expected_allowed']} actual_allowed={c['actual_allowed']}")
    else:
        print(
            f"All {len(cases)} (src_zone, dst_zone) pairs matched the declared policy: "
            f"{result['allowed_pairs_actually_connected']}/{result['allowed_pairs_tested']} allowed pairs connected, "
            f"{result['disallowed_pairs_actually_blocked']}/{result['disallowed_pairs_tested']} disallowed pairs were actually blocked by the kernel -- "
            "not just logged as a violation after the fact."
        )

    if args.write_results:
        out_path = REPO_ROOT / "scenarios" / "results" / "network_segmentation.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(f"\n[scenario] wrote {out_path}")

    if mismatched:
        sys.exit(1)


if __name__ == "__main__":
    main()
