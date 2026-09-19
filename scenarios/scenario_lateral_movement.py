#!/usr/bin/env python3
"""Purple-team scenario: a two-hop lateral-movement pivot, not just a scan.

An attacker with a foothold on a corporate laptop (it-enterprise) reaches
the historian jump host (dmz) -- an *allowed* path, that's what jump hosts
are for. From there, now acting as if operating on the jump host itself,
they reach the engineering workstation (ot-engineering) -- also an
*allowed* path under this lab's current zone policy (see
lab/network_zones.json: "ot-engineering": ["dmz"]). Neither hop alone
violates the zone policy, so rule_cross_zone_violation stays silent on
both. What catches it is rule_lateral_movement_pivot (detection/rules.py),
which looks at the *sequence*: the same host being a destination and then,
shortly after, a source reaching a new zone.

Requires the lab's remote-management banner simulator running behind the
two mgmt taps -- see `make lab-up` (which now also starts it) or run it
directly: python3 lab/services/mgmt_banner_service.py --port 5040

Usage:
    python scenarios/scenario_lateral_movement.py --write-results
"""
import argparse
import json
import subprocess  # nosec B404
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from detection.engine import DetectionEngine, load_zones, read_jsonl  # noqa: E402


def run_pivot(conn_log: Path) -> tuple[list[dict], float]:
    if conn_log.exists():
        conn_log.unlink()
    conn_log.parent.mkdir(parents=True, exist_ok=True)

    scan_start = time.time()

    # Hop 1: corp-laptop (it-enterprise, 127.0.0.30) reaches the jump host's
    # management port. This alone is a completely ordinary, allowed
    # connection -- exactly what a jump host is for.
    subprocess.run(  # nosec B603
        [
            sys.executable, str(REPO_ROOT / "lab/scanner/ot_scanner.py"),
            "127.0.0.1", "--ports", "6530", "--src-ip", "127.0.0.30",
            "--timeout", "0.5", "--delay", "0",
        ],
        check=True, capture_output=True, text=True,
    )

    time.sleep(3.0)  # simulated attacker dwell time on the jump host

    # Hop 2: the jump host (dmz, 127.0.0.20) -- now acting as the pivot
    # point -- reaches the engineering workstation's management port. Also
    # individually allowed under the current zone policy.
    subprocess.run(  # nosec B603
        [
            sys.executable, str(REPO_ROOT / "lab/scanner/ot_scanner.py"),
            "127.0.0.1", "--ports", "6531", "--src-ip", "127.0.0.20",
            "--timeout", "0.5", "--delay", "0",
        ],
        check=True, capture_output=True, text=True,
    )

    time.sleep(0.3)  # let the tap flush the last log line
    records = read_jsonl(conn_log)
    return records, scan_start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conn-log", default=str(REPO_ROOT / "logs/conn.log"))
    parser.add_argument("--zones", default=str(REPO_ROOT / "lab/network_zones.json"))
    parser.add_argument("--write-results", action="store_true", help="Also write scenarios/results/lateral_movement.json")
    args = parser.parse_args()

    conn_log = Path(args.conn_log)
    print("[scenario] running the two-hop pivot against the live lab (requires the tap + mgmt banner service running -- see README)")
    records, scan_start = run_pivot(conn_log)
    if len(records) < 2:
        print(
            f"ERROR: expected 2 real connection records, got {len(records)}. "
            "Is the network tap running, and is lab/services/mgmt_banner_service.py up on port 5040? See make lab-up.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"[scenario] captured {len(records)} real connection record(s)")

    zones = load_zones(Path(args.zones))
    engine = DetectionEngine(zones)
    eval_start = time.time()
    alerts = engine.process_batch(records)
    eval_elapsed = time.time() - eval_start

    cross_zone_alerts = [a for a in alerts if a.rule == "cross_zone_violation"]
    pivot_alerts = [a for a in alerts if a.rule == "lateral_movement_pivot"]

    result = {
        "generated_at": time.time(),
        "records_observed": len(records),
        "cross_zone_violation_alerts": len(cross_zone_alerts),
        "lateral_movement_pivot_alerts": len(pivot_alerts),
        "pivot_detected": len(pivot_alerts) > 0,
        "eval_latency_s": round(eval_elapsed, 4),
    }

    print(json.dumps(result, indent=2))
    print()
    if pivot_alerts:
        for a in pivot_alerts:
            print(f"[{a.severity}] {a.rule}: {a.summary}")
    print(
        "\nBoth hops were individually zone-allowed "
        f"({len(cross_zone_alerts)} cross_zone_violation alert(s) raised on either hop), "
        f"yet the pivot itself was {'caught' if pivot_alerts else 'MISSED'} by rule_lateral_movement_pivot."
    )

    if args.write_results:
        out_path = REPO_ROOT / "scenarios" / "results" / "lateral_movement.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(f"\n[scenario] wrote {out_path}")


if __name__ == "__main__":
    main()
