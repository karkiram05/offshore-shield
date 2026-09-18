#!/usr/bin/env python3
"""Purple-team scenario: OT network discovery/port-scan from an IT-zone host.

Runs a real scan against the live lab (turbine + HVAC simulators, behind the
network tap), then replays the resulting real conn.log records through the
detection engine twice: once under a deliberately loose zone policy (before
hardening) and once under the corrected policy (after hardening). Every
number in the output is computed from that run, not hand-written -- rerun
this script and you regenerate docs/results.md's numbers from scratch.

Usage:
    python scenarios/scenario_discovery.py --write-results
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


def run_scan(conn_log: Path) -> list[dict]:
    if conn_log.exists():
        conn_log.unlink()
    conn_log.parent.mkdir(parents=True, exist_ok=True)

    scan_start = time.time()
    # Fixed argument list, shell=False (the default), no user/network input
    # reaches this call -- it always runs this repo's own scanner script
    # against this repo's own lab.
    subprocess.run(  # nosec B603
        [
            sys.executable, str(REPO_ROOT / "lab/scanner/ot_scanner.py"),
            "127.0.0.1", "--ports", "6495-6525", "--src-ip", "127.0.0.30",
            "--timeout", "0.3", "--delay", "0.02",
        ],
        check=True, capture_output=True, text=True,
    )
    time.sleep(0.3)  # let the tap flush the last log line
    records = read_jsonl(conn_log)
    return records, scan_start


def evaluate(records: list[dict], zones_path: Path) -> tuple[list, float | None]:
    zones = load_zones(zones_path)
    engine = DetectionEngine(zones)
    eval_start = time.time()
    alerts = engine.process_batch(records)
    eval_elapsed = time.time() - eval_start
    return alerts, eval_elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conn-log", default=str(REPO_ROOT / "logs/conn.log"))
    parser.add_argument("--baseline-zones", default=str(REPO_ROOT / "lab/network_zones_baseline_loose.json"))
    parser.add_argument("--hardened-zones", default=str(REPO_ROOT / "lab/network_zones.json"))
    parser.add_argument("--write-results", action="store_true", help="Also write scenarios/results/discovery.json")
    args = parser.parse_args()

    conn_log = Path(args.conn_log)
    print("[scenario] running discovery scan against the live lab (requires the tap + simulators running -- see README)")
    records, scan_start = run_scan(conn_log)
    if not records:
        print("ERROR: no conn.log records captured. Is the network tap running? See make lab-up.", file=sys.stderr)
        sys.exit(1)
    print(f"[scenario] captured {len(records)} real connection record(s) from the scan")

    before_alerts, before_eval_s = evaluate(records, Path(args.baseline_zones))
    after_alerts, after_eval_s = evaluate(records, Path(args.hardened_zones))

    first_record_ts = min(r["ts"] for r in records)
    after_first_alert_ts = min((a.ts for a in after_alerts), default=None)
    detection_latency_s = (after_first_alert_ts - first_record_ts) if after_first_alert_ts else None

    result = {
        "generated_at": time.time(),
        "records_observed": len(records),
        "before_hardening": {
            "zones_config": args.baseline_zones,
            "alerts_raised": len(before_alerts),
            "cross_zone_violations_detected": sum(1 for a in before_alerts if a.rule == "cross_zone_violation"),
        },
        "after_hardening": {
            "zones_config": args.hardened_zones,
            "alerts_raised": len(after_alerts),
            "cross_zone_violations_detected": sum(1 for a in after_alerts if a.rule == "cross_zone_violation"),
            "detection_latency_s": round(detection_latency_s, 4) if detection_latency_s is not None else None,
        },
    }

    print(json.dumps(result, indent=2))

    if args.write_results:
        out_path = REPO_ROOT / "scenarios" / "results" / "discovery.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(f"[scenario] wrote {out_path}")


if __name__ == "__main__":
    main()
