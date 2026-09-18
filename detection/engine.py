#!/usr/bin/env python3
"""Ties the rules together: reads conn.log records, runs every rule, scores
findings, and emits alerts. Two modes:

  engine.process_batch(records)   -- run once over a fixed list (tests, and
                                      scenario replay/reporting)
  engine.follow(log_path)         -- tail a live conn.log forever (the demo)
"""
import argparse
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from detection import attck_ics, risk
from detection.rules import ALL_RULES, Finding


@dataclass
class Alert:
    ts: float
    rule: str
    src_ip: str
    summary: str
    score: float
    severity: str
    technique: dict
    evidence: dict
    prior_alerts_from_source: int


class DetectionEngine:
    def __init__(self, zones: dict):
        self.zones = zones
        self._rule_state: dict = {}
        self._alert_counts: dict = {}  # src_ip -> count, for repeat-offender boost
        self.alerts: list[Alert] = []

    def process_batch(self, records: list[dict]) -> list[Alert]:
        new_alerts = []
        for rule_fn in ALL_RULES:
            findings: list[Finding] = rule_fn(records, self.zones, self._rule_state)
            for finding in findings:
                prior = self._alert_counts.get(finding.src_ip, 0)
                score = risk.base_score(finding.confidence)
                score = risk.apply_repeat_offender_boost(score, prior)
                alert = Alert(
                    ts=time.time(),
                    rule=finding.rule,
                    src_ip=finding.src_ip,
                    summary=finding.summary,
                    score=round(score, 1),
                    severity=risk.severity_band(score),
                    technique=attck_ics.describe(finding.technique_id),
                    evidence=finding.evidence,
                    prior_alerts_from_source=prior,
                )
                self._alert_counts[finding.src_ip] = prior + 1
                self.alerts.append(alert)
                new_alerts.append(alert)
        return new_alerts


def load_zones(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def follow(conn_log: Path, zones_path: Path, alerts_out: Path, poll_interval: float = 1.0):
    engine = DetectionEngine(load_zones(zones_path))
    seen = 0
    alerts_out.parent.mkdir(parents=True, exist_ok=True)
    print(f"[engine] watching {conn_log} ...")
    while True:
        records = read_jsonl(conn_log)
        new_records = records[seen:]
        seen = len(records)
        if new_records:
            alerts = engine.process_batch(new_records)
            for alert in alerts:
                line = json.dumps(asdict(alert))
                with open(alerts_out, "a") as f:
                    f.write(line + "\n")
                print(f"[ALERT] {alert.severity:<8} score={alert.score:<5} {alert.summary} "
                      f"[{alert.technique['id']} {alert.technique['name']}]")
        time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conn-log", default="logs/conn.log")
    parser.add_argument("--zones", default="lab/network_zones.json")
    parser.add_argument("--alerts-out", default="logs/alerts.log")
    args = parser.parse_args()
    follow(Path(args.conn_log), Path(args.zones), Path(args.alerts_out))


if __name__ == "__main__":
    main()
