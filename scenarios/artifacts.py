"""Keep the evidence behind each scenario result, not just the summary.

With --write-results, the live scenarios also save:

- data/raw/scenario_captures/<scenario>.jsonl: the exact conn.log records
  the network tap captured during the run (raw data);
- data/processed/scenario_alerts/<scenario>.json: every alert the detection
  engine raised on those records (processed data).

So each number in scenarios/results/*.json can be recomputed from the
captured traffic: feed the .jsonl back through detection/engine.py.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIR = REPO_ROOT / "data" / "raw" / "scenario_captures"
ALERT_DIR = REPO_ROOT / "data" / "processed" / "scenario_alerts"


def repo_relative(path) -> str:
    """Path relative to the repo root, so results files don't leak the
    absolute path of whichever machine produced them."""
    p = Path(path).resolve()
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return p.name


def save_capture(scenario: str, records: list[dict]) -> Path:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    out = CAPTURE_DIR / f"{scenario}.jsonl"
    out.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    return out


def save_alerts(scenario: str, alerts_by_label: dict[str, list]) -> Path:
    ALERT_DIR.mkdir(parents=True, exist_ok=True)
    out = ALERT_DIR / f"{scenario}.json"
    out.write_text(json.dumps(
        {label: [asdict(a) for a in alerts] for label, alerts in alerts_by_label.items()},
        indent=2, sort_keys=True) + "\n")
    return out
