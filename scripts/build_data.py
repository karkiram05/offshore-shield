#!/usr/bin/env python3
"""Turn the lab's raw inputs and captures into clean and processed tables.

Reads (raw):
    data/kelmarsh/km_scada_sample_2022.csv          full Kelmarsh file, if downloaded
    data/kelmarsh/km_scada_sample_2022_excerpt.csv  otherwise, the 20-row excerpt
    data/raw/scenario_captures/*.jsonl              tap records from each live scenario
    scenarios/results/*.json                        scenario summaries
Writes (clean):
    data/clean/kelmarsh_power_clean.csv             typed, checked, plus the Modbus
                                                    register value the simulator serves
    data/clean/kelmarsh_quality_report.json
Writes (processed):
    data/processed/scenario_alert_counts.csv        alerts per scenario, rule and severity
    data/processed/setpoint_writes.csv              every captured setpoint write and
                                                    whether each rule fired on it
    data/processed/segmentation_cases.csv           the 20 kernel-enforcement test cases
    data/processed/prioritizer_examples.csv         the two worked examples in docs/results.md
    data/processed/prioritizer_sweep.csv            CVSS 0-10 under four exposure profiles

Every value comes from running the project's own code on those inputs.

Usage:
    python scripts/build_data.py
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from lab.plc_sim.turbine_modbus_server import to_fixed  # noqa: E402
from vuln.ot_prioritizer import VulnerabilityContext, Zone, score  # noqa: E402
from detection.engine import DetectionEngine, load_zones  # noqa: E402

KELMARSH_DIR = REPO / "data" / "kelmarsh"
CAPTURES = REPO / "data" / "raw" / "scenario_captures"
ALERTS = REPO / "data" / "processed" / "scenario_alerts"
RESULTS = REPO / "scenarios" / "results"
CLEAN = REPO / "data" / "clean"
PROCESSED = REPO / "data" / "processed"


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {path.relative_to(REPO)} ({len(rows)} rows)")


def kelmarsh() -> None:
    full = KELMARSH_DIR / "km_scada_sample_2022.csv"
    source = full if full.exists() else KELMARSH_DIR / "km_scada_sample_2022_excerpt.csv"
    with source.open() as handle:
        raw = list(csv.DictReader(handle))

    rows, problems = [], Counter()
    previous = None
    for i, r in enumerate(raw):
        try:
            ts = dt.datetime.fromisoformat(r["timestamp"])
            mean, std = float(r["power_kw"]), float(r["power_std_kw"])
            lo, hi = float(r["power_min_kw"]), float(r["power_max_kw"])
        except (KeyError, TypeError, ValueError):
            problems["unparseable_row"] += 1
            continue
        if not lo <= mean <= hi:
            problems["mean_outside_min_max"] += 1
        if std < 0:
            problems["negative_std"] += 1
        if lo < 0:
            # Turbines draw a little power when idle; worth counting, not an error.
            problems["negative_min_power_rows"] += 1
        gap = (ts - previous).total_seconds() / 60 if previous else None
        if gap is not None and gap != 10:
            problems["non_10_minute_step"] += 1
        previous = ts
        rows.append({
            "row": i, "timestamp": ts.isoformat(sep=" "),
            "power_kw": round(mean, 3), "power_std_kw": round(std, 3),
            "power_min_kw": round(lo, 3), "power_max_kw": round(hi, 3),
            # What turbine_modbus_server.py actually puts in holding register
            # 40001 for this row (kW x10, clamped to 16 bits).
            "register_40001_power_x10": to_fixed(r["power_kw"]),
        })

    write_csv(CLEAN / "kelmarsh_power_clean.csv", rows)
    report = {
        "source_file": str(source.relative_to(REPO)),
        "is_full_dataset": source == full,
        "rows_in": len(raw),
        "rows_clean": len(rows),
        "first_timestamp": rows[0]["timestamp"] if rows else None,
        "last_timestamp": rows[-1]["timestamp"] if rows else None,
        "checks": {
            "unparseable_row": problems["unparseable_row"],
            "mean_outside_min_max": problems["mean_outside_min_max"],
            "negative_std": problems["negative_std"],
            "non_10_minute_step": problems["non_10_minute_step"],
            "negative_min_power_rows": problems["negative_min_power_rows"],
        },
        "power_kw_mean": round(sum(r["power_kw"] for r in rows) / len(rows), 3) if rows else None,
        "power_kw_max": max((r["power_max_kw"] for r in rows), default=None),
    }
    (CLEAN / "kelmarsh_quality_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Wrote data/clean/kelmarsh_quality_report.json (source: {report['source_file']})")


def scenario_alerts() -> None:
    rows = []
    for path in sorted(ALERTS.glob("*.json")):
        data = json.loads(path.read_text())
        for label, alerts in data.items():
            for (rule, severity), n in sorted(Counter((a["rule"], a["severity"]) for a in alerts).items()):
                rows.append({"scenario": path.stem, "run": label, "rule": rule,
                             "severity": severity, "alerts": n})
    write_csv(PROCESSED / "scenario_alert_counts.csv", rows)


def setpoint_writes() -> None:
    """Replay the raw process-manipulation capture one record at a time
    through a fresh detection engine, so each alert can be tied to the write
    that caused it (alerts don't carry a record id). The per-rule totals
    must equal the scenario's own batch run, or this fails loudly."""
    records = [json.loads(line) for line in
               (CAPTURES / "process_manipulation.jsonl").read_text().splitlines() if line.strip()]
    records.sort(key=lambda r: r["ts"])
    batch = Counter(a["rule"] for a in json.loads((ALERTS / "process_manipulation.json").read_text())["alerts"])

    engine = DetectionEngine(load_zones(REPO / "lab" / "network_zones.json"))
    replayed, rows, prev = Counter(), [], None
    for r in records:
        fired = Counter(a.rule for a in engine.process_batch([r]))
        replayed.update(fired)
        if r.get("modbus_function_code") != 6:
            continue
        value = r["modbus_write_register_value"]
        rows.append({
            "ts": r["ts"], "src_ip": r["src_ip"], "register": r["modbus_write_register_addr"],
            "value_pct": value, "delta": None if prev is None else value - prev,
            **{rule: fired.get(rule, 0) for rule in
               ("unexpected_modbus_write", "unsafe_setpoint_write", "automated_collection")},
        })
        prev = value
    if replayed != batch:
        raise SystemExit(f"Record-by-record replay {dict(replayed)} != batch run {dict(batch)}")
    write_csv(PROCESSED / "setpoint_writes.csv", rows)


def segmentation() -> None:
    cases = json.loads((RESULTS / "network_segmentation.json").read_text())["cases"]
    write_csv(PROCESSED / "segmentation_cases.csv", [
        {k: (int(v) if isinstance(v, bool) else v) for k, v in c.items()} for c in cases])


def context(**overrides) -> VulnerabilityContext:
    base = dict(cve_id="example", cvss_base=5.0, asset_name="asset", zone=Zone.SCADA,
                internet_exposed=False, reachable_from_vendor_remote_access=False,
                exploit_publicly_known=False, patch_requires_outage=False,
                compensating_firewall_rule_available=False,
                safety_impact="none", availability_impact="none")
    base.update(overrides)
    return VulnerabilityContext(**base)


def prioritizer() -> None:
    examples = {
        "isolated, high CVSS": context(
            cvss_base=9.8, asset_name="engineering-workstation", zone=Zone.SCADA,
            patch_requires_outage=True, compensating_firewall_rule_available=True,
            safety_impact="low", availability_impact="medium"),
        "exposed, lower CVSS": context(
            cvss_base=6.1, asset_name="historian-jumphost", zone=Zone.DMZ,
            reachable_from_vendor_remote_access=True, exploit_publicly_known=True,
            safety_impact="high", availability_impact="high"),
    }
    rows = []
    for name, ctx in examples.items():
        t = score(ctx)
        rows.append({"example": name, "cvss": ctx.cvss_base, "zone": ctx.zone.value,
                     "internet_exposed": int(ctx.internet_exposed),
                     "vendor_reachable": int(ctx.reachable_from_vendor_remote_access),
                     "exploit_public": int(ctx.exploit_publicly_known),
                     "safety_impact": ctx.safety_impact, "availability_impact": ctx.availability_impact,
                     "operational_risk_score": t.operational_risk_score,
                     "operational_risk": t.operational_risk, "patch_timing": t.patch_timing})
    write_csv(PROCESSED / "prioritizer_examples.csv", rows)

    profiles = {
        "IT zone, isolated": dict(zone=Zone.IT_ENTERPRISE),
        "SCADA, isolated": dict(zone=Zone.SCADA),
        "SCADA, vendor-reachable + public exploit": dict(
            zone=Zone.SCADA, reachable_from_vendor_remote_access=True, exploit_publicly_known=True),
        "SCADA, internet-exposed + vendor + exploit": dict(
            zone=Zone.SCADA, internet_exposed=True, reachable_from_vendor_remote_access=True,
            exploit_publicly_known=True),
    }
    sweep = []
    for name, overrides in profiles.items():
        for tenth in range(0, 101, 5):
            cvss = tenth / 10
            t = score(context(cvss_base=cvss, safety_impact="medium", availability_impact="medium",
                              **overrides))
            sweep.append({"profile": name, "cvss": cvss,
                          "operational_risk_score": t.operational_risk_score,
                          "operational_risk": t.operational_risk})
    write_csv(PROCESSED / "prioritizer_sweep.csv", sweep)


def main() -> int:
    kelmarsh()
    scenario_alerts()
    setpoint_writes()
    segmentation()
    prioritizer()
    return 0


if __name__ == "__main__":
    sys.exit(main())
