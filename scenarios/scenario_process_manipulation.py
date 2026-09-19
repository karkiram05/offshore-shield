#!/usr/bin/env python3
"""Purple-team scenario: process manipulation via a Modbus write, safe vs unsafe.

The turbine simulator (lab/plc_sim/turbine_modbus_server.py) exposes a
writable holding register, 40007 (index 6): a curtailment setpoint,
0-100%. TelemetryFeeder never overwrites this index, so a written value
persists -- exactly like a real turbine's control setpoint would.

This scenario sends two real Modbus TCP writes to that register through
the live network tap, using an actual pymodbus client (not a hand-rolled
frame) so the bytes on the wire are genuine Modbus, then replays the
tap's real conn.log records through the detection engine:

  1. A RAMPED sequence first: five small 5-point steps (0->5->10->15->20->25).
     Triggers rule_unexpected_modbus_write every time (any write to this
     asset is policy-unexpected in this lab), but should NOT trigger
     rule_unsafe_setpoint_write, since no single step is abrupt -- this is
     the safety-impact distinction STATUS.md calls for: not every write
     is equally dangerous, and the detection should be able to say so.

  2. Then an ABRUPT write: 25% -> 100% in a single command, a 75-point
     jump. Real turbine controllers ramp a curtailment setpoint
     gradually; a jump this size risks sudden torque/blade-pitch swings
     that stress the drivetrain. Expected to trigger BOTH
     rule_unexpected_modbus_write (any write to this read-only-by-policy
     lab asset) and rule_unsafe_setpoint_write (the abrupt value itself)
     -- intentional overlapping detection, see detection/rules.py.

Requires the live lab (turbine simulator + network tap) running -- see
`make lab-up`.

Usage:
    python scenarios/scenario_process_manipulation.py --write-results
"""
import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pymodbus.client import ModbusTcpClient  # noqa: E402

from detection.engine import DetectionEngine, load_zones, read_jsonl  # noqa: E402

SETPOINT_REGISTER = 6  # holding register index 6 == register 40007
TAP_HOST = "127.0.0.1"
TAP_PORT = 6502  # turbine-plc tap listen port


def write_setpoint(value: int, src_ip: str | None) -> None:
    kwargs = {"port": TAP_PORT, "timeout": 2.0}
    if src_ip:
        kwargs["source_address"] = (src_ip, 0)
    client = ModbusTcpClient(TAP_HOST, **kwargs)
    if not client.connect():
        raise RuntimeError(
            f"Could not reach the turbine tap at {TAP_HOST}:{TAP_PORT}. "
            "Is the lab running? See `make lab-up`."
        )
    try:
        result = client.write_register(SETPOINT_REGISTER, value, slave=1)
        if result.isError():
            raise RuntimeError(f"Modbus write of {value} to register {SETPOINT_REGISTER} failed: {result}")
    finally:
        client.close()


def run_writes(conn_log: Path, src_ip: str | None) -> list[dict]:
    if conn_log.exists():
        conn_log.unlink()
    conn_log.parent.mkdir(parents=True, exist_ok=True)

    # Establish a baseline value first -- rule_unsafe_setpoint_write needs a
    # prior value to compute a delta against (see its docstring: the very
    # first observed write to a register has nothing to compare against).
    write_setpoint(0, src_ip)
    time.sleep(0.2)

    # 1. Ramped: five 5-point steps, 5 -> 25. None of these individual
    # steps should read as abrupt.
    for step in (5, 10, 15, 20, 25):
        write_setpoint(step, src_ip)
        time.sleep(0.2)

    # 2. Abrupt: 25% -> 100% in one write, a 75-point jump.
    write_setpoint(100, src_ip)
    time.sleep(0.2)

    time.sleep(0.3)  # let the tap flush the last log line
    return read_jsonl(conn_log)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conn-log", default=str(REPO_ROOT / "logs/conn.log"))
    parser.add_argument("--zones", default=str(REPO_ROOT / "lab/network_zones.json"))
    parser.add_argument("--src-ip", default="127.0.0.10", help="Simulated source host (default: the provisioned engineering workstation)")
    parser.add_argument("--write-results", action="store_true", help="Also write scenarios/results/process_manipulation.json")
    args = parser.parse_args()

    conn_log = Path(args.conn_log)
    print("[scenario] sending real Modbus writes (ramped, then abrupt) against the live lab -- requires the tap + turbine simulator running, see README")
    records = run_writes(conn_log, args.src_ip)
    if len(records) < 7:  # baseline + 5 ramp steps + 1 abrupt write
        print(
            f"ERROR: expected at least 7 real connection records, got {len(records)}. "
            "Is the network tap running, and is lab/plc_sim/turbine_modbus_server.py up on port 5020? See make lab-up.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"[scenario] captured {len(records)} real connection record(s), all genuine Modbus Write Single Register frames")

    zones = load_zones(Path(args.zones))
    engine = DetectionEngine(zones)
    eval_start = time.time()
    alerts = engine.process_batch(records)
    eval_elapsed = time.time() - eval_start

    unexpected_write_alerts = [a for a in alerts if a.rule == "unexpected_modbus_write"]
    unsafe_setpoint_alerts = [a for a in alerts if a.rule == "unsafe_setpoint_write"]

    # Exactly one write in this sequence is abrupt (the final 25->100 jump);
    # the five ramped steps before it should each be too small to trip
    # rule_unsafe_setpoint_write.
    abrupt_deltas = [a.evidence["delta"] for a in unsafe_setpoint_alerts]

    result = {
        "generated_at": time.time(),
        "records_observed": len(records),
        "unexpected_modbus_write_alerts": len(unexpected_write_alerts),
        "unsafe_setpoint_write_alerts": len(unsafe_setpoint_alerts),
        "unsafe_setpoint_write_deltas": abrupt_deltas,
        "abrupt_write_flagged_unsafe": any(d >= 25 for d in abrupt_deltas),
        "ramped_writes_not_flagged_unsafe": len(unsafe_setpoint_alerts) == 1,
        "eval_latency_s": round(eval_elapsed, 4),
    }

    print(json.dumps(result, indent=2))
    print()
    for a in unsafe_setpoint_alerts:
        print(f"[{a.severity}] {a.rule}: {a.summary}")
    print(
        f"\n{len(unexpected_write_alerts)} write(s) total flagged as policy-unexpected (any write counts); "
        f"only {len(unsafe_setpoint_alerts)} flagged as an unsafe abrupt change -- "
        "the ramped sequence's individual steps were each small enough not to trip that rule."
    )

    if args.write_results:
        out_path = REPO_ROOT / "scenarios" / "results" / "process_manipulation.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(f"\n[scenario] wrote {out_path}")


if __name__ == "__main__":
    main()
