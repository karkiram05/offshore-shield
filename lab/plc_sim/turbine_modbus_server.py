#!/usr/bin/env python3
"""Modbus TCP server standing in for a wind turbine's PLC.

Serves real Kelmarsh power measurements (see data/kelmarsh/README.md) as
holding registers, looping the available rows to produce a continuous
stream. This is a simulator, not a protocol emulator for any specific PLC
vendor -- it exists so the rest of the lab (network tap, detection engine,
scenarios) has something real to observe and attack that isn't a bare TCP
echo server.

Register map (holding registers, 16-bit, values scaled x10 where the
source value isn't an integer so no precision is lost through Modbus's
integer registers):

    40001  power_kw          (actual kW, x10 fixed point)
    40002  power_std_kw      (x10 fixed point)
    40003  power_min_kw      (x10 fixed point)
    40004  power_max_kw      (x10 fixed point)
    40005  row_index         (which source row is currently loaded)
    40006  status            (0=normal, 1=fault-simulated)
    40007  curtailment_setpoint_pct  (0-100, writable -- see below)

Register 40007 (index 6) is the one holding register in this map that's
meant to be *written*, not just read. It models a real wind-turbine
control point: a SCADA/engineering client can command the turbine to
curtail (reduce) its power output to a percentage of capacity, e.g. for
grid-operator curtailment orders or high-wind protection. Real turbine
controllers ramp this kind of setpoint gradually -- an abrupt 0%->100%
jump is mechanically abnormal (sudden torque/blade-pitch swings stress
the drivetrain) and is exactly the kind of write a process-manipulation
attack would send. TelemetryFeeder deliberately does NOT touch index 6
on its periodic tick (it only overwrites indices 0-5), so a written
setpoint value persists until another client writes it again -- see
scenarios/scenario_process_manipulation.py, which writes both an abrupt
and a gradual/ramped setpoint change and shows the detection engine
telling them apart.
"""
import argparse
import csv
import logging
import threading
import time
from pathlib import Path

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartTcpServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("turbine-sim")

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "kelmarsh"
FULL_FILE = DATA_DIR / "km_scada_sample_2022.csv"
EXCERPT_FILE = DATA_DIR / "km_scada_sample_2022_excerpt.csv"


def load_rows() -> list[dict]:
    """Prefer the full downloaded dataset; fall back to the committed excerpt."""
    source = FULL_FILE if FULL_FILE.exists() else EXCERPT_FILE
    if not source.exists():
        raise FileNotFoundError(
            f"No Kelmarsh data found at {FULL_FILE} or {EXCERPT_FILE}. "
            "Run `make fetch-dataset` or check data/kelmarsh/README.md."
        )
    with open(source, newline="") as f:
        rows = list(csv.DictReader(f))
    log.info("Loaded %d real Kelmarsh rows from %s", len(rows), source.name)
    return rows


def to_fixed(value: str) -> int:
    """kW value -> x10 fixed-point unsigned 16-bit register value."""
    scaled = round(float(value) * 10)
    return max(0, min(scaled, 65535))


class TelemetryFeeder(threading.Thread):
    """Advances the simulated turbine's registers through real rows on a timer."""

    def __init__(self, context: ModbusSlaveContext, rows: list[dict], interval: float, fault_after: int | None):
        super().__init__(daemon=True)
        self.context = context
        self.rows = rows
        self.interval = interval
        self.fault_after = fault_after
        self._stop = threading.Event()
        self._tick = 0

    def run(self):
        while not self._stop.is_set():
            row = self.rows[self._tick % len(self.rows)]
            status = 1 if self.fault_after and self._tick >= self.fault_after else 0
            values = [
                to_fixed(row["power_kw"]),
                to_fixed(row["power_std_kw"]),
                to_fixed(row["power_min_kw"]),
                to_fixed(row["power_max_kw"]),
                self._tick % len(self.rows),
                status,
            ]
            self.context.setValues(3, 0, values)  # function code 3 = holding registers
            self._tick += 1
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()


def build_context(rows: list[dict]) -> tuple[ModbusServerContext, ModbusSlaveContext]:
    store = ModbusSlaveContext(
        hr=ModbusSequentialDataBlock(0, [0] * 16),
    )
    context = ModbusServerContext(slaves=store, single=True)
    return context, store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    # Intentional: needs to be reachable from every simulated lab host
    # (loopback addresses or docker-compose containers), not just localhost.
    parser.add_argument("--host", default="0.0.0.0")  # nosec B104
    parser.add_argument("--port", type=int, default=5020, help="Modbus TCP port (5020, not 502, so it runs without root)")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between register updates")
    parser.add_argument("--fault-after", type=int, default=None, help="Tick count after which status register flips to fault, for demo purposes")
    args = parser.parse_args()

    rows = load_rows()
    context, store = build_context(rows)

    feeder = TelemetryFeeder(store, rows, args.interval, args.fault_after)
    feeder.start()

    identity = ModbusDeviceIdentification()
    identity.VendorName = "OffshoreShield Lab"
    identity.ProductCode = "TURBINE-SIM"
    identity.ProductName = "Simulated Wind Turbine PLC"
    identity.ModelName = "Kelmarsh-replay"

    log.info("Turbine simulator listening on %s:%d (Modbus TCP)", args.host, args.port)
    try:
        StartTcpServer(context=context, identity=identity, address=(args.host, args.port))
    finally:
        feeder.stop()


if __name__ == "__main__":
    main()
