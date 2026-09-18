#!/usr/bin/env python3
"""Modbus TCP server standing in for a substation/nacelle HVAC controller.

Unlike the turbine simulator, this one is NOT backed by real data -- there
is no public dataset used here, and nothing in this repo claims otherwise.
It generates a plausible, bounded temperature/humidity signal (sine wave +
small noise) purely so the lab has a second OT asset in a different zone
(auxiliary systems, not SCADA) for the cross-zone and multi-asset detection
scenarios to have something to reason about.

Register map (holding registers):

    40001  temperature_c   (x10 fixed point)
    40002  humidity_pct    (x10 fixed point)
    40003  fan_state       (0=off, 1=on)
"""
import argparse
import logging
import math
import random
import threading
import time

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartTcpServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("hvac-sim")


class SignalFeeder(threading.Thread):
    def __init__(self, context: ModbusSlaveContext, interval: float):
        super().__init__(daemon=True)
        self.context = context
        self.interval = interval
        self._stop = threading.Event()
        self._t = 0.0

    def run(self):
        while not self._stop.is_set():
            # random.uniform here is cosmetic sensor-noise for a synthetic
            # signal, not a security-relevant value -- not a place that
            # needs a cryptographic RNG.
            temp_c = 18.0 + 6.0 * math.sin(self._t / 20.0) + random.uniform(-0.3, 0.3)  # nosec B311
            humidity = 45.0 + 10.0 * math.sin(self._t / 35.0 + 1.0) + random.uniform(-1.0, 1.0)  # nosec B311
            fan_on = 1 if temp_c > 21.0 else 0
            self.context.setValues(3, 0, [
                max(0, round(temp_c * 10)),
                max(0, round(humidity * 10)),
                fan_on,
            ])
            self._t += self.interval
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    # Intentional: needs to be reachable from every simulated lab host
    # (loopback addresses or docker-compose containers), not just localhost.
    parser.add_argument("--host", default="0.0.0.0")  # nosec B104
    parser.add_argument("--port", type=int, default=5021)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()

    store = ModbusSlaveContext(hr=ModbusSequentialDataBlock(0, [0] * 8))
    context = ModbusServerContext(slaves=store, single=True)
    feeder = SignalFeeder(store, args.interval)
    feeder.start()

    log.info("HVAC simulator (synthetic signal) listening on %s:%d", args.host, args.port)
    try:
        StartTcpServer(context=context, address=(args.host, args.port))
    finally:
        feeder.stop()


if __name__ == "__main__":
    main()
