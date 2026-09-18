#!/usr/bin/env python3
"""A minimal network tap: a TCP proxy that logs every connection it forwards.

This is NOT Zeek. It doesn't do deep protocol parsing, doesn't sit on a span
port, and doesn't see traffic it isn't explicitly in the path of. It's a
small asyncio TCP proxy: each protected OT asset in the lab sits behind one
of these, so any tool -- nmap, a real Modbus client, this repo's own
scanner -- that talks to that asset necessarily talks through the tap
first, and every connection attempt (successful or not) gets logged in a
conn.log-inspired JSON-lines format that the detection engine reads.

That's a real, honest architectural substitute for Zeek in an environment
where Zeek can't be installed (see docs/architecture.md for why), not a
claim that it does what Zeek does. It captures exactly the signal this
lab's detections need -- connection 5-tuples, timing, byte counts -- and
nothing more.

Log record shape (one JSON object per line, appended to logs/conn.log):

    {
      "ts": 1234567890.123,
      "uid": "C1a2b3c4",
      "src_ip": "10.50.20.10",
      "src_port": 51410,
      "dst_ip": "10.50.30.20",
      "dst_port": 502,
      "zone": "scada",
      "service": "turbine-plc",
      "proto": "tcp",
      "duration_s": 0.014,
      "orig_bytes": 12,
      "resp_bytes": 0,
      "connected": true
    }

`connected: false` means the backend refused/was unreachable -- still a
real, loggable event (e.g. a scan of a closed port).
"""
import argparse
import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


MODBUS_FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    23: "Read/Write Multiple Registers",
}
# Function codes a passive/monitoring client has no business sending against
# this lab's read-only telemetry point. Real deployments would derive this
# from an engineering baseline, not a hardcoded list -- this is a lab-scale
# stand-in for that baseline (see docs/architecture.md).
UNEXPECTED_WRITE_CODES = {5, 6, 15, 16}


def parse_modbus_function_code(first_bytes: bytes) -> int | None:
    """Modbus TCP frame: 7-byte MBAP header, then 1-byte function code."""
    if len(first_bytes) < 8:
        return None
    return first_bytes[7]


@dataclass
class TapTarget:
    listen_port: int
    backend_host: str
    backend_port: int
    zone: str
    service: str
    protocol: str = "tcp"


def load_targets(config_path: Path) -> list[TapTarget]:
    with open(config_path) as f:
        raw = json.load(f)
    return [TapTarget(**t) for t in raw["taps"]]


class ConnLogger:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def write(self, record: dict):
        line = json.dumps(record) + "\n"
        async with self._lock:
            with open(self.log_path, "a") as f:
                f.write(line)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, counter: dict, key: str, first_bytes_holder: list):
    try:
        first = True
        while True:
            data = await reader.read(4096)
            if not data:
                break
            counter[key] += len(data)
            if first:
                first_bytes_holder.append(data[:16])
                first = False
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_connection(reader, writer, target: TapTarget, logger: ConnLogger):
    peer = writer.get_extra_info("peername")
    src_ip, src_port = (peer[0], peer[1]) if peer else ("unknown", 0)
    uid = uuid.uuid4().hex[:8]
    start = time.time()
    counter = {"orig": 0, "resp": 0}

    try:
        backend_reader, backend_writer = await asyncio.wait_for(
            asyncio.open_connection(target.backend_host, target.backend_port), timeout=2.0
        )
        connected = True
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        connected = False
        backend_reader = backend_writer = None

    orig_first: list = []
    if connected:
        await asyncio.gather(
            pipe(reader, backend_writer, counter, "orig", orig_first),
            pipe(backend_reader, writer, counter, "resp", []),
            return_exceptions=True,
        )
    else:
        writer.close()

    modbus_function_code = None
    modbus_function_name = None
    if target.protocol == "modbus" and orig_first:
        modbus_function_code = parse_modbus_function_code(orig_first[0])
        if modbus_function_code is not None:
            modbus_function_name = MODBUS_FUNCTION_NAMES.get(modbus_function_code, f"unknown ({modbus_function_code})")

    duration = time.time() - start
    await logger.write({
        "ts": start,
        "uid": uid,
        "src_ip": src_ip,
        "src_port": src_port,
        # dst_ip/dst_port are what the scanning/connecting party actually
        # touched (this tap's own listen address) -- not the internal
        # backend it proxies to, which is a lab implementation detail.
        "dst_ip": "127.0.0.1",
        "dst_port": target.listen_port,
        "backend_port": target.backend_port,
        "zone": target.zone,
        "service": target.service,
        "proto": "tcp",
        "duration_s": round(duration, 4),
        "orig_bytes": counter["orig"],
        "resp_bytes": counter["resp"],
        "connected": connected,
        "modbus_function_code": modbus_function_code,
        "modbus_function_name": modbus_function_name,
    })


async def run_tap(target: TapTarget, logger: ConnLogger, listen_host: str):
    async def handler(reader, writer):
        await handle_connection(reader, writer, target, logger)

    server = await asyncio.start_server(handler, listen_host, target.listen_port)
    async with server:
        await server.serve_forever()


async def main_async(args):
    targets = load_targets(Path(args.config))
    logger = ConnLogger(Path(args.log))
    print(f"[tap] loaded {len(targets)} target(s) from {args.config}, logging to {args.log}")
    for t in targets:
        print(f"[tap]   :{t.listen_port} -> {t.backend_host}:{t.backend_port}  zone={t.zone} service={t.service}")
    await asyncio.gather(*(run_tap(t, logger, args.host) for t in targets))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="lab/tap/taps.json")
    parser.add_argument("--log", default="logs/conn.log")
    # 0.0.0.0 is correct here, not a hardening gap: this lab's whole point
    # is to be reachable from every simulated "host" (distinct 127.0.0.x
    # loopback addresses, or separate containers on the docker-compose
    # network) so their traffic can be tapped and detected. Binding to a
    # single interface would defeat the lab.
    parser.add_argument("--host", default="0.0.0.0")  # nosec B104
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
