#!/usr/bin/env python3
"""A minimal remote-management banner service, standing in for whatever
protocol real engineering workstations and jump hosts expose for remote
administration (SSH, RDP, a vendor's own remote-access agent -- the
specific protocol isn't the point). It sends one fixed banner line and
closes the connection.

This is deliberately NOT a real SSH server: no negotiation, no
authentication, no shell, no libraries that implement a real remote-access
protocol. It exists purely so scenarios/scenario_lateral_movement.py has a
real TCP service to connect to at more than one simulated lab host, so the
network tap logs real connection records for the detection engine to
reason about -- see docs/ethics.md. Two taps in lab/tap/taps.json point at
one running instance of this script, tagged with different zone/service
labels (jumphost-mgmt on the DMZ host, engws-mgmt on the engineering
workstation) -- from the tap's point of view those are two distinct
assets, exactly as they would be if each ran its own instance.
"""
import argparse
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("mgmt-banner-sim")

BANNER = b"SSH-2.0-OffshoreShield-mgmt-sim (fictional, not a real SSH implementation)\r\n"


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    log.info("connection from %s", peer)
    try:
        writer.write(BANNER)
        await writer.drain()
    finally:
        writer.close()


async def main_async(host: str, port: int) -> None:
    server = await asyncio.start_server(handle, host, port)
    log.info("remote-management banner simulator listening on %s:%d", host, port)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    # Intentional: needs to be reachable from every simulated lab host
    # (loopback addresses), not just localhost.
    parser.add_argument("--host", default="0.0.0.0")  # nosec B104
    parser.add_argument("--port", type=int, default=5040)
    args = parser.parse_args()
    asyncio.run(main_async(args.host, args.port))


if __name__ == "__main__":
    main()
