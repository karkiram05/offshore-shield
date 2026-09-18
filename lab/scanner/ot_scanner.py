#!/usr/bin/env python3
"""A small, honest port scanner for exercising the lab -- this is not a
repackaged nmap and doesn't claim to be Kali. It does exactly what the
discovery scenario needs: open a burst of TCP connections to a target host
across a port range from a chosen source identity, so the tap logs it and
the detection engine has something real to catch.

Binding to a specific source IP lets one script simulate "which lab host"
the scan is coming from (see lab/network_zones.json) without needing
separate containers per host.
"""
import argparse
import socket
import time


def scan(target_host: str, ports: list[int], src_ip: str | None, timeout: float, delay: float) -> list[int]:
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if src_ip:
            sock.bind((src_ip, 0))
        try:
            sock.connect((target_host, port))
            open_ports.append(port)
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        finally:
            sock.close()
        if delay:
            time.sleep(delay)
    return open_ports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="Target host (e.g. 127.0.0.1)")
    parser.add_argument("--ports", default="6500-6530", help="Port or range, e.g. 6500-6530")
    parser.add_argument("--src-ip", default=None, help="Source IP to bind to, simulating a specific lab host")
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between connection attempts")
    args = parser.parse_args()

    if "-" in args.ports:
        lo, hi = (int(x) for x in args.ports.split("-"))
        ports = list(range(lo, hi + 1))
    else:
        ports = [int(args.ports)]

    print(f"[scanner] scanning {args.target} ports {args.ports} from src={args.src_ip or 'default'}")
    open_ports = scan(args.target, ports, args.src_ip, args.timeout, args.delay)
    print(f"[scanner] done. open: {open_ports}")


if __name__ == "__main__":
    main()
