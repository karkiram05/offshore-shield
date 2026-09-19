#!/usr/bin/env python3
"""Minimal TCP listener run inside each zone's network namespace by
netns_lab.py -- stands in for "the service reachable in this zone" for
real connectivity testing (see netns_lab.py's module docstring). Not a
protocol implementation of anything; it just accepts a connection,
announces which zone it's in, and closes."""
import argparse
import socket


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zone", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(8)
    banner = f"zone={args.zone}".encode()
    while True:
        conn, _addr = sock.accept()
        try:
            conn.send(banner)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
