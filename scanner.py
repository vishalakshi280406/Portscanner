"""
Port Scanner - A beginner cybersecurity project
Author: You!
Description: Scans a target IP for open TCP ports using threading for speed.
Usage: python3 scanner.py --target 127.0.0.1 --start 1 --end 1024

ETHICS NOTICE: Only scan 127.0.0.1 (your own machine) or networks you own.
Scanning others without permission is illegal.
"""

import socket
import threading
import argparse
import time


# ─────────────────────────────────────────────
# CLI Arguments
# ─────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="Python Port Scanner - Cybersecurity Beginner Project"
)
parser.add_argument(
    "--target",
    type=str,
    default="127.0.0.1",
    help="Target IP address to scan (default: 127.0.0.1)"
)
parser.add_argument(
    "--start",
    type=int,
    default=1,
    help="Start port number (default: 1)"
)
parser.add_argument(
    "--end",
    type=int,
    default=1024,
    help="End port number (default: 1024)"
)
parser.add_argument(
    "--timeout",
    type=float,
    default=0.5,
    help="Socket timeout in seconds (default: 0.5)"
)
parser.add_argument(
    "--threads",
    type=int,
    default=100,
    help="Max concurrent threads (default: 100)"
)
args = parser.parse_args()


# ─────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────
open_ports = []               # list of (port, service_name) tuples
lock = threading.Lock()       # prevents threads writing at the same time
sem = threading.Semaphore(args.threads)  # limits concurrent threads


# ─────────────────────────────────────────────
# Helper: get service name for a port number
# ─────────────────────────────────────────────
def get_service(port):
    """Returns the common service name for a port, or 'unknown'."""
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────
# Core: scan a single port
# ─────────────────────────────────────────────
def scan_port(port):
    """
    Tries to connect to the target on the given port.
    If connection succeeds (result == 0), the port is open.
    Uses a semaphore to limit concurrent threads.
    """
    with sem:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)

        result = sock.connect_ex((args.target, port))

        if result == 0:
            service = get_service(port)
            with lock:
                open_ports.append((port, service))

        sock.close()


# ─────────────────────────────────────────────
# Print banner
# ─────────────────────────────────────────────
def print_banner():
    print("=" * 50)
    print("         PYTHON PORT SCANNER v1.0")
    print("=" * 50)
    print(f"  Target  : {args.target}")
    print(f"  Ports   : {args.start} - {args.end}")
    print(f"  Timeout : {args.timeout}s per port")
    print(f"  Threads : {args.threads} max concurrent")
    print("=" * 50)
    print()


# ─────────────────────────────────────────────
# Print results table
# ─────────────────────────────────────────────
def print_results(elapsed):
    print()
    print("=" * 50)
    if not open_ports:
        print("  No open ports found.")
    else:
        print(f"  {'PORT':<10} {'SERVICE':<20}")
        print("  " + "-" * 30)
        for port, service in sorted(open_ports):
            print(f"  {port:<10} {service:<20}")
    print()
    print(f"  Scanned {args.end - args.start + 1} ports in {elapsed:.2f}s")
    print(f"  Found {len(open_ports)} open port(s)")
    print("=" * 50)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    print_banner()
    print(f"[*] Starting scan...")

    start_time = time.time()

    # Create one thread per port
    threads = []
    for port in range(args.start, args.end + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    # Wait for all threads to finish
    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    print_results(elapsed)


if __name__ == "__main__":
    main()
