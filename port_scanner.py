#!/usr/bin/env python3
"""
Port Scanner — by Obada Hamed (NEPHOS)
A simple TCP port scanner with banner grabbing.
GitHub: https://github.com/obadahamed
"""

import socket
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
#  COMMON PORTS
# ─────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5900, 8080, 8443
]


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner.split("\n")[0] if banner else "No banner"
    except Exception:
        return "No banner"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """Scan a single port. Returns result dict if open, None if closed."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                banner = grab_banner(ip, port)
                return {"port": port, "service": service, "banner": banner}
    except Exception:
        pass
    return None


def resolve_host(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        exit(1)


def parse_ports(port_arg: str) -> list:
    """Parse port argument: 'common', range like '1-1000', or comma list."""
    if port_arg == "common":
        return COMMON_PORTS
    elif "-" in port_arg:
        start, end = port_arg.split("-")
        return list(range(int(start), int(end) + 1))
    else:
        return [int(p) for p in port_arg.split(",")]


def main():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner with Banner Grabbing — by NEPHOS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py 192.168.1.1
  python3 port_scanner.py 192.168.1.1 -p common
  python3 port_scanner.py 192.168.1.1 -p 1-1000
  python3 port_scanner.py scanme.nmap.org -p 22,80,443 -t 10
        """
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Ports to scan: 'common', range '1-1000', or list '22,80,443' (default: common)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int, default=50,
        help="Number of threads (default: 50)"
    )
    parser.add_argument(
        "--timeout",
        type=float, default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    args = parser.parse_args()

    ip = resolve_host(args.target)
    ports = parse_ports(args.ports)

    print("\n" + "=" * 55)
    print(f"  🔍 Port Scanner — by NEPHOS")
    print("=" * 55)
    print(f"  Target   : {args.target} ({ip})")
    print(f"  Ports    : {len(ports)} ports")
    print(f"  Threads  : {args.threads}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55 + "\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, args.timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"  [+] PORT {result['port']:>5}/tcp  OPEN  "
                      f"{result['service']:<12}  {result['banner'][:50]}")

    print("\n" + "=" * 55)
    print(f"  ✅ Scan complete — {len(open_ports)} open port(s) found")
    print(f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55 + "\n")


if __name__ == "__main__":
    main()
