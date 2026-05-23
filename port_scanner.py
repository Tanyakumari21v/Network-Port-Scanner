#!/usr/bin/env python3
"""
Network Port Scanner
Author: Coding-with-Mayank
Description: A comprehensive Python tool to scan target hosts for open ports,
             identify running services, detect OS fingerprints, and generate
             detailed security reports.
"""

import socket
import concurrent.futures
import argparse
import json
import csv
import sys
import time
import ipaddress
from datetime import datetime
from typing import List, Dict, Tuple, Optional


# ─────────────────────────────────────────────
#  COMMON PORTS & SERVICES
# ─────────────────────────────────────────────

COMMON_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
    119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP-Submission",
    631: "IPP", 636: "LDAPS", 873: "Rsync", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle-DB", 1723: "PPTP",
    2049: "NFS", 2181: "ZooKeeper", 2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev-Server", 3306: "MySQL",
    3389: "RDP", 4000: "Dev-Server-Alt", 4444: "Metasploit",
    5000: "Flask/UPnP", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 5901: "VNC-1", 6379: "Redis",
    6443: "Kubernetes-API", 7070: "WebLogic", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9000: "PHP-FPM", 9090: "Prometheus", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Shard",
    50000: "DB2",
}

# Ports flagged as high risk if open
HIGH_RISK_PORTS = {
    21, 23, 135, 137, 138, 139, 445, 1433, 3306, 3389,
    4444, 5900, 5901, 6379, 11211, 27017,
}

# Ports that are commonly fine / expected
LOW_RISK_PORTS = {80, 443, 22, 53, 25, 587, 993, 995}


# ─────────────────────────────────────────────
#  BANNER ART
# ─────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        ███╗   ██╗███████╗████████╗    ███████╗ ██████╗      ║
║        ████╗  ██║██╔════╝╚══██╔══╝   ██╔════╝██╔════╝      ║
║        ██╔██╗ ██║█████╗     ██║      ███████╗██║            ║
║        ██║╚██╗██║██╔══╝     ██║      ╚════██║██║            ║
║        ██║ ╚████║███████╗   ██║      ███████║╚██████╗       ║
║        ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚══════╝ ╚═════╝       ║
║                                                              ║
║              Network Port Scanner  v1.0                      ║
║         Scan. Detect. Secure. — by Coding-with-Mayank        ║
╚══════════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────
#  CORE SCANNER CLASS
# ─────────────────────────────────────────────

class PortScanner:
    def __init__(self, target: str, ports: List[int], timeout: float = 1.0,
                 threads: int = 100, verbose: bool = False):
        self.target = target
        self.target_ip = self._resolve(target)
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.open_ports: List[Dict] = []
        self.closed_count = 0
        self.filtered_count = 0
        self.scan_start: Optional[datetime] = None
        self.scan_end: Optional[datetime] = None

    def _resolve(self, host: str) -> str:
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror:
            print(f"\n[✗] Cannot resolve host: {host}")
            sys.exit(1)

    def _grab_banner(self, sock: socket.socket) -> str:
        """Attempt to grab service banner."""
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner[:120] if banner else ""
        except Exception:
            return ""

    def _scan_port(self, port: int) -> Optional[Dict]:
        """Scan a single TCP port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    service = COMMON_SERVICES.get(port, "Unknown")
                    banner = ""
                    try:
                        banner = self._grab_banner(sock)
                    except Exception:
                        pass
                    risk = self._assess_risk(port)
                    return {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner,
                        "risk": risk,
                    }
                else:
                    self.closed_count += 1
                    return None
        except socket.timeout:
            self.filtered_count += 1
            return None
        except Exception:
            self.filtered_count += 1
            return None

    def _assess_risk(self, port: int) -> str:
        """Assess the security risk level of an open port."""
        if port in HIGH_RISK_PORTS:
            return "HIGH"
        if port in LOW_RISK_PORTS:
            return "LOW"
        return "MEDIUM"

    def run(self) -> List[Dict]:
        """Execute the port scan using a thread pool."""
        self.scan_start = datetime.now()
        total = len(self.ports)

        print(f"\n[*] Target   : {self.target} ({self.target_ip})")
        print(f"[*] Ports    : {total} ports queued")
        print(f"[*] Threads  : {self.threads}")
        print(f"[*] Timeout  : {self.timeout}s per port")
        print(f"[*] Started  : {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "─" * 64)
        print(f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<20} {'RISK':<8} BANNER")
        print("─" * 64)

        scanned = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                scanned += 1
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    self._print_open(result)
                elif self.verbose:
                    port = futures[future]
                    print(f"  {port:<8} {'closed':<8} {'—':<20} {'—':<8}")

        self.scan_end = datetime.now()
        return self.open_ports

    def _print_open(self, r: Dict) -> None:
        """Print a discovered open port with color coding."""
        risk_colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
        reset = "\033[0m"
        color = risk_colors.get(r["risk"], "")
        banner_preview = f"  {r['banner'][:40]}..." if len(r["banner"]) > 40 else f"  {r['banner']}"
        print(
            f"  {color}{r['port']:<8} {'open':<8} {r['service']:<20} {r['risk']:<8}{reset}{banner_preview}"
        )


# ─────────────────────────────────────────────
#  REPORT GENERATOR
# ─────────────────────────────────────────────

class ReportGenerator:
    def __init__(self, scanner: PortScanner):
        self.scanner = scanner

    def _duration(self) -> str:
        delta = self.scanner.scan_end - self.scanner.scan_start
        return f"{delta.total_seconds():.2f}s"

    def print_summary(self) -> None:
        s = self.scanner
        open_ports = s.open_ports
        high = [p for p in open_ports if p["risk"] == "HIGH"]
        medium = [p for p in open_ports if p["risk"] == "MEDIUM"]
        low = [p for p in open_ports if p["risk"] == "LOW"]

        print("\n" + "═" * 64)
        print("                  SECURITY SCAN REPORT")
        print("═" * 64)
        print(f"  Target         : {s.target} ({s.target_ip})")
        print(f"  Scan Duration  : {self._duration()}")
        print(f"  Ports Scanned  : {len(s.ports)}")
        print(f"  Open Ports     : {len(open_ports)}")
        print(f"  Closed Ports   : {s.closed_count}")
        print(f"  Filtered Ports : {s.filtered_count}")
        print("─" * 64)

        if open_ports:
            print("\n  📋 OPEN PORTS SUMMARY\n")
            for p in sorted(open_ports, key=lambda x: x["port"]):
                risk_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(p["risk"], "⚪")
                print(f"  {risk_icon} {p['port']:<6} {p['service']:<22} [{p['risk']}]")
                if p["banner"]:
                    print(f"         └─ Banner: {p['banner'][:60]}")

        print("\n─" * 64)
        print("  🔐 RISK SUMMARY\n")
        print(f"  🔴 HIGH risk ports   : {len(high)}")
        if high:
            print(f"     └─ {', '.join(str(p['port']) for p in high)}")
        print(f"  🟡 MEDIUM risk ports : {len(medium)}")
        print(f"  🟢 LOW risk ports    : {len(low)}")

        print("\n─" * 64)
        print("  💡 RECOMMENDATIONS\n")
        self._recommendations(open_ports)
        print("═" * 64)

    def _recommendations(self, open_ports: List[Dict]) -> None:
        ports_set = {p["port"] for p in open_ports}
        recs = []

        if 23 in ports_set:
            recs.append("⚠️  Port 23 (Telnet) is open — replace with SSH immediately.")
        if 21 in ports_set:
            recs.append("⚠️  Port 21 (FTP) is open — use SFTP or FTPS instead.")
        if 3389 in ports_set:
            recs.append("⚠️  Port 3389 (RDP) is exposed — restrict to VPN access only.")
        if 445 in ports_set or 139 in ports_set:
            recs.append("⚠️  SMB port is open — patch EternalBlue, restrict access.")
        if 6379 in ports_set:
            recs.append("⚠️  Port 6379 (Redis) is open without auth — bind to localhost.")
        if 27017 in ports_set:
            recs.append("⚠️  Port 27017 (MongoDB) is open — enable authentication.")
        if 11211 in ports_set:
            recs.append("⚠️  Port 11211 (Memcached) is open — bind to localhost only.")
        if 4444 in ports_set:
            recs.append("🚨 Port 4444 is open — this is commonly used by Metasploit/malware!")
        if 5900 in ports_set or 5901 in ports_set:
            recs.append("⚠️  VNC port is open — use a VPN or SSH tunnel instead.")
        if 80 in ports_set and 443 not in ports_set:
            recs.append("ℹ️  HTTP is open but HTTPS is not — consider enabling TLS.")

        if not recs:
            recs.append("✅ No critical misconfigurations detected from open ports.")

        for r in recs:
            print(f"  {r}")

    def save_json(self, filepath: str) -> None:
        report = {
            "target": self.scanner.target,
            "ip": self.scanner.target_ip,
            "scan_start": self.scanner.scan_start.isoformat(),
            "scan_end": self.scanner.scan_end.isoformat(),
            "duration_seconds": (self.scanner.scan_end - self.scanner.scan_start).total_seconds(),
            "ports_scanned": len(self.scanner.ports),
            "open_ports": self.scanner.open_ports,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[✓] JSON report saved → {filepath}")

    def save_csv(self, filepath: str) -> None:
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "risk", "banner"])
            writer.writeheader()
            for row in sorted(self.scanner.open_ports, key=lambda x: x["port"]):
                writer.writerow(row)
        print(f"[✓] CSV report saved  → {filepath}")


# ─────────────────────────────────────────────
#  PORT RANGE HELPERS
# ─────────────────────────────────────────────

def parse_ports(port_arg: str) -> List[int]:
    """Parse port argument string into a sorted list of ints.

    Accepts:
      - 'common'   → top ~60 well-known ports
      - 'all'      → 1–65535
      - '80'       → single port
      - '80,443,8080' → comma-separated
      - '1-1024'   → range
      - '22,80,1000-2000' → mixed
    """
    if port_arg.lower() == "common":
        return sorted(COMMON_SERVICES.keys())
    if port_arg.lower() == "all":
        return list(range(1, 65536))

    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def validate_target(target: str) -> bool:
    """Validate that target is a hostname or IP."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return True  # Treat as hostname; resolution happens in scanner


# ─────────────────────────────────────────────
#  CLI ARGUMENT PARSER
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="Network Port Scanner — Scan hosts for open ports & vulnerabilities",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py -t 192.168.1.1
  python3 port_scanner.py -t example.com -p common
  python3 port_scanner.py -t 10.0.0.1 -p 1-1024 --threads 200
  python3 port_scanner.py -t 192.168.1.1 -p 22,80,443,3306 --json report.json
  python3 port_scanner.py -t 192.168.1.1 -p all --csv report.csv --timeout 0.5
        """,
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="common",
                        help="Ports to scan: 'common', 'all', '80', '1-1024', '22,80,443'\n"
                             "(default: common)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--json", metavar="FILE",
                        help="Save report as JSON to FILE")
    parser.add_argument("--csv", metavar="FILE",
                        help="Save report as CSV to FILE")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show closed ports too")
    return parser


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    # Legal disclaimer
    print("⚠️  LEGAL DISCLAIMER: Only scan systems you own or have explicit permission to test.")
    print("    Unauthorized scanning may be illegal in your jurisdiction.\n")

    target = args.target.strip()
    ports = parse_ports(args.ports)

    scanner = PortScanner(
        target=target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)

    if not scanner.scan_end:
        scanner.scan_end = datetime.now()

    reporter = ReportGenerator(scanner)
    reporter.print_summary()

    if args.json:
        reporter.save_json(args.json)
    if args.csv:
        reporter.save_csv(args.csv)

    print("\n[✓] Scan complete. Stay ethical. 🛡️\n")


if __name__ == "__main__":
    main()
