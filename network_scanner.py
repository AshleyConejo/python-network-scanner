import argparse
import csv
import ipaddress
import json
import math
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional


COMMON_PORTS: Dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp-submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


@dataclass
class OpenPort:
    port: int
    service: str
    banner: Optional[str] = None


@dataclass
class HostResult:
    ip: str
    alive: bool
    hostname: Optional[str]
    open_ports: List[OpenPort]
    scanned_ports: int
    scan_time_ms: int


def parse_ports(port_input: str) -> List[int]:
    if port_input.lower() == "common":
        return sorted(COMMON_PORTS.keys())

    ports = set()

    for part in port_input.split(","):
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            start_raw, end_raw = part.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)

            if start > end:
                raise ValueError(f"Invalid port range: {part}")

            for port in range(start, end + 1):
                validate_port(port)
                ports.add(port)
        else:
            port = int(part)
            validate_port(port)
            ports.add(port)

    if not ports:
        raise ValueError("No valid ports were provided.")

    return sorted(ports)


def validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(f"Invalid TCP port: {port}. Valid range is 1-65535.")


def normalize_target(target: str) -> ipaddress.IPv4Network:
    if "/" not in target:
        target = f"{target}/32"

    network = ipaddress.ip_network(target, strict=False)

    if network.version != 4:
        raise ValueError("This scanner version supports IPv4 only.")

    return network


def get_hosts(network: ipaddress.IPv4Network) -> List[str]:
 
    if network.prefixlen == 32:
        return [str(network.network_address)]

    return [str(ip) for ip in network.hosts()]


def ping_host(ip: str, timeout_ms: int) -> bool:
   
    system_name = platform.system().lower()

    if "windows" in system_name:
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_seconds = max(1, math.ceil(timeout_ms / 1000))
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), ip]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1, math.ceil(timeout_ms / 1000) + 1),
        )
        return result.returncode == 0
    except Exception:
        return False


def grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    
    try:
        sock.settimeout(0.8)

        if port in {80, 8000, 8080, 8888}:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        data = sock.recv(128)

        if not data:
            return None

        return data.decode(errors="replace").strip().replace("\r", " ").replace("\n", " ")[:120]

    except Exception:
        return None


def check_tcp_port(ip: str, port: int, timeout: float, banner: bool) -> Optional[OpenPort]:

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            service = COMMON_PORTS.get(port, "unknown")
            found_banner = grab_banner(sock, port) if banner else None

            return OpenPort(
                port=port,
                service=service,
                banner=found_banner,
            )

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def reverse_dns(ip: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def scan_host(
    ip: str,
    ports: List[int],
    timeout: float,
    ping_first: bool,
    ping_timeout_ms: int,
    dns: bool,
    banner: bool,
) -> HostResult:
    started = time.perf_counter()

    ping_alive = False

    if ping_first:
        ping_alive = ping_host(ip, ping_timeout_ms)

        if not ping_alive:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return HostResult(
                ip=ip,
                alive=False,
                hostname=reverse_dns(ip) if dns else None,
                open_ports=[],
                scanned_ports=0,
                scan_time_ms=elapsed_ms,
            )

    open_ports: List[OpenPort] = []

    for port in ports:
        result = check_tcp_port(ip, port, timeout, banner)

        if result:
            open_ports.append(result)

    hostname = reverse_dns(ip) if dns else None
    alive = ping_alive or len(open_ports) > 0

    elapsed_ms = int((time.perf_counter() - started) * 1000)

    return HostResult(
        ip=ip,
        alive=alive,
        hostname=hostname,
        open_ports=open_ports,
        scanned_ports=len(ports),
        scan_time_ms=elapsed_ms,
    )


def print_results(results: List[HostResult]) -> None:
    print()
    print("Scan Results")
    print("=" * 100)
    print(f"{'IP':<18} {'STATE':<8} {'HOSTNAME':<30} {'OPEN PORTS'}")
    print("-" * 100)

    for result in sorted(results, key=lambda x: ipaddress.ip_address(x.ip)):
        state = "up" if result.alive else "down"
        hostname = result.hostname or "-"

        if result.open_ports:
            ports = ", ".join(
                f"{item.port}/{item.service}" for item in result.open_ports
            )
        else:
            ports = "-"

        print(f"{result.ip:<18} {state:<8} {hostname:<30} {ports}")

    print("=" * 100)

    live_hosts = sum(1 for r in results if r.alive)
    hosts_with_open_ports = sum(1 for r in results if r.open_ports)
    total_open_ports = sum(len(r.open_ports) for r in results)

    print(f"Live hosts: {live_hosts}")
    print(f"Hosts with open ports: {hosts_with_open_ports}")
    print(f"Total open ports found: {total_open_ports}")
    print()


def save_json(results: List[HostResult], path: str) -> None:
    data = []

    for result in results:
        item = asdict(result)
        data.append(item)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    print(f"[+] JSON report saved to: {path}")


def save_csv(results: List[HostResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "ip",
            "alive",
            "hostname",
            "open_port_count",
            "open_ports",
            "scanned_ports",
            "scan_time_ms",
        ])

        for result in results:
            open_ports = ";".join(
                f"{item.port}/{item.service}" for item in result.open_ports
            )

            writer.writerow([
                result.ip,
                result.alive,
                result.hostname or "",
                len(result.open_ports),
                open_ports,
                result.scanned_ports,
                result.scan_time_ms,
            ])

    print(f"[+] CSV report saved to: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized IPv4 TCP network scanner."
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IPv4 address or CIDR subnet. Example: 192.168.1.0/24",
    )

    parser.add_argument(
        "--ports",
        default="common",
        help="Ports to scan. Use common, 22,80,443, or ranges like 1-1024.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.6,
        help="TCP connection timeout in seconds. Default: 0.6",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=64,
        help="Number of concurrent host workers. Default: 64",
    )

    parser.add_argument(
        "--ping-first",
        action="store_true",
        help="Ping host before scanning ports. Faster, but can miss hosts blocking ICMP.",
    )

    parser.add_argument(
        "--ping-timeout-ms",
        type=int,
        default=800,
        help="Ping timeout in milliseconds. Default: 800",
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Try reverse DNS lookup for each host.",
    )

    parser.add_argument(
        "--banner",
        action="store_true",
        help="Try light banner grabbing on open ports.",
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        help="Save results to JSON file.",
    )

    parser.add_argument(
        "--csv",
        dest="csv_path",
        help="Save results to CSV file.",
    )

    parser.add_argument(
        "--max-hosts",
        type=int,
        default=1024,
        help="Maximum hosts allowed without --force. Default: 1024",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow scanning more hosts than --max-hosts.",
    )

    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="Allow public IP scanning. Use only with written permission.",
    )

    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        help="Required confirmation that you have permission to scan the target.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.i_have_permission:
        print("[-] Permission confirmation missing.")
        print("    Add --i-have-permission only when you are authorized to scan this target.")
        return 1

    try:
        network = normalize_target(args.target)
        ports = parse_ports(args.ports)
    except ValueError as error:
        print(f"[-] Input error: {error}")
        return 1

    if not network.is_private and not args.allow_public:
        print("[-] Public IP scanning is blocked by default.")
        print("    Use --allow-public only when you have written permission.")
        return 1

    hosts = get_hosts(network)

    if len(hosts) > args.max_hosts and not args.force:
        print(f"[-] Target contains {len(hosts)} hosts.")
        print(f"    This exceeds the default limit of {args.max_hosts}.")
        print("    Use --force only when this is intentional and authorized.")
        return 1

    if args.workers < 1:
        print("[-] Workers must be at least 1.")
        return 1

    print("[+] Authorized Python Network Scanner")
    print(f"[+] Target: {network}")
    print(f"[+] Hosts to scan: {len(hosts)}")
    print(f"[+] Ports: {len(ports)} selected")
    print(f"[+] Timeout: {args.timeout} seconds")
    print(f"[+] Workers: {args.workers}")
    print(f"[+] Ping first: {args.ping_first}")
    print(f"[+] Reverse DNS: {args.dns}")
    print(f"[+] Banner grab: {args.banner}")

    started = time.perf_counter()
    results: List[HostResult] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(
                scan_host,
                ip,
                ports,
                args.timeout,
                args.ping_first,
                args.ping_timeout_ms,
                args.dns,
                args.banner,
            ): ip
            for ip in hosts
        }

        completed = 0

        for future in as_completed(future_map):
            completed += 1

            try:
                result = future.result()
                results.append(result)

                if result.open_ports:
                    ports_found = ", ".join(
                        str(item.port) for item in result.open_ports
                    )
                    print(f"[open] {result.ip}: {ports_found}")

            except Exception as error:
                ip = future_map[future]
                print(f"[!] Error scanning {ip}: {error}")

    elapsed = time.perf_counter() - started

    print_results(results)

    if args.json_path:
        save_json(results, args.json_path)

    if args.csv_path:
        save_csv(results, args.csv_path)

    print(f"[+] Scan completed in {elapsed:.2f} seconds.")

    return 0


if __name__ == "__main__":
    sys.exit(main())