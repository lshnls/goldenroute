#!/usr/bin/env python3

# sudo python3 scripts/route_diagram.py --domain nn.ru --real-load
import argparse
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time


DEFAULT_FILES = {
    "russian_only": "fw/russian-only-ips.txt",
    "tor_only": "fw/tor-only-ips.txt",
    "russian": "fw/russian-ips.txt",
}
DEFAULT_CONNECTIONS = 100
DEFAULT_CONNECTION_TIMEOUT_SECONDS = 1.0
DEFAULT_CONNECTION_WAIT_SECONDS = 0.01
DEFAULT_TARGETS_FILE = "scripts/route_diagram.txt"


class RouteAnalyzer:
    def __init__(self, target_ip: str | None = None, target_domain: str | None = None):
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.data = {
            "russian_only": self._load_file(DEFAULT_FILES["russian_only"]),
            "tor_only": self._load_file(DEFAULT_FILES["tor_only"]),
            "russian": self._load_file(DEFAULT_FILES["russian"]),
        }

    @staticmethod
    def _load_file(path: str):
        entries = []
        if not os.path.exists(path):
            return entries

        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line)
        return entries

    def _collect_iptables_counters(self) -> dict[str, object]:
        counters: dict[str, object] = {"wsproxy": 0, "tor": 0, "error": None}
        chains = ["FW_LB", "FW_OUTPUT", "FW_REDIRECT"]

        for chain in chains:
            try:
                proc = subprocess.run(
                    ["iptables", "-t", "nat", "-vnL", chain],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                counters["error"] = "iptables command not found"
                return counters

            if proc.returncode != 0:
                counters["error"] = (proc.stderr or proc.stdout or f"iptables exited with code {proc.returncode}").strip()
                return counters

            if not proc.stdout:
                counters["error"] = "iptables returned no output"
                return counters

            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("Chain ") or line.startswith("pkts bytes"):
                    continue
                if "REDIRECT" not in line:
                    continue
                parts = line.split()
                if len(parts) < 8:
                    continue
                try:
                    pkts = int(parts[0])
                except ValueError:
                    continue
                target = parts[-1]
                if target == "12345":
                    counters["wsproxy"] += pkts
                elif target == "12346":
                    counters["tor"] += pkts
        return counters

    def _generate_tcp_connections(self, targets: list[str], port: int, count: int) -> dict[str, int]:
        stats = {"attempted": 0, "connected": 0, "failed": 0}
        for index in range(count):
            target = targets[index % len(targets)]
            try:
                with socket.create_connection((target, port), timeout=DEFAULT_CONNECTION_TIMEOUT_SECONDS):
                    stats["connected"] += 1
            except OSError:
                stats["failed"] += 1
            finally:
                stats["attempted"] += 1
                time.sleep(DEFAULT_CONNECTION_WAIT_SECONDS)
        return stats

    def _read_real_distribution(self, port: int, count: int) -> dict[str, object]:
        targets = self.resolve_targets()
        if not targets:
            return {
                "mode": "fallback",
                "balance": {"TOR_BALANCE": 0, "WSTUNNEL_BALANCE": 0},
                "sample": {"attempted": 0, "connected": 0, "failed": 0},
            }

        before = self._collect_iptables_counters()
        if before.get("error"):
            return {
                "mode": "real-load-unavailable",
                "balance": {"TOR_BALANCE": 0, "WSTUNNEL_BALANCE": 0},
                "sample": {"attempted": 0, "connected": 0, "failed": 0},
                "error": str(before["error"]),
            }

        sample = self._generate_tcp_connections(targets, port, count)
        time.sleep(0.2)
        after = self._collect_iptables_counters()

        if after.get("error"):
            return {
                "mode": "real-load-unavailable",
                "balance": {"TOR_BALANCE": 0, "WSTUNNEL_BALANCE": 0},
                "sample": sample,
                "error": str(after["error"]),
            }

        tor_delta = max(int(after["tor"]) - int(before["tor"]), 0)
        wsproxy_delta = max(int(after["wsproxy"]) - int(before["wsproxy"]), 0)
        total = tor_delta + wsproxy_delta

        if total == 0:
            distribution = {
                "TOR_BALANCE": 0,
                "WSTUNNEL_BALANCE": 0,
            }
        else:
            distribution = {
                "TOR_BALANCE": int(round((tor_delta / total) * 100)),
                "WSTUNNEL_BALANCE": int(round((wsproxy_delta / total) * 100)),
            }

        return {
            "mode": "real-load",
            "balance": distribution,
            "sample": sample,
        }

    @staticmethod
    def _ip_in_entries(ip: str, entries: list[str]) -> bool:
        try:
            check_ip = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for entry in entries:
            try:
                if "/" in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    if check_ip in network:
                        return True
                else:
                    if str(check_ip) == entry:
                        return True
            except ValueError:
                continue
        return False

    def resolve_targets(self):
        if self.target_ip:
            return [self.target_ip]
        if self.target_domain:
            try:
                addr_info = socket.getaddrinfo(self.target_domain, None, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                print(f"Could not resolve {self.target_domain}: {exc}", file=sys.stderr)
                sys.exit(1)
            ips = sorted(
                {
                    item[4][0]
                    for item in addr_info
                    if item[0] == socket.AF_INET
                }
            )
            return ips or [self.target_domain]
        raise ValueError("Provide either --ip or --domain")

    def analyze(self, real_load: bool = False, connections: int = DEFAULT_CONNECTIONS, port: int = 443):
        targets = self.resolve_targets()
        ip = targets[0]
        result = {
            "ip": ip,
            "targets": targets,
            "russian_only": self._ip_in_entries(ip, self.data["russian_only"]),
            "tor_only": self._ip_in_entries(ip, self.data["tor_only"]),
            "russian": self._ip_in_entries(ip, self.data["russian"]),
            "balance": {"TOR_BALANCE": 0, "WSTUNNEL_BALANCE": 0},
        }

        if real_load:
            load_info = self._read_real_distribution(port=port, count=connections)
            result["balance"] = load_info["balance"]
            result["load_info"] = load_info
        else:
            result["load_info"] = {
                "mode": "static-only",
                "balance": {"TOR_BALANCE": 0, "WSTUNNEL_BALANCE": 0},
                "sample": {"attempted": 0, "connected": 0, "failed": 0},
            }

        if result["russian_only"]:
            path = "direct (russian-only-ips.txt)"
        elif result["tor_only"]:
            path = "tor (tor-only-ips.txt)"
        elif result["russian"]:
            path = "direct (russian-ips.txt)"
        else:
            path = "wsproxy"

        result["route"] = path
        result["load_distribution"] = {
            "tor": result["balance"]["TOR_BALANCE"],
            "wsproxy": result["balance"]["WSTUNNEL_BALANCE"],
        }
        result["load_checks"] = [
            f"tor balance = {result['balance']['TOR_BALANCE']}%",
            f"wsproxy balance = {result['balance']['WSTUNNEL_BALANCE']}%",
            f"proxy path selected = {path}",
        ]
        return result

    def render_mermaid(self, result: dict):
        lines = [
            "flowchart LR",
            f"    A[Target {result['ip']}] --> B{{In russian-only-ips.txt?}}",
        ]

        if result["russian_only"]:
            lines.append("    B -- Yes --> C[Direct route]")
        else:
            lines.append("    B -- No --> D{{In tor-only-ips.txt?}}")

        if result["tor_only"]:
            lines.append("    D -- Yes --> E[Tor route]")
        else:
            lines.append("    D -- No --> F{{In russian-ips.txt?}}")

        if result["russian"]:
            lines.append("    F -- Yes --> G[Direct route]")
        else:
            lines.append("    F -- No --> H[wsproxy route]")

        lines.append("")
        lines.append("    I[Load distribution] --> J[tor: " + str(result["load_distribution"]["tor"]) + "%]")
        lines.append("    I --> K[wsproxy: " + str(result["load_distribution"]["wsproxy"]) + "%]")

        return "\n".join(lines)

    @staticmethod
    def format_table(rows: list[dict]) -> str:
        headers = ["Target", "Route", "Direct", "Attempted", "Connected", "Failed", "Tor%", "WSProxy%"]
        widths = [len(header) for header in headers]
        normalized_rows = []

        for row in rows:
            normalized = {
                "target": str(row["target"]),
                "route": str(row["route"]),
                "direct": str(row["direct"]),
                "attempted": str(row["attempted"]),
                "connected": str(row["connected"]),
                "failed": str(row["failed"]),
                "tor_balance": str(row["tor_balance"]),
                "wsproxy": str(row["wsproxy"]),
            }
            normalized_rows.append(normalized)
            for index, value in enumerate([
                normalized["target"],
                normalized["route"],
                normalized["direct"],
                normalized["attempted"],
                normalized["connected"],
                normalized["failed"],
                normalized["tor_balance"],
                normalized["wsproxy"],
            ]):
                widths[index] = max(widths[index], len(value))

        def render_line(values: list[str]) -> str:
            return " | ".join(value.ljust(widths[index]) for index, value in enumerate(values))

        header_line = render_line(headers)
        divider = "-+-".join("-" * width for width in widths)
        lines = [header_line, divider]
        for row in normalized_rows:
            lines.append(render_line([
                row["target"],
                row["route"],
                row["direct"],
                row["attempted"],
                row["connected"],
                row["failed"],
                row["tor_balance"],
                row["wsproxy"],
            ]))
        return "\n".join(lines)


def _load_targets_file(path: str) -> list[str]:
    entries = []
    if not os.path.exists(path):
        raise FileNotFoundError(f"Targets file not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)
    return entries


def main():
    parser = argparse.ArgumentParser(description="Analyze IP routing path against russian-only, tor-only, russian and wsproxy")
    parser.add_argument("--ip", help="Destination IP to analyze")
    parser.add_argument("--domain", help="Domain to resolve and analyze")
    parser.add_argument("--targets-file", default=DEFAULT_TARGETS_FILE, help="Path to a file with one target host or IP per line")
    parser.add_argument("--real-load", action="store_true", help="Generate live TCP traffic and read actual FW_LB iptables counters")
    parser.add_argument("--connections", type=int, default=DEFAULT_CONNECTIONS, help="TCP connections to generate when --real-load is enabled")
    parser.add_argument("--port", type=int, default=443, help="TCP port to target during the live traffic sample")
    args = parser.parse_args()

    if args.ip or args.domain:
        if args.ip and args.domain:
            parser.error("Provide either --ip or --domain, not both")
        analyzer = RouteAnalyzer(target_ip=args.ip, target_domain=args.domain)
        result = analyzer.analyze(real_load=args.real_load, connections=args.connections, port=args.port)

        print("Route result:")
        print(f"  IP: {result['ip']}")
        print(f"  Targets: {', '.join(result['targets'])}")
        print(f"  russian-only-ips.txt: {result['russian_only']}")
        print(f"  tor-only-ips.txt: {result['tor_only']}")
        print(f"  russian-ips.txt: {result['russian']}")
        print(f"  Selected path: {result['route']}")
        print("  Load distribution checks:")
        for item in result["load_checks"]:
            print(f"    - {item}")
        print("  Rule-hit distribution:")
        print(f"    - tor: {result['load_distribution']['tor']}%")
        print(f"    - wsproxy: {result['load_distribution']['wsproxy']}%")
        if result["load_info"]["mode"] == "real-load":
            print("  Traffic sample:")
            sample = result["load_info"]["sample"]
            print(f"    - attempted: {sample['attempted']}")
            print(f"    - connected: {sample['connected']}")
            print(f"    - failed: {sample['failed']}")
        elif result["load_info"].get("mode") == "real-load-unavailable":
            print("  Traffic sample: real-load measurement unavailable")
            print(f"    - reason: {result['load_info']['error']}")
        else:
            print("  Traffic sample: disabled (run with --real-load for actual rule-hit measurement)")
        print()
        print("Mermaid:")
        print(analyzer.render_mermaid(result))
        return

    targets = _load_targets_file(args.targets_file)
    if not targets:
        parser.error(f"No targets found in {args.targets_file}")

    rows = []
    for target in targets:
        try:
            if re.fullmatch(r"\d+(?:\.\d+){3}", target):
                analyzer = RouteAnalyzer(target_ip=target)
            else:
                analyzer = RouteAnalyzer(target_domain=target)
            result = analyzer.analyze(real_load=args.real_load, connections=args.connections, port=args.port)
            sample = result["load_info"].get("sample", {}) if result["load_info"].get("mode") == "real-load" else {"attempted": 0, "connected": 0, "failed": 0}
            direct_route = "yes" if result["russian_only"] or result["russian"] else "no"
            rows.append({
                "target": target,
                "route": result["route"],
                "direct": direct_route,
                "attempted": sample.get("attempted", 0),
                "connected": sample.get("connected", 0),
                "failed": sample.get("failed", 0),
                "tor_balance": result["load_distribution"]["tor"],
                "wsproxy": result["load_distribution"]["wsproxy"],
            })
        except (socket.gaierror, ValueError) as exc:
            rows.append({
                "target": target,
                "route": "error",
                "direct": "no",
                "attempted": 0,
                "connected": 0,
                "failed": 0,
                "tor_balance": 0,
                "wsproxy": 0,
            })
            print(f"Skipping {target}: {exc}", file=sys.stderr)

    print("Route test summary:")
    print(RouteAnalyzer.format_table(rows))


if __name__ == "__main__":
    main()
