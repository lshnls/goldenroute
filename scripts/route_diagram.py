#!/usr/bin/env python3
"""Analyze goldenroute destination routing and measure proxy split via iptables.

Classifies a target IP/domain against fw IP lists (order matches fw/entrypoint.sh):
  private → tor-only → russian-only → russian → load-balance (FW_LB).

Tor/WSProxy/Direct columns show connection counts from iptables (with --real-load),
never percentages or .env values. Without --real-load those columns are n/a.

Examples:
  sudo python3 scripts/route_diagram.py --domain nn.ru --real-load
  sudo python3 scripts/route_diagram.py --ip 160.79.104.1 --real-load --connections 50
  sudo python3 scripts/route_diagram.py --real-load
  python3 scripts/route_diagram.py --help
"""

# sudo python3 scripts/route_diagram.py --domain nn.ru --real-load
# sudo python3 scripts/route_diagram.py --real-load
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
ROUTE_TOR_ONLY = "tor (tor-only-ips.txt)"
ROUTE_RUSSIAN_ONLY = "direct (russian-only-ips.txt)"
ROUTE_RUSSIAN = "direct (russian-ips.txt)"
ROUTE_PRIVATE = "direct (private)"
ROUTE_LB = "load-balance (wstunnel/tor)"
ROUTE_MIXED = "mixed"
EMPTY_BALANCE = {"TOR_BALANCE": None, "WSTUNNEL_BALANCE": None}


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

    @staticmethod
    def _run_iptables(args: list[str]) -> subprocess.CompletedProcess[str]:
        # Prefer sudo so non-root runs work; if already root, sudo still succeeds.
        commands = [
            ["sudo", "iptables", *args],
            ["iptables", *args],
        ]
        last: subprocess.CompletedProcess[str] | None = None
        for cmd in commands:
            try:
                last = subprocess.run(cmd, capture_output=True, text=True, check=False)
            except FileNotFoundError:
                continue
            if last.returncode == 0:
                return last
        if last is None:
            raise FileNotFoundError("iptables command not found")
        return last

    def _collect_iptables_counters(self, mode: str = "lb") -> dict[str, object]:
        """Read REDIRECT packet counters from iptables.

        mode:
          lb       — FW_LB only (wstunnel/tor load-balance)
          tor_only — tor-only match-set REDIRECT rules in FW_OUTPUT/FW_REDIRECT
        """
        counters: dict[str, object] = {"wsproxy": 0, "tor": 0, "error": None}
        if mode == "lb":
            chains = ["FW_LB"]
        elif mode == "tor_only":
            chains = ["FW_OUTPUT", "FW_REDIRECT"]
        else:
            counters["error"] = f"unknown counter mode: {mode}"
            return counters

        for chain in chains:
            try:
                proc = self._run_iptables(["-t", "nat", "-vnL", chain])
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
                if mode == "lb":
                    if target == "12345":
                        counters["wsproxy"] += pkts
                    elif target == "12346":
                        counters["tor"] += pkts
                elif mode == "tor_only":
                    # Only the dedicated tor-only set rule, not generic LB leftovers.
                    if "match-set" in line and "tor-only" in line and target == "12346":
                        counters["tor"] += pkts
        return counters

    def _generate_tcp_connections(self, targets: list[str], port: int, count: int) -> dict[str, int]:
        stats = {"attempted": 0, "connected": 0, "failed": 0}
        if not targets:
            return stats
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

    def _measure_deltas(self, mode: str, targets: list[str], port: int, count: int) -> dict[str, object]:
        before = self._collect_iptables_counters(mode=mode)
        if before.get("error"):
            return {
                "mode": "real-load-unavailable",
                "balance": dict(EMPTY_BALANCE),
                "sample": {"attempted": 0, "connected": 0, "failed": 0},
                "error": str(before["error"]),
                "sampled_ips": targets,
                "deltas": {"tor": 0, "wsproxy": 0},
                "counter_mode": mode,
            }

        sample = self._generate_tcp_connections(targets, port, count)
        time.sleep(0.2)
        after = self._collect_iptables_counters(mode=mode)

        if after.get("error"):
            return {
                "mode": "real-load-unavailable",
                "balance": dict(EMPTY_BALANCE),
                "sample": sample,
                "error": str(after["error"]),
                "sampled_ips": targets,
                "deltas": {"tor": 0, "wsproxy": 0},
                "counter_mode": mode,
            }

        tor_delta = max(int(after["tor"]) - int(before["tor"]), 0)
        wsproxy_delta = max(int(after["wsproxy"]) - int(before["wsproxy"]), 0)
        total = tor_delta + wsproxy_delta

        if total == 0:
            distribution = dict(EMPTY_BALANCE)
            result_mode = "real-load-no-hits"
        else:
            distribution = {
                "TOR_BALANCE": int(round((tor_delta / total) * 100)),
                "WSTUNNEL_BALANCE": int(round((wsproxy_delta / total) * 100)),
            }
            result_mode = "real-load"

        return {
            "mode": result_mode,
            "balance": distribution,
            "sample": sample,
            "sampled_ips": targets,
            "deltas": {"tor": tor_delta, "wsproxy": wsproxy_delta},
            "counter_mode": mode,
        }

    def _read_real_distribution(self, targets: list[str], port: int, count: int) -> dict[str, object]:
        """Measure proxy split from iptables counters for the matching path.

        - load-balance IPs → FW_LB (:12345 / :12346)
        - tor-only IPs → tor-only REDIRECT rules (:12346), before FW_LB
        - direct-only → no proxy counters (n/a)
        """
        by_route: dict[str, list[str]] = {}
        for ip in targets:
            by_route.setdefault(self.classify_ip(ip), []).append(ip)

        lb_targets = by_route.get(ROUTE_LB, [])
        tor_targets = by_route.get(ROUTE_TOR_ONLY, [])

        # Prefer LB measurement when any LB IP is present; else tor-only counters.
        if lb_targets:
            result = self._measure_deltas("lb", lb_targets, port, count)
            result["lb_targets_only"] = True
            return result

        if tor_targets:
            result = self._measure_deltas("tor_only", tor_targets, port, count)
            result["lb_targets_only"] = False
            return result

        # Direct / private — generate traffic for connectivity stats, but no proxy %.
        sample_targets = targets
        sample = self._generate_tcp_connections(sample_targets, port, count)
        return {
            "mode": "real-load-no-hits",
            "balance": dict(EMPTY_BALANCE),
            "sample": sample,
            "sampled_ips": sample_targets,
            "deltas": {"tor": 0, "wsproxy": 0},
            "counter_mode": "none",
            "lb_targets_only": False,
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

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local)

    def classify_ip(self, ip: str) -> str:
        """Match fw/entrypoint.sh order: private → tor-only → russian-only → russian → FW_LB."""
        if self._is_private(ip):
            return ROUTE_PRIVATE
        if self._ip_in_entries(ip, self.data["tor_only"]):
            return ROUTE_TOR_ONLY
        if self._ip_in_entries(ip, self.data["russian_only"]):
            return ROUTE_RUSSIAN_ONLY
        if self._ip_in_entries(ip, self.data["russian"]):
            return ROUTE_RUSSIAN
        return ROUTE_LB

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
        routes_by_ip = {ip: self.classify_ip(ip) for ip in targets}
        unique_routes = sorted(set(routes_by_ip.values()))
        route = unique_routes[0] if len(unique_routes) == 1 else ROUTE_MIXED

        primary_ip = targets[0]
        result = {
            "ip": primary_ip,
            "targets": targets,
            "routes_by_ip": routes_by_ip,
            "russian_only": self._ip_in_entries(primary_ip, self.data["russian_only"]),
            "tor_only": self._ip_in_entries(primary_ip, self.data["tor_only"]),
            "russian": self._ip_in_entries(primary_ip, self.data["russian"]),
            "private": self._is_private(primary_ip),
            "balance": dict(EMPTY_BALANCE),
            "route": route,
        }

        if real_load:
            load_info = self._read_real_distribution(targets, port=port, count=connections)
            result["balance"] = load_info["balance"]
            result["load_info"] = load_info
        else:
            result["load_info"] = {
                "mode": "no-sample",
                "balance": dict(EMPTY_BALANCE),
                "sample": {"attempted": 0, "connected": 0, "failed": 0},
                "deltas": {"tor": 0, "wsproxy": 0},
                "counter_mode": "none",
            }

        counts = self.path_connection_counts(result)
        result["load_distribution"] = counts
        result["load_checks"] = [
            f"direct connections = {counts['direct'] if counts['direct'] is not None else 'n/a'}",
            f"tor connections = {counts['tor'] if counts['tor'] is not None else 'n/a'}",
            f"wsproxy connections = {counts['wsproxy'] if counts['wsproxy'] is not None else 'n/a'}",
            f"proxy path selected = {route}",
        ]
        return result

    def render_mermaid(self, result: dict):
        # Order matches fw: tor-only → russian-only → russian → load-balance
        ip = result["ip"]
        route = result["routes_by_ip"].get(ip, result["route"])
        lines = [
            "flowchart LR",
            f"    A[Target {ip}] --> B{{In tor-only-ips.txt?}}",
        ]

        if route == ROUTE_TOR_ONLY:
            lines.append("    B -- Yes --> C[Tor route]")
        else:
            lines.append("    B -- No --> D{{In russian-only-ips.txt?}}")
            if route == ROUTE_RUSSIAN_ONLY:
                lines.append("    D -- Yes --> E[Direct route]")
            else:
                lines.append("    D -- No --> F{{In russian-ips.txt?}}")
                if route == ROUTE_RUSSIAN:
                    lines.append("    F -- Yes --> G[Direct route]")
                elif route == ROUTE_PRIVATE:
                    lines.append("    F -- No --> P[Direct private]")
                else:
                    lines.append("    F -- No --> H[load-balance wstunnel/tor]")

        tor_count = result["load_distribution"]["tor"]
        ws_count = result["load_distribution"]["wsproxy"]
        direct_count = result["load_distribution"].get("direct")
        if tor_count is not None or ws_count is not None or direct_count is not None:
            source = result["load_info"].get("counter_mode", "iptables")
            lines.append("")
            lines.append(f"    I[iptables {source}] --> Jd[direct: {direct_count if direct_count is not None else 0}]")
            lines.append(f"    I --> J[tor: {tor_count if tor_count is not None else 0}]")
            lines.append(f"    I --> K[wsproxy: {ws_count if ws_count is not None else 0}]")

        return "\n".join(lines)

    @staticmethod
    def path_connection_counts(result: dict) -> dict[str, int | None]:
        """Connection counts per path from iptables deltas / sample (not percentages)."""
        load_info = result.get("load_info") or {}
        mode = load_info.get("mode")
        if mode not in {"real-load", "real-load-no-hits"}:
            return {"direct": None, "tor": None, "wsproxy": None}

        sample = load_info.get("sample") or {}
        deltas = load_info.get("deltas") or {}
        connected = int(sample.get("connected", 0) or 0)
        tor = int(deltas.get("tor", 0) or 0)
        wsproxy = int(deltas.get("wsproxy", 0) or 0)
        counter_mode = load_info.get("counter_mode")
        route = result.get("route", "")

        if counter_mode == "none" or (
            isinstance(route, str) and route.startswith("direct") and counter_mode != "lb"
        ):
            return {"direct": connected, "tor": 0, "wsproxy": 0}

        if counter_mode == "tor_only":
            return {"direct": 0, "tor": tor if tor else connected, "wsproxy": 0}

        if counter_mode == "lb":
            return {"direct": 0, "tor": tor, "wsproxy": wsproxy}

        # mixed / unknown — attribute iptables hits to proxy, remainder to direct
        attributed = tor + wsproxy
        direct = max(connected - attributed, 0)
        return {"direct": direct, "tor": tor, "wsproxy": wsproxy}

    @staticmethod
    def format_table(rows: list[dict]) -> str:
        headers = ["Target", "Route", "Attempted", "Connected", "Failed", "Direct", "Tor", "WSProxy"]
        widths = [len(header) for header in headers]
        normalized_rows = []

        for row in rows:
            normalized = {
                "target": str(row["target"]),
                "route": str(row["route"]),
                "attempted": str(row["attempted"]),
                "connected": str(row["connected"]),
                "failed": str(row["failed"]),
                "direct": str(row["direct"]),
                "tor": str(row["tor"]),
                "wsproxy": str(row["wsproxy"]),
            }
            normalized_rows.append(normalized)
            for index, value in enumerate([
                normalized["target"],
                normalized["route"],
                normalized["attempted"],
                normalized["connected"],
                normalized["failed"],
                normalized["direct"],
                normalized["tor"],
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
                row["attempted"],
                row["connected"],
                row["failed"],
                row["direct"],
                row["tor"],
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
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Analyze goldenroute routing for a destination and optionally measure "
            "Tor/wstunnel split from live iptables counters."
        ),
        epilog=f"""\
Parameters:
  --ip IP               Single destination IPv4 to classify (no DNS).
                        Mutually exclusive with --domain.

  --domain NAME         Resolve NAME to IPv4 and classify each address.
                        If routes differ across A-records, result is "mixed".
                        Mutually exclusive with --ip.

  --targets-file PATH   Batch mode (default when neither --ip nor --domain).
                        One host or IP per line; # comments allowed.
                        Default: {DEFAULT_TARGETS_FILE}

  --real-load           Open TCP connections to the target(s) and count
                        Direct/Tor/WSProxy hits from iptables REDIRECT deltas:
                          • load-balance IPs → chain FW_LB (:12345 / :12346)
                          • tor-only IPs     → match-set tor-only (:12346)
                          • direct IPs       → Direct = connected count
                        Needs root or sudo for iptables. Without this flag
                        Direct/Tor/WSProxy columns are n/a.

  --connections N       How many TCP connections to open with --real-load.
                        Default: {DEFAULT_CONNECTIONS}

  --port PORT           Destination TCP port for --real-load samples.
                        Default: 443

Routing order (same as fw):
  private → tor-only-ips → russian-only-ips → russian-ips → FW_LB

Examples:
  sudo python3 scripts/route_diagram.py --domain youtube.com --real-load
  sudo python3 scripts/route_diagram.py --ip 13.107.4.200
  sudo python3 scripts/route_diagram.py --real-load --connections 200
""",
    )
    parser.add_argument(
        "--ip",
        metavar="IP",
        help="Destination IPv4 to analyze (no DNS). Cannot be used with --domain.",
    )
    parser.add_argument(
        "--domain",
        metavar="NAME",
        help="Domain to resolve and analyze (all IPv4 A-records). Cannot be used with --ip.",
    )
    parser.add_argument(
        "--targets-file",
        metavar="PATH",
        default=DEFAULT_TARGETS_FILE,
        help=f"File with one target host/IP per line for batch summary (default: {DEFAULT_TARGETS_FILE}).",
    )
    parser.add_argument(
        "--real-load",
        action="store_true",
        help=(
            "Generate live TCP traffic and count Direct/Tor/WSProxy connections "
            "from iptables REDIRECT counters (FW_LB or tor-only rules). Requires sudo/root."
        ),
    )
    parser.add_argument(
        "--connections",
        metavar="N",
        type=int,
        default=DEFAULT_CONNECTIONS,
        help=f"Number of TCP connections for --real-load (default: {DEFAULT_CONNECTIONS}).",
    )
    parser.add_argument(
        "--port",
        metavar="PORT",
        type=int,
        default=443,
        help="TCP port used for --real-load samples (default: 443).",
    )
    args = parser.parse_args()

    if args.ip or args.domain:
        if args.ip and args.domain:
            parser.error("Provide either --ip or --domain, not both")
        analyzer = RouteAnalyzer(target_ip=args.ip, target_domain=args.domain)
        result = analyzer.analyze(real_load=args.real_load, connections=args.connections, port=args.port)

        print("Route result:")
        print(f"  IP: {result['ip']}")
        print(f"  Targets: {', '.join(result['targets'])}")
        if len(result["routes_by_ip"]) > 1:
            print("  Per-IP routes:")
            for ip, route in result["routes_by_ip"].items():
                print(f"    - {ip}: {route}")
        print(f"  tor-only-ips.txt: {result['tor_only']}")
        print(f"  russian-only-ips.txt: {result['russian_only']}")
        print(f"  russian-ips.txt: {result['russian']}")
        print(f"  Selected path: {result['route']}")
        print("  Connection counts (from iptables counters / sample):")
        for item in result["load_checks"]:
            print(f"    - {item}")
        counts = result["load_distribution"]
        print("  Path hits:")
        print(f"    - direct: {counts['direct'] if counts['direct'] is not None else 'n/a'}")
        print(f"    - tor: {counts['tor'] if counts['tor'] is not None else 'n/a'}")
        print(f"    - wsproxy: {counts['wsproxy'] if counts['wsproxy'] is not None else 'n/a'}")
        mode = result["load_info"]["mode"]
        if mode == "real-load":
            print("  Traffic sample:")
            sample = result["load_info"]["sample"]
            deltas = result["load_info"].get("deltas", {})
            counter_mode = result["load_info"].get("counter_mode", "lb")
            print(f"    - attempted: {sample['attempted']}")
            print(f"    - connected: {sample['connected']}")
            print(f"    - failed: {sample['failed']}")
            print(f"    - counter source: {counter_mode}")
            print(f"    - deltas: tor={deltas.get('tor', 0)} wsproxy={deltas.get('wsproxy', 0)}")
            print(f"    - sampled IPs: {', '.join(result['load_info'].get('sampled_ips', []))}")
        elif mode == "real-load-no-hits":
            print("  Traffic sample: no matching iptables proxy counter hits (counted as Direct if connected)")
            sample = result["load_info"]["sample"]
            print(f"    - attempted: {sample['attempted']}")
            print(f"    - connected: {sample['connected']}")
            print(f"    - failed: {sample['failed']}")
            print(f"    - counter source: {result['load_info'].get('counter_mode', 'none')}")
        elif mode == "real-load-unavailable":
            print("  Traffic sample: real-load measurement unavailable")
            print(f"    - reason: {result['load_info']['error']}")
        else:
            print("  Traffic sample: disabled (use --real-load to measure connection counts)")
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
            sample = result["load_info"].get("sample", {}) if result["load_info"].get("mode") in {
                "real-load",
                "real-load-no-hits",
            } else {"attempted": 0, "connected": 0, "failed": 0}
            counts = result["load_distribution"]
            rows.append({
                "target": target,
                "route": result["route"],
                "attempted": sample.get("attempted", 0),
                "connected": sample.get("connected", 0),
                "failed": sample.get("failed", 0),
                "direct": "n/a" if counts["direct"] is None else counts["direct"],
                "tor": "n/a" if counts["tor"] is None else counts["tor"],
                "wsproxy": "n/a" if counts["wsproxy"] is None else counts["wsproxy"],
            })
        except (socket.gaierror, ValueError) as exc:
            rows.append({
                "target": target,
                "route": "error",
                "attempted": 0,
                "connected": 0,
                "failed": 0,
                "direct": "n/a",
                "tor": "n/a",
                "wsproxy": "n/a",
            })
            print(f"Skipping {target}: {exc}", file=sys.stderr)

    print("Route test summary:")
    print(RouteAnalyzer.format_table(rows))


if __name__ == "__main__":
    main()
