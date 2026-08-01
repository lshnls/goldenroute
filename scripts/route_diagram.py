#!/usr/bin/env python3
"""Analyze goldenroute destination routing and measure proxy split via iptables.

Classifies a target IP/domain against fw IP lists (order matches fw/entrypoint.sh):
  private → tor-only → russian-only → russian → load-balance (FW_LB).

Tor/WSProxy/Direct columns show successful end-to-end connection counts
(with --real-load: TLS handshake on :443, not bare TCP to redsocks).
Without --real-load those columns are n/a.

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
import ssl
import subprocess
import sys
import time


DEFAULT_FILES = {
    "russian_only": "fw/russian-only-ips.txt",
    "tor_only": "fw/tor-only-ips.txt",
    "russian": "fw/russian-ips.txt",
}
DEFAULT_CONNECTIONS = 10
# TLS/connect timeout per probe (needs headroom for Tor/wstunnel; 1s is too short).
DEFAULT_CONNECTION_TIMEOUT_SECONDS = 5.0
# Pause between probes (rate limiting / avoid hammering).
DEFAULT_CONNECTION_WAIT_SECONDS = 0
DEFAULT_TARGETS_FILE = "scripts/route_diagram.txt"
ROUTE_TOR_ONLY = "tor (tor-only-ips.txt)"
ROUTE_RUSSIAN_ONLY = "direct (russian-only-ips.txt)"
ROUTE_RUSSIAN = "direct (russian-ips.txt)"
ROUTE_PRIVATE = "direct (private)"
ROUTE_LB = "load-balance (wstunnel/tor)"
ROUTE_MIXED = "mixed"
EMPTY_BALANCE = {"TOR_BALANCE": None, "WSTUNNEL_BALANCE": None}


def _progress(message: str, *, same_line: bool = False) -> None:
    """Progress to stderr so stdout stays clean for the final report."""
    if same_line:
        sys.stderr.write(f"\r{message}")
        sys.stderr.flush()
    else:
        print(message, file=sys.stderr, flush=True)


def _format_eta(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


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

    def _probe_end_to_end(self, host: str, port: int, server_hostname: str | None = None) -> bool:
        """True only if the connection works past local REDIRECT/redsocks.

        TCP accept by redsocks is not enough: when Tor/wstunnel is down, create_connection
        still succeeds locally. Require a TLS handshake (port 443) or a short I/O probe.

        server_hostname: SNI/Host for TLS when connecting by IP (must be the real domain).
        """
        sock: socket.socket | None = None
        sni = server_hostname or host
        try:
            sock = socket.create_connection((host, port), timeout=DEFAULT_CONNECTION_TIMEOUT_SECONDS)
            sock.settimeout(DEFAULT_CONNECTION_TIMEOUT_SECONDS)
            if port == 443:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ssock = ctx.wrap_socket(sock, server_hostname=sni)
                sock = None  # ownership transferred
                try:
                    ssock.do_handshake()
                finally:
                    ssock.close()
                return True

            # Non-TLS: force upstream activity; failed SOCKS usually resets soon after accept.
            try:
                sock.sendall(b"\r\n")
                sock.recv(64)
            except socket.timeout:
                # Still open after timeout — treat as usable enough for this probe.
                return True
            return True
        except OSError:
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _attribute_lb_hit(self, before: dict[str, object], after: dict[str, object]) -> str:
        """Which FW_LB backend absorbed this probe (best-effort if concurrent traffic)."""
        tor_delta = max(int(after["tor"]) - int(before["tor"]), 0)
        ws_delta = max(int(after["wsproxy"]) - int(before["wsproxy"]), 0)
        if tor_delta > ws_delta:
            return "tor"
        if ws_delta > tor_delta:
            return "wsproxy"
        if tor_delta > 0:
            return "tor"
        return "wsproxy"

    def _generate_tcp_connections(
        self,
        targets: list[str],
        port: int,
        count: int,
        progress_label: str = "",
        counter_mode: str | None = None,
        server_hostname: str | None = None,
    ) -> dict[str, int]:
        stats = {
            "attempted": 0,
            "connected": 0,
            "failed": 0,
            "direct": 0,
            "tor": 0,
            "wsproxy": 0,
        }
        if not targets:
            return stats

        label = progress_label or targets[0]
        sni = server_hostname or self.target_domain
        started = time.monotonic()
        for index in range(count):
            target = targets[index % len(targets)]
            before = None
            if counter_mode == "lb":
                before = self._collect_iptables_counters(mode="lb")
                if before.get("error"):
                    before = None

            ok = self._probe_end_to_end(target, port, server_hostname=sni)
            if ok:
                stats["connected"] += 1
                if counter_mode == "tor_only":
                    stats["tor"] += 1
                elif counter_mode == "lb":
                    if before is not None and not before.get("error"):
                        after = self._collect_iptables_counters(mode="lb")
                        if after.get("error"):
                            stats["wsproxy"] += 1
                        else:
                            stats[self._attribute_lb_hit(before, after)] += 1
                    else:
                        stats["wsproxy"] += 1
                else:
                    stats["direct"] += 1
            else:
                stats["failed"] += 1
            stats["attempted"] += 1

            done = index + 1
            elapsed = time.monotonic() - started
            remaining = count - done
            eta = (elapsed / done) * remaining if done else 0
            _progress(
                f"  [{label}] probe {done}/{count} "
                f"ok={stats['connected']} fail={stats['failed']} "
                f"ETA {_format_eta(eta)}   ",
                same_line=True,
            )
            time.sleep(DEFAULT_CONNECTION_WAIT_SECONDS)

        sys.stderr.write("\n")
        sys.stderr.flush()
        return stats

    def _measure_deltas(
        self,
        mode: str,
        targets: list[str],
        port: int,
        count: int,
        progress_label: str = "",
    ) -> dict[str, object]:
        sample = self._generate_tcp_connections(
            targets,
            port,
            count,
            progress_label=progress_label or ",".join(targets[:3]),
            counter_mode=mode,
            server_hostname=self.target_domain,
        )

        # Prefer per-probe attribution; keep iptables batch deltas as diagnostics.
        tor_hits = int(sample.get("tor", 0))
        ws_hits = int(sample.get("wsproxy", 0))
        total = tor_hits + ws_hits
        if total == 0:
            distribution = dict(EMPTY_BALANCE)
            result_mode = "real-load-no-hits" if sample["connected"] == 0 else "real-load"
        else:
            distribution = {
                "TOR_BALANCE": int(round((tor_hits / total) * 100)),
                "WSTUNNEL_BALANCE": int(round((ws_hits / total) * 100)),
            }
            result_mode = "real-load"

        return {
            "mode": result_mode,
            "balance": distribution,
            "sample": sample,
            "sampled_ips": targets,
            "deltas": {"tor": tor_hits, "wsproxy": ws_hits},
            "counter_mode": mode,
        }

    def _read_real_distribution(
        self,
        targets: list[str],
        port: int,
        count: int,
        progress_label: str = "",
    ) -> dict[str, object]:
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
        label = progress_label or (self.target_domain or self.target_ip or targets[0])

        # Prefer LB measurement when any LB IP is present; else tor-only counters.
        if lb_targets:
            result = self._measure_deltas("lb", lb_targets, port, count, progress_label=label)
            result["lb_targets_only"] = True
            return result

        if tor_targets:
            result = self._measure_deltas("tor_only", tor_targets, port, count, progress_label=label)
            result["lb_targets_only"] = False
            return result

        # Direct / private — generate traffic for connectivity stats, but no proxy %.
        sample_targets = targets
        sample = self._generate_tcp_connections(
            sample_targets,
            port,
            count,
            progress_label=label,
            counter_mode=None,
            server_hostname=self.target_domain,
        )
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

    def analyze(
        self,
        real_load: bool = False,
        connections: int = DEFAULT_CONNECTIONS,
        port: int = 443,
        progress_label: str = "",
    ):
        targets = self.resolve_targets()
        routes_by_ip = {ip: self.classify_ip(ip) for ip in targets}
        unique_routes = sorted(set(routes_by_ip.values()))
        route = unique_routes[0] if len(unique_routes) == 1 else ROUTE_MIXED

        primary_ip = targets[0]
        label = progress_label or (self.target_domain or self.target_ip or primary_ip)
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
            _progress(f"→ {label}: route={route}, probing {connections} connections…")
            load_info = self._read_real_distribution(
                targets, port=port, count=connections, progress_label=label
            )
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
        """Successful end-to-end connection counts per path (from per-probe attribution)."""
        load_info = result.get("load_info") or {}
        mode = load_info.get("mode")
        if mode not in {"real-load", "real-load-no-hits"}:
            return {"direct": None, "tor": None, "wsproxy": None}

        sample = load_info.get("sample") or {}
        # Prefer counters collected during probes (direct/tor/wsproxy keys).
        if all(key in sample for key in ("direct", "tor", "wsproxy")):
            return {
                "direct": int(sample.get("direct", 0) or 0),
                "tor": int(sample.get("tor", 0) or 0),
                "wsproxy": int(sample.get("wsproxy", 0) or 0),
            }

        connected = int(sample.get("connected", 0) or 0)
        counter_mode = load_info.get("counter_mode")
        if counter_mode == "tor_only":
            return {"direct": 0, "tor": connected, "wsproxy": 0}
        if counter_mode == "lb":
            return {"direct": 0, "tor": 0, "wsproxy": connected}
        return {"direct": connected, "tor": 0, "wsproxy": 0}

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
        label = args.domain or args.ip or ""
        result = analyzer.analyze(
            real_load=args.real_load,
            connections=args.connections,
            port=args.port,
            progress_label=label,
        )

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
    total_targets = len(targets)
    batch_started = time.monotonic()
    if args.real_load:
        _progress(
            f"Batch: {total_targets} targets × {args.connections} probes "
            f"(timeout {DEFAULT_CONNECTION_TIMEOUT_SECONDS:g}s each)"
        )

    for target_index, target in enumerate(targets, start=1):
        try:
            if re.fullmatch(r"\d+(?:\.\d+){3}", target):
                analyzer = RouteAnalyzer(target_ip=target)
            else:
                analyzer = RouteAnalyzer(target_domain=target)

            elapsed = time.monotonic() - batch_started
            done_before = target_index - 1
            batch_eta = (elapsed / done_before) * (total_targets - done_before) if done_before else 0
            _progress(
                f"[{target_index}/{total_targets}] {target}"
                + (f"  (batch ETA {_format_eta(batch_eta)})" if args.real_load and done_before else "")
            )

            result = analyzer.analyze(
                real_load=args.real_load,
                connections=args.connections,
                port=args.port,
                progress_label=target,
            )
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
            if args.real_load:
                _progress(
                    f"  ✓ {target}: ok={sample.get('connected', 0)} "
                    f"fail={sample.get('failed', 0)} route={result['route']}"
                )
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

    if args.real_load:
        _progress(f"Done in {_format_eta(time.monotonic() - batch_started)}")

    print("Route test summary:")
    print(RouteAnalyzer.format_table(rows))


if __name__ == "__main__":
    main()
