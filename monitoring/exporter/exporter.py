#!/usr/bin/env python3
"""Export goldenroute iptables metrics as Prometheus counters.

Connections (nat, first packet ≈ new flow):
  - Direct: RETURN match-set russian-only-ips / russian-ips (FW_OUTPUT + FW_REDIRECT)
  - WSProxy: FW_LB REDIRECT :12345
  - Tor: FW_LB REDIRECT :12346 + tor-only REDIRECT :12346

Traffic bytes (filter jump rules into ACC chains, all packets):
  - direction=out: client → path (INPUT dport redsocks / OUTPUT|FORWARD dst russian)
  - direction=in:  path → client (OUTPUT sport redsocks / INPUT|FORWARD src russian)

Top proxy destinations (cumulative from nf_conntrack):
  - Flows whose reply sport is redsocks :12345 / :12346
  - Original destination = first dst= in the conntrack tuple
  - orig bytes (tuple1) = upload/out; reply bytes (tuple2) = download/in
  - Per-flow deltas → goldenroute_proxy_dst_bytes_total{direction="in"|"out"}
  - Requires nf_conntrack_acct=1 for byte accounting

FW_LB is periodically flushed by fw healthcheck; this exporter accumulates
deltas so Prometheus counters remain monotonic.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


LISTEN_HOST = os.environ.get("EXPORTER_LISTEN", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("EXPORTER_PORT", "9101"))
SCRAPE_INTERVAL = float(os.environ.get("EXPORTER_INTERVAL", "5"))
TOP_DST_N = int(os.environ.get("EXPORTER_TOP_DST", "20"))
MAX_DST_SERIES = int(os.environ.get("EXPORTER_MAX_DST_SERIES", "200"))
CONNTRACK_PATH = Path(os.environ.get("EXPORTER_CONNTRACK", "/proc/net/nf_conntrack"))
CONNTRACK_ACCT_PATH = Path("/proc/sys/net/netfilter/nf_conntrack_acct")

PATHS = ("direct", "wsproxy", "tor")
DIRECTIONS = ("in", "out")
BYTE_KEYS = tuple(f"{path}:{direction}" for path in PATHS for direction in DIRECTIONS)

ACC_WSPROXY = "FW_ACC_WSPROXY"
ACC_TOR = "FW_ACC_TOR"
ACC_DIRECT = "FW_ACC_DIRECT"
REDSOCKS_PORT = "12345"
TOR_REDSOCKS_PORT = "12346"
PROXY_PORTS = {
    REDSOCKS_PORT: "wsproxy",
    TOR_REDSOCKS_PORT: "tor",
}

_CT_TCP_RE = re.compile(
    r"\btcp\b.*?"
    r"src=(?P<src1>\S+)\s+dst=(?P<dst1>\S+)\s+sport=(?P<sport1>\d+)\s+dport=(?P<dport1>\d+)"
    r"(?:\s+packets=(?P<pkts1>\d+)\s+bytes=(?P<bytes1>\d+))?"
    r".*?"
    r"src=(?P<src2>\S+)\s+dst=(?P<dst2>\S+)\s+sport=(?P<sport2>\d+)\s+dport=(?P<dport2>\d+)"
    r"(?:\s+packets=(?P<pkts2>\d+)\s+bytes=(?P<bytes2>\d+))?",
)

_lock = threading.Lock()
_last_raw_conn: dict[str, int] = {p: 0 for p in PATHS}
_cumulative_conn: dict[str, int] = {p: 0 for p in PATHS}
_last_raw_bytes: dict[str, int] = {k: 0 for k in BYTE_KEYS}
_cumulative_bytes: dict[str, int] = {k: 0 for k in BYTE_KEYS}
# flow_id → (orig_bytes, reply_bytes)
_last_flow_bytes: dict[str, tuple[int, int]] = {}
# (path, dst) → cumulative bytes by direction
_cumulative_dst_bytes_out: dict[tuple[str, str], int] = {}
_cumulative_dst_bytes_in: dict[tuple[str, str], int] = {}
_cumulative_dst_flows: dict[tuple[str, str], int] = {}
_active_dst_conns: dict[tuple[str, str], int] = {}
_last_error: str = ""
_last_scrape_ts: float = 0.0


def _dst_total_bytes(key: tuple[str, str]) -> int:
    return _cumulative_dst_bytes_out.get(key, 0) + _cumulative_dst_bytes_in.get(key, 0)

def _ensure_conntrack_acct() -> None:
    """Enable per-flow byte counters so top-dst can rank by volume."""
    try:
        if CONNTRACK_ACCT_PATH.exists() and CONNTRACK_ACCT_PATH.read_text().strip() != "1":
            CONNTRACK_ACCT_PATH.write_text("1\n")
            print("[exporter] enabled net.netfilter.nf_conntrack_acct=1", flush=True)
    except OSError as exc:
        print(f"[exporter] warning: cannot enable nf_conntrack_acct: {exc}", flush=True)


def _is_private_ip(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
        except (ValueError, IndexError):
            return False
        return 16 <= second <= 31
    return ip in ("0.0.0.0", "::", "::1")


def _run_iptables(args: list[str]) -> str:
    commands = (
        ["iptables", *args],
        ["sudo", "iptables", *args],
    )
    last_err = ""
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            last_err = str(exc)
            continue
        if proc.returncode == 0:
            return proc.stdout
        last_err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
    raise RuntimeError(last_err or "iptables failed")


def _parse_count(token: str) -> int:
    """Parse iptables pkts/bytes field (exact int or human K/M/G suffix)."""
    token = token.strip().upper()
    if not token:
        raise ValueError("empty count")
    mult = 1
    if token[-1] == "K":
        mult, token = 1000, token[:-1]
    elif token[-1] == "M":
        mult, token = 1_000_000, token[:-1]
    elif token[-1] == "G":
        mult, token = 1_000_000_000, token[:-1]
    return int(float(token) * mult)


def _parse_chain(output: str) -> list[dict[str, str | int]]:
    rows: list[dict[str, str | int]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Chain ") or line.startswith("pkts bytes"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            pkts = _parse_count(parts[0])
            nbytes = _parse_count(parts[1])
        except ValueError:
            continue
        target = parts[2] if len(parts) > 2 else ""
        rows.append({"pkts": pkts, "bytes": nbytes, "target": target, "line": line})
    return rows


def _bump_delta(cumulative: dict[str, int], last_raw: dict[str, int], key: str, current: int) -> None:
    previous = last_raw[key]
    if current >= previous:
        delta = current - previous
    else:
        # Chain flush / counter reset.
        delta = current
    cumulative[key] += delta
    last_raw[key] = current


def _read_raw_connections() -> dict[str, int]:
    counts = {"direct": 0, "wsproxy": 0, "tor": 0}

    for chain in ("FW_OUTPUT", "FW_REDIRECT"):
        try:
            rows = _parse_chain(_run_iptables(["-t", "nat", "-vnL", chain, "-x"]))
        except RuntimeError:
            continue
        for row in rows:
            line = str(row["line"])
            pkts = int(row["pkts"])
            if "match-set" in line and "russian-only-ips" in line and row["target"] == "RETURN":
                counts["direct"] += pkts
            elif "match-set" in line and "russian-ips" in line and "russian-only" not in line and row["target"] == "RETURN":
                counts["direct"] += pkts
            elif "match-set" in line and "tor-only" in line and "REDIRECT" in line and line.endswith("12346"):
                counts["tor"] += pkts

    try:
        rows = _parse_chain(_run_iptables(["-t", "nat", "-vnL", "FW_LB", "-x"]))
    except RuntimeError:
        rows = []
    for row in rows:
        line = str(row["line"])
        pkts = int(row["pkts"])
        if "REDIRECT" not in line:
            continue
        if line.endswith("12345"):
            counts["wsproxy"] += pkts
        elif line.endswith("12346"):
            counts["tor"] += pkts

    return counts


def _add_bytes(counts: dict[str, int], path: str, direction: str, nbytes: int) -> None:
    counts[f"{path}:{direction}"] += nbytes


def _read_raw_bytes() -> dict[str, int]:
    """Bytes by path and direction from ACC jump rules (not the shared RETURN)."""
    counts = {k: 0 for k in BYTE_KEYS}

    # Proxy: INPUT dport = client upload (out); OUTPUT sport = download to client (in).
    for filter_chain, direction, port_key in (
        ("INPUT", "out", "dpt:"),
        ("OUTPUT", "in", "spt:"),
    ):
        try:
            rows = _parse_chain(_run_iptables(["-vnL", filter_chain, "-x"]))
        except RuntimeError:
            continue
        for row in rows:
            line = str(row["line"])
            nbytes = int(row["bytes"])
            if row["target"] == ACC_WSPROXY and f"{port_key}{REDSOCKS_PORT}" in line:
                _add_bytes(counts, "wsproxy", direction, nbytes)
            elif row["target"] == ACC_TOR and f"{port_key}{TOR_REDSOCKS_PORT}" in line:
                _add_bytes(counts, "tor", direction, nbytes)

    # Direct: dst = client→RU (out); src = RU→client (in). INPUT/OUTPUT + FORWARD.
    for filter_chain in ("INPUT", "OUTPUT", "FORWARD"):
        try:
            rows = _parse_chain(_run_iptables(["-vnL", filter_chain, "-x"]))
        except RuntimeError:
            continue
        for row in rows:
            if row["target"] != ACC_DIRECT:
                continue
            line = str(row["line"])
            nbytes = int(row["bytes"])
            if "match-set" not in line:
                continue
            if "russian-only-ips" not in line and "russian-ips" not in line:
                continue
            # iptables: "... match-set russian-ips dst|src"
            if line.rstrip().endswith("dst") and filter_chain in ("OUTPUT", "FORWARD"):
                _add_bytes(counts, "direct", "out", nbytes)
            elif line.rstrip().endswith("src") and filter_chain in ("INPUT", "FORWARD"):
                _add_bytes(counts, "direct", "in", nbytes)

    return counts


def _scrape_proxy_dst() -> None:
    """Accumulate per-destination bytes/flows from nf_conntrack proxy REDIRECT flows."""
    global _active_dst_conns
    if not CONNTRACK_PATH.exists():
        _active_dst_conns = {}
        return

    try:
        text = CONNTRACK_PATH.read_text(errors="replace")
    except OSError:
        return

    seen_flows: set[str] = set()
    active: dict[tuple[str, str], int] = {}

    for line in text.splitlines():
        if "tcp" not in line:
            continue
        if f"sport={REDSOCKS_PORT}" not in line and f"sport={TOR_REDSOCKS_PORT}" not in line:
            continue
        m = _CT_TCP_RE.search(line)
        if not m:
            continue
        reply_sport = m.group("sport2")
        path = PROXY_PORTS.get(reply_sport)
        if not path:
            continue
        dst = m.group("dst1")
        if _is_private_ip(dst):
            continue

        sport1 = m.group("sport1")
        dport1 = m.group("dport1")
        flow_id = f"{path}|{dst}|{sport1}|{dport1}|{reply_sport}"
        seen_flows.add(flow_id)

        # tuple1 = original (client → dst) = upload/out
        # tuple2 = reply (dst → client via redsocks) = download/in
        orig = int(m.group("bytes1") or 0)
        reply = int(m.group("bytes2") or 0)

        key = (path, dst)
        active[key] = active.get(key, 0) + 1

        if flow_id not in _last_flow_bytes:
            _cumulative_dst_flows[key] = _cumulative_dst_flows.get(key, 0) + 1
            d_out, d_in = orig, reply
        else:
            prev_out, prev_in = _last_flow_bytes[flow_id]
            d_out = orig - prev_out if orig >= prev_out else orig
            d_in = reply - prev_in if reply >= prev_in else reply
        if d_out:
            _cumulative_dst_bytes_out[key] = _cumulative_dst_bytes_out.get(key, 0) + d_out
        if d_in:
            _cumulative_dst_bytes_in[key] = _cumulative_dst_bytes_in.get(key, 0) + d_in
        _last_flow_bytes[flow_id] = (orig, reply)

    for flow_id in list(_last_flow_bytes):
        if flow_id not in seen_flows:
            del _last_flow_bytes[flow_id]

    _active_dst_conns = active

    # Bound cardinality: drop cold destinations with lowest cumulative bytes.
    all_keys = set(_cumulative_dst_bytes_out) | set(_cumulative_dst_bytes_in) | set(_cumulative_dst_flows)
    if len(all_keys) > MAX_DST_SERIES:
        keep = {
            k
            for k, _ in sorted(
                ((k, _dst_total_bytes(k)) for k in all_keys),
                key=lambda kv: kv[1],
                reverse=True,
            )[:MAX_DST_SERIES]
        }
        for store in (_cumulative_dst_bytes_out, _cumulative_dst_bytes_in, _cumulative_dst_flows):
            for key in list(store):
                if key not in keep:
                    del store[key]


def _dst_series_for_export() -> list[tuple[str, str]]:
    """Keys to export, preferring currently active then highest cumulative volume."""
    active_keys = list(_active_dst_conns.keys())
    all_keys = set(_cumulative_dst_bytes_out) | set(_cumulative_dst_bytes_in) | set(_cumulative_dst_flows)
    ranked = sorted(all_keys, key=_dst_total_bytes, reverse=True)
    keys: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for key in active_keys + ranked:
        if key in seen:
            continue
        seen.add(key)
        keys.append(key)
        if len(keys) >= MAX_DST_SERIES:
            break
    return keys


def _accumulate() -> None:
    global _last_error, _last_scrape_ts
    try:
        raw_conn = _read_raw_connections()
        raw_bytes = _read_raw_bytes()
        with _lock:
            _scrape_proxy_dst()
            for path in PATHS:
                _bump_delta(_cumulative_conn, _last_raw_conn, path, raw_conn[path])
            for key in BYTE_KEYS:
                _bump_delta(_cumulative_bytes, _last_raw_bytes, key, raw_bytes[key])
            _last_error = ""
            _last_scrape_ts = time.time()
    except Exception as exc:  # noqa: BLE001 — keep exporter alive
        with _lock:
            _last_error = str(exc)
            _last_scrape_ts = time.time()


def _metrics_body() -> bytes:
    with _lock:
        cumulative_conn = dict(_cumulative_conn)
        cumulative_bytes = dict(_cumulative_bytes)
        dst_out = dict(_cumulative_dst_bytes_out)
        dst_in = dict(_cumulative_dst_bytes_in)
        dst_flows = dict(_cumulative_dst_flows)
        active_conns = dict(_active_dst_conns)
        export_keys = _dst_series_for_export()
        err = _last_error
        ts = _last_scrape_ts

    lines = [
        "# HELP goldenroute_connections_total New flows matched by goldenroute nat rules (approx. connections).",
        "# TYPE goldenroute_connections_total counter",
    ]
    for path in PATHS:
        lines.append(f'goldenroute_connections_total{{path="{path}"}} {cumulative_conn[path]}')

    lines.extend(
        [
            "# HELP goldenroute_traffic_bytes_total Bytes matched by goldenroute ACC jump rules.",
            "# TYPE goldenroute_traffic_bytes_total counter",
        ]
    )
    for path in PATHS:
        for direction in DIRECTIONS:
            value = cumulative_bytes[f"{path}:{direction}"]
            lines.append(
                f'goldenroute_traffic_bytes_total{{path="{path}",direction="{direction}"}} {value}'
            )

    lines.extend(
        [
            "# HELP goldenroute_proxy_dst_bytes_total Cumulative conntrack bytes to proxy destination IP.",
            "# TYPE goldenroute_proxy_dst_bytes_total counter",
        ]
    )
    for path, dst in export_keys:
        lines.append(
            f'goldenroute_proxy_dst_bytes_total{{path="{path}",dst="{dst}",direction="out"}} '
            f"{dst_out.get((path, dst), 0)}"
        )
        lines.append(
            f'goldenroute_proxy_dst_bytes_total{{path="{path}",dst="{dst}",direction="in"}} '
            f"{dst_in.get((path, dst), 0)}"
        )
    lines.extend(
        [
            "# HELP goldenroute_proxy_dst_flows_total Cumulative proxy flows seen to destination IP.",
            "# TYPE goldenroute_proxy_dst_flows_total counter",
        ]
    )
    for path, dst in export_keys:
        lines.append(
            f'goldenroute_proxy_dst_flows_total{{path="{path}",dst="{dst}"}} {dst_flows.get((path, dst), 0)}'
        )

    lines.extend(
        [
            "# HELP goldenroute_proxy_dst_connections Active proxy conntrack flows to destination IP.",
            "# TYPE goldenroute_proxy_dst_connections gauge",
        ]
    )
    for (path, dst), conns in sorted(active_conns.items(), key=lambda kv: kv[1], reverse=True)[
        :TOP_DST_N
    ]:
        lines.append(
            f'goldenroute_proxy_dst_connections{{path="{path}",dst="{dst}"}} {conns}'
        )

    lines.extend(
        [
            "# HELP goldenroute_exporter_scrape_timestamp_seconds Unix time of last successful/attempted scrape.",
            "# TYPE goldenroute_exporter_scrape_timestamp_seconds gauge",
            f"goldenroute_exporter_scrape_timestamp_seconds {ts if ts else 0}",
            "# HELP goldenroute_exporter_up 1 if last iptables scrape succeeded.",
            "# TYPE goldenroute_exporter_up gauge",
            f"goldenroute_exporter_up {0 if err else 1}",
        ]
    )
    if err:
        safe = err.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
        lines.append(f'goldenroute_exporter_error{{reason="{safe}"}} 1')
    lines.append("")
    return ("\n".join(lines)).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path not in ("/metrics", "/"):
            self.send_response(404)
            self.end_headers()
            return
        body = _metrics_body()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _loop() -> None:
    while True:
        _accumulate()
        time.sleep(SCRAPE_INTERVAL)


def main() -> None:
    _ensure_conntrack_acct()
    _accumulate()
    threading.Thread(target=_loop, name="iptables-scrape", daemon=True).start()
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[exporter] listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
