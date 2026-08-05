# Goldenroute monitoring (Grafana + Prometheus)

Stack:
  iptables-exporter  :9101  — reads host iptables + nf_conntrack
  prometheus         :9090  — scrapes exporter every 5s
  grafana            :${GRAFANA_PORT:-3000}

Metrics (Prometheus):
  goldenroute_connections_total{path="direct"|"wsproxy"|"tor"}
  goldenroute_traffic_bytes_total{path="...",direction="in"|"out"}
    in  = to client (download): OUTPUT sport redsocks / INPUT|FORWARD src russian
    out = from client (upload): INPUT dport redsocks / OUTPUT|FORWARD dst russian
  goldenroute_proxy_dst_bytes_total{path="wsproxy"|"tor",dst="...",direction="in"|"out"}
  goldenroute_proxy_dst_flows_total{path="wsproxy"|"tor",dst="..."}
  goldenroute_proxy_dst_connections{path="wsproxy"|"tor",dst="..."}
    Cumulative byte/flow counters from nf_conntrack for REDIRECT to :12345/:12346.
    direction=out = orig (client→dst, upload); direction=in = reply (dst→client, download).
    Dashboard uses increase(...[$__range]) / @ start() for volume in the selected period.
    Bytes need net.netfilter.nf_conntrack_acct=1 (enabled by fw/exporter).

Dashboards:
  Goldenroute connections      — conn/s and connection totals
  Goldenroute traffic          — bit/s and bytes, split by path and in/out
  Goldenroute top destinations — top 20 proxy destination IPs

Open:
  http://<host>:${GRAFANA_PORT:-3000}
  login: admin / admin  (or GRAFANA_ADMIN_* from .env)
  /d/goldenroute-connections
  /d/goldenroute-traffic
  /d/goldenroute-top-dst

Notes:
  - All three services use network_mode: host so exporter can read host iptables
    and Prometheus/Grafana talk over 127.0.0.1.
  - FW_LB counters are periodically reset by fw healthcheck; the exporter
    accumulates deltas so Prometheus counters stay monotonic.
  - Connections: nat first-packet ≈ new flow (russian RETURN / FW_LB / tor-only).
  - Traffic bytes: ACC jump rule counters on INPUT/OUTPUT/FORWARD (not shared RETURN).
  - Top destinations: cumulative conntrack byte deltas per destination IP;
    Grafana shows volume for the selected time range, sorted descending.
  - EXPORTER_TOP_DST / EXPORTER_MAX_DST_SERIES control export cardinality.
