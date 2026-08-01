# Goldenroute monitoring (Grafana + Prometheus)

Stack:
  iptables-exporter  :9101  — reads host iptables nat counters
  prometheus         :9090  — scrapes exporter every 5s
  grafana            :3000  — dashboard "Goldenroute connections"

Metrics (Prometheus):
  goldenroute_connections_total{path="direct"|"wsproxy"|"tor"}
  goldenroute_traffic_bytes_total{path="...",direction="in"|"out"}
    in  = to client (download): OUTPUT sport redsocks / INPUT|FORWARD src russian
    out = from client (upload): INPUT dport redsocks / OUTPUT|FORWARD dst russian

Dashboards:
  Goldenroute connections — conn/s and connection totals
  Goldenroute traffic     — bit/s and bytes, split by path and in/out

Open:
  http://<host>:${GRAFANA_PORT:-3000}
  login: admin / admin  (or GRAFANA_ADMIN_* from .env)
  /d/goldenroute-connections
  /d/goldenroute-traffic

Notes:
  - All three services use network_mode: host so exporter can read host iptables
    and Prometheus/Grafana talk over 127.0.0.1.
  - FW_LB counters are periodically reset by fw healthcheck; the exporter
    accumulates deltas so Prometheus counters stay monotonic.
  - Connections: nat first-packet ≈ new flow (russian RETURN / FW_LB / tor-only).
  - Traffic bytes: ACC jump rule counters on INPUT/OUTPUT/FORWARD (not shared RETURN).
