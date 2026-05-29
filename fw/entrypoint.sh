#!/bin/sh
set -eu

CHAIN_NAME="FW_REDIRECT"
RULES_APPLIED=0

cleanup() {
    if [ "$RULES_APPLIED" = "1" ]; then
        iptables -t nat -D PREROUTING -j "$CHAIN_NAME" 2>/dev/null || true
        iptables -t nat -F "$CHAIN_NAME" 2>/dev/null || true
        iptables -t nat -X "$CHAIN_NAME" 2>/dev/null || true
        iptables -t nat -F OUTPUT 2>/dev/null || true
        ipset destroy russian-ips 2>/dev/null || true
    fi
}
trap cleanup EXIT SIGTERM SIGINT

# flush stale rules from previous runs
iptables -t nat -D PREROUTING -j "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -F "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -X "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -D OUTPUT -p tcp -j REDIRECT --to-ports 12345 2>/dev/null || true

# download Russian IP ranges from RIPE and load into ipset
ipset create russian-ips hash:net 2>/dev/null || ipset flush russian-ips

RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU"
curl -sS --max-time 30 "$RIPE_URL" | \
    jq -r '.data.resources.ipv4[]' | \
    sed 's/^/add russian-ips /' | \
    ipset restore -! || echo "[fw] Warning: failed to load Russian IPs from RIPE"

# start redsocks
redsocks -c /etc/redsocks.conf &
REDSOCKS_PID=$!
sleep 1

# -------------------------------------------------------
# 1. OUTPUT chain — traffic from the host itself
# -------------------------------------------------------
iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN
iptables -t nat -A OUTPUT -d 10.0.0.0/8 -j RETURN
iptables -t nat -A OUTPUT -d 172.16.0.0/12 -j RETURN
iptables -t nat -A OUTPUT -d 192.168.0.0/16 -j RETURN
iptables -t nat -A OUTPUT -m set --match-set russian-ips dst -j RETURN
iptables -t nat -A OUTPUT -p tcp --dport 12345 -j RETURN
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 12345

# -------------------------------------------------------
# 2. PREROUTING — forwarded traffic from LAN clients
#    (uses a custom chain to avoid flushing Docker's rules)
# -------------------------------------------------------
iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -A PREROUTING -j "$CHAIN_NAME"

# don't redirect traffic already destined for this host
iptables -t nat -A "$CHAIN_NAME" -m addrtype --dst-type LOCAL -j RETURN

# don't redirect traffic FROM Docker containers (bridge 172.16.0.0/12)
iptables -t nat -A "$CHAIN_NAME" -s 172.16.0.0/12 -j RETURN

# don't redirect private / LAN ranges
iptables -t nat -A "$CHAIN_NAME" -d 10.0.0.0/8 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 172.16.0.0/12 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 192.168.0.0/16 -j RETURN

# don't redirect Russian IPs
iptables -t nat -A "$CHAIN_NAME" -m set --match-set russian-ips dst -j RETURN

# don't redirect traffic to redsocks itself
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 12345 -j RETURN

# redirect foreign TCP → redsocks
iptables -t nat -A "$CHAIN_NAME" -p tcp -j REDIRECT --to-ports 12345

# redirect client DNS (UDP/TCP :53) to local unbound
iptables -t nat -A "$CHAIN_NAME" -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 53 -j REDIRECT --to-ports 53

# -------------------------------------------------------
# 3. FORWARD — allow LAN clients to route through gateway
# -------------------------------------------------------
iptables -I DOCKER-USER -s 192.168.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -I DOCKER-USER -d 192.168.1.0/24 -j ACCEPT 2>/dev/null || true

# -------------------------------------------------------
# 4. MASQUERADE — SNAT LAN traffic so replies come back here
# -------------------------------------------------------
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 ! -d 192.168.1.0/24 -j MASQUERADE

RULES_APPLIED=1

echo "[fw] Transparent proxy ready"
echo "       Host TCP(OUTPUT) → redsocks → wstunnel SOCKS5:41080"
echo "       LAN TCP(PREROUTING) → redsocks → wstunnel SOCKS5:41080"
echo "       LAN DNS → unbound :53"
echo "       LAN FORWARD + MASQUERADE enabled for 192.168.1.0/24"

wait $REDSOCKS_PID
