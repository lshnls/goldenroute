#!/bin/sh
set -eu

CHAIN_NAME="FW_REDIRECT"
OUTPUT_CHAIN="FW_OUTPUT"
RULES_APPLIED=0

PROXY_BACKEND="${PROXY_BACKEND:-wstunnel}"

case "$PROXY_BACKEND" in
    tor)
        SOCKS5_PORT="${TOR_SOCKS_PORT:-9050}"
        echo "[fw] Backend: tor (SOCKS5 :$SOCKS5_PORT)"
        ;;
    off)
        SOCKS5_PORT=""
        echo "[fw] Proxy disabled — all traffic direct"
        ;;
    load_balancing)
        SOCKS5_PORT=41080
        echo "[fw] Backend: load balancing (wstunnel :41080 + tor :9050)"
        ;;
    *)
        SOCKS5_PORT="${LLP_SOCKS5_PROXY:-41080}"
        echo "[fw] Backend: wstunnel (SOCKS5 :$SOCKS5_PORT)"
        ;;
esac

cleanup() {
    if [ "$RULES_APPLIED" = "1" ]; then
        iptables -D DOCKER-USER -s 192.168.1.0/24 -j ACCEPT 2>/dev/null || true
        iptables -D DOCKER-USER -d 192.168.1.0/24 -j ACCEPT 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s 192.168.1.0/24 ! -d 192.168.1.0/24 -j MASQUERADE 2>/dev/null || true
        iptables -t nat -D PREROUTING -j "$CHAIN_NAME" 2>/dev/null || true
        iptables -t nat -F "$CHAIN_NAME" 2>/dev/null || true
        iptables -t nat -X "$CHAIN_NAME" 2>/dev/null || true
        iptables -t nat -D OUTPUT -j "$OUTPUT_CHAIN" 2>/dev/null || true
        iptables -t nat -F "$OUTPUT_CHAIN" 2>/dev/null || true
        iptables -t nat -X "$OUTPUT_CHAIN" 2>/dev/null || true
        iptables -t nat -F FW_LB 2>/dev/null || true
        iptables -t nat -X FW_LB 2>/dev/null || true
        ipset destroy russian-ips 2>/dev/null || true
        ipset destroy russian-ips-tmp 2>/dev/null || true
    fi
}
trap cleanup EXIT SIGTERM SIGINT

# flush stale rules from previous runs
iptables -t nat -D PREROUTING -j "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -F "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -X "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -D OUTPUT -j "$OUTPUT_CHAIN" 2>/dev/null || true
iptables -t nat -F "$OUTPUT_CHAIN" 2>/dev/null || true
iptables -t nat -X "$OUTPUT_CHAIN" 2>/dev/null || true
iptables -t nat -F FW_LB 2>/dev/null || true
iptables -t nat -X FW_LB 2>/dev/null || true
iptables -D DOCKER-USER -s 192.168.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -D DOCKER-USER -d 192.168.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s 192.168.1.0/24 ! -d 192.168.1.0/24 -j MASQUERADE 2>/dev/null || true

if [ "$PROXY_BACKEND" != "off" ]; then
# download Russian IP ranges from RIPE and load into ipset (atomic swap)
ipset create russian-ips-tmp hash:net 2>/dev/null || ipset flush russian-ips-tmp

RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU"
curl -sS --max-time 30 "$RIPE_URL" | \
    jq -r '.data.resources.ipv4[]' | \
    sed 's/^/add russian-ips-tmp /' | \
    ipset restore -! || echo "[fw] Warning: failed to load Russian IPs from RIPE"

# atomically swap — main set is never flushed before load
ipset create russian-ips hash:net 2>/dev/null || true
ipset swap russian-ips-tmp russian-ips
ipset destroy russian-ips-tmp

# generate redsocks config with the selected backend
cat > /tmp/redsocks.conf <<EOF
base {
    log_debug = off;
    log_info = on;
    log = "stderr";
    daemon = off;
    redirector = iptables;
}

redsocks {
    local_ip = 0.0.0.0;
    local_port = 12345;
    ip = 127.0.0.1;
    port = ${SOCKS5_PORT};
    type = socks5;
}
EOF

# start redsocks
redsocks -c /tmp/redsocks.conf &
REDSOCKS_PID=$!
sleep 1
kill -0 "$REDSOCKS_PID" 2>/dev/null || { echo "[fw] redsocks failed to start"; exit 1; }

# second redsocks for tor when load balancing
if [ "$PROXY_BACKEND" = "load_balancing" ]; then
    cat > /tmp/redsocks-tor.conf <<EOF
base {
    log_debug = off; log_info = on; log = "stderr"; daemon = off;
    redirector = iptables;
}
redsocks {
    local_ip = 0.0.0.0; local_port = 12346;
    ip = 127.0.0.1; port = 9050; type = socks5;
}
EOF
    redsocks -c /tmp/redsocks-tor.conf &
    REDSOCKS_TOR_PID=$!
    sleep 1
    kill -0 "$REDSOCKS_TOR_PID" 2>/dev/null || { echo "[fw] redsocks-tor failed to start"; exit 1; }
fi

if [ "$PROXY_BACKEND" = "load_balancing" ]; then
iptables -t nat -N FW_LB 2>/dev/null || iptables -t nat -F FW_LB
iptables -t nat -A FW_LB -p tcp -m statistic --mode random --probability 0.5 -j REDIRECT --to-ports 12345
iptables -t nat -A FW_LB -p tcp -j REDIRECT --to-ports 12346
fi

# -------------------------------------------------------
# 1. OUTPUT chain — traffic from the host itself
# -------------------------------------------------------
iptables -t nat -N "$OUTPUT_CHAIN" 2>/dev/null || true
iptables -t nat -I OUTPUT -j "$OUTPUT_CHAIN"

iptables -t nat -A "$OUTPUT_CHAIN" -d 127.0.0.0/8 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -d 10.0.0.0/8 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -d 172.16.0.0/12 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -d 192.168.0.0/16 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -m set --match-set russian-ips dst -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport 12345 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport "${SOCKS5_PORT}" -j RETURN
if [ "$PROXY_BACKEND" = "load_balancing" ]; then
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport 9050 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport 12346 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp -j FW_LB
else
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp -j REDIRECT --to-ports 12345
fi
fi

# -------------------------------------------------------
# 2. PREROUTING — forwarded traffic from LAN clients
# -------------------------------------------------------
iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -A PREROUTING -j "$CHAIN_NAME"

iptables -t nat -A "$CHAIN_NAME" -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A "$CHAIN_NAME" -s 172.16.0.0/12 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 10.0.0.0/8 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 172.16.0.0/12 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 192.168.0.0/16 -j RETURN
if [ "$PROXY_BACKEND" != "off" ]; then
iptables -t nat -A "$CHAIN_NAME" -m set --match-set russian-ips dst -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 12345 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport "${SOCKS5_PORT}" -j RETURN
if [ "$PROXY_BACKEND" = "load_balancing" ]; then
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 9050 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 12346 -j RETURN
fi
fi
iptables -t nat -A "$CHAIN_NAME" -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 53 -j REDIRECT --to-ports 53
if [ "$PROXY_BACKEND" != "off" ]; then
if [ "$PROXY_BACKEND" = "load_balancing" ]; then
iptables -t nat -A "$CHAIN_NAME" -p tcp -j FW_LB
else
iptables -t nat -A "$CHAIN_NAME" -p tcp -j REDIRECT --to-ports 12345
fi
fi

# -------------------------------------------------------
# 3. FORWARD — allow LAN clients to route through gateway
# -------------------------------------------------------
iptables -I DOCKER-USER -s 192.168.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -I DOCKER-USER -d 192.168.1.0/24 -j ACCEPT 2>/dev/null || true

# -------------------------------------------------------
# 5. FW_LB — load balancing chain
# -------------------------------------------------------
if [ "$PROXY_BACKEND" = "load_balancing" ]; then
healthcheck_loop() {
    while true; do
        sleep 30
        wstunnel=false; tor=false
        nc -z -w2 127.0.0.1 41080 2>/dev/null && wstunnel=true
        nc -z -w2 127.0.0.1 9050 2>/dev/null && tor=true
        iptables -t nat -F FW_LB 2>/dev/null || true
        if $wstunnel && $tor; then
            iptables -t nat -A FW_LB -p tcp -m statistic --mode random --probability 0.5 -j REDIRECT --to-ports 12345
            iptables -t nat -A FW_LB -p tcp -j REDIRECT --to-ports 12346
        elif $wstunnel; then
            iptables -t nat -A FW_LB -p tcp -j REDIRECT --to-ports 12345
        elif $tor; then
            iptables -t nat -A FW_LB -p tcp -j REDIRECT --to-ports 12346
        fi
    done
}
healthcheck_loop & HEALTH_PID=$!
fi

# -------------------------------------------------------
# 4. MASQUERADE — SNAT LAN traffic so replies come back here
# -------------------------------------------------------
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 ! -d 192.168.1.0/24 -j MASQUERADE

RULES_APPLIED=1

echo "[fw] Firewall ready"
echo "       Mode: $PROXY_BACKEND"
if [ "$PROXY_BACKEND" != "off" ]; then
if [ "$PROXY_BACKEND" = "load_balancing" ]; then
echo "       Load balancing: wstunnel(:12345) + tor(:12346)"
else
echo "       Host TCP(OUTPUT) → redsocks → ${PROXY_BACKEND}"
echo "       LAN TCP(PREROUTING) → redsocks → ${PROXY_BACKEND}"
fi
fi
echo "       LAN DNS → unbound :53"
echo "       LAN FORWARD + MASQUERADE enabled for 192.168.1.0/24"

if [ "$PROXY_BACKEND" = "load_balancing" ]; then
wait $REDSOCKS_PID $REDSOCKS_TOR_PID $HEALTH_PID
elif [ "$PROXY_BACKEND" != "off" ]; then
wait $REDSOCKS_PID
else
# держим контейнер живым — нет демона для wait
tail -f /dev/null
fi
