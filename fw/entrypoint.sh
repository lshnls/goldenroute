#!/bin/sh
set -eu

set -o pipefail
CHAIN_NAME="FW_REDIRECT"
OUTPUT_CHAIN="FW_OUTPUT"
RULES_APPLIED=0
REDSOCKS_PID=""
REDSOCKS_TOR_PID=""
HEALTH_PID=""

# Balancing configuration (default 70/30)
TOR_BALANCE="${TOR_BALANCE:-50}"
WSTUNNEL_BALANCE="${WSTUNNEL_BALANCE:-50}"

# Validate balances
if ! { [ "$TOR_BALANCE" -eq 0 ] && [ "$WSTUNNEL_BALANCE" -eq 0 ]; } && \
     [ $((TOR_BALANCE + WSTUNNEL_BALANCE)) -ne 100 ]; then
    echo "ERROR: TOR_BALANCE + WSTUNNEL_BALANCE must equal 100, or both must be 0"
    exit 1
fi

# Determine proxy mode
if [ "$TOR_BALANCE" -eq 0 ] && [ "$WSTUNNEL_BALANCE" -eq 0 ]; then
    echo "[fw] Proxy disabled — all traffic direct"
    SOCKS5_PORT="${TOR_SOCKS_PORT:-9050}"
else
    echo "[fw] Proxy active — balancing: wstunnel ${WSTUNNEL_BALANCE}% / tor ${TOR_BALANCE}%"
    if [ "$WSTUNNEL_BALANCE" -eq 0 ]; then
        SOCKS5_PORT="${TOR_SOCKS_PORT:-9050}"
    else
        SOCKS5_PORT="${LLP_SOCKS5_PROXY:-41080}"
    fi
fi


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
        ipset destroy tor-only 2>/dev/null || true
        kill "$REDSOCKS_PID" 2>/dev/null || true
        kill "$REDSOCKS_TOR_PID" 2>/dev/null || true
        kill "$HEALTH_PID" 2>/dev/null || true
    fi
    echo "[fw] cleanup done"
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

RUSSIAN_IPS_FILE="/etc/goldenroute/russian-ips.txt"
TOR_ONLY_IPS_FILE="/etc/goldenroute/tor-only-ips.txt"

# --- Load tor-only IPs ---
ipset create tor-only hash:net 2>/dev/null || ipset flush tor-only
if [ -s "$TOR_ONLY_IPS_FILE" ]; then
    sed '/^#/d; /^$/d; s/^/add tor-only /' "$TOR_ONLY_IPS_FILE" | ipset restore -! 2>/dev/null || true
    TOR_LOADED=$(ipset list tor-only | sed -n 's/^Number of entries: //p')
    echo "[fw] tor-only loaded from file: $TOR_LOADED entries"
else
    echo "[fw] $TOR_ONLY_IPS_FILE not found or empty — no tor-only IPs"
fi

if [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]; then

# load Russian IP ranges from cached file, then update in background
if [ -s "$RUSSIAN_IPS_FILE" ]; then
    echo "[fw] Loading Russian IP ranges from $RUSSIAN_IPS_FILE..."
    ipset create russian-ips hash:net 2>/dev/null || ipset flush russian-ips
    sed 's/^/add russian-ips /' "$RUSSIAN_IPS_FILE" | ipset restore -!
    LOADED=$(ipset list russian-ips | sed -n 's/^Number of entries: //p')
    echo "[fw] russian-ips loaded from file: $LOADED entries"
else
    echo "[fw] $RUSSIAN_IPS_FILE not found — skipping Russian IP matching, all traffic through proxy"
    ipset create russian-ips hash:net 2>/dev/null || true
fi

# background RIPE updater
RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU"
(
    for i in 1 2 3 4; do
        TMP=$(mktemp)
        if curl -sS --max-time 30 "$RIPE_URL" 2>/dev/null | \
            jq -r '.data.resources.ipv4[]' > "$TMP" 2>/dev/null && [ -s "$TMP" ]; then
            cp "$TMP" "$RUSSIAN_IPS_FILE"
            echo "[fw] RIPE download successful, $(wc -l < "$TMP") ranges saved to $RUSSIAN_IPS_FILE"
            ipset create russian-ips-tmp hash:net 2>/dev/null || ipset flush russian-ips-tmp
            sed 's/^/add russian-ips-tmp /' "$RUSSIAN_IPS_FILE" | ipset restore -!
            ipset swap russian-ips-tmp russian-ips
            ipset destroy russian-ips-tmp
            rm -f "$TMP"
            break
        fi
        echo "[fw] RIPE download failed (attempt $i/4), retrying in 5s..."
        rm -f "$TMP"
        sleep 5
    done
) &

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

iptables -t nat -N FW_LB 2>/dev/null || iptables -t nat -F FW_LB
WSTUNNEL_PROB=$(awk "BEGIN {printf \"%.6f\", $WSTUNNEL_BALANCE / 100}")
    iptables -t nat -A FW_LB -p tcp -m statistic --mode random --probability "$WSTUNNEL_PROB" -j REDIRECT --to-ports 12345
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

# tor-only: forced through Tor before everything else
iptables -t nat -A "$OUTPUT_CHAIN" -m set --match-set tor-only dst -p tcp -j REDIRECT --to-ports 12346

if [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]; then
iptables -t nat -A "$OUTPUT_CHAIN" -m set --match-set russian-ips dst -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport 12345 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport 12346 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport "${SOCKS5_PORT}" -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport 9050 -j RETURN
iptables -t nat -A "$OUTPUT_CHAIN" -p tcp -j FW_LB
fi

# start redsocks-tor for tor-only IPs (in any mode, not just load_balancing)
if ipset list tor-only >/dev/null 2>&1; then
    TOR_ONLY_COUNT=$(ipset list tor-only 2>/dev/null | sed -n 's/^Number of entries: //p')
    if [ -n "$TOR_ONLY_COUNT" ] && [ "$TOR_ONLY_COUNT" -gt 0 ]; then
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
fi

# -------------------------------------------------------

# Redirect DNS to unbound
if [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]; then
    iptables -t nat -A "$OUTPUT_CHAIN" -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A "$OUTPUT_CHAIN" -p tcp --dport 53 -j REDIRECT --to-ports 53
fi
# 2. PREROUTING — forwarded traffic from LAN clients
# -------------------------------------------------------
iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -A PREROUTING -j "$CHAIN_NAME"

iptables -t nat -A "$CHAIN_NAME" -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A "$CHAIN_NAME" -s 172.16.0.0/12 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 10.0.0.0/8 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 172.16.0.0/12 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -d 192.168.0.0/16 -j RETURN

# tor-only: forced through Tor before everything else
iptables -t nat -A "$CHAIN_NAME" -m set --match-set tor-only dst -p tcp -j REDIRECT --to-ports 12346

if [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]; then
iptables -t nat -A "$CHAIN_NAME" -m set --match-set russian-ips dst -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 12345 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 12346 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport "${SOCKS5_PORT}" -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 9050 -j RETURN
iptables -t nat -A "$CHAIN_NAME" -p udp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A "$CHAIN_NAME" -p tcp --dport 53 -j REDIRECT --to-ports 53
iptables -t nat -A "$CHAIN_NAME" -p tcp -j FW_LB
fi

# -------------------------------------------------------
# 3. FORWARD — allow LAN clients to route through gateway
# -------------------------------------------------------
iptables -I DOCKER-USER -s 192.168.1.0/24 -j ACCEPT 2>/dev/null || true
iptables -I DOCKER-USER -d 192.168.1.0/24 -j ACCEPT 2>/dev/null || true

# -------------------------------------------------------
# 5. FW_LB — load balancing chain
# -------------------------------------------------------
if [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]; then
healthcheck_loop() {
    while true; do
        sleep 30
        wstunnel=false; tor=false
        nc -z -w2 127.0.0.1 41080 2>/dev/null && wstunnel=true
        nc -z -w2 127.0.0.1 9050 2>/dev/null && tor=true
        iptables -t nat -F FW_LB 2>/dev/null || true
        if $wstunnel && $tor; then
            WSTUNNEL_PROB=$(awk "BEGIN {printf \"%.6f\", $WSTUNNEL_BALANCE / 100}")
    iptables -t nat -A FW_LB -p tcp -m statistic --mode random --probability "$WSTUNNEL_PROB" -j REDIRECT --to-ports 12345
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
if [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]; then
echo "       Balancing: wstunnel(:12345) = ${WSTUNNEL_BALANCE}% / tor(:12346) = ${TOR_BALANCE}%"
fi
echo "       tor-only IPs → tor(:12346)"
echo "       LAN DNS → unbound :53"
echo "       LAN FORWARD + MASQUERADE enabled for 192.168.1.0/24"

WAIT_PIDS=""
if [ -n "$REDSOCKS_PID" ]; then WAIT_PIDS="$REDSOCKS_PID"; fi
if [ -n "$REDSOCKS_TOR_PID" ]; then WAIT_PIDS="$WAIT_PIDS $REDSOCKS_TOR_PID"; fi
if [ -n "$HEALTH_PID" ]; then WAIT_PIDS="$WAIT_PIDS $HEALTH_PID"; fi
if [ -n "$WAIT_PIDS" ]; then
    wait $WAIT_PIDS
else
    tail -f /dev/null
fi
