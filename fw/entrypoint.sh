#!/bin/sh
set -eu
set -o pipefail

CHAIN_NAME="FW_REDIRECT"
OUTPUT_CHAIN="FW_OUTPUT"
LB_CHAIN="FW_LB"
LAN_CIDR="${LAN_CIDR:-192.168.1.0/24}"
RUSSIAN_IPS_FILE="/etc/goldenroute/russian-ips.txt"
TOR_ONLY_IPS_FILE="/etc/goldenroute/tor-only-ips.txt"
RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU"
REDSOCKS_PORT=12345
TOR_REDSOCKS_PORT=12346
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"
WSTUNNEL_SOCKS_PORT="${LLP_SOCKS5_PROXY:-41080}"
TOR_BALANCE="${TOR_BALANCE:-50}"
WSTUNNEL_BALANCE="${WSTUNNEL_BALANCE:-50}"
RULES_APPLIED=0
REDSOCKS_PID=""
REDSOCKS_TOR_PID=""
HEALTH_PID=""

proxy_enabled() {
    [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]
}

validate_balance() {
    case "$TOR_BALANCE:$WSTUNNEL_BALANCE" in
        *[!0-9:]*|:*) echo "ERROR: balances must be non-negative integers" >&2; exit 1 ;;
    esac

    if proxy_enabled && [ $((TOR_BALANCE + WSTUNNEL_BALANCE)) -ne 100 ]; then
        echo "ERROR: TOR_BALANCE + WSTUNNEL_BALANCE must equal 100, or both must be 0" >&2
        exit 1
    fi
}

cleanup_chain() {
    chain="$1"
    hook="$2"
    while iptables -t nat -D "$hook" -j "$chain" 2>/dev/null; do :; done
    iptables -t nat -F "$chain" 2>/dev/null || true
    iptables -t nat -X "$chain" 2>/dev/null || true
}

ensure_nat_chain_exists() {
    chain="$1"
    iptables -t nat -L "$chain" >/dev/null 2>&1 || iptables -t nat -N "$chain"
}

reset_nat_chain() {
    chain="$1"
    ensure_nat_chain_exists "$chain" || return 1
    iptables -t nat -F "$chain" || return 1
}

cleanup() {
    cleanup_chain "$CHAIN_NAME" PREROUTING
    cleanup_chain "$OUTPUT_CHAIN" OUTPUT
    if [ -n "${HEALTH_PID:-}" ]; then
        kill "$HEALTH_PID" 2>/dev/null || true
        wait "$HEALTH_PID" 2>/dev/null || true
        HEALTH_PID=""
    fi
    iptables -t nat -F "$LB_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$LB_CHAIN" 2>/dev/null || true
    iptables -D DOCKER-USER -s "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
    iptables -D DOCKER-USER -d "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$LAN_CIDR" ! -d "$LAN_CIDR" -j MASQUERADE 2>/dev/null || true
    ipset destroy russian-ips-tmp 2>/dev/null || true
    ipset destroy russian-ips 2>/dev/null || true
    ipset destroy tor-only 2>/dev/null || true
    kill ${REDSOCKS_PID:-} ${REDSOCKS_TOR_PID:-} ${HEALTH_PID:-} 2>/dev/null || true
    if [ "$RULES_APPLIED" = "1" ]; then
        echo "[fw] cleanup done"
    fi
}
trap cleanup EXIT INT TERM

load_ipset() {
    set_name="$1"
    file="$2"
    ipset create "$set_name" hash:net 2>/dev/null || ipset flush "$set_name"

    if [ -s "$file" ]; then
        sed '/^#/d; /^$/d; s/^/add '"$set_name"' /' "$file" | ipset restore -!
        count=$(ipset list "$set_name" | sed -n 's/^Number of entries: //p')
        echo "[fw] $set_name loaded from $file: ${count:-0} entries"
    else
        echo "[fw] $file not found or empty — $set_name is empty"
    fi
}

update_russian_ips() {
    for attempt in 1 2 3 4; do
        tmp=$(mktemp)
        if curl -sS --max-time 30 "$RIPE_URL" 2>/dev/null | jq -r '.data.resources.ipv4[]' > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
            if ! cat "$tmp" > "$RUSSIAN_IPS_FILE"; then
                echo "[fw] warning: cannot update $RUSSIAN_IPS_FILE; keeping existing file" >&2
            fi
            ipset create russian-ips-tmp hash:net 2>/dev/null || ipset flush russian-ips-tmp
            sed 's/^/add russian-ips-tmp /' "$tmp" | ipset restore -!
            ipset swap russian-ips-tmp russian-ips
            ipset destroy russian-ips-tmp
            echo "[fw] RIPE updated: $(wc -l < "$tmp") ranges saved"
            rm -f "$tmp"
            return 0
        fi
        echo "[fw] RIPE download failed (attempt $attempt/4), retrying in 5s..."
        rm -f "$tmp"
        sleep 5
    done
}

write_redsocks_config() {
    file="$1"
    listen_port="$2"
    upstream_port="$3"
    cat > "$file" <<EOF_CONF
base {
    log_debug = off;
    log_info = on;
    log = "stderr";
    daemon = off;
    redirector = iptables;
}

redsocks {
    local_ip = 0.0.0.0;
    local_port = $listen_port;
    ip = 127.0.0.1;
    port = $upstream_port;
    type = socks5;
}
EOF_CONF
}

start_redsocks() {
    name="$1"
    config="$2"
    redsocks -c "$config" &
    pid=$!
    sleep 1
    kill -0 "$pid" 2>/dev/null || { echo "[fw] $name failed to start" >&2; exit 1; }
    STARTED_PID="$pid"
}

append_common_returns() {
    chain="$1"
    for cidr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        iptables -t nat -A "$chain" -d "$cidr" -j RETURN
    done
}

append_proxy_rules() {
    chain="$1"
    iptables -t nat -A "$chain" -m set --match-set russian-ips dst -j RETURN
    for port in "$REDSOCKS_PORT" "$TOR_REDSOCKS_PORT" "$WSTUNNEL_SOCKS_PORT" "$TOR_SOCKS_PORT"; do
        iptables -t nat -A "$chain" -p tcp --dport "$port" -j RETURN
    done
    iptables -t nat -A "$chain" -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A "$chain" -p tcp --dport 53 -j REDIRECT --to-ports 53
    ensure_nat_chain_exists "$LB_CHAIN"
    iptables -t nat -A "$chain" -p tcp -j "$LB_CHAIN"
}

configure_lb() {
    reset_nat_chain "$LB_CHAIN"

    if [ "$WSTUNNEL_BALANCE" -eq 100 ]; then
        iptables -t nat -A "$LB_CHAIN" -p tcp -j REDIRECT --to-ports "$REDSOCKS_PORT"
    elif [ "$TOR_BALANCE" -eq 100 ]; then
        iptables -t nat -A "$LB_CHAIN" -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
    else
        probability=$(awk "BEGIN {printf \"%.6f\", $WSTUNNEL_BALANCE / 100}")
        iptables -t nat -A "$LB_CHAIN" -p tcp -m statistic --mode random --probability "$probability" -j REDIRECT --to-ports "$REDSOCKS_PORT"
        iptables -t nat -A "$LB_CHAIN" -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
    fi
}

healthcheck_loop() {
    while sleep 30; do
        wstunnel=false
        tor=false
        nc -z -w2 127.0.0.1 "$WSTUNNEL_SOCKS_PORT" 2>/dev/null && wstunnel=true
        nc -z -w2 127.0.0.1 "$TOR_SOCKS_PORT" 2>/dev/null && tor=true
        if ! reset_nat_chain "$LB_CHAIN"; then
            echo "[fw] warning: failed to reset $LB_CHAIN; retrying healthcheck later" >&2
            continue
        fi

        if $wstunnel && $tor; then
            configure_lb
        elif $wstunnel; then
            iptables -t nat -A "$LB_CHAIN" -p tcp -j REDIRECT --to-ports "$REDSOCKS_PORT"
        elif $tor; then
            iptables -t nat -A "$LB_CHAIN" -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
        fi
    done
}

validate_balance
cleanup
load_ipset tor-only "$TOR_ONLY_IPS_FILE"

if proxy_enabled; then
    echo "[fw] Proxy active — balancing: wstunnel ${WSTUNNEL_BALANCE}% / tor ${TOR_BALANCE}%"
    load_ipset russian-ips "$RUSSIAN_IPS_FILE"
    update_russian_ips &

    if [ "$WSTUNNEL_BALANCE" -gt 0 ]; then
        write_redsocks_config /tmp/redsocks.conf "$REDSOCKS_PORT" "$WSTUNNEL_SOCKS_PORT"
        start_redsocks redsocks /tmp/redsocks.conf
        REDSOCKS_PID="$STARTED_PID"
    fi
else
    echo "[fw] Proxy disabled — all traffic direct"
    ipset create russian-ips hash:net 2>/dev/null || true
fi

TOR_ONLY_COUNT=$(ipset list tor-only 2>/dev/null | sed -n 's/^Number of entries: //p')
TOR_ONLY_COUNT=${TOR_ONLY_COUNT:-0}
if [ "$TOR_BALANCE" -gt 0 ] || [ "$TOR_ONLY_COUNT" -gt 0 ]; then
    write_redsocks_config /tmp/redsocks-tor.conf "$TOR_REDSOCKS_PORT" "$TOR_SOCKS_PORT"
    start_redsocks redsocks-tor /tmp/redsocks-tor.conf
    REDSOCKS_TOR_PID="$STARTED_PID"
fi

iptables -t nat -N "$OUTPUT_CHAIN" 2>/dev/null || true
iptables -t nat -I OUTPUT -j "$OUTPUT_CHAIN"
append_common_returns "$OUTPUT_CHAIN"
iptables -t nat -A "$OUTPUT_CHAIN" -m set --match-set tor-only dst -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
if proxy_enabled; then
    ensure_nat_chain_exists "$LB_CHAIN"
    append_proxy_rules "$OUTPUT_CHAIN"
fi

iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -A PREROUTING -j "$CHAIN_NAME"
iptables -t nat -A "$CHAIN_NAME" -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A "$CHAIN_NAME" -s 172.16.0.0/12 -j RETURN
append_common_returns "$CHAIN_NAME"
iptables -t nat -A "$CHAIN_NAME" -m set --match-set tor-only dst -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
proxy_enabled && append_proxy_rules "$CHAIN_NAME"

if proxy_enabled; then
    configure_lb
    healthcheck_loop &
    HEALTH_PID=$!
fi

iptables -I DOCKER-USER -s "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
iptables -I DOCKER-USER -d "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -s "$LAN_CIDR" ! -d "$LAN_CIDR" -j MASQUERADE

RULES_APPLIED=1

echo "[fw] Firewall ready"
proxy_enabled && echo "       Balancing: wstunnel(:$REDSOCKS_PORT) = ${WSTUNNEL_BALANCE}% / tor(:$TOR_REDSOCKS_PORT) = ${TOR_BALANCE}%"
echo "       tor-only IPs → tor(:$TOR_REDSOCKS_PORT)"
echo "       LAN DNS → unbound :53"
echo "       LAN FORWARD + MASQUERADE enabled for $LAN_CIDR"

WAIT_PIDS="${REDSOCKS_PID:-} ${REDSOCKS_TOR_PID:-} ${HEALTH_PID:-}"
# shellcheck disable=SC2086
[ -n "$(printf '%s' "$WAIT_PIDS" | tr -d ' ')" ] && wait $WAIT_PIDS || tail -f /dev/null
