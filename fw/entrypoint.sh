#!/bin/sh
# ══════════════════════════════════════════════════════════════════
#  GOLDENROUTE FW™ — один маршрут, одна дисциплина.
#  Сезон балансировки закрыт. Единственный бэкенд — Tor.
#  Всё, что не дома и не в списке исключений, уходит туда. Без обсуждений.
# ══════════════════════════════════════════════════════════════════
set -eu
set -o pipefail

<<<<<<< HEAD
CHAIN_NAME="FW_REDIRECT"                       # PREROUTING™ — приговор для трафика LAN
OUTPUT_CHAIN="FW_OUTPUT"                       # OUTPUT™ — приговор для трафика самого хоста
LAN_CIDR="${LAN_CIDR:-192.168.1.0/24}"          # Единственная признанная территория

# --- Гардероб сведён к двум спискам: "дома" и "по спецзаказу" ---
RUSSIAN_IPS_FILE="/etc/goldenroute/russian-ips.txt"        # Базовый уровень™ — не требует Tor
TOR_EXCLUDE_IPS_FILE="/etc/goldenroute/tor-exclude-ips.txt" # Индивидуальные исключения™ — тоже не требуют Tor
RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU"

TOR_REDSOCKS_PORT="${TOR_REDSOCKS_PORT:-12346}"  # Единственный порт. Единственный путь наружу.
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"         # Tor слушает здесь — и этого достаточно
=======
# Порты и файлы
RUSSIAN_IPS_FILE="/etc/goldenroute/russian-ips.txt"
RUSSIAN_ONLY_IPS_FILE="/etc/goldenroute/russian-only-ips.txt"
TOR_ONLY_IPS_FILE="/etc/goldenroute/tor-only-ips.txt"
RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU" # Источник обновления рус. IP
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"                   # Порт wstunnel (redsocks)
TOR_REDSOCKS_PORT="${TOR_REDSOCKS_PORT:-12346}"               # Порт Tor (redsocks)
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"   # Порт Tor
WSTUNNEL_SOCKS_PORT="${LLP_SOCKS5_PROXY:-41080}" # Порт wstunnel
>>>>>>> load_balancing

RULES_APPLIED=0
TOR_REDSOCKS_PID=""

# --- Очистка цепочки: идемпотентность — новый минимализм ---
cleanup_chain() {
    chain="$1"; hook="$2"
    while iptables -t nat -D "$hook" -j "$chain" 2>/dev/null; do :; done
    iptables -t nat -F "$chain" 2>/dev/null || true
    iptables -t nat -X "$chain" 2>/dev/null || true
}

# --- Финальный выход: то, что остаётся после нас, должно быть чистым ---
cleanup() {
    echo "[fw] cleanup triggered"
    kill "${TOR_REDSOCKS_PID:-}" 2>/dev/null || true
    [ "$RULES_APPLIED" = "1" ] && echo "[fw] cleanup done"
    return 0
}
trap cleanup EXIT INT TERM

# --- Один список — один жест. Загружаем ipset из файла ---
load_ipset() {
    set_name="$1"; file="$2"
    ipset create "$set_name" hash:net 2>/dev/null || ipset flush "$set_name"
    if [ -s "$file" ]; then
        sed "/^#/d; /^$/d; s/^/add $set_name /" "$file" | ipset restore -!
        count=$(ipset list "$set_name" | sed -n 's/^Number of entries: //p')
        echo "[fw] $set_name loaded from $file: ${count:-0} entries"
    else
        echo "[fw] $file not found or empty — $set_name is empty"
    fi
}

# --- RIPE — единственный источник правды о том, что уже дома ---
update_russian_ips() {
    for attempt in 1 2 3 4; do
        tmp=$(mktemp)
        if curl -sS --max-time 30 "$RIPE_URL" 2>/dev/null | jq -r '.data.resources.ipv4[]' > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
            cat "$tmp" > "$RUSSIAN_IPS_FILE" || echo "[fw] warning: cannot update $RUSSIAN_IPS_FILE" >&2
            ipset create russian-ips-tmp hash:net 2>/dev/null || ipset flush russian-ips-tmp
            sed 's/^/add russian-ips-tmp /' "$tmp" | ipset restore -!
            ipset swap russian-ips-tmp russian-ips
            ipset destroy russian-ips-tmp
            echo "[fw] RIPE updated: $(wc -l < "$tmp") ranges saved"
            rm -f "$tmp"
            return 0
        fi
        echo "[fw] RIPE download failed (attempt $attempt/4), retrying in 5s..." >&2
        rm -f "$tmp"
        sleep 5
    done
    echo "[fw] warning: RIPE update failed after 4 attempts — keeping existing russian-ips" >&2
}

# --- redsocks — один экземпляр, одна судьба: Tor ---
write_redsocks_config() {
    cat > /tmp/redsocks-tor.conf <<EOF_CONF
base {
    log_debug = off;
    log_info = on;
    log = "stderr";
    daemon = off;
    redirector = iptables;
}
redsocks {
    local_ip = 0.0.0.0;
    local_port = ${TOR_REDSOCKS_PORT};
    ip = 127.0.0.1;
    port = ${TOR_SOCKS_PORT};
    type = socks5;
}
EOF_CONF
}

start_redsocks() {
    redsocks -c /tmp/redsocks-tor.conf &
    pid=$!
    sleep 1
    kill -0 "$pid" 2>/dev/null || { echo "[fw] redsocks-tor failed to start" >&2; exit 1; }
    TOR_REDSOCKS_PID="$pid"
}

# --- Приватные диапазоны — им редирект не к лицу ---
append_common_returns() {
    chain="$1"
    for cidr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        iptables -t nat -A "$chain" -d "$cidr" -j RETURN
    done
}

# --- Главное правило коллекции: не дома, не в исключениях — значит, в Tor ---
append_proxy_rules() {
    target_chain="$1"
    echo "[fw] applying proxy rules to $target_chain"
    iptables -t nat -A "$target_chain" -m set --match-set russian-ips dst -j RETURN
    iptables -t nat -A "$target_chain" -m set --match-set tor-exclude dst -j RETURN
    iptables -t nat -A "$target_chain" -p tcp --dport "$TOR_REDSOCKS_PORT" -j RETURN
    iptables -t nat -A "$target_chain" -p tcp --dport "$TOR_SOCKS_PORT" -j RETURN
    iptables -t nat -A "$target_chain" -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A "$target_chain" -p tcp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A "$target_chain" -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
    echo "[fw] $target_chain -> Tor(:$TOR_REDSOCKS_PORT)"
}

# ══════════════════════════ Показ начинается ══════════════════════════
cleanup_chain "$CHAIN_NAME" PREROUTING
cleanup_chain "$OUTPUT_CHAIN" OUTPUT

<<<<<<< HEAD
load_ipset russian-ips "$RUSSIAN_IPS_FILE"
load_ipset tor-exclude "$TOR_EXCLUDE_IPS_FILE"
update_russian_ips &
=======
# Запуск прокси, если он включён
if proxy_enabled; then
    echo "[fw] Proxy active — balancing: wstunnel ${WSTUNNEL_BALANCE}% / tor ${TOR_BALANCE}%"
    load_ipset russian-ips "$RUSSIAN_IPS_FILE"
    if [ -s "$RUSSIAN_ONLY_IPS_FILE" ]; then
        sed "/^#/d; /^$/d; s/^/add russian-ips /" "$RUSSIAN_ONLY_IPS_FILE" | ipset restore -!
        count=$(ipset list russian-ips | sed -n 's/^Number of entries: //p')
        echo "[fw] russian-ips merged with $RUSSIAN_ONLY_IPS_FILE: ${count:-0} entries"
    else
        echo "[fw] $RUSSIAN_ONLY_IPS_FILE not found or empty"
    fi
    update_russian_ips &
    if [ "$WSTUNNEL_BALANCE" -gt 0 ]; then
        write_redsocks_config /tmp/redsocks.conf "$REDSOCKS_PORT" "$WSTUNNEL_SOCKS_PORT"
        start_redsocks redsocks /tmp/redsocks.conf
        REDSOCKS_PID="$STARTED_PID"
    fi
    if [ "$TOR_BALANCE" -gt 0 ]; then
        write_redsocks_config /tmp/redsocks-tor.conf "$TOR_REDSOCKS_PORT" "$TOR_SOCKS_PORT"
        start_redsocks tor-redsocks /tmp/redsocks-tor.conf
        TOR_REDSOCKS_PID="$STARTED_PID"
    fi
else
    echo "[fw] Proxy disabled — all traffic direct"
    ipset create russian-ips hash:net 2>/dev/null || true
fi
>>>>>>> load_balancing

write_redsocks_config
start_redsocks

# OUTPUT — трафик самого хоста тоже носит Tor, без исключений для себя любимого
iptables -t nat -N "$OUTPUT_CHAIN" 2>/dev/null || true
iptables -t nat -I OUTPUT -j "$OUTPUT_CHAIN"
append_common_returns "$OUTPUT_CHAIN"
append_proxy_rules "$OUTPUT_CHAIN"

# PREROUTING — трафик LAN-клиентов встречает ту же дисциплину
iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -I PREROUTING -j "$CHAIN_NAME"
iptables -t nat -A "$CHAIN_NAME" -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A "$CHAIN_NAME" -s 172.16.0.0/12 -j RETURN
append_common_returns "$CHAIN_NAME"
append_proxy_rules "$CHAIN_NAME"

RULES_APPLIED=1

# Docker-подсеть и маршрутизация для LAN — обязательные детали образа
iptables -I DOCKER-USER -s "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
iptables -I DOCKER-USER -d "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -s "$LAN_CIDR" ! -d "$LAN_CIDR" -j MASQUERADE

# --- QUIC™: UDP, который возомнил себя выше TCP. Не в этом сезоне. ---
# Российским адресам и вашим личным исключениям — разрешено оставаться собой.
# Всем остальным — молчание, и обязательный откат на TCP:443, который уже ждёт в Tor.
while iptables -D FORWARD -p udp --dport 443 -j DROP 2>/dev/null; do :; done
while iptables -D FORWARD -p udp --dport 443 -m set ! --match-set russian-ips dst -j DROP 2>/dev/null; do :; done
while iptables -D OUTPUT -p udp --dport 443 ! -s 127.0.0.1 -j DROP 2>/dev/null; do :; done
while iptables -D OUTPUT -p udp --dport 443 ! -s 127.0.0.1 -m set ! --match-set russian-ips dst -j DROP 2>/dev/null; do :; done
iptables -A FORWARD -p udp --dport 443 \
    -m set ! --match-set russian-ips dst -m set ! --match-set tor-exclude dst -j DROP
iptables -A OUTPUT -p udp --dport 443 ! -s 127.0.0.1 \
    -m set ! --match-set russian-ips dst -m set ! --match-set tor-exclude dst -j DROP

echo "[fw] Firewall ready"
echo "       Весь зарубежный трафик — через Tor(:$TOR_REDSOCKS_PORT)."
echo "       Исключения — только по вашему списку в tor-exclude-ips.txt."

# --- Финальный выход: держим показ, пока не скажут иначе ---
while true; do
    sleep 3600
done
