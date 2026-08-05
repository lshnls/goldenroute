#!/bin/sh
# Резервный вариант: настройка брандмауэра и прокси‑службы с подробными комментариями
# --------------------------------------------------------------
# Основные переменные и цепочки iptables
# --------------------------------------------------------------
CHAIN_NAME="FW_REDIRECT"              # Цепочка, которая перенаправляет трафик
OUTPUT_CHAIN="FW_OUTPUT"              # Цепочка обработки исходящего трафика
LB_CHAIN="FW_LB"                      # Цепочка балансировки между прокси
ACC_DIRECT="FW_ACC_DIRECT"            # filter: учёт байт/пакетов Direct
ACC_WSPROXY="FW_ACC_WSPROXY"          # filter: учёт байт в redsocks wstunnel
ACC_TOR="FW_ACC_TOR"                  # filter: учёт байт в redsocks tor
LAN_CIDR="${LAN_CIDR:-192.168.1.0/24}" # Локальная подсеть (по умолчанию 192.168.1.0/24)

# Порты и файлы
RUSSIAN_IPS_FILE="/etc/goldenroute/russian-ips.txt"
RUSSIAN_ONLY_IPS_FILE="/etc/goldenroute/russian-only-ips.txt"
TOR_ONLY_IPS_FILE="/etc/goldenroute/tor-only-ips.txt"
RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU" # Источник обновления рус. IP
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"                   # Порт wstunnel (redsocks)
TOR_REDSOCKS_PORT="${TOR_REDSOCKS_PORT:-12346}"               # Порт Tor (redsocks)
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"   # Порт Tor
WSTUNNEL_SOCKS_PORT="${LLP_SOCKS5_PROXY:-41080}" # Порт wstunnel
BLOCK_IPV6="${BLOCK_IPV6:-0}"

# Счётчики и PID‑ы
RULES_APPLIED=0
REDSOCKS_PID=""
TOR_REDSOCKS_PID=""
HEALTH_PID=""

# Функция: проверка, включён ли прокси
proxy_enabled() {
    [ "$TOR_BALANCE" -ne 0 ] || [ "$WSTUNNEL_BALANCE" -ne 0 ]
}

# Функция: проверка корректности балансов
validate_balance() {
    case "$TOR_BALANCE:$WSTUNNEL_BALANCE" in
        *[!0-9:]*|:*) echo "ERROR: balances must be non-negative integers" >&2; exit 1 ;;
    esac
    if proxy_enabled && [ $((TOR_BALANCE + WSTUNNEL_BALANCE)) -ne 100 ]; then
        echo "ERROR: TOR_BALANCE + WSTUNNEL_BALANCE must equal 100, or both must be 0" >&2
        exit 1
    fi
}

block_ipv6_if_requested() {
    case "$BLOCK_IPV6" in
        1|true|TRUE|yes|YES|on|ON)
            if command -v ip6tables >/dev/null 2>&1; then
                ip6tables -P OUTPUT DROP
                ip6tables -P FORWARD DROP
                ip6tables -P INPUT DROP
                echo "[fw] IPv6 blocked by BLOCK_IPV6=${BLOCK_IPV6}"
            else
                echo "[fw] BLOCK_IPV6 requested but ip6tables is not available" >&2
            fi
            ;;
        *)
            ;;
    esac
}

# Удаление nat-цепочки
destroy_nat_chain() {
    chain="$1"
    iptables -t nat -F "$chain" 2>/dev/null || true
    iptables -t nat -X "$chain" 2>/dev/null || true
}

# Очистка цепочки iptables (и отвязка от hook, если задан)
cleanup_chain() {
    chain="$1"
    hook="$2"
    if [ -n "$hook" ]; then
        while iptables -t nat -D "$hook" -j "$chain" 2>/dev/null; do :; done
    fi
    destroy_nat_chain "$chain"
}

# Сброс цепочки iptables
reset_nat_chain() {
    chain="$1"
    ensure_nat_chain_exists "$chain" || return 1
    iptables -t nat -F "$chain" || return 1
}

# Создание цепочки, если её нет
ensure_nat_chain_exists() {
    chain="$1"
    iptables -t nat -L "$chain" >/dev/null 2>&1 || iptables -t nat -N "$chain"
}

# Снятие LAN / QUIC правил (идемпотентно, снимает все дубликаты)
cleanup_lan_rules() {
    while iptables -D DOCKER-USER -s "$LAN_CIDR" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D DOCKER-USER -d "$LAN_CIDR" -j ACCEPT 2>/dev/null; do :; done
    while iptables -t nat -D POSTROUTING -s "$LAN_CIDR" ! -d "$LAN_CIDR" -j MASQUERADE 2>/dev/null; do :; done
}

cleanup_quic_rules() {
    while iptables -D FORWARD -p udp --dport 443 -j DROP 2>/dev/null; do :; done
    while iptables -D FORWARD -p udp --dport 443 -m set ! --match-set russian-ips dst -j DROP 2>/dev/null; do :; done
    while iptables -D OUTPUT -p udp --dport 443 ! -s 127.0.0.1 -j DROP 2>/dev/null; do :; done
    while iptables -D OUTPUT -p udp --dport 443 ! -s 127.0.0.1 -m set ! --match-set russian-ips dst -j DROP 2>/dev/null; do :; done
}

# Учёт трафика (filter): Direct по ipset, WSProxy/Tor — INPUT на порты redsocks после REDIRECT
destroy_filter_chain() {
    chain="$1"
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
}

cleanup_accounting_rules() {
    while iptables -D INPUT -p tcp --dport "$REDSOCKS_PORT" -j "$ACC_WSPROXY" 2>/dev/null; do :; done
    while iptables -D OUTPUT -p tcp --sport "$REDSOCKS_PORT" -j "$ACC_WSPROXY" 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport "$TOR_REDSOCKS_PORT" -j "$ACC_TOR" 2>/dev/null; do :; done
    while iptables -D OUTPUT -p tcp --sport "$TOR_REDSOCKS_PORT" -j "$ACC_TOR" 2>/dev/null; do :; done
    while iptables -D OUTPUT -m set --match-set russian-only-ips dst -j "$ACC_DIRECT" 2>/dev/null; do :; done
    while iptables -D OUTPUT -m set --match-set russian-ips dst -j "$ACC_DIRECT" 2>/dev/null; do :; done
    while iptables -D INPUT -m set --match-set russian-only-ips src -j "$ACC_DIRECT" 2>/dev/null; do :; done
    while iptables -D INPUT -m set --match-set russian-ips src -j "$ACC_DIRECT" 2>/dev/null; do :; done
    while iptables -D FORWARD -m set --match-set russian-only-ips dst -j "$ACC_DIRECT" 2>/dev/null; do :; done
    while iptables -D FORWARD -m set --match-set russian-ips dst -j "$ACC_DIRECT" 2>/dev/null; do :; done
    while iptables -D FORWARD -m set --match-set russian-only-ips src -j "$ACC_DIRECT" 2>/dev/null; do :; done
    while iptables -D FORWARD -m set --match-set russian-ips src -j "$ACC_DIRECT" 2>/dev/null; do :; done
    destroy_filter_chain "$ACC_DIRECT"
    destroy_filter_chain "$ACC_WSPROXY"
    destroy_filter_chain "$ACC_TOR"
}

setup_accounting_rules() {
    cleanup_accounting_rules
    for chain in "$ACC_DIRECT" "$ACC_WSPROXY" "$ACC_TOR"; do
        iptables -N "$chain" 2>/dev/null || true
        iptables -F "$chain"
        iptables -A "$chain" -j RETURN
    done
    # Proxied: both directions on redsocks ports (after nat REDIRECT).
    # INPUT dport = client→redsocks; OUTPUT sport = redsocks→client (downloads).
    iptables -I INPUT -p tcp --dport "$REDSOCKS_PORT" -j "$ACC_WSPROXY"
    iptables -I OUTPUT -p tcp --sport "$REDSOCKS_PORT" -j "$ACC_WSPROXY"
    iptables -I INPUT -p tcp --dport "$TOR_REDSOCKS_PORT" -j "$ACC_TOR"
    iptables -I OUTPUT -p tcp --sport "$TOR_REDSOCKS_PORT" -j "$ACC_TOR"
    # Direct: both directions (dst = to RU, src = replies from RU).
    iptables -I OUTPUT -m set --match-set russian-only-ips dst -j "$ACC_DIRECT"
    iptables -I OUTPUT -m set --match-set russian-ips dst -j "$ACC_DIRECT"
    iptables -I INPUT -m set --match-set russian-only-ips src -j "$ACC_DIRECT"
    iptables -I INPUT -m set --match-set russian-ips src -j "$ACC_DIRECT"
    iptables -I FORWARD -m set --match-set russian-only-ips dst -j "$ACC_DIRECT"
    iptables -I FORWARD -m set --match-set russian-ips dst -j "$ACC_DIRECT"
    iptables -I FORWARD -m set --match-set russian-only-ips src -j "$ACC_DIRECT"
    iptables -I FORWARD -m set --match-set russian-ips src -j "$ACC_DIRECT"
    echo "[fw] traffic accounting enabled ($ACC_DIRECT / $ACC_WSPROXY / $ACC_TOR), bidirectional"
}

cleanup_all_rules() {
    cleanup_chain "$CHAIN_NAME" PREROUTING
    cleanup_chain "$OUTPUT_CHAIN" OUTPUT
    destroy_nat_chain "$LB_CHAIN"
    cleanup_lan_rules
    cleanup_quic_rules
    cleanup_accounting_rules
}

# Основная процедура завершения
cleanup() {
    echo "[fw] cleanup triggered"
    if [ -n "${HEALTH_PID:-}" ]; then
        kill "$HEALTH_PID" 2>/dev/null || true
        HEALTH_PID=""
    fi
    kill ${REDSOCKS_PID:-} ${TOR_REDSOCKS_PID:-} 2>/dev/null || true
    if [ "$RULES_APPLIED" = "1" ]; then
        cleanup_all_rules
        RULES_APPLIED=0
        echo "[fw] cleanup done"
    fi
}
trap cleanup EXIT INT TERM

# Нужен ли tor-redsocks (баланс > 0 или непустой tor-only)
tor_only_has_entries() {
    count=$(ipset list tor-only 2>/dev/null | sed -n 's/^Number of entries: //p')
    [ "${count:-0}" -gt 0 ]
}

tor_redsocks_needed() {
    [ "${TOR_BALANCE:-0}" -gt 0 ] || tor_only_has_entries
}

# Управление IPSET‑ами
load_ipset() {
    set_name="$1"
    file="$2"
    ipset create "$set_name" hash:net 2>/dev/null || ipset flush "$set_name"

    if [ -s "$file" ]; then
        sed "/^#/d; /^$/d; s/^/add $set_name /" "$file" | ipset restore -!
        count=$(ipset list "$set_name" | sed -n 's/^Number of entries: //p')
        echo "[fw] $set_name loaded from $file: ${count:-0} entries"
    else
        echo "[fw] $file not found or empty — $set_name is empty"
    fi
}

# Обновление списка российских IP‑адресов
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

# Настройка redsocks
write_redsocks_config() {
    file="$1"
    listen_port="$2"
    upstream_port="$3"
    cat > "$file" <<'EOF_CONF'
base {
    log_debug = off;
    log_info = on;
    log = "stderr";
    daemon = off;
    redirector = iptables;
}
redsocks {
    local_ip = 0.0.0.0;
    local_port = %listen_port%;
    ip = 127.0.0.1;
    port = %upstream_port%;
    type = socks5;
}
EOF_CONF
    sed -e "s/%listen_port%/$listen_port/g" -e "s/%upstream_port%/$upstream_port/g" "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

# Запуск redsocks
start_redsocks() {
    name="$1"
    config="$2"
    redsocks -c "$config" &
    pid=$!
    sleep 1
    kill -0 "$pid" 2>/dev/null || { echo "[fw] $name failed to start"; exit 1; }
    STARTED_PID="$pid"
}

# Добавление общих правил возврата (RETURN) в цепочку
append_common_returns() {
    chain="$1"
    for cidr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        iptables -t nat -A "$chain" -d "$cidr" -j RETURN
    done
}

# Добавление правил прокси
append_proxy_rules() {
    target_chain="$1"
    echo "[fw] applying proxy rules to $target_chain"
    iptables -t nat -A "$target_chain" -m set --match-set russian-only-ips dst -j RETURN
    iptables -t nat -A "$target_chain" -m set --match-set russian-ips dst -j RETURN
    for port in "$REDSOCKS_PORT" "$TOR_REDSOCKS_PORT" "$WSTUNNEL_SOCKS_PORT" "$TOR_SOCKS_PORT"; do
        iptables -t nat -A "$target_chain" -p tcp --dport "$port" -j RETURN
    done
    iptables -t nat -A "$target_chain" -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A "$target_chain" -p tcp --dport 53 -j REDIRECT --to-ports 53
    ensure_nat_chain_exists "$LB_CHAIN"
    iptables -t nat -A "$target_chain" -p tcp -j "$LB_CHAIN"
    echo "[fw] LB rule added: $target_chain -> $LB_CHAIN"
}

# Настройка балансировки (configure_lb)
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

# Цикл проверки «здоровья» прокси‑служб
healthcheck_loop() {
    while sleep 60; do
        wstunnel=false
        tor=false
        # Проверка доступности wstunnel / redsocks
        [ "$WSTUNNEL_BALANCE" -gt 0 ] && \
            nc -z -w2 127.0.0.1 "$WSTUNNEL_SOCKS_PORT" 2>/dev/null && wstunnel=true
        # Tor только если tor-redsocks реально запущен
        [ "$TOR_REDSOCKS_ENABLED" = "1" ] && \
            nc -z -w2 127.0.0.1 "$TOR_SOCKS_PORT" 2>/dev/null && tor=true
        # Перезапуск цепочки, чтобы избежать дублирования правил
        if ! reset_nat_chain "$LB_CHAIN"; then
            echo "[fw] warning: failed to reset $LB_CHAIN; retrying healthcheck later" >&2
            continue
        fi
        # Реализация балансировки в зависимости от доступности
        if $wstunnel && $tor; then
            configure_lb
        elif $wstunnel; then
            iptables -t nat -A "$LB_CHAIN" -p tcp -j REDIRECT --to-ports "$REDSOCKS_PORT"
        elif $tor; then
            iptables -t nat -A "$LB_CHAIN" -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
        fi
    done
}

# --------------------- Основная логика ---------------------
validate_balance
block_ipv6_if_requested
# Очистка старой конфигурации, чтобы избежать дублирования
cleanup_all_rules
load_ipset russian-only-ips "$RUSSIAN_ONLY_IPS_FILE"
load_ipset tor-only "$TOR_ONLY_IPS_FILE"

TOR_REDSOCKS_ENABLED=0

# Запуск прокси, если он включён
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

# tor-redsocks: для баланса Tor и/или для tor-only (даже при TOR_BALANCE=0)
if tor_redsocks_needed; then
    write_redsocks_config /tmp/redsocks-tor.conf "$TOR_REDSOCKS_PORT" "$TOR_SOCKS_PORT"
    start_redsocks tor-redsocks /tmp/redsocks-tor.conf
    TOR_REDSOCKS_PID="$STARTED_PID"
    TOR_REDSOCKS_ENABLED=1
fi

# Настройка цепочки OUTPUT и правилами для tor‑only IP‑сетов
iptables -t nat -N "$OUTPUT_CHAIN" 2>/dev/null || true
iptables -t nat -I OUTPUT -j "$OUTPUT_CHAIN"
append_common_returns "$OUTPUT_CHAIN"
if [ "$TOR_REDSOCKS_ENABLED" = "1" ]; then
    iptables -t nat -A "$OUTPUT_CHAIN" -m set --match-set tor-only dst -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
fi
if proxy_enabled; then
    ensure_nat_chain_exists "$LB_CHAIN"
    append_proxy_rules "$OUTPUT_CHAIN"
fi

# Настройка PREROUTING‑цепочки
iptables -t nat -N "$CHAIN_NAME" 2>/dev/null || true
iptables -t nat -I PREROUTING -j "$CHAIN_NAME"
iptables -t nat -A "$CHAIN_NAME" -m addrtype --dst-type LOCAL -j RETURN
iptables -t nat -A "$CHAIN_NAME" -s 172.16.0.0/12 -j RETURN
append_common_returns "$CHAIN_NAME"
if [ "$TOR_REDSOCKS_ENABLED" = "1" ]; then
    iptables -t nat -A "$CHAIN_NAME" -m set --match-set tor-only dst -p tcp -j REDIRECT --to-ports "$TOR_REDSOCKS_PORT"
fi
proxy_enabled && append_proxy_rules "$CHAIN_NAME"

# Запуск health‑check в фоне, если прокси включён
if proxy_enabled; then
    configure_lb
    healthcheck_loop &
    HEALTH_PID=$!
fi

# Дополнительные правила для Docker‑контейнеров и маскарадинг
iptables -I DOCKER-USER -s "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
iptables -I DOCKER-USER -d "$LAN_CIDR" -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -s "$LAN_CIDR" ! -d "$LAN_CIDR" -j MASQUERADE
# QUIC blocking: allow to Russian IPs, block to foreign IPs (forces TCP fallback into proxy)
if proxy_enabled; then
    iptables -A FORWARD -p udp --dport 443 -m set ! --match-set russian-ips dst -j DROP
    iptables -A OUTPUT -p udp --dport 443 ! -s 127.0.0.1 -m set ! --match-set russian-ips dst -j DROP
fi

setup_accounting_rules

# Per-flow byte counters for top-destination monitoring (conntrack)
if [ -w /proc/sys/net/netfilter/nf_conntrack_acct ]; then
    echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null || true
fi

RULES_APPLIED=1
echo "[fw] Firewall ready"
proxy_enabled && echo "       Balancing: wstunnel(:$REDSOCKS_PORT) = ${WSTUNNEL_BALANCE}% / tor(:$TOR_REDSOCKS_PORT) = ${TOR_BALANCE}%"
[ "$TOR_REDSOCKS_ENABLED" = "1" ] && [ "${TOR_BALANCE:-0}" -eq 0 ] && \
    echo "       tor-redsocks(:$TOR_REDSOCKS_PORT) enabled for tor-only"
# Бесконечный цикл удержания контейнера
while true; do
    sleep 3600
done