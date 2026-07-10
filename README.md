# GOLDENROUTE — INFRASTRUCTURE DIVISION

Прозрачный прокси-шлюз для обхода блокировок. Единственный бэкенд — Tor.

---

## НАЗНАЧЕНИЕ

Система принимает 1 (одно) решение о каждом пакете:

- **Destination в `russian-ips`** (данные RIPE) → напрямую
- **Destination в `tor-exclude`** (ваш список) → напрямую
- **Всё остальное** → Tor

Только обход блокировок, без анонимности.

---

## АРХИТЕКТУРА

```
LAN-клиенты → FW (PREROUTING) → REDIRECT :12346 → redsocks → Tor → интернет
                                                  ↓
                                           unbound (DoT :53)
```

3 (три) цепочки iptables:

1. **`FW_REDIRECT`** — PREROUTING. Встречает трафик LAN-клиентов.
2. **`FW_OUTPUT`** — OUTPUT. Обрабатывает трафик с самого хоста.
3. **DOCKER-USER** — FORWARD. Разрешает транзитный трафик LAN.

Логика для FW_REDIRECT и FW_OUTPUT идентична:

1. `dst-type LOCAL` → RETURN
2. `src 172.16.0.0/12` → RETURN (Docker bridge — предотвращение петли)
3. Приватные диапазоны (10/8, 172.16/12, 192.168/16) → RETURN
4. `match-set russian-ips dst` → RETURN
5. `match-set tor-exclude dst` → RETURN
6. `dport 12346` или `9050` → RETURN (не перехватывать свой трафик)
7. `dport 53` → REDIRECT `:53` (unbound)
8. Весь остальной TCP → REDIRECT `:12346` (redsocks → Tor)

---

## КОМПОНЕНТЫ

| Компонент | Роль |
|-----------|------|
| **`fw`** | Правила iptables + redsocks. Работает в `network_mode: host`. Права `NET_ADMIN` + `NET_RAW`. Очищает старые правила через while-цикл (идемпотентность). Загружает ipset из файлов. Запускает redsocks на порту 12346, апстрим — Tor :9050. |
| **`tor`** | Единственный бэкенд. Мосты obfs4. SOCKS5 :9050. |
| **`unbound`** | DNS-over-TLS форвардер. Все DNS-запросы (порт 53) перехватываются и направляются сюда. `.ru` → Яндекс DNS. Остальное → Cloudflare + Google. |

---

## QUIC — UDP, КОТОРЫЙ ДУМАЕТ, ЧТО ОН ВЫШЕ TCP

QUIC (UDP/443) не может быть перехвачен SOCKS5-прокси. Без блокировки браузер устанавливает прямое соединение с иностранным сервером, минуя Tor.

Правила:

```
FORWARD: UDP/443 !russian-ips !tor-exclude → DROP
OUTPUT:  UDP/443 !127.0.0.1 !russian-ips !tor-exclude → DROP
```

Браузер, не получив ответа по UDP, откатывается на TCP/443. TCP/443 перехватывается правилами PREROUTING/OUTPUT и направляется в Tor.

QUIC к российским адресам и адресам из tor-exclude работает штатно.

---

## ДАННЫЕ

### `fw/russian-ips.txt`

IPv4-диапазоны РФ. Источник: RIPE API. Автоматически обновляется при запуске `fw`. Не редактировать вручную — будет перезаписано.

### `fw/tor-exclude-ips.txt`

Ваш список исключений. Один IP или CIDR на строку, `#` — комментарий. Адреса из этого списка НЕ направляются в Tor.

Полезно для:
- Сервисов, блокирующих Tor exit-ноды
- Сервисов, требующих прямого доступа без задержек Tor
- IP-адресов, которые должны быть доступны напрямую вне зависимости от геолокации

---

## БЫСТРЫЙ СТАРТ

```bash
# 1. Клонировать и подготовить
git clone <repo> goldenroute
cd goldenroute
cp .env.example .env

# 2. Получить свежие мосты Tor
#    https://bridges.torproject.org → tor/bridges.txt

# 3. Добавить исключения (опционально)
#    fw/tor-exclude-ips.txt

# 4. Запустить
docker compose up -d
```

### Настройка клиентов LAN

На каждом клиенте:
- **Шлюз по умолчанию**: IP хоста с goldenroute
- **DNS**: IP хоста (unbound на порту 53)

---

## КОНФИГУРАЦИЯ

`.env`:

| Переменная | По умолчанию | Назначение |
|------------|-------------|------------|
| `UNBOUND_PORT` | 53 | Порт DNS |
| `TOR_SOCKS_PORT` | 9050 | SOCKS5 порт Tor |
| `TOR_CONTROL_PORT` | 9051 | Control-порт Tor |
| `TOR_REDSOCKS_PORT` | 12346 | Порт redsocks, принимающий перенаправленный трафик |
| `LAN_CIDR` | 192.168.1.0/24 | Подсеть LAN |

---

## ДИАГНОСТИКА

### Tor не забутстрапился

```bash
docker compose logs tor | grep "Bootstrapped"
```

Ищите `Bootstrapped 100% (done)`. Если нет — обновите мосты на https://bridges.torproject.org.

### Трафик не идёт через Tor

```bash
docker compose exec fw iptables -t nat -L FW_REDIRECT -n -v
```

Счётчик `REDIRECT tcp --dport 12346` должен расти.

### QUIC не блокируется

```bash
docker compose exec fw iptables -L FORWARD -n -v | grep "udp dpt:443"
```

Счётчик DROP должен расти при обращении к иностранным сайтам.

### Мосты Tor блокированы

```bash
docker compose up -d --force-recreate tor
```

### DNS не резолвится

```bash
nslookup example.com <IP-хоста>
```

---

## ИЗВЕСТНЫЕ ОГРАНИЧЕНИЯ

- Только TCP уходит через Tor. UDP (кроме DNS и заблокированного QUIC) идёт напрямую.
- Snowflake не работает через Docker NAT. Используйте obfs4-мосты.
- `network_mode: host` обязателен для `fw`.
- Только IPv4.

---

## ТРЕБОВАНИЯ

- Linux: `ip_tables`, `iptable_nat`, `ip_set`, `ip_set_hash_net`
- Docker + Docker Compose
- `net.ipv4.ip_forward = 1`
- Порт 53 свободен на хосте

---

BALENCIAGA INFRASTRUCTURE DIVISION

Один маршрут. Tor.
