#!/bin/sh
set -e

# ===== 2. Подготовка временных файлов для конфигурации бэкендов =====
UPSTREAM_FILE=$(mktemp)
SERVER_FILE=$(mktemp)

BACKENDS_FILE="${BACKENDS_FILE:-/etc/nginx/backends.list}"
PORT=8081

if [ -f "$BACKENDS_FILE" ]; then
    grep -vE '^\s*(#|$)' "$BACKENDS_FILE" | while IFS=';' read -r ip_port auth_base64 server_name; do
        [ -z "$ip_port" ] && continue

        # Разбираем ip и порт
        ip="${ip_port%:*}"
        port="${ip_port##*:}"
        if [ "$ip" = "$port" ]; then
            port=443
        fi
        [ -z "$ip" ] && continue

        # Если server_name не задан, используем ip
        [ -z "$server_name" ] && server_name="$ip"

        # Проверяем auth_base64
        if [ -z "$auth_base64" ]; then
            echo "ERROR: missing auth base64 for $ip" >&2
            continue
        fi
        auth_header="Basic $auth_base64"

        # Пишем в upstream-файл
        echo "        server 127.0.0.1:$PORT max_fails=2 fail_timeout=30s;" >> "$UPSTREAM_FILE"

        # Пишем внутренний server-блок
        cat >> "$SERVER_FILE" <<INNER
    server {
        listen 127.0.0.1:$PORT;
        location / {
            proxy_pass https://$ip:$port;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $server_name;
            proxy_set_header Authorization "$auth_header";
            proxy_ssl_verify off;
            proxy_ssl_server_name on;
            proxy_ssl_name $server_name;
            proxy_connect_timeout 5s;
            proxy_read_timeout 3600s;
        }
    }
INNER
        PORT=$((PORT+1))
    done
else
    echo "WARNING: No backends file found at $BACKENDS_FILE. Starting nginx with 503 default."
fi

# ===== 3. Сборка итогового nginx.conf =====
NGINX_CONF="/etc/nginx/nginx.conf"

cat > "$NGINX_CONF" <<EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log /dev/stdout main;
    error_log /dev/stderr notice;

    sendfile on;
    keepalive_timeout 65;

    upstream wss_cluster {
        least_conn;
EOF

# Вставляем список серверов из временного файла (если он не пуст)
if [ -s "$UPSTREAM_FILE" ]; then
    cat "$UPSTREAM_FILE" >> "$NGINX_CONF"
else
    echo "        # No backends available" >> "$NGINX_CONF"
fi

cat >> "$NGINX_CONF" <<EOF
    }
EOF

# Вставляем внутренние server-блоки
if [ -s "$SERVER_FILE" ]; then
    cat "$SERVER_FILE" >> "$NGINX_CONF"
fi

# Добавляем основной server
cat >> "$NGINX_CONF" <<EOF

    server {
        listen 80;

        location / {
            proxy_pass http://wss_cluster;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_read_timeout 3600s;
            proxy_connect_timeout 5s;
        }
    }
}
EOF

# Очистка временных файлов
rm -f "$UPSTREAM_FILE" "$SERVER_FILE"

# ===== 4. Запуск nginx =====
exec nginx -c "$NGINX_CONF" -g 'daemon off;'
