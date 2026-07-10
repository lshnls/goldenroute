#!/bin/sh
set -e

# Initialize trust anchor if missing
if [ ! -f /var/lib/unbound/root.key ]; then
    echo "Initializing root.key..."
    unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || echo "Warning: Could not initialize root.key, continuing without DNSSEC validation"
fi

# Start unbound
exec unbound -d -c /etc/unbound/unbound.conf
