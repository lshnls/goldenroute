#!/bin/sh
set -eu

DATA_DIR="${TOR_DATA_DIR:-/var/lib/tor}"
PROJECT_GID="${PROJECT_GID:-1000}"
HOST_GROUP_NAME="${HOST_GROUP_NAME:-project}" 

# # Check if the data directory exists
if [ -d "$DATA_DIR" ]; then

   if ! grep -q "^[^:]*:[^:]*:${PROJECT_GID}:" /etc/group; then
     # Add group
     addgroup -g "$PROJECT_GID" "$HOST_GROUP_NAME" >/dev/null 2>&1 || true
   fi

  # Get group name
  GROUP_NAME="$(awk -F: -v gid="$PROJECT_GID" '$3 == gid {print $1; exit}' /etc/group)"
  [ -n "$GROUP_NAME" ] || GROUP_NAME="$HOST_GROUP_NAME"

  # Add group to tor user
  addgroup tor "$GROUP_NAME" >/dev/null 2>&1 || true

  # Change ownership and permissions
  chown -R tor "$DATA_DIR"
  chgrp -R "$PROJECT_GID" "$DATA_DIR"

  find "$DATA_DIR" -type d -exec chmod 2770 {} +
  find "$DATA_DIR" -type f -exec chmod 660 {} +
fi

exec "$@"
