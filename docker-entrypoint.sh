#!/bin/bash
set -e

# Work dirs are pre-created in Dockerfile with correct ownership.
# Ensure they exist in case the volume mount replaced them.
mkdir -p /var/www/html/.restore/uploads \
         /var/www/html/.restore/extract \
         /var/www/html/.restore/backups

# Protect work dir from web access
htaccess=/var/www/html/.restore/.htaccess
[ -f "$htaccess" ] || echo 'Deny from all' > "$htaccess"

exec "$@"
