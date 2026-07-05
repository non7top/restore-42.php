#!/bin/bash
set -e

# Ensure work directories exist and are owned by www-data
# (handles the case where volume mount replaces image-created dirs)
mkdir -p /var/www/html/.restore/uploads \
         /var/www/html/.restore/extract \
         /var/www/html/.restore/backups
chown -R www-data:www-data /var/www/html/.restore
# Allow the script to self-modify (embed password hash)
chown www-data:www-data /var/www/html/restore-42.php 2>/dev/null || true
chmod 644 /var/www/html/restore-42.php 2>/dev/null || true

# Protect work dir from web access
htaccess=/var/www/html/.restore/.htaccess
[ -f "$htaccess" ] || echo 'Deny from all' > "$htaccess"

exec "$@"
