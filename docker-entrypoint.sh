#!/bin/bash
set -e

# Ensure work directories exist and are owned by www-data
# (handles the case where volume mount replaces image-created dirs)
mkdir -p /var/www/html/restore_work/uploads \
         /var/www/html/restore_work/extract \
         /var/www/html/restore_backups
chown -R www-data:www-data /var/www/html/restore_work /var/www/html/restore_backups

# Protect work dir from web access
htaccess=/var/www/html/restore_work/.htaccess
[ -f "$htaccess" ] || echo 'Deny from all' > "$htaccess"

exec "$@"
