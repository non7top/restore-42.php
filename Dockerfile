FROM php:8.3-apache

RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
        unzip mariadb-client libzip-dev \
    && docker-php-ext-install pdo pdo_mysql zip \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

COPY php.ini /usr/local/etc/php/conf.d/restore.ini
COPY restore-42.php /var/www/html/restore-42.php

RUN echo '<Directory /var/www/html>\n    AllowOverride All\n    Require all granted\n</Directory>' \
    > /etc/apache2/conf-available/allow-override.conf \
    && a2enconf allow-override

# Pre-create writable directories so www-data can use them regardless of volume mount ownership
RUN mkdir -p /var/www/html/.restore/uploads \
             /var/www/html/.restore/extract \
             /var/www/html/.restore/backups \
    && chown -R www-data:www-data /var/www/html/.restore

# Entrypoint: fix ownership of volume-mounted dirs at startup, then run Apache
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
