FROM php:8.3-apache

# Remap www-data to the host user so volume-mounted files have matching ownership
ARG UID=1001
ARG GID=1001
RUN usermod -u "${UID}" www-data && groupmod -g "${GID}" www-data

RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
        unzip mariadb-client libzip-dev \
    && docker-php-ext-install mysqli zip \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

COPY php.ini /usr/local/etc/php/conf.d/restore.ini
COPY restore-42.php /var/www/html/restore-42.php

RUN echo '<Directory /var/www/html>\n    AllowOverride All\n    Require all granted\n</Directory>' \
    > /etc/apache2/conf-available/allow-override.conf \
    && a2enconf allow-override

# Pre-create writable directories owned by the remapped www-data (= host user UID)
RUN mkdir -p /var/www/html/.restore/uploads \
             /var/www/html/.restore/extract \
             /var/www/html/.restore/backups \
    && chown -R www-data:www-data /var/www/html/.restore \
    && chown www-data:www-data /var/www/html/restore-42.php \
    && chmod 644 /var/www/html/restore-42.php

# Switch Apache to a non-privileged port so the process never needs root
RUN sed -i 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
    && sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' /etc/apache2/sites-enabled/000-default.conf

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Run as the remapped www-data — no root process needed
USER www-data
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
