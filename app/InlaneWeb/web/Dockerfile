# BAN VA. Bon thay doi: nhan OCI provenance, HEALTHCHECK, Apache lang nghe cong
# khong dac quyen, va tien trinh chay bang www-data thay cho root.
FROM php:8.2-apache

ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/vsxkr/btl-devsecops-nhom11" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.title="InlaneWeb portal"

RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli
RUN a2enmod rewrite

COPY php.ini /usr/local/etc/php/conf.d/zz-lab.ini
COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf

# Cong 8080 de tien trinh khong can dac quyen bind cong duoi 1024.
RUN sed -ri 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
 && sed -ri 's/:80>/:8080>/' /etc/apache2/sites-available/000-default.conf \
 && mkdir -p /var/run/apache2 /var/lock/apache2 \
 && chown -R www-data:www-data /var/run/apache2 /var/lock/apache2 /var/log/apache2

WORKDIR /var/www/html
COPY --chown=www-data:www-data src/ /var/www/html/

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s \
  CMD curl -f -s http://127.0.0.1:8080/health || exit 1

USER www-data
