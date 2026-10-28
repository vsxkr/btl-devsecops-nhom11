FROM php:8.2-apache

# mysqli cho ket noi MySQL/MariaDB
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli

# Bat mod_rewrite -> URL sach (khong lo .php), route giong app that
RUN a2enmod rewrite

# php.ini: display_errors=On de phuc vu Error-based SQLi
COPY php.ini /usr/local/etc/php/conf.d/zz-lab.ini

# Cho phep .htaccess ghi de (AllowOverride All)
COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf

# Dat thu muc lam viec
WORKDIR /var/www/html

# Dong goi toan bo ma nguon ung dung vao Docker image (Self-contained Image)
COPY src/ /var/www/html/
