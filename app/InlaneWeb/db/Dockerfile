# BAN VA. Ba thay doi: nhan OCI provenance, HEALTHCHECK, va chay bang tai khoan
# khong dac quyen. Khuon mau init SQL nam ngoai /docker-entrypoint-initdb.d de
# entrypoint ket xuat ra sau khi chen mat khau tu bien moi truong.
FROM mariadb:10.11

ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/vsxkr/btl-devsecops-nhom11" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.title="InlaneWeb database"

COPY lab.cnf /etc/mysql/conf.d/lab.cnf

RUN mkdir -p /opt/inlaneweb
COPY init.sql.template /opt/inlaneweb/init.sql.template

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# entrypoint chay bang mysql nen can ghi duoc vao thu muc init de ket xuat khuon
# mau. Chi tai khoan chay may chu moi ghi duoc thu muc nay.
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && mkdir -p /docker-entrypoint-initdb.d /var/lib/mysql-files \
 && chown -R mysql:mysql /opt/inlaneweb /docker-entrypoint-initdb.d /var/lib/mysql-files \
 && chmod 0750 /var/lib/mysql-files

HEALTHCHECK --interval=5s --timeout=5s --retries=20 \
  CMD healthcheck.sh --connect --innodb_initialized

USER mysql
ENTRYPOINT ["entrypoint.sh"]
CMD ["mariadbd"]
