#!/bin/bash
# =============================================================================
# entrypoint.sh — BAN VA cua fix-perms-entrypoint.sh
#
# Hai thay doi:
#
# 1. Bo doan `chmod 1777 /var/lib/mysql-files`. Doan do co y mo quyen ghi cho
#    moi nguoi de MySQL ghi duoc web shell qua SELECT ... INTO OUTFILE. Cung voi
#    secure_file_priv = NULL trong lab.cnf, duong ghi tep qua SQL bi chan han.
#
# 2. Ket xuat init SQL tu MOT KHUON MAU, chen mat khau tu bien moi truong. Nho
#    vay khong co mat khau nao nam trong kho ma hay trong anh container. Thieu
#    bien thi dung han thay vi dung gia tri mac dinh.
# =============================================================================
set -euo pipefail

TEMPLATE=/opt/inlaneweb/init.sql.template
RENDERED=/docker-entrypoint-initdb.d/10-init.sql

if [ -f "$TEMPLATE" ]; then
  for v in APP_DB_PASSWORD TEST_DB_PASSWORD; do
    if [ -z "${!v:-}" ]; then
      echo "entrypoint: thieu bien moi truong $v, dung han" >&2
      exit 1
    fi
  done
  mkdir -p "$(dirname "$RENDERED")"
  sed -e "s|__APP_DB_PASSWORD__|${APP_DB_PASSWORD}|g" \
      -e "s|__TEST_DB_PASSWORD__|${TEST_DB_PASSWORD}|g" \
      "$TEMPLATE" > "$RENDERED"
  chmod 0644 "$RENDERED"
  echo "entrypoint: da ket xuat $RENDERED tu khuon mau"
fi

exec docker-entrypoint.sh "$@"
