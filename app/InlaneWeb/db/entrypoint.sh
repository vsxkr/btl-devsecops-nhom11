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

# Uu tien dang <TEN>_FILE. Ly do: bien moi truong cua container doc duoc bang
# `docker inspect` va hien trong moi ban ghi su kien, nen mot bi mat dat o day la
# mot bi mat da bi tiet lo. Phep kiem ilf-run-04-no-secrets-in-env trong
# compliance/ do dung dieu nay o trang thai chay. Doi chieu PCI DSS 8.6.2.
read_secret() {
  local name="$1" file_var="${1}_FILE" path
  path="${!file_var:-}"
  if [ -n "$path" ]; then
    if [ ! -r "$path" ]; then
      echo "entrypoint: khong doc duoc tep bi mat $path cho $name, dung han" >&2
      exit 1
    fi
    printf '%s' "$(head -n 1 "$path" | tr -d '[:space:]')"
  else
    printf '%s' "${!name:-}"
  fi
}

if [ -f "$TEMPLATE" ]; then
  APP_DB_PASSWORD="$(read_secret APP_DB_PASSWORD)"
  TEST_DB_PASSWORD="$(read_secret TEST_DB_PASSWORD)"
  for v in APP_DB_PASSWORD TEST_DB_PASSWORD; do
    if [ -z "${!v:-}" ]; then
      echo "entrypoint: thieu $v va ${v}_FILE, dung han" >&2
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
