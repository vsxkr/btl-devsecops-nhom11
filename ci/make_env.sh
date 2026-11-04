#!/usr/bin/env bash
# =============================================================================
# make_env.sh — sinh bi mat cho MOI TRUONG KIEM THU hoac MOI TRUONG DICH TAM.
#
# Sinh hai thu, vi hai noi can bi mat theo hai duong khac nhau:
#
#   1. Tep .env, cho nhung thanh phan chay TREN HOST, vi du bo test hanh vi tu
#      ket noi vao co so du lieu de kiem.
#   2. Cac tep trong secrets/, cho container. Compose dua chung vao
#      /run/secrets/<ten>, va ung dung doc bang DB_PASS_FILE. Bi mat KHONG di
#      qua bien moi truong cua container, vi bien moi truong doc duoc bang
#      `docker inspect` nen bi mat dat o do la bi mat da bi tiet lo. Phep kiem
#      ilf-run-04-no-secrets-in-env do dung dieu nay. Doi chieu PCI DSS 8.6.2.
#
# Dieu khoan CS-04 cam gia tri du phong dang hang, nen khong co mat khau mac
# dinh nao de roi ve. Thieu bi mat thi Compose va ung dung dung han. Do la hanh
# vi dung, nhung mot moi truong kiem thu tu dung van can mot bo bi mat hop le.
#
# Khong dung cho moi truong that. Moi truong that lay bi mat tu noi quan ly bi
# mat, khong sinh tai cho.
#
# Cach dung:
#   bash ci/make_env.sh [duong-dan-tep-env]
# =============================================================================
set -eu

ENV_FILE="${1:-app/InlaneWeb/.env}"
SECRET_DIR="$(dirname "$ENV_FILE")/secrets"

gen() { head -c 18 /dev/urandom | base64 | tr -d '=+/' | cut -c1-20; }

mkdir -p "$SECRET_DIR"

if [ -f "$ENV_FILE" ]; then
  echo "[THONG TIN] Dung $ENV_FILE co san, khong ghi de."
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
else
  MYSQL_ROOT_PASSWORD="$(gen)"
  APP_DB_PASSWORD="$(gen)"
  TEST_DB_PASSWORD="$(gen)"
  GRAFANA_ADMIN_PASSWORD="$(gen)"
  {
    echo "MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD"
    echo "APP_DB_PASSWORD=$APP_DB_PASSWORD"
    echo "TEST_DB_PASSWORD=$TEST_DB_PASSWORD"
    echo "GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD"
    echo "VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
  } > "$ENV_FILE"
  echo "[DAT] Da sinh $ENV_FILE voi bi mat ngau nhien cho lan chay nay."
fi

write_secret() {
  local name="$1" value="$2" target="$SECRET_DIR/$1"
  if [ -z "$value" ]; then
    echo "[LOI] Thieu gia tri cho bi mat $name, dung han." >&2
    exit 1
  fi
  printf '%s' "$value" > "$target"
  # Quyen 0444, khong phai 0600. Ly do da do duoc o run 41815649692: Compose dua
  # tep bi mat vao container va GIU NGUYEN chu so huu cua tep tren host, trong
  # khi hai container chay bang hai tai khoan khong dac quyen khac nhau (mysql va
  # www-data). Voi quyen 0600 thi ca hai deu khong doc duoc va MariaDB khong khoi
  # dong noi.
  # Danh doi nay chi chap nhan duoc o moi truong kiem thu: bi mat la chuoi ngau
  # nhien sinh cho tung lan chay va mat cung lan chay. O moi truong that, bi mat
  # den tu noi quan ly bi mat cua trinh dieu phoi, kem dung chu so huu, nen
  # khong can mo quyen doc cho moi nguoi.
  chmod 444 "$target" 2>/dev/null || true
  echo "      $target"
}

echo "[DAT] Ghi bi mat dang tep cho container:"
write_secret mysql_root_password "${MYSQL_ROOT_PASSWORD:-}"
write_secret app_db_password "${APP_DB_PASSWORD:-}"
write_secret test_db_password "${TEST_DB_PASSWORD:-}"
