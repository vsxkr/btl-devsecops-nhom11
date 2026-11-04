#!/usr/bin/env bash
# =============================================================================
# make_env.sh — sinh tep bien moi truong cho MOI TRUONG KIEM THU hoac MOI TRUONG
# DICH TAM, voi bi mat ngau nhien cho tung lan chay.
#
# Ly do ton tai: dieu khoan CS-04 cam gia tri du phong dang hang, nen Compose
# khong co mat khau mac dinh nao de roi ve. Thieu tep nay thi Compose thay bien
# bang chuoi rong va MariaDB tu choi khoi dong. Do la hanh vi dung, nhung mot
# moi truong kiem thu tu dung van can mot bo bi mat hop le.
#
# Khong dung cho moi truong that. Moi truong that lay bi mat tu noi quan ly bi
# mat, khong sinh tai cho.
#
# Cach dung:
#   bash ci/make_env.sh <duong-dan-tep-env>
# =============================================================================
set -eu

ENV_FILE="${1:-app/InlaneWeb/.env}"

if [ -f "$ENV_FILE" ]; then
  echo "[THONG TIN] Dung $ENV_FILE co san, khong ghi de."
  exit 0
fi

gen() { head -c 18 /dev/urandom | base64 | tr -d '=+/' | cut -c1-20; }

{
  echo "MYSQL_ROOT_PASSWORD=$(gen)"
  echo "APP_DB_PASSWORD=$(gen)"
  echo "TEST_DB_PASSWORD=$(gen)"
  echo "GRAFANA_ADMIN_PASSWORD=$(gen)"
  echo "VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
} > "$ENV_FILE"

echo "[DAT] Da sinh $ENV_FILE voi bi mat ngau nhien cho lan chay nay."
echo "      Cac khoa: MYSQL_ROOT_PASSWORD, APP_DB_PASSWORD, TEST_DB_PASSWORD, GRAFANA_ADMIN_PASSWORD, VCS_REF"
