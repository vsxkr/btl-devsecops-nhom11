#!/usr/bin/env bash
# =============================================================================
# run.sh — Bo dieu phoi Test-Driven Security tren host.
#
# Can cu: Hands-on_guide_updated.docx Phase 4 va Phase 7 (bang 5 lenh kiem
# chung, va yeu cau "Saved output of each verification command").
#
# Viec cua script nay:
#   1. dung stack InlaneWeb
#   2. cho den khi healthcheck cua web bao khoe
#   3. chay compliance_test.php BEN TRONG container web
#   4. kiem mot khang dinh khong lam duoc tu trong container: luong nhat ky
#      cua container khong duoc chua nguyen van cau lenh truy van
#   5. in tong ket, tra ma thoat khac 0 khi co test that bai
#
# Cach dung:
#   bash tests/security/run.sh                 # chay tren ma nguon hien tai
#   bash tests/security/run.sh --keep-up       # giu stack chay sau khi xong
# =============================================================================
set -u -o pipefail

# LUU Y VE DUONG DAN TREN WINDOWS
# Git Bash doi moi doi so trong giong duong dan POSIX thanh duong dan Windows, nen
# "/tmp/compliance_test.php" bi bien thanh "C:/Users/.../Temp/compliance_test.php"
# va php trong container khong mo duoc.
# Khong duoc tat phep doi bang MSYS_NO_PATHCONV=1, vi khi do duong dan PHIA HOST
# cung thoi bi doi va docker nhan "C:\c\Users\...".
# Cach dung la chi chan doi cho duong dan PHIA CONTAINER, bang tien to hai dau
# gach cheo. MSYS bo bot mot dau gach va giu nguyen phan con lai; tren Linux
# "//tmp/x" tuong duong "/tmp/x" nen cung chay dung.
CONTAINER_TEST_PATH='//tmp/compliance_test.php'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/app/InlaneWeb/docker-compose.yml"
WEB_CONTAINER="ilfreight_web"
KEEP_UP=0
[ "${1:-}" = "--keep-up" ] && KEEP_UP=1

say() { printf '\n==> %s\n' "$*"; }

say "1. Dung stack InlaneWeb"
docker compose -f "$COMPOSE_FILE" up -d --wait 2>&1 | tail -5 || {
  echo "LOI: khong dung duoc stack. Docker Desktop da chay chua?"
  exit 2
}

say "2. Cho web bao khoe"
for i in $(seq 1 60); do
  state=$(docker inspect -f '{{.State.Health.Status}}' "$WEB_CONTAINER" 2>/dev/null || echo unknown)
  [ "$state" = "healthy" ] && break
  sleep 2
done
echo "   trang thai healthcheck: ${state:-unknown}"
if [ "${state:-}" != "healthy" ]; then
  echo "LOI: web khong vao trang thai healthy"
  docker compose -f "$COMPOSE_FILE" logs --tail 40 web
  exit 2
fi

say "3. Danh moc thoi gian de khang dinh ve nhat ky chi tinh tren lan chay nay"
# Ban dau buoc nay ghi mot moc bang `docker exec ... >&2`. Cach do KHONG dung:
# stderr cua mot exec session khong di vao luong `docker logs` cua tien trinh
# chinh, nen moc khong bao gio xuat hien va phep loc theo moc tra ve rong, lam
# TDS-6 bao DAT mot cach gia. Dung dau thoi gian cho `docker logs --since`.
LOG_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "   moc: $LOG_SINCE"

say "4. Chay compliance_test.php trong container"
# Dich la THU MUC, khong phai duong dan tep. Dua duong dan tep thi docker bao
# "extraction point is not a directory".
docker cp "$ROOT/tests/security/compliance_test.php" "${WEB_CONTAINER}://tmp/" >/dev/null
set +e
docker exec -e DB_HOST=db -e DB_USER="${TEST_DB_USER:-root}" \
  -e DB_PASS="${TEST_DB_PASS:-password}" -e DB_NAME=ilfreight \
  "$WEB_CONTAINER" php "$CONTAINER_TEST_PATH"
PHP_RC=$?
set -e

say "5. TDS-6  GDPR Art. 5(1)(c): nhat ky khong duoc chua nguyen van cau lenh"
# Phep kiem nay phai TU kich mot loi truy van, khong duoc dua vao viec buoc 4 da
# chay hay chua. Neu khong, khi buoc 4 that bai vi ly do ky thuat thi khong co loi
# SQL nao duoc sinh ra, log sach, va TDS-6 bao DAT mot cach gia.
# Dung endpoint CONG KHAI co di qua helper query() cua ung dung.
# Khong dung /api/track vi trang do goi mysqli_query truc tiep va CO Y nuot loi,
# nen no khong in va khong ghi log, tuc khong cham duoc vao duong can kiem.
curl -s -o /dev/null "http://127.0.0.1:8088/ports?q=1%27" || true
curl -s -o /dev/null "http://127.0.0.1:8088/news?id=1%27" || true
sleep 2
LOGS=$(docker logs --since "$LOG_SINCE" "$WEB_CONTAINER" 2>&1)
PROBE_SEEN=$(printf '%s' "$LOGS" | grep -c 'APP-EXCEPTION' || true)
echo "   da kich loi truy van, so dong APP-EXCEPTION sau moc: ${PROBE_SEEN:-0}"
if [ "${PROBE_SEEN:-0}" -eq 0 ]; then
  echo "  [BO QUA] TDS-6 khong ket luan duoc: khong kich duoc loi nao nen khong co gi de kiem"
  LOG_RC=2
fi
if [ "${PROBE_SEEN:-0}" -gt 0 ]; then
  HITS=$(printf '%s' "$LOGS" | grep -c '"failed_query"' || true)
  if [ "${HITS:-0}" -gt 0 ]; then
    echo "  [LOI ] TDS-6   GDPR Art. 5(1)(c)   nhat ky chua nguyen van cau lenh"
    echo "          -> tim thay $HITS dong co truong failed_query trong luong nhat ky"
    printf '%s' "$LOGS" | grep -m1 '"failed_query"' | cut -c1-220 | sed 's/^/          mau: /'
    LOG_RC=1
  else
    echo "  [DAT ] TDS-6   GDPR Art. 5(1)(c)   nhat ky khong chua nguyen van cau lenh"
    LOG_RC=0
  fi
fi

say "Tong ket"
echo "  compliance_test.php : ma thoat $PHP_RC"
echo "  TDS-6 nhat ky       : ma thoat $LOG_RC"
RC=0
[ "$PHP_RC" -ne 0 ] && RC=1
[ "$LOG_RC" -ne 0 ] && RC=1
echo "  ket qua chung       : $([ $RC -eq 0 ] && echo 'TAT CA DAT' || echo 'CO TEST THAT BAI')"

if [ "$KEEP_UP" -eq 0 ]; then
  say "Ha stack"
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1
fi

exit "$RC"
