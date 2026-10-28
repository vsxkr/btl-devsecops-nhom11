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

say "3. Xoa log cu de khang dinh ve nhat ky chi tinh tren lan chay nay"
MARK="TDS-RUN-$(date +%s)"
docker exec "$WEB_CONTAINER" sh -c "printf '%s\n' '$MARK' >&2"

say "4. Chay compliance_test.php trong container"
docker cp "$ROOT/tests/security/compliance_test.php" "$WEB_CONTAINER:/tmp/compliance_test.php" >/dev/null
set +e
docker exec -e DB_HOST=db -e DB_USER=root -e DB_PASS=password -e DB_NAME=ilfreight \
  "$WEB_CONTAINER" php /tmp/compliance_test.php
PHP_RC=$?
set -e

say "5. TDS-6  GDPR Art. 5(1)(c): nhat ky khong duoc chua nguyen van cau lenh"
LOGS=$(docker logs "$WEB_CONTAINER" 2>&1 | sed -n "/$MARK/,\$p")
HITS=$(printf '%s' "$LOGS" | grep -c '"failed_query"' || true)
if [ "${HITS:-0}" -gt 0 ]; then
  echo "  [LOI ] TDS-6   GDPR Art. 5(1)(c)   nhat ky chua nguyen van cau lenh"
  echo "          -> tim thay $HITS dong co truong \"failed_query\" trong luong nhat ky"
  printf '%s' "$LOGS" | grep -m1 '"failed_query"' | cut -c1-200 | sed 's/^/          mau: /'
  LOG_RC=1
else
  echo "  [DAT ] TDS-6   GDPR Art. 5(1)(c)   nhat ky khong chua nguyen van cau lenh"
  LOG_RC=0
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
