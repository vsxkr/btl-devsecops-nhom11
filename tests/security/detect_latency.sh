#!/usr/bin/env bash
# =============================================================================
# detect_latency.sh — Bang chung BAC 3: tan cong -> phat hien -> canh bao toi
# dich xu ly duoc, va DO DO TRE PHAT HIEN.
#
# Can cu: Juice_Shop_Telemetry_Lab_Guide.docx — kiem luat bang log that, chay
# tan cong co kiem soat, doi chieu canh bao mong doi, canh bao phai toi alert
# sink. Day la bac bang chung cao hon "test do roi xanh": no chay khai thac that
# va do thoi gian tu luc tan cong toi luc nguoi truc nhan duoc tin.
#
# Chuoi duoc chung minh:
#   curl (SQLi) -> Apache JSON access log -> Promtail (che du lieu) -> Loki
#   -> luat tuong quan `sum by (client_ip)` -> Alertmanager -> alert-sink
#
# Cach dung:
#   bash tests/security/detect_latency.sh            # stack web + monitoring da chay
#   bash tests/security/detect_latency.sh --up       # tu dung ca hai stack truoc
# =============================================================================
set -u -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$ROOT/app/InlaneWeb"
WEB_COMPOSE="$APP/docker-compose.yml"
MON_COMPOSE="$APP/docker-compose.monitoring.hardened.yml"
WEB_URL="http://127.0.0.1:8088"
LOKI="http://127.0.0.1:3100"
AM="http://127.0.0.1:9093"
BURST=8          # so request trong loat (nguong luat = 5)
TIMEOUT=60       # giay cho canh bao

say(){ printf '\n==> %s\n' "$*"; }
pyq(){ PYTHONIOENCODING=utf-8 python -I -c "$@"; }

if [ "${1:-}" = "--up" ]; then
  say "Dung stack web"
  docker compose -f "$WEB_COMPOSE" up -d --wait 2>&1 | tail -2
  say "Dung cum giam sat (loki, promtail, alertmanager, alert-sink)"
  docker compose -f "$MON_COMPOSE" up -d loki alertmanager alert-sink promtail 2>&1 | tail -3
  # cho loki + promtail san sang
  for i in $(seq 1 20); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' ilfreight_loki 2>/dev/null)" = "healthy" ] \
      && docker logs --since 40s ilfreight_promtail 2>&1 | grep -q "added Docker target" && break
    sleep 2
  done
fi

say "0. Kiem cum giam sat dang chay"
for c in ilfreight_web ilfreight_loki ilfreight_promtail ilfreight_alertmanager ilfreight_alert_sink; do
  st=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)
  echo "   $c: $st"
  [ "$st" = "running" ] || { echo "LOI: $c khong chay. Chay lai voi --up."; exit 2; }
done

say "1. Kiem luat da nap va khong loi (ruler health)"
curl -s "$LOKI/prometheus/api/v1/rules" | pyq "
import sys,json
d=json.load(sys.stdin)
bad=0
for g in d['data']['groups']:
  for r in g['rules']:
    if r.get('health')!='ok': bad+=1
    if r['name']=='SqliProbeBurstFromSingleSource':
      print('   SqliProbeBurstFromSingleSource: health=%s state=%s'%(r['health'],r['state']))
print('   luat loi:',bad)
sys.exit(1 if bad else 0)
" || { echo "LOI: co luat khong health=ok"; exit 2; }

say "2. Danh moc alert-sink va ghi T0, roi gui loat $BURST SQLi probe"
BASE=$(docker logs ilfreight_alert_sink 2>&1 | wc -l)
T0=$(date +%s.%N); T0H=$(date -u +%H:%M:%SZ)
echo "   T0 = $T0H"
for i in $(seq 1 "$BURST"); do
  curl -s -o /dev/null "$WEB_URL/ports?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users%20--%20-"
done
echo "   da gui $BURST request SQLi toi /ports"

say "3. Cho canh bao SqliProbeBurstFromSingleSource toi alert-sink (toi da ${TIMEOUT}s)"
HIT=""; LAT=""
for i in $(seq 1 "$TIMEOUT"); do
  LINE=$(docker logs ilfreight_alert_sink 2>&1 | tail -n +$((BASE+1)) | grep "SqliProbeBurst" | head -1)
  if [ -n "$LINE" ]; then
    T1=$(date +%s.%N)
    LAT=$(pyq "print(f'{$T1-$T0:.1f}')")
    HIT="$LINE"; break
  fi
  sleep 1
done

say "4. Trang thai chuoi tai thoi diem canh bao"
NOW=$(date +%s)000000000
echo "   [Loki] gia tri bieu thuc theo nguon:"
curl -s -G "$LOKI/loki/api/v1/query" --data-urlencode 'query=sum by (client_ip) (count_over_time({container="ilfreight_web"} | json client_ip="client_ip", q="query", src="source" | src="apache_http_traffic" | q=~"(?i).*(%27|union.+select|%20or%20|information_schema).*" [1m]))' --data-urlencode "time=$NOW" | pyq "import sys,json;d=json.load(sys.stdin);[print('     client_ip=%s count=%s (nguong 5)'%(r['metric'].get('client_ip'),r['value'][1])) for r in d['data']['result']] or print('     (rong)')"
echo "   [Alertmanager] canh bao dang giu:"
curl -s "$AM/api/v2/alerts" | pyq "import sys,json;d=json.load(sys.stdin);[print('     %s | %s | client_ip=%s | %s'%(a['labels'].get('alertname'),a['labels'].get('severity'),a['labels'].get('client_ip','-'),a['status']['state'])) for a in d] or print('     (khong co)')"

say "5. Chung minh CHE DU LIEU (GDPR 5(1)(c)): bi mat khong di vao Loki nguyen van"
curl -s -o /dev/null "$WEB_URL/?debug=1&password=SuperSecret123&token=abcdef123456"
sleep 3
NOW=$(date +%s)000000000; AGO=$(( $(date +%s) - 60 ))000000000
LEAK=$(curl -s -G "$LOKI/loki/api/v1/query_range" --data-urlencode 'query={container="ilfreight_web"} |~ "SuperSecret123"' --data-urlencode "start=$AGO" --data-urlencode "end=$NOW" | pyq "import sys,json;print(len(json.load(sys.stdin)['data']['result']))")
RED=$(curl -s -G "$LOKI/loki/api/v1/query_range" --data-urlencode 'query={container="ilfreight_web"} |~ "REDACTED_CREDENTIAL"' --data-urlencode "start=$AGO" --data-urlencode "end=$NOW" | pyq "import sys,json;print(len(json.load(sys.stdin)['data']['result']))")
echo "   dong Loki con chua 'SuperSecret123' nguyen van : $LEAK  (phai = 0)"
echo "   dong Loki da thay bang [REDACTED_CREDENTIAL]     : $RED   (phai > 0)"

say "Tong ket"
RC=0
if [ -n "$HIT" ]; then
  echo "  [DAT ] Canh bao toi alert-sink. DO TRE PHAT HIEN = ${LAT} giay"
  echo "         $HIT"
else
  echo "  [LOI ] Khong co canh bao sau ${TIMEOUT}s"; RC=1
fi
if [ "${LEAK:-1}" -eq 0 ] && [ "${RED:-0}" -gt 0 ]; then
  echo "  [DAT ] Che du lieu: bi mat khong vao Loki nguyen van, da bi thay the"
else
  echo "  [LOI ] Che du lieu that bai (leak=$LEAK red=$RED)"; RC=1
fi
echo "  ket qua chung: $([ $RC -eq 0 ] && echo 'TAT CA DAT' || echo 'CO BUOC THAT BAI')"
exit "$RC"
