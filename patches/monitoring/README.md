# Cụm giám sát đã vá — nơi triển khai và các lỗi cấu hình đã sửa khi chạy thật

Các tệp đã vá **chạy được** nằm tại nơi triển khai, không phải ở đây:

| Vai trò | Đường dẫn triển khai (nơi compose mount) |
|---|---|
| Compose đã vá, một gốc thư mục | `app/InlaneWeb/docker-compose.monitoring.hardened.yml` |
| Promtail (chỉ che dữ liệu, chỉ bám container web) | `app/InlaneWeb/monitoring/promtail/promtail-config.hardened.yml` |
| Luật Loki (hai chuỗi, tương quan theo nguồn) | `app/InlaneWeb/monitoring/loki/rules-hardened/fake/alert-rules.yml` |
| Alertmanager | `app/InlaneWeb/monitoring/alertmanager/alertmanager.yml` |
| Alert sink | `app/InlaneWeb/monitoring/alert-sink/alert-sink.py` |

Các bản trong thư mục này là bản sao để đối chiếu. Bằng chứng chạy đầu-cuối ở
`evidence/35-chuoi-phat-hien-do-tre.txt`, chạy lại bằng
`bash tests/security/detect_latency.sh --up`.

## Ba lỗi cấu hình chỉ lộ ra khi chạy thật, không khi đọc tệp

Bản dàn ban đầu "trông đúng" nhưng chuỗi không khép kín. Ba lỗi dưới đây minh
hoạ đúng luận điểm của môn học: **một phép kiểm không chạm được vào thứ cần đo
trông giống hệt một phép kiểm đạt.**

1. **Stage `labels` của Promtail không đặt giá trị hằng.** `labels: {k: v}` đọc
   khoá `v` trong map đã trích chứ không gán chuỗi `v`. Mọi nhãn phân loại tấn
   công vì thế không bao giờ được tạo, và nhãn giá-trị-rỗng bị Loki loại bỏ làm
   stream rỗng nhãn → lỗi 400 "at least one label pair is required per stream".
   Sửa: bỏ gắn nhãn ở Promtail, chuyển toàn bộ tương quan sang luật Loki bằng
   `| json` lúc truy vấn. Promtail chỉ còn một việc: **che dữ liệu**.

2. **Stage `replace` của Promtail chỉ chạy khi regex có nhóm bắt**, và nó chỉ
   thay **nhóm bắt**, giữ nguyên phần còn lại của match. Biểu thức không nhóm là
   no-op (không che gì); tham chiếu `$1`/`${1}`/`{{ .ten }}` trong chuỗi thay
   thế đều không hoạt động như mong đợi ở Promtail 3.0. Sửa: bọc **giá trị** cần
   xoá trong một nhóm bắt, thay bằng chuỗi hằng — khoá được giữ, giá trị bị che.

3. **`relabel` với `action: keep` không ngăn Promtail mở luồng đọc log của mọi
   container.** Nó vẫn đọc log của chính nó (đệ quy) và của Loki (log Loki chứa
   đúng chuỗi lỗi, tạo vòng tự nuôi). Sửa: lọc ngay tại Docker API bằng
   `docker_sd_configs.filters` để chỉ khám phá container ứng dụng.

Lỗi (1) và (2) đều do hành vi của Promtail khác tài liệu tưởng, lỗi (3) do
`keep` lọc muộn hơn mức cần. Cả ba chỉ phát hiện khi dựng cụm thật, gửi tấn công
thật, và kiểm bằng log mẫu trước — đúng quy trình của lab Telemetry.

## Hai tmpfs cần quyền ghi (Docker Desktop)

- `/loki/rules-temp` phải đặt `mode: 0777` (long-form tmpfs) vì Loki chạy uid
  10001 còn tmpfs mặc định thuộc root.
- Promtail không-root đọc `/var/run/docker.sock` bằng `group_add` khớp nhóm chủ
  socket: trên Docker Desktop là gid **0**, trên Linux thật là nhóm `docker`.
