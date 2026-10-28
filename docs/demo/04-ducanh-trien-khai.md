# Lê Đức Anh, B26CHAT003

**Chính sách:** P1 least privilege và P2 RBAC, ở tầng triển khai
**Nhóm lỗi:** triển khai
**Pha DevSecOps:** Release, Deploy
**Điều khoản:** GDPR Điều 32 và Điều 5(1)(f), CIS Docker Benchmark 5.3, 5.4, 5.12, 5.25, 5.31

## Vấn đề

| Nơi | Nội dung |
|---|---|
| `docker-compose.monitoring.yml:43` | Grafana công bố cổng ở `0.0.0.0:3000`, mở ra mọi giao diện |
| `docker-compose.monitoring.yml:73` | autoheal mount `/var/run/docker.sock` **ghi được**, tương đương quyền root trên máy chủ |
| `docker-compose.monitoring.yml:26` | promtail chạy bằng `user: root` |
| mọi dịch vụ, cả ba tệp compose | không có `cap_drop`, không có `security_opt: no-new-privileges`, không có `read_only` |
| `web/Dockerfile`, `db/Dockerfile` | không có `USER`, không có `HEALTHCHECK`, thiếu hai nhãn OCI provenance |
| `docker-compose.monitoring.yml:64` | autoheal dùng ảnh `:latest` |
| `pages/privacy_export.php:30` | lấy `user_id` từ query string nên người này đọc được dữ liệu người khác |

## Cách phát hiện, chiều đỏ

```
conftest test app/InlaneWeb/docker-compose.monitoring.yml -p policy/ --namespace compose
# 20 tests, 0 passed, 7 warnings, 13 failures   exit=1

conftest test app/InlaneWeb/web/Dockerfile -p policy/ --namespace dockerfile
# 11 tests, 6 passed, 1 warning, 4 failures     exit=1
```

Và trên container đang chạy, đây là Compliance as Code:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/compliance:/profile" chef/inspec exec /profile \
  --input container=ilfreight_web --chef-license=accept-silent
```

Sáu control: không chạy root, không đặc quyền cộng `no-new-privileges` cộng
`cap_drop ALL`, mọi cổng buộc loopback, không có bí mật trong biến môi trường,
không mount docker.sock, hệ tệp gốc chỉ đọc.

Phần phân quyền ngang chứng minh bằng test hành vi:

```
bash tests/security/run.sh
# TDS-3  GDPR Art. 5(1)(f)  khong doc duoc du lieu cua chu the khac
```

## Chiều xanh

```
conftest test fixtures/docker-compose.hardened.yml -p policy/ --namespace compose
# 13 tests, 13 passed, 0 warnings, 0 failures   exit=0

conftest test fixtures/Dockerfile.hardened -p policy/ --namespace dockerfile
# 11 tests, 10 passed, 1 warning, 0 failures    exit=0

conftest test patches/monitoring/docker-compose.monitoring.hardened.yml -p policy/ --namespace compose
# 13 tests, 10 passed, 3 warnings, 0 failures   exit=0
```

Ba cảnh báo còn lại ở bản monitoring đã sửa là **chủ ý**, và phải giải thích được:
promtail cùng autoheal cần `docker.sock` ở chế độ chỉ đọc để làm việc của chúng, và
autoheal không có endpoint HTTP nên không đặt được healthcheck. Chính sách phân biệt
đúng giữa mount ghi được là **lỗi** và mount chỉ đọc là **cảnh báo**.

## Bản cố ý sai, dùng để chứng minh luật thật sự bắt được

```
conftest test fixtures/docker-compose.insecure.yml -p policy/ --namespace compose
# 18 tests, 0 passed, 4 warnings, 14 failures   exit=1

conftest test fixtures/Dockerfile.insecure -p policy/ --namespace dockerfile
# 11 tests, 2 passed, 0 warnings, 9 failures    exit=1
```

Chín vi phạm của `Dockerfile.insecure` phủ cả năm nhóm luật, trong đó có dạng
`5432/tcp` để chứng minh luật xử lý được hậu tố giao thức, và `20-25` để chứng minh
luật xử lý được dải cổng. Đây đúng là bài tập ở mục 2.2 của handout.

## Điều cổng của Đức Anh không chứng minh được

**Chính sách đọc tệp cấu hình, không đọc thực tế.** Một tệp compose có thể khai báo
`cap_drop: [ALL]` nhưng người vận hành lại chạy container bằng tay với tham số khác.
Đó là lý do cần Compliance as Code: InSpec đọc `docker inspect` của container đang
chạy, nên bắt được khoảng lệch giữa khai báo và thực tế.

**Trivy chỉ quét được Dockerfile.** Danh sách `misconfig-scanners` của nó gồm
azure-arm, cloudformation, dockerfile, helm, kubernetes, terraform, ansible, **không
có docker-compose**. Trên hai Dockerfile nó tìm đúng 2 lỗi mỗi tệp, so với 4 lỗi của
chính sách nhóm, và trên ba tệp compose nó không tìm được gì vì không đọc. Đây là lý
do bộ luật compose của nhóm cần tồn tại.
