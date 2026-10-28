# Bài tập lớn DevSecOps, Nhóm 11, M26CQAT01-B

Đánh giá an toàn ứng dụng **InlaneWeb Logistics Portal** theo yêu cầu bảo vệ dữ
liệu cá nhân, với bốn cổng kiểm soát viết thành mã và chứng minh hai chiều.

Giảng viên: TS. Phạm Hoàng Duy. Hạn nộp 31/10/2026.

## Cấu trúc

```
app/InlaneWeb/        ung dung duoc danh gia, giu nguyen khiem khuyet lam doi tuong
policy/              Policy as Code, ba lop, kem unit test cho chinh chinh sach
  docker_security.rego        + _test.rego    lop build
  compose_security.rego       + _test.rego    lop trien khai
  repo_policy.rego            + _test.rego    lop quan tri
ci/                  Security as Code
  semgrep-policy-php.yml      8 luat P1 den P5 cho PHP
  semgrep-local-rules.yml     2 luat bi mat gan cung
  sonarqube.py, policy_guard.py, semgrep_report.py, validate_configs.py
tests/security/      Test-Driven Security, 6 phep kiem hanh vi
compliance/          Compliance as Code, 6 control InSpec tren container dang chay
fixtures/            cap doi chung: ban co y sai va ban da sua, cho tung lop
patches/             ban va, gom phan chua telemetry
evidence/            output da luu cua tung lenh kiem chung, co ghi ma thoat
sbom/                SBOM CycloneDX cua hai anh nen
.github/workflows/
  devsecops-gate.yml          day chuyen CO CHAN
  security-baseline.yml       ghi nhan trang thai, KHONG chan
docs/demo/           huong dan demo cho tung nguoi (KHONG nop cho thay)
report/              bao cao nop thay
```

## Bốn cổng, bốn lớp khác nhau

| Cổng | Công cụ | Lớp kiểm | Bắt được loại gì |
|---|---|---|---|
| Policy as Code | Conftest 0.71.1, OPA 1.21.1 | cấu hình trước khi triển khai | thiếu `USER`, bí mật trong compose, `docker.sock` ghi được, cổng mở ra mọi giao diện, nhánh không được bảo vệ |
| Security as Code | SonarQube Community, Semgrep 1.182.1 | mã nguồn tĩnh | chèn mã truy vấn, bí mật gán cứng, định danh từ client |
| Test-Driven Security | PHP, socket thô, mysqli | hành vi khi chạy | quyền được xoá không được thực thi, bản xuất lộ thông tin xác thực, phân quyền ngang |
| Compliance as Code | InSpec qua `docker inspect` | container đang chạy | khoảng lệch giữa cấu hình khai báo và thực tế |
| Chuỗi cung ứng | Trivy 0.70.0 | ảnh container | CVE của ảnh nền, SBOM |

## Trạng thái đo được của hệ thống

| Lớp | Đối tượng | Lỗi | Cảnh báo |
|---|---|---|---|
| Build | hai Dockerfile | 8 | 2 |
| Triển khai | ba tệp compose | 31 | 11 |
| Quản trị | nhánh `main` và `dev` | 2 | 0 |
| Mã nguồn | 23 tệp PHP | 36 phát hiện | |
| Chuỗi cung ứng | hai ảnh nền | 145 CVE mức HIGH và CRITICAL | |

`conftest verify` hiện 36 test, 36 đạt. Toàn bộ số liệu trên có tệp bằng chứng
tương ứng trong `evidence/`, mỗi tệp ghi lệnh đã chạy, kết quả, và mã thoát.

## Chứng minh hai chiều

| Lớp | Bản cố ý sai | Bản đã sửa |
|---|---|---|
| Dockerfile | 9 lỗi, exit 1 | 0 lỗi, 1 cảnh báo, exit 0 |
| Compose | 14 lỗi, exit 1 | 0 lỗi, 0 cảnh báo, exit 0 |
| Quản trị | 1 lỗi, exit 1 | 0 lỗi, exit 0 |
| Mã PHP | 8 phát hiện, exit 1 | 0 phát hiện, exit 0 |

## Hai cái bẫy mọi người phải biết

**Thiếu `--namespace`** thì Conftest in `0 tests, 0 failures` và trả mã thoát 0, tức
cổng xanh trong khi không đánh giá gì. Xem `evidence/05`.

**Thiếu `--error` cho Semgrep hoặc `--exit-code 1` cho Trivy** thì công cụ chỉ báo
cáo: 36 phát hiện vẫn exit 0, 119 CVE vẫn exit 0. Xem `evidence/17` và `evidence/23`.

Dây chuyền `devsecops-gate.yml` có một bước kiểm riêng để bảo đảm không cổng nào
chạy ở trạng thái 0 test.

## Chạy toàn bộ

```
conftest verify -p policy/
conftest test app/InlaneWeb/web/Dockerfile -p policy/ --namespace dockerfile
conftest test app/InlaneWeb/docker-compose.prod.yml -p policy/ --namespace compose
conftest test evidence/api/branch-main-slim.json -p policy/ --namespace repo
semgrep --metrics off --error --config ci/semgrep-policy-php.yml app/InlaneWeb/web/src
trivy image --severity HIGH,CRITICAL --exit-code 1 php:8.2-apache
bash tests/security/run.sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/compliance:/profile" chef/inspec exec /profile \
  --input container=ilfreight_web --chef-license=accept-silent
```

Trên Windows, đặt `PYTHONIOENCODING=utf-8` trước mỗi lệnh Semgrep.

## Căn cứ tài liệu

Yêu cầu chính thức của thầy gồm bảy điểm, hạn 31/10. Phương pháp lấy từ ba lab
trong đường dẫn môn học: `Policy_as_code_Lab ConfTest.docx`,
`SonarQube and juice shop Lab.docx`, `Juice_Shop_Telemetry_Lab_Guide.docx`, cùng
`Hands-on_guide_updated.docx` với 7 phase và 5 mốc chấm. Khung phân tích lấy từ
`3.Threat Modeling and Risk Management in DevSecOps Architecture.docx`.
