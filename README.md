# Bài tập lớn DevSecOps, Nhóm 11, M26CQAT01-B

Đánh giá an toàn ứng dụng **InlaneWeb Logistics Portal** theo yêu cầu bảo vệ dữ
liệu cá nhân, bằng một pipeline năm stage có cổng chặn thật, mọi cổng viết
thành mã và chứng minh hai chiều, và mọi cổng truy được về một điều khoản chính
sách của doanh nghiệp.

Giảng viên: TS. Phạm Hoàng Duy. Hạn nộp 31/10/2026.

## Cấu trúc

```
app/InlaneWeb/        ung dung duoc danh gia, giu nguyen khiem khuyet lam doi tuong
policy/              Chinh sach va Policy as Code
  00-chinh-sach-attt.md       chinh sach ATTT doanh nghiep, CS-01 den CS-08
  exceptions.json             ngoai le co thoi han, theo CS-08
  docker_security.rego        + _test.rego    lop build
  compose_security.rego       + _test.rego    lop trien khai
  repo_policy.rego            + _test.rego    lop quan tri
ci/                  Security as Code
  semgrep-policy-php.yml      8 luat P1 den P5 cho PHP
  semgrep-local-rules.yml     2 luat bi mat gan cung
  sonarqube.py, policy_guard.py, semgrep_report.py, validate_configs.py
  check_branch_payload.py     kiem cau truc phan hoi API truoc khi danh gia
  check_exceptions.py         thi hanh CS-08, ngoai le het han lam stage 1 do
  cve_watch.py                theo doi CVE moi sau khi phat hanh
tests/security/      Test-Driven Security, 6 phep kiem hanh vi
compliance/          Compliance as Code, 7 control InSpec tren container dang chay
fixtures/            cap doi chung: ban co y sai va ban da sua, cho tung lop
patches/             ban va, gom phan chua telemetry
evidence/            output da luu cua tung lenh kiem chung, co ghi ma thoat
sbom/                SBOM CycloneDX cua hai anh nen
.github/workflows/
  devsecops-gate.yml          pipeline nam stage, CO CHAN, co stage CD
  auto-remediate.yml          vong doi quy tac, tu dong mo pull request va CVE
  security-baseline.yml       ghi nhan trang thai, KHONG chan
docs/demo/           huong dan demo cho tung nguoi (KHONG nop cho thay)
report/              bao cao nop thay
```

## Năm lớp kiểm soát, năm đối tượng khác nhau

| Cổng | Công cụ | Lớp kiểm | Bắt được loại gì |
|---|---|---|---|
| Policy as Code | Conftest 0.71.1, OPA 1.21.1 | cấu hình trước khi triển khai | thiếu `USER`, bí mật trong compose, `docker.sock` ghi được, cổng mở ra mọi giao diện, nhánh không được bảo vệ |
| Security as Code | SonarQube Community, Semgrep 1.182.1 | mã nguồn tĩnh | chèn mã truy vấn, bí mật gán cứng, định danh từ client |
| Test-Driven Security | PHP, socket thô, mysqli | hành vi khi chạy | quyền được xoá không được thực thi, bản xuất lộ thông tin xác thực, phân quyền ngang |
| Compliance as Code | InSpec qua `docker inspect` | container đang chạy | khoảng lệch giữa cấu hình khai báo và thực tế |
| Chuỗi cung ứng | Trivy 0.70.0 | ảnh container | CVE của ảnh nền, SBOM |
| CD, phát hành có xác minh | docker compose, InSpec | môi trường đích sau khi phát hành | sai lệch phát sinh trong chính quá trình phát hành |

## Trạng thái đo được của hệ thống

| Lớp | Đối tượng | Lỗi | Cảnh báo |
|---|---|---|---|
| Build | hai Dockerfile | 8 | 2 |
| Triển khai | ba tệp compose | 31 | 11 |
| Quản trị | nhánh `main` | 1 trước khi bật bảo vệ nhánh, 0 sau khi bật | 0 |
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

## Ba cái bẫy mọi người phải biết

**Thiếu `--namespace`** thì Conftest in `0 tests, 0 failures` và trả mã thoát 0, tức
cổng xanh trong khi không đánh giá gì. Xem `evidence/05`.

**Thiếu `--error` cho Semgrep hoặc `--exit-code 1` cho Trivy** thì công cụ chỉ báo
cáo: 36 phát hiện vẫn exit 0, 119 CVE vẫn exit 0. Xem `evidence/17` và `evidence/23`.

**Thiếu `shell: bash` cho một bước có dấu pipe** thì mã thoát của cả chuỗi lệnh là
mã thoát của `tee` và luôn bằng 0. Ba cổng stage 1 và hai cổng stage 4 từng báo
thành công trong khi tệp kết quả của chính chúng chứa dòng FAIL, trong run
`40748974196` và `40748974200`. Sau khi sửa, cùng mã nguồn cho kết quả trái
ngược trong run `41810794218`. Xem bao cao muc 4.2.

Pipeline `devsecops-gate.yml` có một bước kiểm riêng để bảo đảm không cổng nào
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
