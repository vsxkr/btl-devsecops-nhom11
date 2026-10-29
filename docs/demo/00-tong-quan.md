# Phân chia công việc và hướng dẫn demo, Nhóm 11

> **Tệp này và toàn bộ thư mục `docs/demo/` KHÔNG nộp cho thầy.** Đây là tài liệu
> nội bộ để từng người biết mình demo gì và chạy lệnh nào.

## Căn cứ phân chia

Yêu cầu của thầy đòi mỗi thành viên chỉ ra **một** vấn đề an toàn, kèm cách phát
hiện, cách xử lý, điều khoản bị vi phạm, pha DevSecOps, và một đoạn mã demo. Tài
liệu môn học (`SonarQube and juice shop Lab.docx`, mục 2) đã có sẵn bộ **năm chính
sách P1 đến P5**, nên nhóm chia theo đúng bộ đó: năm chính sách, năm người. Cách
này tự nhiên thoả điều kiện "tối thiểu 2 nhóm lỗi: code và triển khai/vận hành",
vì P1 đến P4 là lỗi mã còn P5 cùng các luật cấu hình là lỗi triển khai và vận hành.

## Bảng phân chia

| Thành viên | Mã học viên | Chính sách | Vấn đề | Nhóm lỗi | Pha DevSecOps |
|---|---|---|---|---|---|
| Nguyễn Giang Nam (trưởng nhóm) | B26CHAT030 | Quản trị + P3 | Thiếu kiểm soát thay đổi mã nguồn và cổng chất lượng bị tắt | vận hành | Plan, Code |
| Nguyễn Đình Hải | B26CHAT010 | P4 | Chèn mã truy vấn làm lộ dữ liệu cá nhân | code | Build, Test |
| Đào Xuân Mạnh | B26CHAT026 | P3 | Bí mật gán cứng, mật khẩu dạng rõ, tài khoản CSDL đặc quyền | code và triển khai | Code, Build |
| Lê Đức Anh | B26CHAT003 | P1 và P2 | Cấu hình triển khai mất an toàn và phân quyền ngang | triển khai | Release, Deploy |
| Nguyễn Phương Mai | B26CHAT025 | P5 | Rò rỉ dữ liệu cá nhân qua nhật ký, thiếu sự kiện kiểm toán, cảnh báo không tới đích | vận hành | Monitor |

Tên và mã học viên lấy theo danh sách thầy gửi trong `yeucau-bai-tap-nhom.txt`.

## Khuôn demo chung, ai cũng theo đúng bốn bước này

Tài liệu môn học đánh giá theo **chứng minh hai chiều**. Thang điểm mốc 1 ghi
*"correctly fails the insecure Dockerfile and compose files"* và mốc 5 ghi
*"explain each control and a deliberate failure case"*. Vì vậy mỗi người demo:

1. **Chỉ ra khiếm khuyết trên mã thật**, nói rõ tệp và dòng.
2. **Chạy công cụ phát hiện của mình**, cho thầy thấy nó **báo lỗi** và **mã thoát khác 0**.
3. **Chạy lại trên bản đã sửa**, cho thấy nó **im lặng** và **mã thoát 0**.
4. **Nói điều công cụ của mình không chứng minh được**, và ai trong nhóm bù phần đó.

Bước 4 là bước nhiều nhóm bỏ, nhưng tài liệu môn học bắt buộc có mục
"What static analysis cannot prove".

## Chuẩn bị một lần, trước buổi demo

```bash
# 1. Conftest, bản ghim đúng phiên bản lab đã kiểm
curl -sSL https://github.com/open-policy-agent/conftest/releases/download/v0.71.1/conftest_0.71.1_Windows_x86_64.zip -o conftest.zip
# kiểm hash trước khi dùng, hash công bố: 34d623334b5e7ed4465bf62a4cb3b092684859cd3d224bbd390925a0852b922a

# 2. Semgrep trong môi trường riêng, vì bản cài toàn cục trên máy Mạnh bị xung đột OpenTelemetry
python -m venv .venv-semgrep
.venv-semgrep/Scripts/python -m pip install semgrep==1.182.1

# 3. Trivy đã có, kiểm: trivy --version  ->  0.70.0

# 4. Docker Desktop phải chạy cho phần TDS và InSpec
```

Luôn đặt `PYTHONIOENCODING=utf-8` trước mỗi lệnh Semgrep trên Windows, nếu không
Semgrep sẽ trả mã thoát 2 kèm `Received output encoding error`.

## Lệnh chạy toàn bộ cổng, dùng khi muốn xem tổng thể

```bash
conftest verify -p policy/                                    # 36 test cho chính chính sách
conftest test app/InlaneWeb/web/Dockerfile -p policy/ --namespace dockerfile
conftest test app/InlaneWeb/docker-compose.prod.yml -p policy/ --namespace compose
conftest test evidence/api/branch-main-slim.json -p policy/ --namespace repo
semgrep --metrics off --error --config ci/semgrep-policy-php.yml app/InlaneWeb/web/src
trivy image --severity HIGH,CRITICAL --exit-code 1 php:8.2-apache
bash tests/security/run.sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v "$PWD/compliance:/profile" \
  chef/inspec exec /profile --input container=ilfreight_web --chef-license=accept-silent
```

**Luôn truyền `--namespace`.** Thiếu cờ đó Conftest in `0 tests, 0 failures` và trả
mã thoát 0, tức trông như đạt trong khi không đánh giá gì. Xem `evidence/05`.

**Luôn truyền `--error` cho Semgrep và `--exit-code 1` cho Trivy.** Mặc định cả hai
chỉ báo cáo và trả 0. Xem `evidence/17` và `evidence/23`.

## Bằng chứng đã có sẵn trong `evidence/`

26 tệp, mỗi tệp ghi lệnh đã chạy, kết quả, và mã thoát. Dùng trực tiếp khi viết
báo cáo, không cần chạy lại.

## Hai lần chạy quét trên GitHub Actions

| Nhánh | Run ID | Commit | Trạng thái |
|---|---|---|---|
| `main` (khiếm khuyết) | `40748974196` | `94004f3` | thất bại ở cổng chất lượng (ERROR), 25 vấn đề Sonar, 0 lỗ hổng, 64 phát hiện Semgrep |
| `patched` (đã vá) | `40748974200` | `0c9cdfd` | thất bại ở cổng chất lượng (ERROR), 27 vấn đề Sonar, 0 lỗ hổng, 46 phát hiện Semgrep |

Cả hai đều dừng tại cổng chất lượng SonarQube vì `reliability_rating` bằng 3, không phải vì an toàn. Số liệu lấy từ artifact `evidence-security-as-code` của mỗi lần chạy.

Artifact của bốn run đầu còn tải được tới 18 đến 21 tháng 11. Đã tải sẵn vào
`evidence/` của phiên làm việc.
