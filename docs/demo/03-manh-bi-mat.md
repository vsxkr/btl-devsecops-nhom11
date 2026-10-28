# Đào Xuân Mạnh, B26CHAT026

**Chính sách:** P3, quản lý bí mật và an toàn phiên
**Nhóm lỗi:** code và triển khai
**Pha DevSecOps:** Code, Build
**Điều khoản:** GDPR Điều 32 và Điều 5(1)(f), PCI DSS v4.0.1 mục 8.6.2

## Vấn đề

| Nơi | Nội dung |
|---|---|
| `lib/db.php:19` | `getenv('DB_PASS')` có giá trị dự phòng là chuỗi hằng `password` |
| `lib/db.php:18` | `getenv('DB_USER')` có giá trị dự phòng là `root`, ứng dụng kết nối bằng tài khoản đặc quyền |
| `docker-compose.yml:17` và `prod.yml:15` | `MYSQL_ROOT_PASSWORD: password`, dạng **từ điển** |
| `docker-compose.yml:56` và `prod.yml:50` | `DB_PASS: password`, dạng **từ điển** |
| `docker-compose.monitoring.yml:46` | mật khẩu Grafana, dạng **danh sách** |
| `db/init.sql:11` | tạo `root@%` kèm `GRANT ALL` và quyền `FILE` |
| `users.password` | mật khẩu người dùng lưu dạng rõ |

## Cách phát hiện, chiều đỏ

```
conftest test app/InlaneWeb/docker-compose.prod.yml -p policy/ --namespace compose
```

Kết quả mong đợi, 9 lỗi, trong đó:

```
FAIL - CREDENTIALS: service 'db' hard-codes secret 'MYSQL_ROOT_PASSWORD' ...
FAIL - CREDENTIALS: service 'web' hard-codes secret 'DB_PASS' ...
FAIL - LEAST-PRIVILEGE: service 'web' connects to the database as privileged account 'root' ...
exit=1
```

Và ở tầng mã:

```
PYTHONIOENCODING=utf-8 semgrep --metrics off --error \
  --config ci/semgrep-policy-php.yml app/InlaneWeb/web/src/lib/db.php
# policy-p3-hardcoded-credential-fallback
# policy-p3-privileged-db-account-default
```

## Luật mở rộng của Mạnh, và lý do nó cần tồn tại

Compose cho phép `environment` ở **hai dạng**: từ điển và danh sách. Luật Rego mẫu
trong tài liệu môn học chỉ xử lý dạng danh sách, nên áp nguyên vào InlaneWeb sẽ
**bỏ sót mật khẩu root của cơ sở dữ liệu**. Đoạn mã Python trong bản báo cáo cũ của
nhóm thì ngược lại, chỉ xử lý dạng từ điển và **vỡ với AttributeError** khi gặp
dạng danh sách. Luật của Mạnh xử lý đúng cả hai.

Thang điểm mốc 1 của tài liệu yêu cầu sinh viên **tự thêm một luật mới**. Đây là
luật đó, và nó có lý do kỹ thuật thật chứ không phải thêm cho đủ số.

Một điểm cần nói trung thực: phiên bản đầu của luật này dùng regex đòi `password`
hoặc `passwd` nên **bỏ sót khoá `DB_PASS`**. Lỗi đó chỉ lộ ra khi đối chiếu với sự
thật đã biết trước, vì một chính sách khớp rỗng trông giống hệt một chính sách đạt.
Sau khi sửa sang khớp theo biên từ, `docker-compose.yml` tăng từ 7 lên 9 lỗi, và có
thêm hai test chứng minh không báo sai trên `BYPASS_CACHE` và `PASSTHROUGH_MODE`.

## Chiều xanh

```
conftest test fixtures/docker-compose.hardened.yml -p policy/ --namespace compose
# 13 tests, 13 passed, 0 warnings, 0 failures   exit=0
```

Bản hardened tiêm bí mật lúc triển khai qua biến môi trường và dùng tài khoản
`ilf_app` thay cho `root`.

## Bản vá

```
-- db/init.sql: tai khoan rieng cho ung dung, quyen toi thieu
CREATE USER IF NOT EXISTS 'ilf_app'@'%' IDENTIFIED BY '...';
GRANT SELECT, INSERT, UPDATE, DELETE ON ilfreight.* TO 'ilf_app'@'%';
-- khong cap FILE, khong cap GRANT OPTION, khong cap quyen tren CSDL dev
```

Mật khẩu người dùng chuyển sang `password_hash()` với `PASSWORD_DEFAULT`, và
`TDS-4` là phép kiểm cho việc đó.

## Điều cổng của Mạnh không chứng minh được

**Trivy, một công cụ quét bí mật phổ dụng, báo "No issues detected" trên cả bốn tệp
nói trên**, kể cả mật khẩu Grafana có entropy cao. Lý do là bộ luật của nó nhắm
định dạng của nhà cung cấp cụ thể như khoá AWS hay token GitHub, không nhắm bí mật
dạng chung. Đây là điểm đáng nói với thầy: chính sách riêng của tổ chức bắt được cả
bốn, công cụ phổ dụng bắt được không nơi nào.

Ngoài ra chính sách chỉ thấy bí mật **trong tệp**. Nó không biết mật khẩu đó đã bị
dùng ở đâu, đã được xoay vòng chưa, hay đã lộ trong lịch sử Git chưa.
