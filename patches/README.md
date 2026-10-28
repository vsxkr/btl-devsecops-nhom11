# Bản vá: khiếm khuyết, cổng phát hiện, cách sửa, chủ sở hữu

Nhánh `main` giữ ứng dụng ở trạng thái **có khiếm khuyết**, vì đó là đối tượng
được đánh giá. Nhánh `patched` là bản vá. Mỗi dòng dưới đây có cổng phát hiện
tương ứng và một tệp bằng chứng.

## Đợt 1, đã vá

| # | Khiếm khuyết | Tệp | Cổng phát hiện | Điều khoản | Chủ sở hữu |
|---|---|---|---|---|---|
| 1 | Nhật ký ghi nguyên văn câu lệnh và thông điệp lỗi của MariaDB | `lib/logger.php` | TDS-6 | GDPR 5(1)(c), CWE-532 | Mai |
| 2 | Lỗi CSDL đi ra phản hồi HTTP | `lib/db.php` | TDS-5, `policy-p4-error-detail-to-response` | GDPR 32 | Hải |
| 3 | Bí mật có giá trị dự phòng là chuỗi hằng | `lib/db.php` | `policy-p3-hardcoded-credential-fallback` | GDPR 32, PCI 8.6.2 | Mạnh |
| 4 | Ứng dụng kết nối CSDL bằng `root` | `lib/db.php`, compose, `init.sql.template` | `policy-p3-privileged-db-account-default`, luật CREDENTIALS | GDPR 32 | Mạnh |
| 5 | Mật khẩu người dùng lưu dạng rõ | `init.sql.template`, `login.php` | TDS-4 | GDPR 32, 5(1)(f) | Mạnh |
| 6 | Vượt xác thực bằng chèn mã tại trang đăng nhập | `login.php` | `policy-p4-sql-injection` | GDPR 32 | Hải |
| 7 | Không có sự kiện kiểm toán khi đăng nhập thất bại | `logger.php`, `login.php` | luật tương quan Loki | GDPR 32, OWASP A09 | Mai |
| 8 | Yêu cầu xoá không xoá gì | `privacy_erase.php` | TDS-1 | GDPR 17 | Mai |
| 9 | Bản xuất trả về `password`, `api_key`, `remember_token` | `privacy_export.php` | TDS-2 | GDPR 15, 5(1)(c) | Đức Anh |
| 10 | Người này đọc được dữ liệu người khác | `privacy_export.php` | TDS-3 | GDPR 5(1)(f) | Đức Anh |
| 11 | `display_errors = On`, cookie phiên không có `HttpOnly` | `web/php.ini` | TDS-5 | GDPR 32 | Hải |
| 12 | `secure_file_priv = ""` và `local_infile = 1` cho phép đọc ghi tệp qua SQL | `db/lab.cnf` | kiểm bằng tay | GDPR 32 | Đức Anh |
| 13 | Entrypoint mở quyền ghi `1777` cho thư mục chia sẻ | `db/entrypoint.sh` | kiểm bằng tay | GDPR 32 | Đức Anh |
| 14 | `root@%` với `ALL PRIVILEGES` và quyền `FILE` | `init.sql.template` | luật CREDENTIALS | GDPR 32 | Mạnh |
| 15 | Hai Dockerfile thiếu `USER`, `HEALTHCHECK`, nhãn OCI | `web/Dockerfile`, `db/Dockerfile` | `docker_security.rego` | CIS Docker 4.1, 4.6 | Đức Anh |
| 16 | Compose thiếu `cap_drop`, `no-new-privileges`, `read_only`, ảnh không ghim | `docker-compose.yml` | `compose_security.rego` | CIS Docker 5.x | Đức Anh |
| 17 | Cảnh báo gửi tới `alertmanager:9093` không tồn tại | `patches/monitoring/` | kiểm bằng tay | GDPR 33, 34 | Mai |
| 18 | Không có chặng che dữ liệu trong Promtail | `patches/monitoring/promtail-config.hardened.yml` | TDS-6 | GDPR 5(1)(c) | Mai |
| 19 | Luật cảnh báo không tương quan theo nguồn | `patches/monitoring/loki-alert-rules.hardened.yml` | kiểm bằng tay | GDPR 32 | Mai |
| 20 | Nhánh `main` và `dev` không được bảo vệ | thiết lập GitHub | `repo_policy.rego` | GDPR 32 | Nam |
| 21 | Cổng chất lượng bị tắt bằng biểu thức luôn cho `false` | `.github/workflows/devsecops-gate.yml` | so sánh mã thoát | GDPR 32 | Nam |
| 22 | Kết thúc dòng CRLF làm container không khởi động được trên Windows | `.gitattributes` | chạy thật | nguyên tắc tái lập | Nam |

## Đợt 2, chưa vá, có chủ đích

Mười điểm chèn mã truy vấn còn lại trong các trang nghiệp vụ:

| Tệp | Loại | Chủ sở hữu |
|---|---|---|
| `pages/ports.php` | SELECT, UNION | Hải |
| `pages/news.php` | SELECT | Hải |
| `pages/port_detail.php` | SELECT | Hải |
| `pages/track_api.php` | SELECT, time-based | Hải |
| `pages/account.php` | SELECT | Mai |
| `pages/account_update.php` | UPDATE, nâng quyền | Đức Anh |
| `pages/comment_add.php` | INSERT | Mai |
| `pages/comment_delete.php` | DELETE | Mai |
| `pages/shipment_detail.php` | SELECT, thiếu kiểm quyền sở hữu | Hải |
| `pages/report_download.php` | SELECT, đọc tệp | Đức Anh |
| `pages/admin_console.php` | stacked query | Đức Anh |

**Lý do hoãn có chủ đích, không phải bỏ sót.** `TDS-6` khẳng định luồng nhật ký
không chứa nguyên văn câu lệnh. Để khẳng định được điều đó, phải có một truy vấn
thất bại thật. Nếu vá hết mười điểm trên trong cùng một đợt thì không còn truy
vấn nào lỗi, và phép kiểm mất đối tượng đo: nó sẽ báo đạt vì không có gì để kiểm,
đúng loại đạt giả mà chúng tôi đã gặp ba lần khi dựng bộ test.

Trình tự đúng là vá tầng kiểm soát trước, chứng minh tầng đó hoạt động bằng một
khiếm khuyết còn lại, rồi mới vá nốt các khiếm khuyết đó ở đợt sau, lúc này
`TDS-6` được thay bằng một phép kiểm trực tiếp trên hàm ghi nhật ký.

Cách chuyển sang câu lệnh chuẩn bị trước đã có sẵn trợ giúp trong `lib/db.php`:
`query_p()`, `query_one_p()`, `exec_write_p()`, và mẫu đầy đủ ở
`fixtures/php/profile_update.patched.php`.

## Hai chỗ cố tình giữ nguyên

`pages/admin_console.php` dùng `mysqli_multi_query`, và `pages/track_api.php` cố
ý nuốt lỗi truy vấn. Cả hai được giữ để báo cáo nói về chúng: điểm thứ nhất cho
thấy một API cho phép nhiều câu lệnh trong một lời gọi mở ra lớp tấn công khác,
điểm thứ hai cho thấy **một endpoint nuốt lỗi thì không công cụ nào và không phép
kiểm nào dựa trên phản hồi phát hiện được nó**. Chúng tôi phát hiện điều thứ hai
khi chọn sai endpoint làm phép thăm dò cho `TDS-5`.
