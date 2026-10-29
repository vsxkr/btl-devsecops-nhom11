# Nguyễn Đình Hải, B26CHAT010

**Chính sách:** P4, kiểm tra đầu vào và vệ sinh lỗi
**Nhóm lỗi:** code
**Pha DevSecOps:** Build, Test
**Điều khoản:** GDPR Điều 32, PCI DSS v4.0.1 mục 6.2.4, OWASP A03:2021

## Vấn đề

Dữ liệu từ client được nối thẳng vào chuỗi truy vấn tại 12 vị trí. Hai ví dụ nói
rõ nhất:

| Tệp | Dòng | Nội dung |
|---|---|---|
| `pages/login.php` | 19 | `WHERE username = '$username' AND password = '$password'` |
| `pages/shipment_detail.php` | 15 | `WHERE id = $id`, và **không có phép kiểm quyền sở hữu** dù bảng `shipments` có cột `customer_id` |

Kèm theo, `lib/db.php` in nguyên `mysqli_error()` ra phản hồi HTTP, và
`web/php.ini:6` đặt `display_errors = On`, nên lỗi cú pháp SQL quay về cho client,
đủ để khai thác theo kiểu error-based.

## Cách phát hiện, chiều đỏ

```
PYTHONIOENCODING=utf-8 semgrep --metrics off --error \
  --config ci/semgrep-policy-php.yml app/InlaneWeb/web/src
```

Kết quả mong đợi: **36 phát hiện**, trong đó `policy-p4-sql-injection` 12 lần và
`policy-p4-error-detail-to-response` 4 lần, `exit=1`.

Trên cặp fixture:

```
semgrep --metrics off --error --config ci/semgrep-policy-php.yml \
  fixtures/php/profile_update.vulnerable.php    # 8 phat hien, exit=1
semgrep --metrics off --error --config ci/semgrep-policy-php.yml \
  fixtures/php/profile_update.patched.php       # 0 phat hien, exit=0
```

## Chiều xanh của test hành vi

```
bash tests/security/run.sh
```

`TDS-5` khẳng định phản hồi lỗi không được chứa `SQL Error`, `mysqli`, `syntax`.
Trên mã hiện tại test này **thất bại**, đó là điều đúng ở bước này.

## Bản vá

Dùng câu lệnh chuẩn bị trước với tham số ràng buộc, và trả về cho client một thông
điệp chung kèm mã sự kiện. Mẫu đầy đủ ở `fixtures/php/profile_update.patched.php`:

```
$read = mysqli_prepare($conn, 'SELECT id, username, email FROM users WHERE id = ?');
mysqli_stmt_bind_param($read, 'i', $userId);
```

Với `php.ini`, đặt `display_errors = Off` và `log_errors = On`.

## Điều cổng của Hải không chứng minh được

**Semgrep Community Edition không theo được luồng dữ liệu qua ranh giới hàm.** Lab
đã đo đúng giới hạn này với trường hợp một hàm phụ trả về `req.body`. Trong
InlaneWeb, đường `$_GET` rồi `$sql` rồi `query($sql)` rồi
`InlaneLogger::logSqlError($sql)` đi qua hai hàm, nên phần rò rỉ sang nhật ký không
chứng minh được bằng taint. Đó là phần của Mai.

Và quan trọng hơn: **việc thiếu phép kiểm quyền sở hữu không có mẫu cú pháp nào thể
hiện được.** Semgrep thấy định danh đến từ client, nhưng không thể biết lẽ ra phải
có một phép kiểm mà không có. Chứng minh phần đó là `TDS-3` của Đức Anh.

## Lưu ý về run

Số liệu SQL injection lấy từ hai lần chạy thật của kho: run `40748974196` trên
nhánh `main` và run `40748974200` trên nhánh `patched`. Cả hai sinh artifact
`evidence-security-as-code` chứa `ci-05-semgrep.json`. Luật `policy-p4-sql-injection`
của nhóm bắt 12 vị trí trên `main` và 8 trên `patched`.
