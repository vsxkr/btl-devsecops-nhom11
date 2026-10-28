# Mẫu một mục của Chương 4 ở độ sâu đầy đủ

> Đây là bản mẫu để nhóm xem hình dạng. Mười trường dưới đây lấy từ bốn khung
> phân tích trong tài liệu môn học, không phải do nhóm tự đặt ra:
> STRIDE và DREAD từ `3.Threat Modeling and Risk Management`, Abuse Case và
> Compliance User Story từ cùng tài liệu đó, bốn trường bằng chứng từ mốc chấm
> số 2 của `Hands-on_guide_updated.docx`.

---

## 4.3 Nguyễn Đình Hải, B26CHAT010: chèn mã truy vấn làm lộ dữ liệu cá nhân

### 4.3.1 Tài sản bị ảnh hưởng và vòng đời dữ liệu

Từ điển dữ liệu đo từ lược đồ thật cho 36 cột trong CSDL `ilfreight`, trong đó
**5 cột mức Restricted** và **5 cột mức Confidential**. Khiếm khuyết này đặt cả
mười cột đó vào tầm với của một yêu cầu HTTP không cần xác thực.

| Trạng thái dữ liệu | Nơi | Tài sản |
|---|---|---|
| Đang truyền | trình duyệt tới Apache | tên đăng nhập và mật khẩu người dùng nhập |
| Đang dùng | tiến trình PHP | chuỗi truy vấn được ghép từ dữ liệu người dùng |
| Khi lưu | MariaDB | `users.password`, `users.api_key`, `users.remember_token`, `users.email`, `users.username`, `comments.content` |

Ranh giới tin cậy bị vượt là ranh giới giữa **đầu vào không tin cậy** và **trình
thông dịch truy vấn**. Dữ liệu từ client đi qua ranh giới đó mà không có bước
chuyển đổi nào, nên nó không còn là dữ liệu mà trở thành một phần câu lệnh.

### 4.3.2 Kịch bản lạm dụng

Một người ngoài, không có tài khoản, gửi `admin'-- -` vào trường tên đăng nhập.
Phần sau dấu `--` bị MariaDB coi là chú thích, nên điều kiện kiểm mật khẩu biến
mất khỏi câu lệnh và phiên được cấp cho tài khoản `admin`. Sau khi có phiên, cùng
người đó dùng điều kiện boolean trên các trang tra cứu để đọc dữ liệu từng ký tự,
hoặc dùng `UNION SELECT` trên `/ports` để đọc trực tiếp.

### 4.3.3 Vị trí chính xác trong mã

| Tệp | Dòng | Nội dung |
|---|---|---|
| `pages/login.php` | 19 | `WHERE username = '$username' AND password = '$password'` |
| `pages/shipment_detail.php` | 15 | `WHERE id = $id`, không kiểm `customer_id` |
| `lib/db.php` | 50 | `echo ... mysqli_error($conn)` đưa lỗi ra phản hồi |
| `web/php.ini` | 6 | `display_errors = On` |

Tổng 12 vị trí nối chuỗi, đo bằng `policy-p4-sql-injection`.

### 4.3.4 Phân loại STRIDE và điểm thi hành trong dây chuyền

| STRIDE | Thuộc tính an toàn bị phá | Pha DevSecOps | Cổng lẽ ra phải bắt |
|---|---|---|---|
| Tampering | Toàn vẹn | Build | Chặng 2, Semgrep taint |
| Information Disclosure | Bí mật | Build và Test | Chặng 2 và chặng 4 |
| Elevation of Privilege | Phân quyền | Test | Chặng 4, test hành vi |

Cột điểm thi hành trả lời yêu cầu của đề bài về pha DevSecOps bằng **tên cổng cụ
thể** thay vì tên pha chung. Ba vector STRIDE của cùng một khiếm khuyết rơi vào
hai chặng khác nhau, nên không cổng nào một mình đủ.

### 4.3.5 Xếp hạng DREAD

Thang 1 đến 10 mỗi trục, kèm căn cứ đo được.

| Trục | Điểm | Căn cứ |
|---|---|---|
| Damage Potential | 9 | Đọc được toàn bộ 5 cột Restricted và 5 cột Confidential của 4 chủ thể dữ liệu |
| Reproducibility | 10 | Một yêu cầu HTTP, kết quả xác định, lặp lại được mọi lần |
| Exploitability | 9 | Không cần tài khoản, không cần công cụ ngoài trình duyệt |
| Affected Users | 10 | 4 trên 4 chủ thể dữ liệu trong bảng `users` |
| Discoverability | 10 | Trang in nguyên câu truy vấn ra HTML, và Semgrep bắt 12 vị trí |
| **Tổng** | **48 / 50** | |

### 4.3.6 Bán kính ảnh hưởng, đo bằng quyền thật của tài khoản CSDL

Hậu quả của cùng một lỗi chèn mã phụ thuộc vào quyền của tài khoản kết nối, một
điểm mà bảng xếp hạng thường bỏ qua.

| | Trước khi vá | Sau khi vá |
|---|---|---|
| Quyền | `ALL PRIVILEGES ON *.*` kèm `GRANT OPTION` | `SELECT, INSERT, UPDATE, DELETE ON ilfreight.*` |
| Số CSDL trong tầm với | **5**, gồm cả `mysql` chứa băm mật khẩu của mọi tài khoản | **1** |
| Quyền `FILE` | có, nên đọc và ghi được tệp trên máy chủ | **không** |
| Ghi web shell qua `INTO OUTFILE` | được, `secure_file_priv` để rỗng | không, và `secure_file_priv` đã giới hạn |

Đo bằng `SHOW GRANTS` trên CSDL đang chạy và `SHOW DATABASES`.

### 4.3.7 Chính sách bị vi phạm, có ghi phiên bản

| Khung | Mục |
|---|---|
| GDPR | Điều 32 về an toàn xử lý, Điều 5(1)(f) về toàn vẹn và bảo mật |
| Pháp luật Việt Nam hiện hành | Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15 và Nghị định 356/2025/NĐ-CP |
| PCI DSS v4.0.1 | 6.2.4 về phòng chống tấn công trong phần mềm tự phát triển |
| OWASP | A03:2021 Injection |
| CWE | CWE-89 |

Ghi rõ phiên bản PCI DSS là yêu cầu của handout: *"Pick one version, state it in
the report, and be consistent."*

### 4.3.8 Cách phát hiện, chiều đỏ có bằng chứng

```
$ semgrep --metrics off --error --config ci/semgrep-policy-php.yml app/InlaneWeb/web/src
...
policy-p4-sql-injection                    12
policy-p4-error-detail-to-response          4
 • Findings: 36 (36 blocking)
exit=1
```

```
$ bash tests/security/run.sh
  [LOI ] TDS-5   GDPR Art. 32   phan hoi loi khong duoc lo noi bo
          -> phan hoi chua: SQL Error, syntax, SQL syntax, MariaDB server version
exit=1
```

Bằng chứng lưu ở `evidence/16-semgrep-policy-app-baseline.txt` và
`evidence/26-tds-baseline.txt`.

### 4.3.9 Compliance User Story và tiêu chí chấp nhận

Tài liệu môn học yêu cầu diễn đạt yêu cầu tuân thủ thành story của lập trình viên
kèm tiêu chí chấp nhận tường minh, để nó vào được hàng đợi công việc thay vì nằm
trong một bảng tính quản trị rủi ro.

> **Là** hệ thống kiểm soát tuân thủ,
> **tôi cần** mọi truy vấn có tham số dùng câu lệnh chuẩn bị trước với tham số
> ràng buộc, và mọi phản hồi lỗi chỉ chứa thông điệp chung kèm mã sự kiện,
> **để** dữ liệu cá nhân của chủ thể không bị đọc qua đầu vào không tin cậy.
>
> **Tiêu chí chấp nhận:**
> 1. `semgrep --config ci/semgrep-policy-php.yml` không còn phát hiện
>    `policy-p4-sql-injection` trên các tệp thuộc phạm vi.
> 2. `TDS-5` đạt: phản hồi của `/ports?q=1%27` không chứa `SQL Error`, `mysqli`,
>    `syntax`, `MariaDB server version`.
> 3. Cả hai điều trên được kiểm trong chặng 2 và chặng 4 của dây chuyền, và cổng
>    trả mã thoát khác 0 khi vi phạm.

Tiêu chí chấp nhận chính là phép kiểm, nên nó viết được thành mã.

### 4.3.10 Cách xử lý và chiều xanh có bằng chứng

```php
$read = mysqli_prepare($conn, 'SELECT id, username, role, password FROM users WHERE username = ? LIMIT 1');
mysqli_stmt_bind_param($read, 's', $username);
```

Cộng với `password_verify` thay cho so sánh chuỗi trong SQL, `session_regenerate_id`
sau khi đăng nhập, `display_errors = Off`, và trình xử lý lỗi trả mã sự kiện.

```
$ bash tests/security/run.sh
  [DAT ] TDS-5   GDPR Art. 32   phan hoi loi khong duoc lo noi bo
5 test, 5 dat, 0 that bai
exit=0
```

Bằng chứng ở `evidence/29-tds-patched.txt`.

Chiến lược xử lý rủi ro theo bốn lựa chọn trong tài liệu: **Mitigate**, vì chức
năng tra cứu là nghiệp vụ cốt lõi nên không thể Avoid, và rủi ro dữ liệu cá nhân
không thể Transfer hay Accept.

### 4.3.11 Điều cổng này không chứng minh được

| Giới hạn | Ai bù |
|---|---|
| Semgrep CE không theo luồng dữ liệu qua ranh giới hàm, nên đường `$_GET` tới `logSqlError` qua hai hàm không chứng minh được bằng taint | Mai, bằng `TDS-6` đo trực tiếp luồng nhật ký |
| Việc **thiếu** phép kiểm quyền sở hữu không có mẫu cú pháp nào thể hiện được | Đức Anh, bằng `TDS-3` đo hành vi |
| `pages/track_api.php` cố ý nuốt lỗi, nên không phép kiểm nào dựa trên phản hồi phát hiện được nó | ghi nhận là giới hạn, cần rà soát người đọc mã |
| Mười điểm chèn mã còn lại thuộc đợt vá 2 | ghi trong `patches/README.md`, có chủ sở hữu và lý do hoãn |

Mục này là yêu cầu bắt buộc của handout trong phần *"What static analysis cannot
prove"*, và phải nói thật thay vì để trống.
