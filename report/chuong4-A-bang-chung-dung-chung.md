# Chương 4, BẢN A: bảng tra cứu dùng chung + 11 trường cho mỗi người

> Bản này đưa bốn bảng tra cứu dùng chung lên mục 4.1. Mỗi thành viên ở các mục
> sau giữ đủ mười một trường phân tích nhưng **tham chiếu** bảng chung thay vì
> lặp lại. Ước lượng ~1,8 trang/người, cả chương ~9 trang.
>
> Mười một trường lấy từ bốn khung trong tài liệu môn học, không do nhóm tự đặt:
> STRIDE và DREAD từ `3.Threat Modeling and Risk Management`, Abuse Case và
> Compliance User Story từ cùng tài liệu, bốn trường bằng chứng từ mốc chấm số 2
> của `Hands-on_guide_updated.docx`.

---

## 4.1 Bảng tra cứu dùng chung

### 4.1.1 Thang phân loại dữ liệu (đo từ lược đồ thật)

Từ điển dữ liệu ở `docs/01-tu-dien-du-lieu.md` sinh từ lược đồ MariaDB đang chạy,
36 cột, phân loại bốn mức theo bước 1 của Rapid Risk Assessment.

| Mức nhạy cảm | Số cột | Ví dụ cột |
|---|---|---|
| Restricted | 5 | `users.password`, `users.api_key`, `users.remember_token`, `legacy_service_accounts.password_hash`, `legacy_service_accounts.api_key` |
| Confidential | 5 | `users.username`, `users.email`, `comments.content`, `privacy_requests.reason`, `legacy_service_accounts.username` |
| Internal | 10 | `users.role`, `shipments.customer_id`, `comments.user_id`, … |
| Public | 16 | `ports.*`, `news.*`, các khoá `id` |
| **Tổng** | **36** | |

Năm cột Restricted là thông tin xác thực (GDPR Điều 32). Năm cột Confidential là
dữ liệu định danh cá nhân (GDPR Điều 4(1), 15, 17). Mỗi vấn đề dưới đây được xếp
theo việc nó đặt những cột mức nào vào tầm với của kẻ tấn công.

### 4.1.2 Chú giải STRIDE và điểm thi hành

Cột điểm thi hành trả lời yêu cầu của đề bài về **pha DevSecOps** bằng tên cổng
cụ thể thay vì tên pha chung.

| STRIDE | Thuộc tính an toàn bị phá | Điểm thi hành trong dây chuyền |
|---|---|---|
| Spoofing | Xác thực | Chặng 4, test hành vi đăng nhập |
| Tampering | Toàn vẹn | Chặng 2, Semgrep taint / chính sách |
| Repudiation | Truy vết, chống chối bỏ | Chặng 5, telemetry + luật tương quan |
| Information Disclosure | Bí mật | Chặng 2 và chặng 4 |
| Denial of Service | Khả dụng | Chặng 6, hạ tầng + luật khả dụng |
| Elevation of Privilege | Phân quyền | Chặng 4, test hành vi phân quyền |

Tài liệu `3.Threat Modeling` thêm một cột **CI/CD Pipeline Control**: một mối đe
doạ có thể nằm ở chính dây chuyền (ví dụ cổng chất lượng bị tắt). Vấn đề của Nam
ở mục 4.6 rơi đúng vào cột đó.

### 4.1.3 Năm trục DREAD

Thang 1 đến 10 mỗi trục. Mỗi mục dưới cho điểm **kèm căn cứ đo được**, không cho
điểm cảm tính.

| Trục | Nội dung |
|---|---|
| Damage Potential | Mức thiệt hại khi khai thác thành công |
| Reproducibility | Mức độ lặp lại được của cuộc tấn công |
| Exploitability | Điều kiện, kỹ năng và công cụ cần có |
| Affected Users | Số chủ thể dữ liệu bị ảnh hưởng |
| Discoverability | Mức độ dễ bị kẻ tấn công tìm ra |

### 4.1.4 Bốn chiến lược xử lý rủi ro

Theo `3.Threat Modeling`: **Avoid** (bỏ chức năng), **Mitigate** (giảm thiểu),
**Transfer** (chuyển giao), **Accept** (chấp nhận có điều kiện). Mọi vấn đề dưới
đây đều chọn **Mitigate**, vì các chức năng liên quan là nghiệp vụ cốt lõi (không
Avoid được) và rủi ro dữ liệu cá nhân không thể Transfer hay Accept.

### 4.1.5 Phương pháp đo bán kính ảnh hưởng

Hậu quả của cùng một lỗi phụ thuộc quyền của tài khoản CSDL mà ứng dụng dùng.
Bán kính đo bằng `SHOW GRANTS` và `SHOW DATABASES` trên CSDL đang chạy, trước và
sau khi vá. Kết quả dùng chung cho mọi vấn đề có thể dẫn tới truy vấn tuỳ ý:

| | Trước khi vá | Sau khi vá |
|---|---|---|
| Tài khoản ứng dụng | `root@%` | `ilf_app@%` |
| Quyền | `ALL PRIVILEGES ON *.*` kèm `GRANT OPTION` | `SELECT, INSERT, UPDATE, DELETE ON ilfreight.*` |
| Số CSDL trong tầm với | **5**, gồm `mysql` chứa băm mật khẩu mọi tài khoản | **1** |
| Quyền `FILE` | có (`secure_file_priv` rỗng), cho phép đọc/ghi tệp máy chủ và ghi web shell qua `INTO OUTFILE` | **không** |

---

## 4.2 Nguyễn Đình Hải (B26CHAT010): chèn mã truy vấn và lộ lỗi ra phản hồi

**Nhóm lỗi:** lỗi mã nguồn. **Cổng:** `policy-p4-sql-injection`, TDS-5.

**(1) Tài sản và vòng đời dữ liệu.** Khiếm khuyết đặt cả mười cột Restricted và
Confidential (Bảng 4.1.1) vào tầm với một yêu cầu HTTP không cần xác thực. Dữ
liệu từ client đi qua ranh giới **đầu vào không tin cậy → trình thông dịch truy
vấn** mà không có bước chuyển đổi, nên không còn là dữ liệu mà thành câu lệnh.

**(2) Kịch bản lạm dụng.** Người ngoài gửi `admin'-- -` vào trường tên đăng
nhập; phần sau `--` bị coi là chú thích, điều kiện mật khẩu biến mất, phiên được
cấp cho `admin`. Sau đó dùng `UNION SELECT` trên `/ports` để đọc trực tiếp.

**(3) Vị trí trong mã.**

| Tệp | Dòng | Nội dung |
|---|---|---|
| `pages/login.php` | 19 | `WHERE username = '$username' AND password = '$password'` |
| `lib/db.php` | ~50 | `echo … mysqli_error($conn)` đưa lỗi ra phản hồi |
| `web/php.ini` | 6 | `display_errors = On` |

Tổng 12 vị trí nối chuỗi, đo bằng `policy-p4-sql-injection`.

**(4) STRIDE + điểm thi hành.** Tampering (Toàn vẹn), Information Disclosure (Bí
mật), Elevation of Privilege (Phân quyền), rơi vào chặng 2 và chặng 4 (Bảng
4.1.2), nên không cổng nào một mình đủ.

**(5) DREAD = 48/50.** Damage 9 (đọc toàn bộ 10 cột Restricted+Confidential của
4 chủ thể); Reproducibility 10 (một yêu cầu, xác định); Exploitability 9 (không
cần tài khoản); Affected Users 10 (4/4 chủ thể trong `users`); Discoverability 10
(trang in nguyên câu truy vấn; Semgrep bắt 12 vị trí).

**(6) Bán kính ảnh hưởng.** Theo Bảng 4.1.5: trước khi vá, lỗi này kết hợp quyền
`FILE` của `root` cho phép ghi web shell; sau khi vá còn 1 CSDL, không `FILE`.

**(7) Chính sách bị vi phạm.** GDPR Điều 32, Điều 5(1)(f); Luật Bảo vệ dữ liệu cá
nhân số 91/2025/QH15 và Nghị định 356/2025/NĐ-CP; PCI DSS v4.0.1 mục 6.2.4;
OWASP A03:2021; CWE-89.

**(8) Phát hiện (chiều đỏ).** `semgrep --error --config ci/semgrep-policy-php.yml`
→ `policy-p4-sql-injection 12`, exit 1 (`evidence/16`). TDS-5 đỏ: phản hồi của
`/ports?q=1%27` chứa `SQL Error`, `MariaDB server version` (`evidence/26`).

**(9) Compliance User Story.** *Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi
truy vấn dùng câu lệnh chuẩn bị trước với tham số ràng buộc và mọi phản hồi lỗi
chỉ chứa mã sự kiện, *để* dữ liệu cá nhân không bị đọc qua đầu vào không tin cậy.
**Tiêu chí chấp nhận:** Semgrep không còn `policy-p4-sql-injection`; TDS-5 đạt;
cả hai kiểm trong chặng 2 và 4, cổng trả mã thoát ≠ 0 khi vi phạm.

**(10) Xử lý (chiều xanh).** `mysqli_prepare` + `bind_param`, `password_verify`,
`display_errors = Off`, trình xử lý lỗi trả mã sự kiện. TDS-5 xanh, 5/5 test đạt,
exit 0 (`evidence/29`). Chiến lược: **Mitigate** (Bảng 4.1.4).

**(11) Giới hạn.** Semgrep CE không theo luồng dữ liệu qua ranh giới hàm (taint),
nên đường dữ liệu từ `$_GET` tới `logSqlError` qua hai hàm không chứng minh được
bằng taint, Mai bù bằng TDS-6. Mười điểm chèn mã còn lại thuộc đợt vá 2, ghi trong
`patches/README.md` có chủ sở hữu và lý do hoãn.

---

## 4.3 Nguyễn Phương Mai (B26CHAT025): vệ sinh nhật ký, thiếu kiểm toán, và chuỗi phát hiện

**Nhóm lỗi:** vận hành / giám sát. **Cổng:** TDS-6 và chuỗi telemetry đo được
(bậc 3), `evidence/35`.

**(1) Tài sản và vòng đời dữ liệu.** Nhật ký ứng dụng ở trạng thái **đang lưu**.
Bản cũ ghi `failed_query` là nguyên văn câu lệnh và thông điệp lỗi MariaDB. Với
`/login`, nhật ký chứa cả tên đăng nhập và mật khẩu người dùng vừa gõ (cột Restricted
`users.password` rò qua một đường vòng). Đồng thời không có sự kiện kiểm toán khi
đăng nhập thất bại, nên **không có dữ liệu để phát hiện** do quét thông tin.

**(2) Kịch bản lạm dụng.** Một người có quyền đọc log (quản trị, bên thứ ba vận
hành, hoặc kẻ tấn công đã có một chỗ đứng) đọc được mật khẩu nguyên văn. Vì đăng
nhập thất bại không để lại dấu, một cuộc dò mật khẩu hàng loạt diễn ra **vô hình**
với hệ thống giám sát.

**(3) Vị trí trong mã.** `lib/logger.php` (hàm `logSqlError`, `logAuthEvent`),
`pages/login.php:49`; phía giám sát: `monitoring/promtail/promtail-config.hardened.yml`,
`monitoring/loki/rules-hardened/fake/alert-rules.yml`.

**(4) STRIDE + điểm thi hành.** Repudiation (Truy vết, thiếu kiểm toán),
Information Disclosure (Bí mật, log rò bí mật), chặng 5 telemetry (Bảng 4.1.2).

**(5) DREAD = 37/50.** Damage 7 (log rò thông tin xác thực nhưng cần quyền đọc
log); Reproducibility 10 (mọi lỗi truy vấn đều ghi nguyên văn); Exploitability 6
(quan sát bị động + mù phát hiện); Affected Users 8 (mọi người dùng có lỗi truy
vấn); Discoverability 6 (cần soi log).

**(6) Bán kính ảnh hưởng.** Không mở rộng quyền CSDL; bán kính là **thời gian mù**
, khoảng thời gian một cuộc tấn công diễn ra mà không ai biết. Bậc 3 đo chính đại
lượng này: sau khi vá, độ trễ phát hiện là **15–25 giây** (ba lần: 15,1 / 20,9 /
24,6s, `evidence/35`).

**(7) Chính sách bị vi phạm.** GDPR Điều 5(1)(c) (tối giản dữ liệu), Điều 32,
Điều 33–34 (thông báo vi phạm: không phát hiện được thì không thông báo kịp);
OWASP A09:2021 (Security Logging and Monitoring Failures); CWE-532.

**(8) Phát hiện (chiều đỏ).** TDS-6 đỏ: luồng `docker logs` chứa trường
`failed_query` nguyên văn (`evidence/26`). Thiếu kiểm toán được phát hiện khi
viết luật tương quan cho Loki và nhận ra **không có dữ liệu nào để đếm**, một
đường phát hiện mà không công cụ tĩnh nào cung cấp.

**(9) Compliance User Story.** *Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi
dòng log đi qua một chặng che dữ liệu trước khi lưu, và mỗi lần đăng nhập thất
bại phát một sự kiện kiểm toán đếm được theo nguồn, *để* bí mật không bị lưu và
một cuộc dò quét không còn vô hình. **Tiêu chí chấp nhận:** không dòng Loki nào
chứa mật khẩu gửi lên; một loạt tấn công kích cảnh báo tới alert-sink trong vòng
≤30 giây.

**(10) Xử lý (chiều xanh).** `logger.php` thay nguyên văn câu lệnh bằng **dấu vân
tay** đã bỏ hằng + mã sự kiện; `logAuthEvent` phát `AUTH-EVENT`. Promtail thay
giá trị bí mật bằng `[REDACTED_CREDENTIAL]` trước khi lưu; luật Loki hai chuỗi
đếm `sum by (client_ip)`; Alertmanager → alert-sink. Đo đầu-cuối: che dữ liệu
đạt (0 dòng lộ mật khẩu), cảnh báo tới sink, độ trễ 15–25s (`evidence/35`).
Chiến lược: **Mitigate**.

**(11) Giới hạn.** `AUTH-EVENT` chưa mang `client_ip` (Apache ghi địa chỉ ở dòng
riêng), nên ở lab luật dò mật khẩu đếm **tổng** số lần thất bại; triển khai thật
cần bổ sung `client_ip` vào sự kiện để tương quan theo nguồn. Ba lỗi cấu hình
Promtail/Loki chỉ lộ khi chạy thật được ghi ở `patches/monitoring/README.md`.

---

## 4.4 Lê Đức Anh (B26CHAT003): quyền của chủ thể dữ liệu không được thực thi

**Nhóm lỗi:** lỗi mã nguồn (kiểm soát truy cập). **Cổng:** TDS-1, TDS-2, TDS-3.

**(1) Tài sản và vòng đời dữ liệu.** Hai điểm cuối quyền chủ thể dữ liệu trên
`privacy_*.php` thao tác trực tiếp các cột Restricted/Confidential (Bảng 4.1.1).
Bản xuất đọc dữ liệu **khi lưu**; bản xoá ghi **khi lưu**.

**(2) Kịch bản lạm dụng.** (a) Người dùng đã đăng nhập gọi
`/privacy/export?user_id=1` đọc hồ sơ người khác (IDOR). (b) Bản xuất trả cả
`password`, `api_key`, `remember_token` của chính chủ thể, vượt quyền truy cập
theo Điều 15. (c) Yêu cầu xoá (Điều 17) chỉ **ghi nhận** mà không xoá bản ghi nào.

**(3) Vị trí trong mã.** `pages/privacy_export.php` (chọn định danh từ client
thay vì phiên; danh sách cột gồm cột xác thực), `pages/privacy_erase.php` (chỉ
INSERT vào `privacy_requests`, không DELETE/UPDATE).

**(4) STRIDE + điểm thi hành.** Information Disclosure (Bí mật), Elevation of
Privilege (Phân quyền ngang), chặng 4, test hành vi (Bảng 4.1.2).

**(5) DREAD = 44/50.** Damage 9 (đọc 5 cột Restricted của chủ thể khác);
Reproducibility 10; Exploitability 8 (cần một tài khoản, đổi `user_id`);
Affected Users 10 (mọi chủ thể); Discoverability 7 (tham số lộ trong URL).

**(6) Bán kính ảnh hưởng.** Không qua CSDL mà qua **tầng ứng dụng**: một tài
khoản bất kỳ chạm tới toàn bộ chủ thể. Sau khi vá, định danh lấy từ phiên nên bán
kính thu về đúng một chủ thể.

**(7) Chính sách bị vi phạm.** GDPR Điều 15 (quyền truy cập), Điều 17 (quyền được
xoá), Điều 5(1)(c), Điều 5(1)(f); CWE-639 (IDOR), CWE-200.

**(8) Phát hiện (chiều đỏ).** TDS-1/2/3 đỏ: bản xuất chứa `password`; đọc được hồ
sơ `user_id` khác; sau yêu cầu xoá, bản ghi vẫn còn (`evidence/26`).

**(9) Compliance User Story.** *Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi
điểm cuối quyền chủ thể lấy định danh **từ phiên**, bản xuất loại bỏ cột xác
thực, và yêu cầu xoá thực sự xoá hoặc ẩn danh hoá, *để* quyền theo Điều 15/17
được thực thi chứ không chỉ được hứa. **Tiêu chí chấp nhận:** TDS-1/2/3 đạt.

**(10) Xử lý (chiều xanh).** `privacy_export.php` lấy `id` từ `current_user()`,
từ chối `user_id` lạ bằng 403, danh sách cột không có cột xác thực, truy vấn tham
số hoá. `privacy_erase.php` xoá bình luận, ẩn danh hoá hồ sơ, xoá thông tin xác
thực, giữ bản ghi kiểm toán đã ẩn danh. TDS-1/2/3 xanh (`evidence/29`). Chiến
lược: **Mitigate** (ẩn danh hoá thay vì xoá cứng do ràng buộc toàn vẹn tham
chiếu, lựa chọn có chủ đích, GDPR cho phép).

**(11) Giới hạn.** Test hành vi chứng minh **hành vi hiện tại** đúng; nó không
chứng minh mọi điểm cuối tương lai đều lấy định danh từ phiên. Cần một kiểm thử
hồi quy cho mỗi điểm cuối mới, ghi là nợ kỹ thuật.

---

## 4.5 Đào Xuân Mạnh (B26CHAT026): bí mật gán cứng, tài khoản CSDL đặc quyền, mật khẩu lưu rõ

**Nhóm lỗi:** lỗi triển khai/cấu hình + dữ liệu khi lưu. **Cổng:**
`policy-p3-hardcoded-credential-fallback`, `policy-p3-privileged-db-account-default`,
luật CREDENTIALS, Conftest, TDS-4.

**(1) Tài sản và vòng đời dữ liệu.** Thông tin xác thực ở ba trạng thái: trong
**mã** (giá trị dự phòng hằng), trong **cấu hình** (compose), và **khi lưu**
(`users.password` dạng rõ, cột Restricted, Bảng 4.1.1).

**(2) Kịch bản lạm dụng.** (a) Bất kỳ ai đọc được mã nguồn đều thấy mật khẩu dự
phòng. (b) Ứng dụng kết nối bằng `root@%` với `ALL PRIVILEGES` + `FILE`: bất kỳ
lỗi chèn mã nào (mục 4.2) lập tức thành đọc/ghi toàn CSDL và ghi web shell. (c)
Mật khẩu người dùng lưu dạng rõ: một lần rò bảng `users` làm lộ trực tiếp mật khẩu.

**(3) Vị trí trong mã.** `lib/db.php` (giá trị dự phòng hằng), `docker-compose.yml`
+ `db/init.sql.template` (`root@%`, `ALL PRIVILEGES`, `FILE`), `init.sql.template`
+ `login.php` (so sánh mật khẩu dạng rõ).

**(4) STRIDE + điểm thi hành.** Information Disclosure, Elevation of Privilege,
Spoofing (mật khẩu rõ cho phép mạo danh), chặng 2 (chính sách/Conftest) và chặng
4 (TDS-4) (Bảng 4.1.2).

**(5) DREAD = 45/50.** Damage 10 (root + FILE → toàn CSDL + ghi tệp máy chủ);
Reproducibility 10; Exploitability 7 (cần một chỗ đứng như SQLi để tận dụng);
Affected Users 10; Discoverability 8 (bí mật hằng lộ khi đọc mã).

**(6) Bán kính ảnh hưởng.** Bảng 4.1.5 áp dụng trực tiếp cho vấn đề này: trước khi
vá có 5 CSDL (gồm `mysql`) và quyền `FILE`; sau khi vá `ilf_app` chỉ còn 4 quyền
DML trên 1 CSDL, không `FILE`, `secure_file_priv` đã giới hạn.

**(7) Chính sách bị vi phạm.** GDPR Điều 32, Điều 5(1)(f); PCI DSS v4.0.1 mục
8.6.2 (quản lý bí mật) và 8.3 (băm mật khẩu); nguyên tắc *"Hard-coded credentials
in source control are strictly prohibited"* (`1.Technical devSecOps Report`);
CWE-798, CWE-256, CWE-269.

**(8) Phát hiện (chiều đỏ).** `policy-p3-*` và luật CREDENTIALS bắt bí mật hằng
và `root` (`evidence/14`); Conftest bắt compose đặc quyền (`evidence/06`,`09`);
TDS-4 đỏ: mật khẩu khớp bằng so sánh chuỗi (`evidence/26`).

**(9) Compliance User Story.** *Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi bí
mật lấy từ biến môi trường không có giá trị dự phòng hằng, ứng dụng kết nối bằng
tài khoản quyền tối thiểu, và mật khẩu lưu bằng băm một chiều, *để* một lần rò
không biến thành chiếm toàn hệ thống. **Tiêu chí chấp nhận:** `policy-p3-*` và
CREDENTIALS sạch; `conftest test … --namespace compose` đạt; TDS-4 đạt.

**(10) Xử lý (chiều xanh).** Bí mật từ `.env` không dự phòng; `ilf_app` quyền tối
thiểu; `password_hash`/`password_verify`. Conftest compose đạt (`evidence/10`),
TDS-4 xanh (`evidence/29`). Chiến lược: **Mitigate**.

**(11) Giới hạn.** Hai cổng không đồng ý (`evidence/34`): sau vá, Conftest đạt
trên compose nhưng InSpec vẫn đỏ vì `DB_PASS` đọc được qua `docker inspect`: bí mật vẫn ở biến môi trường, chưa chuyển sang Docker secrets/Vault. Đây là nợ kỹ
thuật đợt vá 2, và là ví dụ hai cổng đo hai thứ khác nhau trên cùng một tài sản.

---

## 4.6 Nam (B26CHAT030): cổng chất lượng bị vô hiệu, nhánh không bảo vệ, CRLF

**Nhóm lỗi:** lỗi triển khai/vận hành (CI/CD). **Cổng:** `repo_policy.rego`,
so sánh mã thoát cổng, việc chạy thật.

**(1) Tài sản và vòng đời dữ liệu.** Tài sản ở đây không phải một bảng mà là
**tính toàn vẹn của chính dây chuyền**: nếu cổng không chặn, mọi cột ở Bảng 4.1.1
đều mất lớp bảo vệ mà các mục trên vừa dựng. Điều này tương ứng với luận điểm
*"Configuration is as dangerous as source code"* (`1.Technical devSecOps Report`).

**(2) Kịch bản lạm dụng.** (a) Cổng chất lượng dùng một biểu thức luôn cho
`false`, nên commit có lỗi vẫn qua. (b) Nhánh `main`/`dev` không bảo vệ, cho phép
đẩy thẳng không review. (c) Kết thúc dòng CRLF làm container không khởi động trên
Windows, một lỗi vận hành mà không cổng phân tích nào thấy.

**(3) Vị trí trong mã.** `.github/workflows/devsecops-gate.yml` (biểu thức vô
hiệu), thiết lập bảo vệ nhánh GitHub (`repo_policy.rego` kiểm qua `gh api`),
`.gitattributes` (ép LF).

**(4) STRIDE + điểm thi hành.** Tampering (Toàn vẹn dây chuyền), Elevation of
Privilege (đẩy không review), rơi vào cột **CI/CD Pipeline Control** của Bảng
4.1.2, một mối đe doạ của chính pha triển khai.

**(5) DREAD = 37/50.** Damage 8 (một commit lỗi ship ra sản phẩm);
Reproducibility 10; Exploitability 5 (cần quyền commit); Affected Users 10 (toàn
bộ triển khai); Discoverability 4 (ẩn trong biểu thức workflow).

**(6) Bán kính ảnh hưởng.** Bán kính là **toàn bộ các lớp bảo vệ khác**: một cổng
hỏng vô hiệu hoá mọi kết quả ở mục 4.2–4.5. Sau khi vá, cổng trả mã thoát ≠ 0 khi
có vi phạm và nhánh được đặt `protected: true`.

**(7) Chính sách bị vi phạm.** GDPR Điều 32 (biện pháp kỹ thuật phù hợp: một cổng
giả tạo không phải biện pháp phù hợp); nguyên tắc **regulatory non-compliance
phải được mô hình hoá như một vector đe doạ kỹ thuật** (`3.Threat Modeling`);
nguyên tắc cấu hình phải được kiểm thử tự động như mã nguồn.

**(8) Phát hiện (chiều đỏ).** So sánh mã thoát cho thấy cổng cũ trả 0 dù có vi
phạm (`evidence/17`, `23`); `repo_policy.rego` trên nhánh thật báo `protected:
false` (`evidence/11`, `12`); CRLF làm container không khởi động, chỉ lộ khi chạy
thật (`evidence/27`).

**(9) Compliance User Story.** *Là* hệ thống kiểm soát tuân thủ, *tôi cần* cổng
dây chuyền trả mã thoát ≠ 0 khi có vi phạm, nhánh bảo vệ bắt buộc review, và
chuẩn hoá kết thúc dòng, *để* các biện pháp kỹ thuật không bị một dòng cấu hình
vô hiệu hoá âm thầm. **Tiêu chí chấp nhận:** cổng đỏ khi có vi phạm; `gh api`
báo `protected: true`; container khởi động trên cả Windows và Linux.

**(10) Xử lý (chiều xanh).** Sửa biểu thức cổng để chặn thật (`devsecops-gate.yml`
6 job có chặn); `.gitattributes` ép LF; `repo_policy.rego` kiểm MFA/bảo vệ nhánh
bằng JSON từ `gh api`. Cổng đỏ đúng lúc (`evidence/23`), container khởi động được
(`evidence/27`). Chiến lược: **Mitigate**.

**(11) Giới hạn.** Bảo vệ nhánh **chưa bật** trên repo của nhóm (cần Nam bật bằng
quyền quản trị GitHub); `repo_policy.rego` kiểm được điều kiện nhưng không tự bật
được. Đây là ranh giới giữa Policy-as-Code (kiểm) và hành động quản trị (thực
thi), ghi rõ là việc còn lại.
