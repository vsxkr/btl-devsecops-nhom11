# Chương 4, BẢN B: mỗi người một mục tự chứa (lặp bảng khung)

> Bản này không có mục bảng dùng chung. Mỗi thành viên là một mục **tự chứa**:
> bảng STRIDE riêng, bảng DREAD năm trục đầy đủ, trích từ điển dữ liệu liên quan,
> và bảng bán kính ảnh hưởng ngay trong mục. Ưu điểm: mỗi người in riêng phần
> của mình để demo trực tiếp với thầy mà không cần giở chương khác. Nhược điểm:
> khung STRIDE/DREAD và một số bảng lặp lại giữa các mục. Ước lượng ~2,7
> trang/người, cả chương ~13,5 trang.
>
> Mười một trường lấy từ bốn khung trong tài liệu môn học (STRIDE, DREAD, Abuse
> Case, Compliance User Story + bốn trường bằng chứng của mốc chấm số 2).

---

## 4.1 Nguyễn Đình Hải (B26CHAT010): chèn mã truy vấn và lộ lỗi ra phản hồi

**Nhóm lỗi:** lỗi mã nguồn. **Cổng phát hiện:** `policy-p4-sql-injection`, TDS-5.

### 4.1.1 Tài sản và vòng đời dữ liệu

Khiếm khuyết đặt mười cột nhạy cảm nhất của CSDL vào tầm với một yêu cầu HTTP
không cần xác thực.

| Cột | Mức | Điều khoản |
|---|---|---|
| `users.password`, `users.api_key`, `users.remember_token` | Restricted | GDPR 32 |
| `users.username`, `users.email`, `comments.content` | Confidential | GDPR 4(1), 15, 17 |

Dữ liệu đi qua ranh giới **đầu vào không tin cậy → trình thông dịch truy vấn** mà
không chuyển đổi, nên không còn là dữ liệu mà thành câu lệnh.

### 4.1.2 Kịch bản lạm dụng

Người ngoài gửi `admin'-- -` vào tên đăng nhập; phần sau `--` thành chú thích,
điều kiện mật khẩu biến mất, phiên cấp cho `admin`; sau đó `UNION SELECT` trên
`/ports` đọc trực tiếp.

### 4.1.3 Vị trí trong mã

| Tệp | Dòng | Nội dung |
|---|---|---|
| `pages/login.php` | 19 | `WHERE username = '$username' AND password = '$password'` |
| `lib/db.php` | ~50 | `echo … mysqli_error($conn)` |
| `web/php.ini` | 6 | `display_errors = On` |

Tổng 12 vị trí nối chuỗi, đo bằng `policy-p4-sql-injection`.

### 4.1.4 Phân loại STRIDE và điểm thi hành

| STRIDE | Thuộc tính bị phá | Pha | Cổng lẽ ra phải bắt |
|---|---|---|---|
| Tampering | Toàn vẹn | Build | Chặng 2, Semgrep taint |
| Information Disclosure | Bí mật | Build + Test | Chặng 2 và 4 |
| Elevation of Privilege | Phân quyền | Test | Chặng 4, test hành vi |

### 4.1.5 Xếp hạng DREAD

| Trục | Điểm | Căn cứ |
|---|---|---|
| Damage Potential | 9 | Đọc 10 cột Restricted+Confidential của 4 chủ thể |
| Reproducibility | 10 | Một yêu cầu HTTP, kết quả xác định |
| Exploitability | 9 | Không cần tài khoản, chỉ cần trình duyệt |
| Affected Users | 10 | 4/4 chủ thể trong `users` |
| Discoverability | 10 | Trang in nguyên câu truy vấn; Semgrep bắt 12 vị trí |
| **Tổng** | **48/50** | |

### 4.1.6 Bán kính ảnh hưởng

| | Trước vá | Sau vá |
|---|---|---|
| Quyền | `root` `ALL PRIVILEGES` + `FILE` | `ilf_app` 4 quyền DML |
| CSDL trong tầm với | 5 (gồm `mysql`) | 1 |
| Ghi web shell `INTO OUTFILE` | được | không |

### 4.1.7 Chính sách bị vi phạm

GDPR Điều 32, 5(1)(f); Luật 91/2025/QH15 và NĐ 356/2025/NĐ-CP; PCI DSS v4.0.1
mục 6.2.4; OWASP A03:2021; CWE-89.

### 4.1.8 Phát hiện (chiều đỏ)

`policy-p4-sql-injection 12`, exit 1 (`evidence/16`); TDS-5 đỏ, phản hồi chứa
`SQL Error`, `MariaDB server version` (`evidence/26`).

### 4.1.9 Compliance User Story

*Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi truy vấn dùng câu lệnh chuẩn bị
trước và mọi phản hồi lỗi chỉ chứa mã sự kiện, *để* dữ liệu cá nhân không bị đọc
qua đầu vào không tin cậy. **Tiêu chí:** Semgrep sạch `policy-p4`; TDS-5 đạt; kiểm
ở chặng 2 và 4, cổng ≠ 0 khi vi phạm.

### 4.1.10 Xử lý (chiều xanh)

`mysqli_prepare` + `bind_param`, `password_verify`, `display_errors = Off`, trình
xử lý lỗi trả mã sự kiện. TDS-5 xanh, 5/5, exit 0 (`evidence/29`). **Mitigate.**

### 4.1.11 Giới hạn

Semgrep CE không theo taint qua ranh giới hàm, nên Mai bù bằng TDS-6. Mười điểm
chèn mã còn lại thuộc đợt vá 2 (`patches/README.md`).

---

## 4.2 Nguyễn Phương Mai (B26CHAT025): vệ sinh nhật ký, thiếu kiểm toán, chuỗi phát hiện

**Nhóm lỗi:** vận hành / giám sát. **Cổng:** TDS-6 và chuỗi telemetry đo được
(bậc 3, `evidence/35`).

### 4.2.1 Tài sản và vòng đời dữ liệu

Nhật ký ứng dụng ở trạng thái **đang lưu**. Bản cũ ghi `failed_query` nguyên văn;
với `/login`, dòng đó chứa cả `users.password` (Restricted). Thiếu sự kiện kiểm
toán khi đăng nhập thất bại nghĩa là **không có dữ liệu để phát hiện** dò quét.

### 4.2.2 Kịch bản lạm dụng

Người đọc được log thấy mật khẩu nguyên văn. Vì đăng nhập thất bại không để lại
dấu, một cuộc dò mật khẩu hàng loạt diễn ra vô hình với hệ thống giám sát.

### 4.2.3 Vị trí trong mã

`lib/logger.php` (`logSqlError`, `logAuthEvent`), `pages/login.php:49`; phía giám
sát `promtail-config.hardened.yml`, `loki/rules-hardened/fake/alert-rules.yml`.

### 4.2.4 Phân loại STRIDE và điểm thi hành

| STRIDE | Thuộc tính bị phá | Pha | Cổng lẽ ra phải bắt |
|---|---|---|---|
| Repudiation | Truy vết, chống chối bỏ | Operate | Chặng 5, luật tương quan |
| Information Disclosure | Bí mật | Operate | Chặng 5, che dữ liệu Promtail |

### 4.2.5 Xếp hạng DREAD

| Trục | Điểm | Căn cứ |
|---|---|---|
| Damage Potential | 7 | Log rò thông tin xác thực, cần quyền đọc log |
| Reproducibility | 10 | Mọi lỗi truy vấn đều ghi nguyên văn |
| Exploitability | 6 | Quan sát bị động + mù phát hiện |
| Affected Users | 8 | Mọi người dùng có lỗi truy vấn |
| Discoverability | 6 | Cần soi log |
| **Tổng** | **37/50** | |

### 4.2.6 Bán kính ảnh hưởng

Không mở rộng quyền CSDL; bán kính là **thời gian mù**, khoảng thời gian tấn công
diễn ra mà không ai biết. Bậc 3 đo trực tiếp: sau vá độ trễ phát hiện **15–25
giây** (15,1 / 20,9 / 24,6s, `evidence/35`).

### 4.2.7 Chính sách bị vi phạm

GDPR Điều 5(1)(c), 32, 33–34 (không phát hiện thì không thông báo kịp); OWASP
A09:2021; CWE-532.

### 4.2.8 Phát hiện (chiều đỏ)

TDS-6 đỏ: `docker logs` chứa `failed_query` nguyên văn (`evidence/26`). Thiếu kiểm
toán phát hiện khi viết luật tương quan và nhận ra **không có dữ liệu nào để đếm**.

### 4.2.9 Compliance User Story

*Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi dòng log qua một chặng che dữ liệu
trước khi lưu và mỗi lần đăng nhập thất bại phát một sự kiện đếm được, *để* bí mật
không bị lưu và dò quét không còn vô hình. **Tiêu chí:** 0 dòng Loki chứa mật khẩu
gửi lên; loạt tấn công kích cảnh báo tới alert-sink ≤30 giây.

### 4.2.10 Xử lý (chiều xanh)

`logger.php` thay nguyên văn bằng **dấu vân tay** + mã sự kiện; `logAuthEvent`
phát `AUTH-EVENT`; Promtail thay bí mật bằng `[REDACTED_CREDENTIAL]`; luật Loki
hai chuỗi `sum by (client_ip)`; Alertmanager → alert-sink. Đo đầu-cuối: che đạt
(0 rò), cảnh báo tới sink, độ trễ 15–25s (`evidence/35`). **Mitigate.**

### 4.2.11 Giới hạn

`AUTH-EVENT` chưa mang `client_ip`, nên ở lab luật dò mật khẩu đếm **tổng** số lần
thất bại; triển khai thật cần bổ sung `client_ip`. Ba lỗi cấu hình chỉ lộ khi chạy
thật ghi ở `patches/monitoring/README.md`.

---

## 4.3 Lê Đức Anh (B26CHAT003): quyền của chủ thể dữ liệu không được thực thi

**Nhóm lỗi:** lỗi mã nguồn (kiểm soát truy cập). **Cổng:** TDS-1, TDS-2, TDS-3.

### 4.3.1 Tài sản và vòng đời dữ liệu

| Cột | Mức | Điều khoản |
|---|---|---|
| `users.password`, `users.api_key`, `users.remember_token` | Restricted | GDPR 32 |
| `users.email`, `users.username` | Confidential | GDPR 15, 17 |
| `comments.content`, `privacy_requests.reason` | Confidential | GDPR 17, 5(1)(c) |

Bản xuất đọc các cột này **khi lưu**; bản xoá ghi **khi lưu**.

### 4.3.2 Kịch bản lạm dụng

(a) `/privacy/export?user_id=1` đọc hồ sơ người khác (IDOR). (b) Bản xuất trả cả
`password`, `api_key`, `remember_token`. (c) Yêu cầu xoá chỉ ghi nhận, không xoá.

### 4.3.3 Vị trí trong mã

`pages/privacy_export.php` (định danh từ client; danh sách cột gồm cột xác thực),
`pages/privacy_erase.php` (chỉ INSERT, không DELETE/UPDATE).

### 4.3.4 Phân loại STRIDE và điểm thi hành

| STRIDE | Thuộc tính bị phá | Pha | Cổng lẽ ra phải bắt |
|---|---|---|---|
| Information Disclosure | Bí mật | Test | Chặng 4, TDS-2 |
| Elevation of Privilege | Phân quyền ngang | Test | Chặng 4, TDS-3 |

### 4.3.5 Xếp hạng DREAD

| Trục | Điểm | Căn cứ |
|---|---|---|
| Damage Potential | 9 | Đọc 5 cột Restricted của chủ thể khác |
| Reproducibility | 10 | Đổi một tham số, xác định |
| Exploitability | 8 | Cần một tài khoản, đổi `user_id` |
| Affected Users | 10 | Mọi chủ thể |
| Discoverability | 7 | Tham số lộ trong URL |
| **Tổng** | **44/50** | |

### 4.3.6 Bán kính ảnh hưởng

Qua **tầng ứng dụng**: một tài khoản bất kỳ chạm toàn bộ chủ thể. Sau vá, định
danh lấy từ phiên nên bán kính thu về một chủ thể.

### 4.3.7 Chính sách bị vi phạm

GDPR Điều 15, 17, 5(1)(c), 5(1)(f); CWE-639 (IDOR), CWE-200.

### 4.3.8 Phát hiện (chiều đỏ)

TDS-1/2/3 đỏ: bản xuất chứa `password`; đọc được `user_id` khác; sau yêu cầu xoá
bản ghi vẫn còn (`evidence/26`).

### 4.3.9 Compliance User Story

*Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi điểm cuối quyền chủ thể lấy định
danh **từ phiên**, bản xuất loại bỏ cột xác thực, và yêu cầu xoá thực sự xoá hoặc
ẩn danh hoá, *để* quyền theo Điều 15/17 được thực thi. **Tiêu chí:** TDS-1/2/3 đạt.

### 4.3.10 Xử lý (chiều xanh)

`privacy_export.php` lấy `id` từ `current_user()`, từ chối `user_id` lạ bằng 403,
bỏ cột xác thực, truy vấn tham số hoá. `privacy_erase.php` xoá bình luận, ẩn danh
hoá hồ sơ, xoá thông tin xác thực. TDS-1/2/3 xanh (`evidence/29`). **Mitigate**
(ẩn danh hoá thay vì xoá cứng do ràng buộc toàn vẹn tham chiếu).

### 4.3.11 Giới hạn

Test hành vi chứng minh hành vi **hiện tại** đúng, không chứng minh mọi điểm cuối
tương lai lấy định danh từ phiên. Cần kiểm thử hồi quy cho mỗi điểm cuối mới.

---

## 4.4 Đào Xuân Mạnh (B26CHAT026): bí mật gán cứng, tài khoản CSDL đặc quyền, mật khẩu lưu rõ

**Nhóm lỗi:** lỗi triển khai/cấu hình + dữ liệu khi lưu. **Cổng:**
`policy-p3-*`, luật CREDENTIALS, Conftest, TDS-4.

### 4.4.1 Tài sản và vòng đời dữ liệu

Thông tin xác thực ở ba trạng thái: trong **mã** (giá trị dự phòng hằng), trong
**cấu hình** (compose), và **khi lưu** (`users.password` dạng rõ, Restricted,
GDPR 32).

### 4.4.2 Kịch bản lạm dụng

(a) Mật khẩu dự phòng lộ ngay khi đọc mã nguồn. (b) Ứng dụng kết nối `root@%`
`ALL PRIVILEGES` + `FILE`: lỗi chèn mã bất kỳ thành đọc/ghi toàn CSDL và ghi web
shell. (c) Mật khẩu rõ: rò bảng `users` làm lộ trực tiếp mật khẩu.

### 4.4.3 Vị trí trong mã

`lib/db.php` (dự phòng hằng), `docker-compose.yml` + `db/init.sql.template`
(`root@%`, `ALL PRIVILEGES`, `FILE`), `login.php` (so sánh mật khẩu rõ).

### 4.4.4 Phân loại STRIDE và điểm thi hành

| STRIDE | Thuộc tính bị phá | Pha | Cổng lẽ ra phải bắt |
|---|---|---|---|
| Information Disclosure | Bí mật | Build | Chặng 2, `policy-p3` + CREDENTIALS |
| Elevation of Privilege | Phân quyền | Build | Chặng 2, Conftest compose |
| Spoofing | Xác thực | Test | Chặng 4, TDS-4 |

### 4.4.5 Xếp hạng DREAD

| Trục | Điểm | Căn cứ |
|---|---|---|
| Damage Potential | 10 | root + FILE → toàn CSDL + ghi tệp máy chủ |
| Reproducibility | 10 | Xác định |
| Exploitability | 7 | Cần một chỗ đứng như SQLi để tận dụng |
| Affected Users | 10 | Mọi chủ thể |
| Discoverability | 8 | Bí mật hằng lộ khi đọc mã |
| **Tổng** | **45/50** | |

### 4.4.6 Bán kính ảnh hưởng

| | Trước vá | Sau vá |
|---|---|---|
| Tài khoản | `root@%` | `ilf_app@%` |
| Quyền | `ALL PRIVILEGES ON *.*` + `GRANT OPTION` | 4 quyền DML trên `ilfreight.*` |
| CSDL | 5 (gồm `mysql`) | 1 |
| `FILE` | có, `secure_file_priv` rỗng | không, đã giới hạn |

### 4.4.7 Chính sách bị vi phạm

GDPR Điều 32, 5(1)(f); PCI DSS v4.0.1 mục 8.6.2 và 8.3; *"Hard-coded credentials
in source control are strictly prohibited"*; CWE-798, CWE-256, CWE-269.

### 4.4.8 Phát hiện (chiều đỏ)

`policy-p3-*` + CREDENTIALS bắt bí mật hằng và `root` (`evidence/14`); Conftest
bắt compose đặc quyền (`evidence/06`, `09`); TDS-4 đỏ (`evidence/26`).

### 4.4.9 Compliance User Story

*Là* hệ thống kiểm soát tuân thủ, *tôi cần* mọi bí mật lấy từ biến môi trường
không dự phòng hằng, ứng dụng kết nối bằng tài khoản tối thiểu, mật khẩu băm một
chiều, *để* một lần rò không thành chiếm toàn hệ thống. **Tiêu chí:** `policy-p3`
và CREDENTIALS sạch; Conftest compose đạt; TDS-4 đạt.

### 4.4.10 Xử lý (chiều xanh)

Bí mật từ `.env` không dự phòng; `ilf_app` tối thiểu; `password_hash`/
`password_verify`. Conftest compose đạt (`evidence/10`), TDS-4 xanh
(`evidence/29`). **Mitigate.**

### 4.4.11 Giới hạn

Hai cổng không đồng ý (`evidence/34`): sau vá Conftest đạt nhưng InSpec vẫn đỏ vì
`DB_PASS` đọc được qua `docker inspect`: bí mật còn ở biến môi trường, chưa
chuyển sang Docker secrets/Vault. Nợ kỹ thuật đợt vá 2.

---

## 4.5 Nam (B26CHAT030): cổng chất lượng bị vô hiệu, nhánh không bảo vệ, CRLF

**Nhóm lỗi:** lỗi triển khai/vận hành (CI/CD). **Cổng:** `repo_policy.rego`,
so sánh mã thoát cổng, việc chạy thật.

### 4.5.1 Tài sản và vòng đời dữ liệu

Tài sản là **tính toàn vẹn của chính dây chuyền**: nếu cổng không chặn, mọi cột
nhạy cảm mất lớp bảo vệ các mục trên vừa dựng. Điều này tương ứng với luận điểm
*"Configuration is as dangerous as source code"* (`1.Technical devSecOps Report`).

### 4.5.2 Kịch bản lạm dụng

(a) Cổng dùng biểu thức luôn `false`, nên commit lỗi vẫn qua. (b) Nhánh
`main`/`dev` không bảo vệ, cho phép đẩy thẳng không review. (c) CRLF làm container
không khởi động trên Windows, lỗi vận hành không cổng phân tích nào thấy.

### 4.5.3 Vị trí trong mã

`.github/workflows/devsecops-gate.yml` (biểu thức vô hiệu), thiết lập bảo vệ nhánh
GitHub (`repo_policy.rego` qua `gh api`), `.gitattributes` (ép LF).

### 4.5.4 Phân loại STRIDE và điểm thi hành

| STRIDE | Thuộc tính bị phá | Pha | Cổng lẽ ra phải bắt |
|---|---|---|---|
| Tampering | Toàn vẹn dây chuyền | CI/CD | **CI/CD Pipeline Control** |
| Elevation of Privilege | Đẩy không review | CI/CD | Chặng 1, bảo vệ nhánh |

Hai vector rơi vào cột CI/CD Pipeline Control của `3.Threat Modeling`, mối đe doạ
của chính pha triển khai.

### 4.5.5 Xếp hạng DREAD

| Trục | Điểm | Căn cứ |
|---|---|---|
| Damage Potential | 8 | Một commit lỗi ship ra sản phẩm |
| Reproducibility | 10 | Xác định |
| Exploitability | 5 | Cần quyền commit |
| Affected Users | 10 | Toàn bộ triển khai |
| Discoverability | 4 | Ẩn trong biểu thức workflow |
| **Tổng** | **37/50** | |

### 4.5.6 Bán kính ảnh hưởng

Bán kính là **toàn bộ các lớp bảo vệ khác**: một cổng hỏng vô hiệu hoá kết quả
mục 4.1–4.4. Sau vá, cổng trả mã thoát ≠ 0 khi vi phạm và nhánh `protected: true`.

### 4.5.7 Chính sách bị vi phạm

GDPR Điều 32 (một cổng giả tạo không phải biện pháp phù hợp); **regulatory
non-compliance phải được mô hình hoá như một vector đe doạ kỹ thuật**
(`3.Threat Modeling`); nguyên tắc cấu hình phải được kiểm thử tự động như mã.

### 4.5.8 Phát hiện (chiều đỏ)

So sánh mã thoát: cổng cũ trả 0 dù có vi phạm (`evidence/17`, `23`);
`repo_policy.rego` báo `protected: false` trên nhánh thật (`evidence/11`, `12`);
CRLF làm container không khởi động, chỉ lộ khi chạy thật (`evidence/27`).

### 4.5.9 Compliance User Story

*Là* hệ thống kiểm soát tuân thủ, *tôi cần* cổng trả mã thoát ≠ 0 khi vi phạm,
nhánh bảo vệ bắt buộc review, và chuẩn hoá kết thúc dòng, *để* các biện pháp kỹ
thuật không bị một dòng cấu hình vô hiệu hoá âm thầm. **Tiêu chí:** cổng đỏ khi vi
phạm; `gh api` báo `protected: true`; container khởi động trên Windows và Linux.

### 4.5.10 Xử lý (chiều xanh)

Sửa biểu thức cổng để chặn thật (6 job có chặn); `.gitattributes` ép LF;
`repo_policy.rego` kiểm MFA/bảo vệ nhánh bằng JSON từ `gh api`. Cổng đỏ đúng lúc
(`evidence/23`), container khởi động (`evidence/27`). **Mitigate.**

### 4.5.11 Giới hạn

Bảo vệ nhánh **chưa bật** trên repo của nhóm (cần quyền quản trị GitHub);
`repo_policy.rego` kiểm được nhưng không tự bật được. Ranh giới giữa Policy-as-Code
(kiểm) và hành động quản trị (thực thi).
