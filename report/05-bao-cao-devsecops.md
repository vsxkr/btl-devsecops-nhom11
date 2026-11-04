# BÁO CÁO BÀI TẬP LỚN HỌC PHẦN DEVSECOPS

**Đề tài:** Đánh giá an toàn ứng dụng và bảo vệ dữ liệu người dùng trên pipeline DevSecOps CI/CD của hệ thống InlaneWeb Logistics

| | |
| :--- | :--- |
| **Cơ sở đào tạo** | Học viện Công nghệ Bưu chính Viễn thông |
| **Học phần** | Thực hành DevOps / DevSecOps |
| **Giảng viên hướng dẫn** | TS. Phạm Hoàng Duy |
| **Nhóm thực hiện** | Nhóm 11, lớp M26CQAT01-B |
| **Kho mã nguồn** | `github.com/vsxkr/btl-devsecops-nhom11` |
| **Mốc mã nguồn khảo sát** | `main` tại `94004f3`, trạng thái có khiếm khuyết; `patched` tại `eaf0241`, đi hết năm stage ở run `41817338284` |
| **Thời gian** | Tháng 11 năm 2026 |

---

## PHÂN CÔNG NHIỆM VỤ

*Bảng: Phân công nhiệm vụ và vấn đề an toàn phụ trách*

| TT | Họ và tên | Mã học viên | Vấn đề an toàn phụ trách |
| :---: | :--- | :--- | :--- |
| 1 | Nguyễn Giang Nam (trưởng nhóm) | B26CHAT030 | Kiểm soát thay đổi khai báo mà không có hiệu lực |
| 2 | Nguyễn Đình Hải | B26CHAT010 | Tiêm mã SQL qua hàm bao nội bộ, công cụ không thấy |
| 3 | Đào Xuân Mạnh | B26CHAT026 | Bí mật có giá trị dự phòng hằng, mật khẩu dạng rõ |
| 4 | Lê Đức Anh | B26CHAT003 | Cổng chính sách kiểm sai tệp được triển khai |
| 5 | Nguyễn Phương Mai | B26CHAT025 | Kênh rò rỉ dữ liệu cá nhân qua nhật ký |

## DANH MỤC TỪ VIẾT TẮT

| Viết tắt | Tiếng Anh | Tiếng Việt |
| :--- | :--- | :--- |
| PaC | Policy as Code | Chính sách viết thành mã |
| SaC | Security as Code | Tiêu chí an toàn viết thành mã |
| CWE | Common Weakness Enumeration | Danh mục phân loại điểm yếu phần mềm |
| OWASP | Open Worldwide Application Security Project | Tổ chức về an toàn ứng dụng web |
| XSS | Cross-Site Scripting | Chèn mã kịch bản liên trang |
| PR | Pull Request | Pull request nhánh mã nguồn |
| GDPR | General Data Protection Regulation | Quy định bảo vệ dữ liệu chung của Liên minh châu Âu |
| LogQL | Log Query Language | Ngôn ngữ truy vấn nhật ký của Loki |

---

# MỞ ĐẦU

**Bối cảnh và lý do chọn đề tài.** Trong phát hành liên tục, kiểm định an toàn thủ công mất nhiều ngày không theo kịp mã nguồn hợp nhất nhiều lần mỗi ngày, dễ làm chậm pipeline hoặc bị bỏ qua.

DevSecOps giải quyết mâu thuẫn nhờ kiểm tra an toàn: pipeline dừng ngay stage phát hiện lỗi.

Để kiểm chứng việc dừng pipeline và bảo vệ dữ liệu, Chương 3 ghi nhận quality gate ban đầu báo lỗi nhưng không dừng pipeline; sau hiệu chỉnh, hai run dừng đúng quality gate. SonarQube Community chấm mức A, không ghi nhận lỗ hổng trên hai nhánh, còn Semgrep phát hiện hàng chục vị trí tiêm mã, xác thực hiệu lực từng cổng kiểm soát.

**Mục tiêu và phạm vi.** Đề tài đánh giá an toàn dữ liệu InlaneWeb Logistics từ mã nguồn đến vận hành qua bốn mục tiêu:

- Khảo sát ứng dụng, hai nghiệp vụ dữ liệu cá nhân.
- Đối chiếu môi trường theo chuẩn an toàn tối thiểu.
- Từng thành viên phân tích phát hiện, xử lý, vi phạm, phase DevSecOps, Policy/Security as Code, mã khắc phục.
- Đánh giá khiếm khuyết công cụ tự động bỏ sót.

Báo cáo khảo sát kho `btl-devsecops-nhom11` trên nhánh `main` (commit `94004f3`, khiếm khuyết), `patched` (commit `0c9cdfd`, đã vá) qua run GitHub Actions `40748974196` (`main`), `40748974200` (`patched`).

**Phương pháp và nguồn minh chứng.** Báo cáo dựa trên ba nguồn: số dòng mã thực tế; tệp SonarQube, Semgrep từ Artifacts run `40748974196`, `40748974200`; trạng thái GitHub Actions. Khi có mâu thuẫn, dữ liệu ghi nhận khách quan như mục Kết quả quét thực tế tại Chương 3.

---

# CHƯƠNG 1. ỨNG DỤNG INLANEWEB VÀ DỮ LIỆU CÁ NHÂN CẦN BẢO VỆ

## 1.1 Giới thiệu ứng dụng

InlaneWeb Logistics là cổng vận tải biển cho khách tra cứu, nhân viên cập nhật, quản trị viên xem báo cáo, dùng PHP 8.2 trên Apache, MariaDB 10.11, Docker. Luồng xử lý qua `InlaneWeb/web/src/index.php` tới `pages`; thư mục `lib` gồm `db.php` truy vấn CSDL và `layout.php` kết xuất giao diện.

Ứng dụng cài sẵn tiêm mã SQL với chú thích "CO Y DE LO" tại `lib/db.php:5-8` và biểu ngữ "INTENTIONALLY VULNERABLE, TRAINING ONLY" tại `lib/layout.php:25`; ranh giới thực nghiệm được phân tích cuối Chương 2.

Các tuyến đường chính: `/`, `/news`, `/login`, `/logout` cho trang chủ, tin tức và phiên đăng nhập; `/account` với `/account/update` cho hồ sơ, vận đơn và cập nhật thư điện tử, xử lý tại `account.php` và `account_update.php`; `/ports`, `/ports/{mã}`, `/track`, `/api/track` cho tra cứu cảng biển và vận đơn, tại `ports.php`, `port_detail.php`, `track.php`, `track_api.php`; `/shipments/{id}`, `/shipments/{id}/comments`, `/comments/{id}/delete` cho chi tiết đơn hàng và bình luận, tại `shipment_detail.php`, `comment_add.php`, `comment_delete.php`; `/admin` với `/admin/console` cho khu quản trị, tại `admin_dashboard.php` và `admin_console.php`; `/health` với `/api/health` là điểm kiểm tra sức khỏe cho CI, xử lý tại `index.php:53`.

## 1.2 Mô hình dữ liệu và phân loại mức độ nhạy cảm

Tệp `app/InlaneWeb/db/init.sql` nhánh `main` tạo CSDL `ilfreight` (năm bảng `users`, `ports`, `shipments`, `comments`, `news`) và `dev` (hai bảng `credentials`, `flags`). Vì nhánh `patched` sinh từ `init.sql.template` khác số dòng, mọi dẫn chứng tính theo `main`. Dùng chung máy chủ và tài khoản khiến tiêm mã SQL có thể truy xuất trái phép sang `dev`.

*Bảng: Phân loại dữ liệu theo mức độ nhạy cảm*

| Bảng và trường | Phân loại theo NĐ 13 | Ghi chú hiện trạng |
| :--- | :--- | :--- |
| `users.username`, `users.email` | DLCN cơ bản | |
| `users.password` | Thông tin xác thực | Lưu dạng rõ tại `init.sql:26`, `:34-38` |
| `users.api_key` | Thông tin xác thực | Hiển thị thẳng trên trang hồ sơ tại `account.php:20` |
| `users.remember_token` | Thông tin xác thực | Khai báo tại `init.sql:30`, chưa dùng trong mã |
| `shipments.customer_id` | DLCN cơ bản, gián tiếp | Ranh giới phân quyền giữa các khách hàng |
| `comments.content` | Do người dùng cung cấp | |
| `dev.credentials` | Thông tin xác thực | Băm bằng MD5 tại `init.sql:133-134` |

Cần bảo vệ mật khẩu, khóa API, thẻ phiên tránh kẻ tấn công mạo danh truy cập dữ liệu cá nhân.

## 1.3 Nghiệp vụ thứ nhất: xác thực và quản lý phiên người dùng

### 1.3.1 Luồng xử lý hiện tại

Người dùng gửi biểu mẫu `POST /login` với `username` và `password` theo quy trình:

```php
// pages/login.php:14-29
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

$sql = "SELECT id, username, role FROM users WHERE username = '$username' AND password = '$password'";
$row = query_one($sql);

if ($row) {
    $_SESSION['uid'] = $row['id'];
    header('Location: /account');
    exit;
} else {
    $error = 'Sai tên đăng nhập hoặc mật khẩu.';
}
```

Khi truy vấn hợp lệ, mã người dùng lưu vào `$_SESSION['uid']`; `current_user()` tại `lib/layout.php:4-11` truy vấn theo `uid` phiên; đăng xuất gọi `session_destroy()` tại `pages/logout.php:3`, bộc lộ bốn thiếu sót xác thực tối thiểu.

### 1.3.2 Đối chiếu với yêu cầu của một luồng xác thực đúng

*Bảng: Đối chiếu nghiệp vụ xác thực với yêu cầu tối thiểu*

| Yêu cầu | Hiện trạng | Vị trí |
| :--- | :--- | :--- |
| Mật khẩu phải băm một chiều, so sánh bằng `password_verify()` | So sánh chuỗi thuần trong câu lệnh SQL | `login.php:19` |
| Tham số đầu vào phải tách khỏi câu lệnh | Nối chuỗi trực tiếp | `login.php:19` |
| Tái sinh định danh phiên sau khi đăng nhập thành công | Không gọi `session_regenerate_id()` | `login.php:22-26` |
| Cookie phiên phải đặt cờ `HttpOnly` | Đặt `session.cookie_httponly = Off` | `web/php.ini:12` |

Thành viên 2 và 3 phân tích ba thiếu sót đầu tại Chương 4; thiếu sót thứ tư để client đọc cookie, biến XSS thành nguy cơ đoạt phiên.

Khi đăng nhập, mật khẩu rõ xuất hiện ở thân HTTP, `$_POST`, `login.php:19` và nhật ký lỗi; băm mật khẩu cùng truy vấn tham số hóa sẽ ngăn mật khẩu rõ, ngắt chuỗi rủi ro.

## 1.4 Nghiệp vụ thứ hai: tra cứu vận đơn và bình luận đơn hàng

### 1.4.1 Luồng xử lý

Sau đăng nhập, khách hàng vào `/account` xem vận đơn lọc theo `customer_id`:

```php
// pages/account.php:39-42
$order = $_GET['order'] ?? 'id';
$sql = "SELECT tracking_no, port_code, status FROM shipments WHERE customer_id = "
     . intval($u['id']) . " ORDER BY $order";
```

Khách hàng xem `/shipments/{id}`, bình luận qua `POST /shipments/{id}/comments`; tuyến nhận, xóa tại `index.php:116-119`, `index.php:124-127`. Tuyến `/api/track?tracking=...` tại `index.php:109` trả JSON trạng thái đơn để tra cứu công khai.

### 1.4.2 Ranh giới phân quyền và điểm yếu

Ranh giới ngăn khách hàng A xem vận đơn khách B ở `/account` dùng `WHERE customer_id = intval($u['id'])`. Do `$order` nối thẳng vào `ORDER BY`, `?order=` có thể truy xuất ngoài `WHERE`; Semgrep ghi nhận luồng này từ `account.php:39` tới `account.php:41`.

Ranh giới giữa người viết và xóa bình luận vi phạm tại `pages/comment_delete.php:18`: lệnh `DELETE FROM comments WHERE id = $comment_id` không kiểm tra quyền sở hữu lẫn kiểu `$comment_id`.

Tuyến `/api/track` tra cứu công khai chỉ an toàn khi mã khó đoán; dải mã `ILF1042CN` đến `ILF1046US` tại `init.sql:70-75` tuần tự nên dễ bị duyệt vét.

---
# CHƯƠNG 2. BỐI CẢNH CHÍNH SÁCH VÀ MÔI TRƯỜNG TRIỂN KHAI

## 2.1 Chính sách an toàn thông tin của doanh nghiệp

Chính sách `CS-ATTT-2026` của Công ty Logistics Inlane (hiệu lực 01/11/2026, lưu tại `policy/00-chinh-sach-attt.md`) điều chỉnh InlaneWeb, CSDL khách hàng, container, công cụ phát triển và làm căn cứ cho mọi cổng kiểm soát.

Theo Điều 26, 27 Nghị định 13/2023/NĐ-CP (tương ứng Điều 24, 32 GDPR), bên kiểm soát dữ liệu phải chứng minh thực tế biện pháp kỹ thuật và quản lý phù hợp. Vì vậy, mỗi điều khoản gắn với một cổng tự động và mỗi lượt chạy pipeline đều lưu tệp minh chứng kiểm chứng được.

Vì tình huống nghiệp vụ phát sinh rủi ro nêu tại Chương 4, bảng dưới chỉ giữ điều khoản, cổng thi hành và người phụ trách.

*Bảng: Tám điều khoản chính sách và cổng kiểm soát thi hành tương ứng*

| Mã | Điều khoản | Cổng thi hành | Thành viên |
| :--- | :--- | :--- | :--- |
| CS-01 | Thay đổi vào nhánh phát hành phải qua pull request có người phê duyệt khác tác giả | `policy_guard.py`, `repo_policy.rego`, bảo vệ nhánh | Nam |
| CS-02 | Cấu hình triển khai phải qua cổng chính sách, và phạm vi kiểm tra phủ đúng tệp được triển khai | `compose_security.rego`, `docker_security.rego` | Đức Anh |
| CS-03 | Dữ liệu nhận từ người dùng không được ghép vào câu lệnh truy vấn | `policy-p4-sql-injection` | Hải |
| CS-04 | Bí mật chỉ đến từ nguồn quản lý bí mật, không có giá trị dự phòng dạng hằng | `php-hardcoded-db-password-fallback`, Trivy, InSpec | Mạnh |
| CS-05 | Dữ liệu cá nhân chỉ truyền qua kênh đã khai báo; nhật ký không thuộc số này | TDS-2, TDS-6, pipeline stage che giấu dữ liệu | Mai |
| CS-06 | Tài khoản và tiến trình ở mức quyền tối thiểu, ảnh phải ghim phiên bản | InSpec, `policy-p3-privileged-db-account-default` | Mạnh, Đức Anh |
| CS-07 | Cổng tự động phải chặn, không được chỉ báo cáo | Đối chiếu mã thoát với nội dung tệp kết quả | Nam |
| CS-08 | Mọi ngoại lệ phải có lý do, người phê duyệt đích danh và thời hạn | `policy/exceptions.json`, `ci/check_exceptions.py` | Nam |

Bốn phase DevSecOps thi hành các điều khoản: Plan, Code (CS-01, CS-03, CS-04); Build, Test (CS-02, CS-03, CS-04, CS-07); Release, Deploy (CS-02, CS-06, CS-07); Operate, Monitor (CS-05, CS-06, CS-08). Chương 4 bám sát ánh xạ này theo từng vi phạm và vị trí workflow.

Pull request vi phạm bị cổng tự động chặn. Nếu lỗi lọt sau phát hành, quy trình truy vết thay đổi và người duyệt trong 72 giờ theo CS-01, CS-08, quay lui qua CD ở mục 3.5 rồi bổ sung quy tắc chặn tương tự.

## 2.2 Kiến trúc triển khai

Hệ thống gồm hai cụm Docker Compose chung mạng: cụm ứng dụng `docker-compose.prod.yml` (`inlaneweb-prod`) có `db` (MariaDB), `web` (PHP-Apache), tạo mạng `inlaneweb_net` (`labnet`) dòng 59-62; cụm giám sát `docker-compose.monitoring.yml` (`inlaneweb-monitoring`) có `loki`, `promtail`, `grafana`, `autoheal`, nối qua `external: true` dòng 77-80.

Tách hai cụm giúp cập nhật ứng dụng độc lập và tránh xóa nhầm container khi chạy `docker compose down`. Web chỉ mở `"127.0.0.1:8088:80"` dòng 38 cho Nginx Proxy Manager cấp TLS, còn CSDL không mở cổng ra ngoài.

## 2.3 Đối chiếu với yêu cầu an toàn tối thiểu

Bốn yêu cầu đầu thuộc CS-02; yêu cầu 5, 7, 8, 13, 14 thuộc CS-06; yêu cầu 6 thuộc CS-04; yêu cầu 9 và 12 thuộc CS-02; yêu cầu 10 và 11 thuộc CS-05.

*Bảng: Bảng kiểm yêu cầu an toàn tối thiểu của môi trường triển khai*

| # | Yêu cầu tối thiểu | Kết quả | Dẫn chứng |
| :---: | :--- | :---: | :--- |
| 1 | CSDL không công bố cổng ra ngoài máy chủ | Đạt | `prod.yml`, `db` không có `ports` |
| 2 | Web chỉ lắng nghe trên giao diện nội bộ | Đạt | `prod.yml:38` |
| 3 | Dữ liệu CSDL lưu trên volume bền vững | Đạt | `prod.yml:26-28`, `:64-66` |
| 4 | Dịch vụ có kiểm tra sức khỏe, tự phục hồi | Đạt | `prod.yml:21-25`, `:41-46` |
| 5 | Container không chạy bằng `root` | Không đạt | hai Dockerfile thiếu `USER` |
| 6 | Không gán cứng bí mật trong tệp cấu hình | Không đạt | `prod.yml:15`, `:50`; `monitoring.yml:46`; `init.sql:11` |
| 7 | Tài khoản CSDL của ứng dụng có quyền tối thiểu | Không đạt | `prod.yml:49` dùng `root`; `init.sql:12-13` cấp `ALL PRIVILEGES`, `FILE` |
| 8 | Tài khoản quản trị CSDL không đăng nhập từ mọi máy | Không đạt | `prod.yml:16`; `init.sql:11` |
| 9 | Ảnh container ghim phiên bản | Không đạt | `prod.yml:11`, `:31`; `monitoring.yml:64` |
| 10 | Không hiển thị lỗi hệ thống ra trình duyệt | Không đạt | `web/php.ini:6-7` |
| 11 | Cookie phiên đặt cờ `HttpOnly` | Không đạt | `web/php.ini:12` |
| 12 | Giao diện quản trị giám sát không mở Internet | Không đạt | `monitoring.yml:43` trên `0.0.0.0:3000` |
| 13 | Container thu thập nhật ký chạy quyền hạn chế | Không đạt | `monitoring.yml:26` đặt `user: root` |
| 14 | Không gắn socket Docker với quyền ghi | Không đạt | `monitoring.yml:73` gắn `docker.sock` ghi |

Bốn yêu cầu đầu đạt chuẩn, mười yêu cầu còn lại không đạt. Nghiêm trọng nhất là yêu cầu 12: web mở nội bộ còn Grafana mở ra mọi mạng, hiển thị nhật ký chứa lệnh SQL lỗi như mục 4.6.

## 2.4 Phân biệt lỗ hổng chủ ý với khiếm khuyết ngoài ý muốn

Phục vụ thực hành tiêm mã SQL, một số tiêu chí chủ ý không đạt: yêu cầu 10 qua báo lỗi, yêu cầu 7 đọc ghi tệp bằng `FILE` và không băm mật khẩu; chúng ghi rõ trong mã nguồn, chỉ tác động khi thực hành.

Các yêu cầu 5, 6, 9, 12, 13, 14 là thiếu sót hạ tầng. Riêng yêu cầu 12 lan rộng hậu quả: thực hành không thể biện minh cho việc mở Grafana ra Internet kèm mật khẩu quản trị ở kho công khai.

---
# CHƯƠNG 3. PIPELINE DEVSECOPS VÀ CÁC CỔNG KIỂM SOÁT BẮT BUỘC

## 3.1 Năm stage của pipeline

Pipeline `.github/workflows/devsecops-gate.yml` kích hoạt khi đẩy lên `main`, `dev`, `patched`, mở pull request vào `main`, `dev` hoặc chạy thủ công; stage lỗi sẽ bỏ qua stage sau, chặn hợp nhất pull request.

*Bảng: Năm stage của pipeline, công việc và điều kiện chặn*

| Stage | Job | Công việc | Điều kiện chặn |
| :---: | :--- | :--- | :--- |
| 1 | `stage1_policy_guard`, `stage1_policy_as_code` | Quy ước commit và pull request, cổng CS-01, Conftest trên Dockerfile, Compose, quản trị | Có `deny`, vi phạm quy ước, hoặc đẩy trực tiếp không có ngoại lệ |
| 2 | `stage2_security_as_code` | SonarQube với quality gate; Semgrep với bộ P1 đến P5 của nhóm và bốn bộ công khai; cú pháp PHP | Quality gate trả `ERROR` |
| 3 | `stage3_supply_chain` | SBOM CycloneDX hai ảnh nền, quét bí mật, cổng CVE | Có CVE CRITICAL trên ảnh nền |
| 4 | `stage4_test_driven_security` | Test hành vi trên ứng dụng đang chạy, InSpec trên container | Một phép kiểm hành vi hoặc tuân thủ thất bại |
| 5 | `stage5_cd_release` | Phát hành, xác minh sau phát hành, quay lui khi thất bại | Container không khỏe, hoặc phép kiểm sau phát hành thất bại |

Ràng buộc `needs` định thứ tự: stage 2 cần hai job stage 1, stage 3 cần Policy as Code, stage 4 cần stage 2, stage 5 cần stage 2, 3, 4. Nhờ `if: always()`, job tổng kết trả mã khác 0 khi lỗi; để phản ánh đúng cổng, từng bước phải giữ mã thoát như mục 3.6.

Stage 5 chỉ chạy trên nhánh `patched` qua `if: github.ref == 'refs/heads/patched'`, vì `main` giữ khiếm khuyết để đánh giá thay vì phát hành.

## 3.2 Policy as Code tại stage 1

Stage 1 quản trị quy trình bằng mã qua biểu thức chính quy với ba cấp: commit theo Conventional Commits, pull request vào `dev` mang mã thành viên, pull request vào `main` đánh số phiên bản phát hành.

Bản đầu `ci/policy_guard.py` hở phạm vi do `validate_push_event()` chỉ kiểm tra thông điệp mà không chặn đẩy vào nhánh phát hành theo CS-01. Bản hiện tại bổ sung cổng CS-01 cùng ngoại lệ theo CS-08:

```python
# ci/policy_guard.py, co che ngoai le co thoi han
exception, rejected = find_valid_exception("CS-01", branch)
if exception is not None:
    print(f"[DAT, CO NGOAI LE] ... ngoai le {exception['id']}, "
          f"het han {exception['expires']}, "
          f"nguoi phe duyet {exception['approved_by']}.")
    return 0
```

Một bản ghi ngoại lệ chỉ có hiệu lực khi đủ năm trường `clause`, `branch`, `reason`, `approved_by`, `expires`, và `expires` còn hiệu lực tính theo ngày chạy. Hết hạn là hết hiệu lực, cơ chế chặn tự động tái kích hoạt. Hook `.githooks/commit-msg` chạy cùng mã trên máy lập trình viên và được chuyển sang fail-closed: khi máy không có Python, hook trả mã khác 0 thay vì bỏ qua kiểm tra.

Lớp thứ hai của stage 1 là Conftest. Bộ test của chính quy tắc phải đạt trước khi quy tắc được dùng làm cổng, vì một quy tắc sai cú pháp vẫn chạy và vẫn trả về kết quả không có vi phạm. Bước đầu tiên của job do đó chạy `conftest verify -p policy/` và đối chiếu dòng tổng kết bằng `grep`.

## 3.3 Security as Code tại stage 2

Stage 2 chạy hai công cụ phân tích tĩnh theo hai cơ chế khác nhau.

Với SonarQube, runner dựng máy chủ tạm quét rồi hủy; tệp `ci/sonarqube-quality-gate.json` đặt năm điều kiện lỗi: `security_rating` > 1, `reliability_rating` > 1, `sqale_rating` > 1, `security_hotspots_reviewed` < 100, `duplicated_lines_density` > 10, xác lập Security as Code qua kho thay cho giao diện.

Với Semgrep, pipeline chạy bộ `p/owasp-top-ten`, `p/php`, `p/security-audit`, `p/cwe-top-25` cùng `ci/semgrep-policy-php.yml` (tám quy tắc P1 đến P5), `ci/semgrep-local-rules.yml` (hai quy tắc chống gán cứng bí mật); thiếu cờ `--error`, Semgrep trả mã 0 dù có phát hiện.

Quy tắc chống gán bí mật dự phòng được viết lại nhằm phủ bốn cú pháp cùng ba nguồn biến môi trường, nội dung chi tiết nằm ở mục 4.4.3.

Quy tắc `compose-hardcoded-mysql-root-password` từng hở phạm vi: mục `paths.include` liệt kê ba mẫu không khớp hai tệp compose triển khai thực tế, khiến quy tắc bị bỏ qua; phân tích và cách khắc phục nằm ở mục 4.5.

## 3.4 Chuỗi cung ứng, Test-Driven Security và Compliance as Code

Stage 3 xử lý ba tác vụ trên ảnh `php:8.2-apache`, `mariadb:10.11`: lập SBOM CycloneDX kiểm kê thành phần, quét bí mật `app/`, đặt cổng CVE. Vì Trivy trả mã 0 nếu thiếu `--exit-code 1` và pipe làm mất mã thoát, bước này lưu mã bằng `${PIPESTATUS[0]}` từng ảnh để đối chiếu tường minh.

Stage 4 chuyển từ đọc mã sang quan sát hành vi: script `tests/security/run.sh` dựng ứng dụng, chờ sẵn sàng, chạy sáu kiểm tra và xác minh nhật ký không chứa truy vấn nguyên văn. InSpec xác thực container đang chạy thay vì khai báo trên tệp, thể hiện Compliance as Code khi kiểm tra trực tiếp hệ thống.

## 3.5 CD tại stage 5: phát hành có xác minh và quay lui

Stage 5 (CD) chỉ chạy trên nhánh vá khi ba stage trước đạt, gồm năm bước với bước 4 quyết định.

| Bước | Tác vụ | Kết quả |
| :---: | :--- | :--- |
| 1 | Ghi lại mốc đang chạy để có điểm quay lui | `evidence/ci-14-cd-rollback-point.txt` |
| 2 | Phát hành lên môi trường đích và chờ kiểm tra sức khỏe báo khỏe | `evidence/ci-15-cd-deploy.txt` |
| 3 | Xác minh sau phát hành bằng InSpec trên container vừa phát hành | `evidence/ci-16-cd-postdeploy-inspec.txt` |
| 4 | Quay lui khi xác minh thất bại, rồi trả mã khác 0 | `evidence/ci-17-cd-rollback.txt` |
| 5 | Kết luận phát hành khi xác minh đạt | `evidence/ci-18-cd-release-ok.txt` |

Bước xác minh chạy lại phép kiểm tuân thủ stage 4 trên container đích thay vì kiểm thử; chạy cùng phép kiểm trên hai môi trường là cách duy nhất phát hiện sai lệch khi phát hành.

Với `if: steps.verify.outcome == 'failure'`, bước quay lui chỉ chạy khi xác minh thất bại; sau khi hoàn nguyên môi trường, bước trả mã khác 0 để run thất bại, chặn bản phát hành lỗi.

*Bảng: Năm lượt chạy liên tiếp và cổng chặn tại mỗi lượt*

| Run | Cổng chặn | Nguyên nhân |
| :--- | :--- | :--- |
| `41810605290` | không tạo được job nào | khóa `administration` không tồn tại trong khối `permissions`, tệp workflow không phân tích được |
| `41810794218` | stage 1, Compose và quản trị | mã thoát đã được giữ lại, nên vi phạm thật làm bước thất bại |
| `41812598120` | stage 1, Policy Guard | cổng CS-01 từ chối dạng scope nhiều phần cách nhau bởi dấu phẩy, dạng kho mã nguồn đang dùng |
| `41814045236` | stage 4, InSpec | ảnh `chef/inspec` không có docker CLI, nên profile báo lỗi thay vì đánh giá |
| `41815649692` | stage 4, bộ test hành vi | tệp bí mật để quyền `0600`, hai container không đặc quyền đều không đọc được |
| `41817338284` | không cổng nào | toàn bộ năm stage đạt, kể cả stage CD |

Năm lượt chặn đầu đều là phát hiện thật, với bốn lượt từ cơ chế kiểm soát thay vì ứng dụng. Trình tự này chứng minh cổng hiệu lực: một pipeline thiếu kiểm soát không thể chặn năm lần liên tiếp do năm nguyên nhân khác nhau.

Tại run `41817338284`, stage CD chạy đủ trình tự, container đạt trạng thái khỏe ở lần kiểm thứ ba. Xác minh sau phát hành đạt 7 control, 12 phép kiểm, 0 thất bại trên container vừa phát hành. Bước quay lui skipped do không thỏa `if: steps.verify.outcome == 'failure'`, đúng thiết kế. Bản ghi tại `evidence/36-cd-phat-hanh-xac-minh-quay-lui.txt` và artifact `evidence-cd-release`.

## 3.6 Hai khiếm khuyết của chính cơ chế chặn

Do CS-07 coi việc báo đạt mà không kiểm tra vi phạm nặng hơn thiếu cổng, hai phát hiện của pipeline thay vì ứng dụng được giữ nguyên trạng.

Ở khiếm khuyết đầu tiên, pipeline khai báo `ENFORCE_QUALITY_GATE: ${{ inputs.enforce_quality_gate || 'false' }}`. Do `inputs` chỉ có khi chạy thủ công, biểu thức luôn trả `'false'` ở mọi run tự động, khiến quality gate chỉ báo cáo thay vì dừng an toàn theo mặc định `"true"` của `ci/sonarqube.py`. Khắc phục bằng cách không ghi đè biến đó.

Phát hiện ngày 04/11/2026 khi đối chiếu với tệp kết quả, khiếm khuyết nghiêm trọng hơn là năm bước workflow dùng `tee` không khai báo `shell`. Khi đó GitHub Actions chạy `bash -e {0}` thiếu `-o pipefail`, khiến mã thoát theo `tee` luôn bằng 0; ba cổng chính sách stage 1 và hai cổng stage 4 không chặn dù có FAIL. Bảng đối chiếu cùng mã thoát đầy đủ nằm ở mục 4.2.

Để sửa, thêm `shell: bash` cho mọi bước dùng pipe nhằm chạy `bash --noprofile --norc -eo pipefail {0}`. Tệp bộc lộ thiếu nhất quán: cổng CVE giữ mã thoát bằng `${PIPESTATUS[0]}`, còn bước kiểm cú pháp PHP đối chiếu lại bằng `grep`.

## 3.7 Kết quả quét thực tế trên hai nhánh

Pipeline đối chứng `main` `94004f3` (run `40748974196`, còn lỗi) với `patched` `0c9cdfd` (run `40748974200`, đã vá), trích từ `sonarqube/metrics.json`, `sonarqube/quality-gate.json`, `ci-05-semgrep.json` thuộc artifact `evidence-security-as-code`.

Ba chỉ số xếp hạng báo lỗi khi lớn hơn 1, còn `duplicated_lines_density` báo lỗi khi lớn hơn 10.

*Bảng: Chỉ số SonarQube của hai nhánh*

| Chỉ số | `main` (`94004f3`) | `patched` (`0c9cdfd`) | Trạng thái |
| :--- | ---: | ---: | :---: |
| `reliability_rating` | 3 | 3 | ERROR |
| `security_rating` | 1 | 1 | OK |
| `sqale_rating` | 1 | 1 | OK |
| `duplicated_lines_density` | 0,0 | 0,0 | OK |
| `vulnerabilities` | 0 | 0 | |
| `security_hotspots` | 0 | 0 | |
| `bugs` và `code_smells` | 10 và 15 | 8 và 19 | |
| Số tệp và số dòng mã | 24 và 734 | 24 và 876 | |

SonarQube ghi 25 lỗi trên `main`, 27 trên `patched` (`Web:InputWithoutLabelCheck`, `Web:S6853`, `php:S100`, `php:S113`, `php:S2003`, `php:S121`). Dù Semgrep bắt 12 lỗi tiêm mã SQL trên `main`, cả hai đều có `vulnerabilities` = 0, `security_hotspots` = 0, `security_rating` = 1 (mức A); quality gate trượt do `reliability_rating` = 3.

Do không phân tích xuyên hàm, tệp, SonarQube Community không nối truy vấn `pages` sang `lib/db.php`; quality gate đạt không bảo đảm an toàn khi hai nhánh đều 0 lỗ hổng, dù Semgrep giảm từ 64 xuống 46 phát hiện.

Phân bố 64 phát hiện trên nhánh `main` ở run `40748974196`: `tainted-sql-string` 19 và `policy-p4-sql-injection` 12 vị trí tiêm mã SQL, CWE-89 và OWASP A03:2021; `policy-p2-client-supplied-identity` 8 vị trí định danh lấy từ client, OWASP A01:2021; `policy-p1-unrestricted-write` 6 vị trí ghi không kiểm quyền; `echoed-request` 5 vị trí XSS, CWE-79, từ bộ công khai `p/php`; `policy-p5-statement-logged-verbatim` 4 và `policy-p4-error-detail-to-response` 4, ghi nhật ký nguyên văn và lộ chi tiết lỗi, OWASP A09 và A05; còn 6 phát hiện thuộc các quy tắc bí mật gán cứng và container chạy `root`, CWE-798 và CWE-250.

Trên `main`, quy tắc tự viết bắt 64 lỗi ERROR; `patched` còn 46 (`policy-p4-sql-injection` còn 8, `tainted-sql-string` còn 14), chủ sở hữu, lý do hoãn tại `patches/README.md`.

---
# CHƯƠNG 4. NĂM VẤN ĐỀ AN TOÀN THEO PHÂN CÔNG THÀNH VIÊN

## 4.1 Bảng tổng hợp và khuôn trình bày

Mỗi thành viên phụ trách một vấn đề theo ba ràng buộc: vi phạm chính sách, không tự bộc lộ trước công cụ tự động, giới hạn khắc phục.

*Bảng: Tổng hợp năm vấn đề an toàn của năm thành viên*

| Thành viên | Vấn đề | Phase | Điều khoản | Dạng chứng minh |
| :--- | :--- | :--- | :--- | :--- |
| Nguyễn Giang Nam | Kiểm soát thay đổi khai báo mà không hiệu lực; chính cổng cũng không chặn | Plan, Code | CS-01, CS-07, CS-08 | Policy as Code |
| Nguyễn Đình Hải | Tiêm mã SQL qua hàm bao nội bộ, bộ quy tắc có sẵn không phát hiện | Code, Build | CS-03, CS-05 | Security as Code |
| Đào Xuân Mạnh | Bí mật ngoài kho mã nguồn nhưng vẫn nhận giá trị mặc định dạng hằng | Code, Build | CS-04, CS-06 | SaC và CaC |
| Lê Đức Anh | Cổng chính sách kiểm tra không đúng tệp được triển khai | Release, Deploy | CS-02, CS-06 | PaC và CaC |
| Nguyễn Phương Mai | Năm mắt xích hợp thành kênh rò rỉ; che giấu xung đột với yêu cầu phát hiện | Operate, Monitor | CS-05, CS-08 | TDS |

Năm vấn đề gồm hai nhóm: ba về mã nguồn, quy trình phát triển; hai về triển khai, vận hành.

Mỗi mục gồm sáu trường: tình huống nghiệp vụ và điều khoản ràng buộc; vấn đề và nguyên nhân không tự bộc lộ; môi trường phải dựng cùng mã dùng để phát hiện; chứng minh hai chiều kèm mã thoát; ràng buộc khắc phục; cách xử lý, vị trí trên workflow và giới hạn kiểm chứng.

Báo cáo dẫn Nghị định 13/2023/NĐ-CP (hết hiệu lực từ 01/01/2026, thay bởi Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15, Nghị định 356/2025/NĐ-CP); do đổi số hiệu và chưa đối chiếu bản gốc Luật 91/2025/QH15, báo cáo không dẫn điều khoản cụ thể.

## 4.2 Thành viên 1, Nguyễn Giang Nam, B26CHAT030: kiểm soát thay đổi được khai báo nhưng không có hiệu lực thi hành

### 4.2.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Khi phát hành ngoài giờ, cấu hình Loki, Grafana bị đẩy thẳng lên nhánh phát hành thay vì mở pull request, tác động luồng nhật ký, ảnh hưởng trực tiếp dữ liệu cá nhân.

Theo CS-01, thay đổi nhánh phát hành phải qua pull request, người duyệt khác tác giả, qua cổng tự động, truy vết tác giả, lý do; CS-07 buộc cổng chặn theo GDPR Điều 24, 32(1) (Điều 26, 27 Nghị định 13/2023/NĐ-CP); thiếu pull request làm mất hồ sơ duyệt khiến nghĩa vụ giải trình 72 giờ không thể bù đắp kỹ thuật.

### 4.2.2 Vấn đề và nguyên nhân không tự bộc lộ

Dù khai báo ba lớp kiểm soát cho CS-01, kho mã không ngăn được tình huống trên.

Lớp đầu `ci/policy_guard.py` có `validate_push_event()` chỉ đối chiếu định dạng commit, pull request mà không từ chối đẩy trực tiếp vào nhánh phát hành.

Lớp bảo vệ nhánh GitHub cũng để lọt: API ngày 04/11/2026 cho thấy `main` có `protected: false`, cho phép đẩy trực tiếp, cưỡng bức bất chấp script kiểm tra.

Cổng kiểm soát quản trị CI (lớp thứ ba) dù chạy đúng quy tắc và ghi nhận vi phạm vẫn báo thành công do lệnh:

```yaml
# .github/workflows/devsecops-gate.yml, ban truoc khi sua
./conftest test "branch-${b}.json" -p policy/ --namespace repo --no-color \
  | tee -a evidence/ci-03-branch-protection.txt
```

Bước `run` không khai báo `shell`, nên GitHub Actions dùng `bash -e {0}`, cấu hình mặc định này không bật `-o pipefail`. Mã thoát của cả chuỗi lệnh pipe là mã thoát của `tee`, luôn bằng 0. Conftest trả về 1 nhưng bước vẫn ghi nhận trạng thái thành công.

*Bảng: Trạng thái bước trên CI đối chiếu với nội dung tệp kết quả của chính bước đó, run `40748974196`*

| Bước | Tệp kết quả do bước sinh ra | Nội dung tệp | Trạng thái bước |
| :--- | :--- | :--- | :---: |
| Chính sách lớp build, Dockerfile | `ci-01-dockerfile.txt` | 4 dòng FAIL cho mỗi Dockerfile | success |
| Chính sách lớp triển khai, Compose | `ci-02-compose.txt` | 9 failures cho `docker-compose.yml`, 9 cho `prod.yml`, 13 cho `monitoring.yml` | success |
| Chính sách lớp quản trị, bảo vệ nhánh | `ci-03-branch-protection.txt` | 2 dòng FAIL, mỗi run ghi `1 failure` | success |

Job `stage1_policy_as_code` trả về trạng thái thành công trong cả hai run `40748974196` và `40748974200`. Hai bước ở stage 4 cũng mất mã thoát theo đúng cơ chế đó. Khiếm khuyết này không tự bộc lộ vì ba nguyên nhân đồng thời: đây là tình trạng thiếu một kiểm soát chứ không phải một đoạn mã sai, nên phân tích tĩnh không có mẫu nào để đối chiếu; đối tượng cần kiểm tra là trạng thái của hệ thống lưu trữ kho mã nguồn, không nằm trong bản sao làm việc; và biểu hiện của nó là trạng thái thành công, một tín hiệu giả khiến khiếm khuyết bị bỏ qua.

Đối chứng nằm ngay trong cùng tệp workflow: bước cổng CVE giữ mã thoát bằng `${PIPESTATUS[0]}` và bước kiểm tra cú pháp PHP đối chiếu lại bằng `grep`, nên hai bước đó thực thi ngăn chặn đúng chức năng. Khiếm khuyết vì vậy xuất phát từ việc áp dụng thiếu nhất quán một nguyên tắc đã biết về cấu hình shell.

### 4.2.3 Môi trường phải dựng và mã dùng để phát hiện

Phép kiểm chứng phải truy vấn đúng hệ thống đang nắm kiểm soát rồi giao cho một policy engine đánh giá dữ liệu trả về: truy vấn hệ thống danh tính, không căn cứ trên một khai báo tĩnh trong kho mã nguồn. Riêng lớp thứ ba cần một phép kiểm chứng thứ hai, đối chiếu trạng thái của bước trên CI với nội dung tệp kết quả do chính bước đó sinh ra.

*Bảng: Thành phần môi trường cần dựng cho phép kiểm chứng lớp quản trị*

| Thành phần | Bản dùng | Vai trò |
| :--- | :--- | :--- |
| GitHub REST API, endpoint `branches/{branch}` | token đọc cấu hình kho mã nguồn | Căn cứ duy nhất về trạng thái bảo vệ nhánh |
| Conftest, namespace `repo` | 0.71.1, bản ghim, đối chiếu mã băm | Công cụ thực thi chính sách khai báo |
| API Actions, endpoint `runs/{id}/jobs` và artifact của run | run thực tế | Đối chiếu trạng thái bước với nội dung tệp kết quả |

Trình tự bắt buộc gồm ba bước: tải Conftest bản ghim và đối chiếu mã băm; chạy `conftest verify -p policy/` để bộ test của quy tắc đạt trước; chỉ sau đó mới dùng quy tắc để đánh giá dữ liệu thực tế. Bước thứ hai mang tính bắt buộc, vì một quy tắc sai cú pháp vẫn chạy và vẫn trả về kết quả không có vi phạm.


Chính sách quản trị viết thành ba quy tắc khai báo: nhánh không có bảo vệ, nhánh có bảo vệ nhưng không bắt buộc status check, và nhánh thiếu đúng cổng kiểm soát cần có trong danh sách status check bắt buộc.

```rego
# policy/repo_policy.rego:22-27
required_check_patterns := {"Policy Guard", "SonarQube", "Semgrep"}

deny contains msg if {
	not input.protected == true
	msg := sprintf("GOVERNANCE: branch '%s' has no protection rule; direct pushes and force pushes are possible.", [input.name])
}
```

Cơ chế ngoại lệ theo CS-08 viết thành một phép kiểm thời hạn trong `ci/policy_guard.py`: một lần đẩy trực tiếp vào nhánh phát hành chỉ được chấp nhận khi có bản ghi ngoại lệ đủ năm trường `clause`, `branch`, `reason`, `approved_by`, `expires`, và `expires` còn hiệu lực tính theo ngày chạy.

### 4.2.4 Chứng minh hai chiều

Bộ quy tắc rego cho hai mã thoát khác nhau trên hai đầu vào khác nhau, tại `evidence/11-repo-branch-main-thucte.txt` và `evidence/13-repo-branch-compliant.txt`:

```
$ conftest test evidence/api/branch-main-slim-truoc.json -p policy/ --namespace repo
FAIL - GOVERNANCE: branch 'main' has no protection rule
3 tests, 2 passed, 0 warnings, 1 failure, 0 exceptions        exit=1

$ conftest test fixtures/branch-protection-compliant.json -p policy/ --namespace repo
3 tests, 3 passed, 0 warnings, 0 failures, 0 exceptions       exit=0
```

Cổng ngoại lệ được kiểm trên ba kịch bản, kết quả tại `evidence/20-policy-guard-cs01.txt`:

*Bảng: Ba kịch bản của cổng CS-01 và mã thoát tương ứng*

| Kịch bản | Kết luận của cổng | Mã thoát |
| :--- | :--- | :---: |
| Đẩy trực tiếp vào `main`, có ngoại lệ `EX-2026-01` còn hạn đến 31/12/2026 | Đạt, có ngoại lệ, ghi rõ người phê duyệt | 0 |
| Cùng lần đẩy đó, ngoại lệ đã hết hạn từ 01/01/2025 | Chặn, nêu tên ngoại lệ bị loại bỏ và lý do hết hạn | 1 |
| Thay đổi đến từ một pull request đã hợp nhất | Đạt, không cần ngoại lệ | 0 |

Hai chiều của chính cổng thì đo trên hệ thống thật, không trên fixture. Trước khi sửa, run `40748974196` và `40748974200` cho trạng thái bước là thành công trong khi tệp kết quả chứa dòng FAIL. Sau khi khai báo `shell: bash` và bật bảo vệ nhánh, cùng bộ quy tắc đó cho kết quả đổi dấu đúng ba lần liên tiếp:

*Bảng: Trạng thái cổng quản trị qua ba lượt đo trên hệ thống thật*

| Lượt | Trạng thái nhánh `main` | Kết quả Conftest | Trạng thái bước |
| :--- | :--- | :--- | :---: |
| run `40748974196`, trước khi sửa | `protected: false` | 1 failure | success, sai |
| run `41810794218`, sau khi giữ mã thoát | `protected: false` | 1 failure | failure, đúng |
| run `41812598120`, sau khi bật bảo vệ nhánh | `protected: true` | 0 failure | success, đúng |

Lượt thứ hai là lượt quan trọng nhất: cùng một trạng thái hệ thống, cùng một bộ quy tắc, nhưng trạng thái bước đổi từ thành công sang thất bại. Khác biệt duy nhất là một dòng khai báo `shell`, nên đó là bằng chứng trực tiếp rằng khiếm khuyết nằm ở cơ chế chuyển mã thoát chứ không ở quy tắc hay ở dữ liệu.

### 4.2.5 Ràng buộc trong quá trình khắc phục

Việc khắc phục vượt quá phạm vi một commit, do bốn ràng buộc tác động đồng thời.

Ràng buộc thẩm quyền: bật bảo vệ nhánh là thao tác trong phần thiết lập kho mã nguồn, và chỉ chủ kho mã nguồn có thẩm quyền thực hiện. Policy as Code ở đây chỉ kiểm chứng chứ không thi hành được kiểm soát, nên bản vá có một phần kỹ thuật và một phần hành chính.

Ràng buộc phạm vi token: khối `permissions` của `GITHUB_TOKEN` không có khóa `administration`. Lần thử khai báo `administration: read` làm cả tệp workflow không phân tích được, và GitHub tạo một run thất bại với 0 job, run `41810605290`. Hệ quả là trường `protection` của một nhánh không đọc được bằng token mặc định của workflow, nên trong CI chỉ quy tắc thứ nhất còn hiệu lực.

Ràng buộc độ tin cậy của điểm thi hành: hook `.githooks/commit-msg` chạy trên máy lập trình viên, và bản trước trả về 0 kèm một dòng cảnh báo khi máy không có Python, tức bỏ qua kiểm tra mà vẫn báo thành công. Lập trình viên cũng có thể vô hiệu hóa hook bằng `git commit --no-verify`.

Ràng buộc giữa chính sách và phương pháp đánh giá: nhánh `main` giữ hệ thống ở trạng thái có khiếm khuyết để làm đối tượng đánh giá, trong khi CS-01 yêu cầu mọi thay đổi vào nhánh phát hành phải qua pull request. Giải pháp là một ngoại lệ có hồ sơ và có thời hạn theo CS-08 thay vì nới lỏng chính sách một cách tùy tiện.

### 4.2.6 Cách xử lý, vị trí trên workflow và giới hạn kiểm chứng

Bản vá gồm bốn thay đổi theo thứ tự hiệu lực giảm dần: khai báo `shell: bash` cho mọi bước có chuỗi lệnh pipe để ba cổng ở stage 1 và hai cổng ở stage 4 thực thi ngăn chặn; bổ sung `ci/check_branch_payload.py` kiểm tra cấu trúc phản hồi API trước khi đánh giá; chỉ đánh giá những nhánh vừa thuộc diện chính sách vừa thực sự tồn tại; và chuyển hook sang fail-closed.

*Bảng: Bốn lớp thi hành của cùng một điều khoản chính sách*

| Lớp | Nơi thi hành | Phase | Cơ chế |
| :--- | :--- | :--- | :--- |
| Phản hồi sớm | máy lập trình viên | Code | hook `commit-msg`, fail-closed |
| Quy ước thay đổi, cổng CS-01 | CI | Code | `policy_guard.py` trên payload sự kiện, có ngoại lệ theo thời hạn |
| Quản trị kho mã nguồn | CI | Plan, Code | `repo_policy.rego` đánh giá JSON lấy từ API |
| Chặn hợp nhất | GitHub | Plan | bảo vệ nhánh, kiểm chứng được nhưng không thi hành được từ mã |

Một điều khoản chính sách cần nhiều điểm thi hành, và điểm thi hành càng gần người viết mã càng cho phản hồi nhanh, đồng thời càng ít tin cậy. Lớp duy nhất thực sự ngăn được một lần hợp nhất không đạt lại nằm ngoài kho mã nguồn, do đó lớp này phải được kiểm chứng liên tục bằng lớp thứ ba, và lớp thứ ba phải tự chứng minh được khả năng ngăn chặn của chính nó.

**Giới hạn kiểm chứng.** Chính sách quản trị chỉ đọc được trạng thái cấu hình. Cổng không xác minh được một thành viên có thực sự dùng xác thực hai yếu tố, cũng không xác minh được người phê duyệt pull request có đọc mã hay chỉ phê duyệt hình thức. Phần đó thuộc phạm vi quản trị nhân sự. Kết quả kiểm chứng còn phụ thuộc phạm vi token như nêu ở mục 4.2.5, nên phạm vi token là một phần của phép kiểm chứng, không phải chi tiết kỹ thuật phụ.

## 4.3 Thành viên 2, Nguyễn Đình Hải, B26CHAT010: tiêm mã SQL đi qua hàm bao nội bộ

### 4.3.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Khách tra cứu vận đơn, cảng biển không cần đăng nhập nhận chuỗi tự do rồi hiển thị dữ liệu người nhận từ cơ sở dữ liệu.

CS-03 cấm ghép dữ liệu người dùng vào truy vấn; CS-05 buộc dữ liệu cá nhân chỉ rời hệ thống qua khai báo (GDPR Điều 5(1)(f), 32; Điều 26, 27 Nghị định 13/2023/NĐ-CP).

### 4.3.2 Vấn đề và nguyên nhân không tự bộc lộ

Khác tiêm mã SQL thông thường, điểm thực thi là hàm bao `query()` (`lib/db.php`) thay vì `mysqli_query`, nhận chuỗi nhiễm `$_GET` qua biến trung gian.

```php
// pages/ports.php:12, 24, 27
$q = $_GET['q'] ?? '';
$sql = "SELECT code, city, country, volume FROM ports WHERE code LIKE '%$q%'";
$res = query($sql);   // diem thuc thi nam o lib/db.php, khong phai o day
```

Bảng bốn cột cho phép `UNION SELECT` bốn cột trích xuất mọi bảng đọc được, gồm `users` chứa mật khẩu rõ, khóa API; thiệt hại tăng do kết nối `root` toàn quyền (`prod.yml:49`), lỗi SQL xuất thẳng HTTP (`lib/db.php:48-49`).

Hai biến thể phức tạp hơn: `pages/track_api.php` trả JSON không in kết quả khiến khai thác thời gian không lưu vết; `pages/shipment_detail.php` thiếu kiểm tra quyền sở hữu, cho phép đăng nhập đọc đơn hàng chủ thể khác không cần tiêm mã.

Do tên hàm bao, `p/php` và SonarQube Community không nối source với sink tự định nghĩa ở tệp khác; hai nhánh đều ghi `vulnerabilities` = 0, `security_hotspots` = 0, `security_rating` = 1 (mức A).

### 4.3.3 Môi trường phải dựng và mã dùng để phát hiện

Môi trường gồm Semgrep 1.182.1 bật taint mode cùng quy tắc tự viết; SonarQube Community đối chứng CI; fixture PHP vi phạm, đã vá; cơ sở dữ liệu hai người dùng kiểm tra quyền sở hữu.

Cùng lượt chạy đối chứng làm rõ giới hạn: trên cùng mã nguồn, Semgrep bắt 12 vị trí tiêm mã SQL, SonarQube báo 0 lỗ hổng.


Quy tắc tự viết khai báo nguồn không tin cậy, điểm thực thi, khử nhiễm, gán `query(...)` làm sink vì luật chuẩn bỏ qua hàm bao.

```yaml
# ci/semgrep-policy-php.yml, quy tac policy-p4-sql-injection
mode: taint
pattern-sources:
  - pattern-either:
      - pattern: $_GET[...]
      - pattern: $_POST[...]
      - pattern: $_REQUEST[...]
      - pattern: $_COOKIE[...]
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: query($SINK, ...)
          - pattern: query_one($SINK, ...)
          - pattern: mysqli_query($CONN, $SINK, ...)
      - focus-metavariable: $SINK
pattern-sanitizers:
  - pattern: mysqli_real_escape_string(...)
  - pattern: intval(...)
```

### 4.3.4 Chứng minh hai chiều

Cặp fixture chạy ngay trong pipeline tại bước chứng minh cặp fixture hai chiều, kết quả ở `evidence/ci-06-fixture-vulnerable.txt` và `evidence/ci-07-fixture-patched.txt`. Bước này so sánh hai mã thoát bằng biến tường minh thay vì dựa vào mã thoát của chuỗi lệnh pipe:

```
ban co y sai: exit=1 (ky vong 1)
ban da va    : exit=0 (ky vong 0)
```

Đối chứng âm nằm trong cùng lượt chạy: trên cùng mã nguồn, SonarQube báo 0 lỗ hổng và `security_rating` mức A, trong khi quy tắc tự viết báo vi phạm ở 12 vị trí trên nhánh `main`. Số phát hiện giảm còn 8 trên nhánh `patched`, phần còn lại thuộc đợt vá thứ hai có chủ đích.

### 4.3.5 Ràng buộc trong quá trình khắc phục

Ràng buộc thứ nhất là thứ tự vá. Phép kiểm TDS-6 khẳng định luồng nhật ký không chứa nguyên văn câu lệnh truy vấn. Để khẳng định được điều đó phải có một truy vấn lỗi thực tế. Vá hết các điểm còn lại trong cùng một đợt làm phép kiểm mất đối tượng kiểm chứng: nó sẽ báo đạt vì không còn gì để kiểm, đúng loại đạt giả đã phát sinh ba lần trong quá trình xây dựng bộ kiểm thử. Danh sách hoãn có chủ sở hữu và lý do trong `patches/README.md`.

Ràng buộc thứ hai là bản chất của hai biến thể. Tham số hóa truy vấn không khắc phục được `shipment_detail.php`, vì thiếu sót ở đó là thiếu điều kiện chủ sở hữu trong logic nghiệp vụ. Bản vá phải thêm điều kiện `WHERE customer_id = ?` và một phép kiểm riêng, TDS-3, chứng minh người này không đọc được dữ liệu người khác.

Ràng buộc thứ ba là tầng quyền. Chừng nào ứng dụng còn kết nối bằng `root` với quyền `FILE`, một lỗ hổng tiêm mã SQL còn lại ở bất kỳ đâu vẫn cho phép đọc ghi tệp trên máy chủ cơ sở dữ liệu. Việc hạ quyền thuộc mục 4.4 và 4.5, nên bản vá của ba thành viên phải phối hợp theo thứ tự.

### 4.3.6 Cách xử lý, vị trí trên workflow và giới hạn kiểm chứng

Quy tắc chạy ở stage 2 với cờ `--error`, nên một phát hiện mức ERROR làm bước thất bại và chặn pull request. Bản vá dùng `mysqli_prepare` với tham số ràng buộc, bổ sung điều kiện chủ sở hữu, và giữ lại một điểm lỗi có chủ đích làm đối tượng cho TDS-6 đến khi phép kiểm đó được thay bằng phép kiểm trực tiếp trên hàm ghi nhật ký.

**Giới hạn kiểm chứng.** Taint mode không lần được vết luồng dữ liệu qua một biến siêu toàn cục ghi ở tệp khác, cũng không lần được chuỗi truy vấn tạo bởi thao tác ghép mảng qua `implode`. Quy tắc cũng không chứng minh được dữ liệu chưa từng bị trích xuất trước thời điểm vá; khẳng định đó cần nhật ký truy cập đầy đủ từ ngày hệ thống lên mạng, điều mà hệ thống hiện chưa có.

## 4.4 Thành viên 3, Đào Xuân Mạnh, B26CHAT026: bí mật có giá trị dự phòng dạng hằng và mật khẩu dạng rõ

### 4.4.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Triển khai lên máy chủ mới nhưng bỏ qua nạp biến môi trường từ nguồn quản lý bí mật, dịch vụ vẫn chạy, nối cơ sở dữ liệu bình thường, không cảnh báo.

CS-04 cấm dự phòng dạng hằng, buộc dừng khi thiếu bí mật từ nguồn quản lý; CS-06 quy định quyền tối thiểu tài khoản dịch vụ theo GDPR Điều 5(1)(f), 25, 32(1)(a).

### 4.4.2 Vấn đề và nguyên nhân không tự bộc lộ

Vì `.env` thuộc `.gitignore`, trình quét không thấy chuỗi tĩnh; container nhận dự phòng dạng hằng khi thiếu biến môi trường, dùng mật khẩu công khai trong kho mã.

Ba lớp liên hoàn gồm toán tử dự phòng `lib/db.php:17-20` nhận chuỗi hằng khi biến môi trường rỗng, tài khoản `root` toàn quyền kèm `FILE` (`prod.yml:49-50`, `init.sql:11-13`), mật khẩu rõ trong `users`.

Dù lớp đầu là cấu hình sai, kết hợp tiêm mã SQL mục 4.3 cho phép đọc ghi tệp máy chủ cơ sở dữ liệu, lộ mật khẩu không cần phá băm.

Lỗi không tự bộc lộ do tệp cấu hình chỉ tham chiếu biến môi trường hợp lệ, chỉ xuất hiện khi thực thi thiếu biến môi trường, ngoài tầm phân tích tĩnh.

### 4.4.3 Môi trường phải dựng và mã dùng để phát hiện

Môi trường gồm hai run compose (có và không biến môi trường) theo dõi giá trị dự phòng; Trivy secret scan `app/` đối chứng âm cho thấy quét bí mật không đủ; InSpec đọc giá trị hiệu lực trên container thay khai báo.

Thành phần thứ ba quyết định: phép kiểm phải đọc trạng thái runtime, nơi khiếm khuyết bộc lộ.


Quy tắc nhận diện toán tử dự phòng, phủ cả `?:` và `??`, trên cả `getenv`, `$_ENV` và `$_SERVER`:

```yaml
# ci/semgrep-local-rules.yml, quy tac php-hardcoded-db-password-fallback
patterns:
  - pattern-either:
      - pattern: "getenv($NAME) ?: $FALLBACK"
      - pattern: "getenv($NAME) ?? $FALLBACK"
      - pattern: "$_ENV[$NAME] ?: $FALLBACK"
      - pattern: "$_SERVER[$NAME] ?? $FALLBACK"
  - metavariable-regex:
      metavariable: $FALLBACK
      regex: ^['"].+['"]$
```

Toán tử `?:` của PHP trùng cú pháp phân tách khóa và giá trị của YAML, nên mọi mẫu chứa toán tử này phải nằm trong dấu nháy; thiếu dấu nháy thì cả tệp quy tắc không phân tích được.

### 4.4.4 Chứng minh hai chiều

Chiều vi phạm: quy tắc báo vi phạm trên `lib/db.php` ở trạng thái hiện tại. Chiều đạt: quy tắc không báo vi phạm sau khi đổi sang bắt buộc có biến môi trường và thoát sớm khi thiếu.

Đối chứng âm trên cùng mã nguồn và cùng lượt chạy: Trivy secret scan ghi kết quả vào `evidence/ci-09-trivy-secret.txt` và không phát hiện bí mật nào trong `app/`. Hai kết quả trái dấu trên cùng một đối tượng là bằng chứng rằng quét bí mật và kiểm tra cấu hình xử lý hai mục tiêu độc lập, không thay thế nhau.

Phép kiểm tuân thủ ở stage 4 kiểm giá trị đang có hiệu lực trên container, kết quả tại `evidence/ci-13-inspec.txt`. Trước khi sửa, hai cổng ở stage 4 cũng mất mã thoát theo cơ chế nêu ở mục 4.2, nên kết quả này chỉ trở thành một cổng thật sau bản vá đó.

### 4.4.5 Ràng buộc trong quá trình khắc phục

Bỏ giá trị dự phòng làm container không khởi động được khi thiếu biến, nên phải sửa cả entrypoint và tài liệu dựng, đồng thời bổ sung một thông điệp lỗi nêu rõ biến bị thiếu.

Áp dụng hàm băm yêu cầu di trú dữ liệu đồng bộ với `login.php`. Nếu làm đơn phương, toàn bộ tài khoản hiện hành mất quyền đăng nhập. Thứ tự đúng là thêm cột băm, ghi song song khi người dùng đăng nhập thành công, rồi mới bỏ cột mật khẩu dạng rõ.

Hạ quyền tài khoản cơ sở dữ liệu làm một số truy vấn hiện có thất bại, vì chúng đang dựa vào quyền rộng của `root`. Mỗi truy vấn thất bại phải được xem lại, thay vì cấp thêm quyền tùy tiện.

### 4.4.6 Cách xử lý, vị trí trên workflow và giới hạn kiểm chứng

Quy tắc chạy ở stage 2, phép kiểm tuân thủ chạy ở stage 4 trên container thực tế, và lặp lại ở stage 5 sau khi phát hành. Thứ tự vá gồm bốn bước: tạo tài khoản quyền tối thiểu, đổi chuỗi kết nối sang tài khoản đó, bắt buộc có biến môi trường và thoát sớm khi thiếu, băm mật khẩu kèm di trú dữ liệu.

**Giới hạn kiểm chứng.** Quy tắc chỉ nhận diện được dạng mã đã khai báo. Một bí mật truyền qua tệp cấu hình sinh lúc chạy, hoặc đọc từ một dịch vụ cấu hình từ xa, nằm ngoài phạm vi. Phép kiểm tuân thủ xác nhận trạng thái tại một thời điểm, không xác nhận bí mật chưa từng bị dùng trước đó, và không thu hồi được bí mật đã lộ trong lịch sử kho mã nguồn.

## 4.5 Thành viên 4, Lê Đức Anh, B26CHAT003: cổng chính sách kiểm tra không đúng tệp được triển khai

### 4.5.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Đội vận hành thêm `docker-compose.prod.yml` cho môi trường thật (khác biến, cổng bản phát triển) cùng tệp giám sát nhưng không cập nhật phạm vi cổng chính sách.

Theo CS-02, cấu hình triển khai phải qua cổng chính sách trước phát hành, phủ đúng tệp; CS-06 đòi quyền tối thiểu, bề mặt tiếp xúc nhỏ nhất theo GDPR Điều 32(1)(b).

### 4.5.2 Vấn đề và nguyên nhân không tự bộc lộ

Dù đủ cổng chính sách, quy tắc rego và kết quả đạt, tệp quét không phải tệp triển khai: `paths.include` Semgrep chỉ gồm `**/docker-compose.yml`, `**/compose.yml`, `**/compose.yaml`, bỏ qua hai tệp chứa mật khẩu gán cứng `docker-compose.prod.yml` và `docker-compose.monitoring.yml` do không khớp mẫu.

Ba khiếm khuyết gồm container chạy `root` do hai Dockerfile thiếu `USER`; compose thiếu `cap_drop`, `no-new-privileges`, `read_only`; ảnh dùng `latest` (`prod.yml:11`, `:31`, `monitoring.yml:64`) khiến các lần triển khai khác bản dù mã nguồn không đổi.

Lỗi không tự bộc lộ do hình thức kết quả: không vi phạm hay không đọc tệp nào đều báo đạt; báo đạt vì bỏ sót tệp tạo tin cậy sai lệch, điều CS-07 xếp rủi ro hơn thiếu cổng.

### 4.5.3 Môi trường phải dựng và mã dùng để phát hiện

Môi trường gồm Conftest quét mọi tệp compose trong kho (cả môi trường thật lẫn cụm giám sát), container thực tế để InSpec đọc giá trị hiệu lực, đối chiếu khai báo với `docker inspect`.

Phép kiểm chứng là chạy cổng trước và sau khi mở rộng `paths.include`: nếu đúng phạm vi, hai lượt cùng kết quả; nếu sai, vi phạm tăng từ 0 lên giá trị thực tế.


```yaml
# ci/semgrep-local-rules.yml, pham vi sau khi sua
paths:
  include:
    - "**/docker-compose*.yml"
    - "**/docker-compose*.yaml"
    - "**/compose*.yml"
    - "**/compose*.yaml"
```

Lớp thứ hai là phép kiểm tuân thủ trên container đang chạy, dùng tài nguyên `docker_container` và `docker_image` để xác nhận trường `User` không rỗng, danh sách `CapDrop` có `ALL`, và ảnh được ghim theo mã băm chứ không theo thẻ `latest`. Lớp này đọc trạng thái thực thi nên không phụ thuộc vào việc tệp nào được khai báo.

### 4.5.4 Chứng minh hai chiều

Bộ quy tắc rego cho hai kết quả trái dấu trên cặp fixture: báo vi phạm trên `fixtures/docker-compose.insecure.yml` và không báo vi phạm trên `fixtures/docker-compose.hardened.yml`, kèm mã thoát 1 và 0.

Chứng minh về phạm vi kiểm tra đặt cạnh nhau hai lượt trên cùng mã nguồn. Với phạm vi cũ, `docker-compose.prod.yml` không được đọc đến và cổng báo đạt. Với phạm vi đã mở rộng, Conftest đo được 9 vi phạm và 2 cảnh báo trên đúng tệp đó trong run `41810794218`: hai bí mật dạng hằng, tài khoản ứng dụng là `root`, bốn thiếu sót `cap_drop` và `no-new-privileges` trên hai dịch vụ, và hai ảnh ghim theo thẻ `latest`. Sau khi vá cả chín, cùng cổng đó báo 0 vi phạm trong run `41812598120`. Phần tăng từ 0 lên 9 rồi về 0 là số đo của chính phạm vi kiểm tra, không phải của mã nguồn, vì mã nguồn ở hai lượt đầu không đổi.

Ở stage 1, kết quả của cổng chính sách lớp triển khai nằm trong `evidence/ci-02-compose.txt`. Trước bản vá nêu ở mục 4.2, tệp này ghi 9 failures cho `prod.yml` và 13 cho `monitoring.yml` trong khi bước vẫn trả về trạng thái thành công. Sau bản vá, nội dung tệp và trạng thái bước khớp nhau.

### 4.5.5 Ràng buộc trong quá trình khắc phục

Bật `read_only` làm Apache không ghi được thư mục tạm, nên phải khai báo thêm `tmpfs` duy nhất cho các thư mục bắt buộc ghi.

Ghim ảnh theo mã băm làm quy trình cập nhật phải đổi: mỗi lần nâng phiên bản là một pull request có người phê duyệt, thay vì một lần khởi động lại container. Nhờ đó, hai lần triển khai từ cùng mã nguồn cho cùng một kết quả.

Hạ `cap_drop` xuống `ALL` làm một số dịch vụ giám sát mất quyền đọc thông tin tiến trình trên máy chủ, nên phải cấp lại từng năng lực cần thiết thay vì mở toàn bộ.

Ràng buộc trình tự: phạm vi kiểm tra phải được sửa trước khi vá nội dung, vì vá nội dung trước làm mất khả năng chứng minh cổng từng không đọc đến tệp đó.

### 4.5.6 Cách xử lý, vị trí trên workflow và giới hạn kiểm chứng

Cổng chính sách chạy ở stage 1, trước khi dựng ảnh. Phép kiểm tuân thủ chạy ở stage 4 sau khi container hoạt động, và lặp lại ở stage 5 ngay sau khi phát hành, trước khi bản phát hành được chấp nhận. Ba vị trí này kiểm ba đối tượng khác nhau: tệp khai báo, container trong môi trường kiểm thử, và container trong môi trường đích.

**Giới hạn kiểm chứng.** Conftest chỉ kiểm tra tệp khai báo, không kiểm soát được các lệnh người vận hành nhập thủ công trên máy chủ. Phép kiểm tuân thủ xác nhận một thời điểm, nên một thay đổi sau đó vẫn nằm ngoài tầm nếu không có cổng chạy định kỳ khi vận hành. Đây là lý do mục 5.4 bổ sung một vòng lặp kiểm tra khi vận hành chứ không chỉ khi phát hành.

## 4.6 Thành viên 5, Nguyễn Phương Mai, B26CHAT025: kênh rò rỉ dữ liệu cá nhân qua luồng nhật ký

### 4.6.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Dù hợp lý để theo dõi sự cố vận hành, gom nhật ký container vào hệ giám sát tập trung lại đưa mật khẩu rõ vào kho nhật ký nhiều người truy cập hơn CSDL.

Theo CS-05, dữ liệu cá nhân chỉ rời hệ thống qua khai báo (trừ nhật ký); CS-08 đòi lưu đủ sự kiện kiểm toán báo vi phạm trong 72 giờ theo Điều 5(1)(c), 33, 34 GDPR (tương ứng Điều 23, 26 Nghị định 13/2023/NĐ-CP).

### 4.6.2 Vấn đề và nguyên nhân không tự bộc lộ

Kênh rò rỉ gồm năm mắt xích đều là lựa chọn kỹ thuật hợp lý.

Năm mắt xích gồm: `pages/login.php:19` ghép mật khẩu vào truy vấn; hàm `query()` tại `lib/db.php:40-50` ghi toàn văn câu lệnh lỗi vào nhật ký; Promtail thiếu stage che giấu nên chuyển nguyên văn; Loki cho truy vấn tự do, Grafana mở mọi giao diện mạng (`monitoring.yml:43`); thiếu sự kiện kiểm toán nên không ghi nhận số lần đăng nhập thất bại.

Dấu nháy đơn ở mật khẩu làm hỏng truy vấn, đẩy câu lệnh kèm mật khẩu qua năm mắt xích; pipeline bỏ sót vì lỗi trải qua PHP và YAML ở hai tệp riêng mà không mắt xích nào khớp mẫu nguy hiểm.

### 4.6.3 Môi trường phải dựng và mã dùng để phát hiện

Môi trường gồm Promtail, Loki, Grafana; đối tượng kiểm chứng là truy vấn lỗi chưa vá đợt hai cùng truy vấn LogQL đối chiếu trước, sau khi thêm stage che giấu dữ liệu.

Về phương pháp, phép kiểm đo hành vi lúc chạy thay vì mã nguồn: khẳng định phủ định về luồng nhật ký chỉ chứng minh được khi kích hoạt lỗi thật rồi đọc lại luồng.


TDS-6 ở `tests/security/run.sh` kích hoạt truy vấn lỗi để xác nhận nhật ký container không chứa câu lệnh, mật khẩu; bản vá `patches/monitoring/promtail-config.hardened.yml` thêm stage che giá trị nhạy cảm, chuyển tương quan sang quy tắc Loki nhằm không giữ dữ liệu gốc.

### 4.6.4 Chứng minh hai chiều

TDS-6 thất bại trên cấu hình gốc kèm trích đoạn nhật ký nhạy cảm, nhưng đạt khi che giấu và LogQL hết kết quả; mã thoát hai lượt ghi tại `evidence/ci-12-tds.txt`.

Mục 5.3 kiểm chứng thêm: gửi tám yêu cầu tiêm mã SQL vào ứng dụng đã vá, độ trễ cảnh báo ba lượt độc lập đạt 15,1, 20,9 và 24,6 giây theo `evidence/35-chuoi-phat-hien-do-tre.txt`.

### 4.6.5 Ràng buộc trong quá trình khắc phục

Xung đột chính sách là ràng buộc lớn nhất: che giấu quá rộng làm mất trường nhận diện tấn công (vi phạm CS-08), quá hẹp lại gây rò rỉ (vi phạm CS-05). Promtail chỉ che giá trị nhạy cảm, giữ nhãn phân loại cùng địa chỉ nguồn; quy tắc Loki tương quan theo nhãn thay vì nội dung.

Về đích nhận: cấu hình gốc gửi tới `alertmanager:9093` không tồn tại khiến phát hiện không tới người nhận, vi phạm nghĩa vụ thông báo trong 72 giờ.

Về hiệu lực cổng: do hai bước stage 4 mất mã thoát theo mục 4.2, TDS-6 có kết quả nhưng không chặn lỗi; bản vá mục 4.2 là điều kiện cần để kết quả thành cổng.

### 4.6.6 Cách xử lý, vị trí trên workflow và giới hạn kiểm chứng

Khi vận hành, stage che giấu dữ liệu thuộc Promtail, TDS-6 đặt tại stage 4 pipeline, còn quy tắc tương quan Loki bổ sung cho vận hành ở mục 5.4.

**Giới hạn kiểm chứng.** Phép kiểm chỉ xác nhận luồng qua Promtail, không gồm nhật ký Apache hay MariaDB ghi thẳng ra tệp container; đồng thời chưa chứng minh dữ liệu cũ trong Loki đã xóa hết, đòi hỏi rà soát riêng theo Điều 17 GDPR.

---
# CHƯƠNG 5. GIÁM SÁT, ỨNG PHÓ VÀ VÒNG ĐỜI QUY TẮC

## 5.1 Kiến trúc nhật ký và nhận diện vector tấn công

Qua socket Docker, hệ thống tách `ilfreight_web` và `ilfreight_db` theo `promtail-config.yml:17-23` thành hai luồng: lỗi ứng dụng gán `log_category: app_exception` (dòng 42-48), lưu lượng HTTP gán `log_category: http_traffic` (dòng 51-56). Phía ứng dụng, `index.php:13-33` dùng `set_exception_handler`, `set_error_handler`, `register_shutdown_function` bảo đảm ghi nhận mọi lỗi.

Promtail phân loại vector tấn công khi thu thập bằng biểu thức chính quy khớp dòng nhật ký.

Bốn nhóm vector được gắn nhãn `vuln_category` ngay khi thu thập: `sqli` mức critical theo `union select`, `sleep(`, `or 1=1`, `information_schema`, `load_file(`, `sqlmap` tại dòng 58-66; `traversal_lfi` mức high theo `../`, `%2e%2e%2f`, `/etc/passwd`, `php://filter` tại dòng 68-76; `xss` mức warning theo `<script`, `onerror=`, `javascript:`, `document.cookie` tại dòng 78-86; `command_injection` mức critical theo `; cat`, `&& ls`, `/bin/sh`, `powershell`, `cmd.exe` tại dòng 88-96.

Nhóm `error_based_leak` (dòng 98-106) nhận diện phản hồi chứa lỗi SQL hoặc mã 4xx, 5xx; do dễ bị qua mặt bằng mã hóa và báo sai khi trùng mẫu, phương pháp này chỉ hỗ trợ điều tra sau sự cố thay vì ngăn chặn chủ động.

## 5.2 Tự động phục hồi dịch vụ

`autoheal` theo dõi container nhãn `autoheal: "true"` để khởi động lại theo `AUTOHEAL_INTERVAL=10`, `AUTOHEAL_START_PERIOD=20` tại `monitoring.yml:68-70`. Container web kiểm tra `/health` mỗi 10 giây (lỗi ba lần theo `prod.yml:41-46`, phát hiện sau 30 giây), còn `index.php:53-90` kiểm tra CSDL qua `mysqli_ping`, trả mã 503 để nhận diện web mất kết nối dữ liệu.

Về an toàn, `autoheal` gắn socket Docker quyền ghi theo `monitoring.yml:73` (tương đương `root` máy chủ) để khởi động container nhưng dùng ảnh `latest` bên thứ ba; nếu bản cập nhật bị can thiệp, kẻ tấn công chiếm toàn bộ máy chủ. Rủi ro này cần cân nhắc với việc tự phục hồi, được theo dõi ở mục 5.4.

## 5.3 Chuỗi tấn công đến cảnh báo và độ trễ phát hiện

Biện pháp Chương 4 trên nhánh vá được kiểm chứng qua cụm giám sát khép kín: Promtail che giấu dữ liệu trước khi lưu, quy tắc Loki tương quan, Alertmanager gửi đích nhận. Tám yêu cầu tiêm mã SQL vào ứng dụng đã vá đi qua Apache, Promtail, Loki đếm địa chỉ nguồn bằng `| json`, Alertmanager báo người trực; độ trễ qua ba lượt độc lập đạt 15,1, 20,9 và 24,6 giây do chu kỳ mười lăm giây của Loki cùng mười giây chờ của Alertmanager quyết định.

Đợt kiểm thử kích hoạt hai mức cảnh báo: thông tin đối chiếu và nghiêm trọng báo người trực; việc che giấu dữ liệu được xác thực khi Loki không lưu mật khẩu nguyên văn; cấu hình gốc trỏ tới Alertmanager không tồn tại làm đứt chuỗi phát hiện ở mắt xích cuối.

## 5.4 Vòng đời quy tắc và tự động vá khi vận hành

Mục này trình bày cơ chế tự đưa phát hiện sau phát hành về đầu pipeline, tương ứng CD trong DevSecOps.

Vòng lặp vận hành gồm ba việc tại `.github/workflows/auto-remediate.yml`, chạy hằng tuần hoặc theo yêu cầu.

*Bảng: Ba việc của vòng lặp vận hành và cơ chế tương ứng*

| Tác vụ | Cơ chế | Kết quả |
| :--- | :--- | :--- |
| Theo dõi chuỗi cung ứng | Trivy quét hai ảnh nền mức CRITICAL và HIGH, đối chiếu mốc cơ sở `sbom/cve-baseline.json` | `evidence/cve-watch.txt` |
| Tự động vá | Có CVE mới thì `ci/cve_watch.py` cập nhật mốc cơ sở và mở pull request vào nhánh vá | `evidence/auto-remediate-pr-body.md` |
| Bổ sung quy tắc | Mẫu tấn công trong Loki thành quy tắc Semgrep hoặc quy tắc tương quan mới, quay lại stage 2 làm cổng | tệp quy tắc trong `ci/`, nhật ký run |

Về thiết kế, pull request từ vòng lặp vẫn phải qua mọi cổng: tự động hóa chỉ phát hiện, soạn thay đổi chứ không thay phê duyệt vì CS-01 không có ngoại lệ cho tác nhân tự động.

Vòng lặp giải quyết giới hạn bốn stage đầu: lỗ hổng công bố sau phát hành không vướng cổng nào lúc phát hành nên thiếu kiểm tra định kỳ sẽ bị bỏ sót; mỗi lượt giúp đối chiếu hiện trạng với tri thức lỗ hổng mới nhất.

## 5.5 Tổng hợp những gì công cụ không phát hiện được

*Bảng: Khiếm khuyết công cụ không phát hiện và nguyên nhân*

| Khiếm khuyết | Vị trí | Nguyên nhân công cụ không báo |
| :--- | :--- | :--- |
| Mật khẩu lưu dạng rõ trong cơ sở dữ liệu | `init.sql:26`, `:34-38` | Thuộc dữ liệu, không ở mã; tệp SQL không được quét |
| Quality gate chỉ báo cáo; cổng báo thành công trong khi tệp kết quả chứa FAIL | `enforce_quality_gate`, năm bước có pipe | Không công cụ nào tự kiểm cấu hình của chính pipeline, cũng không đối chiếu trạng thái bước với tệp kết quả |
| Kênh rò rỉ mật khẩu ra Grafana | 5 tệp, 2 ngôn ngữ | Kênh trải qua PHP và YAML, không công cụ nào phân tích xuyên lớp |
| Bí mật trong compose của môi trường thật và của cụm giám sát | `monitoring.yml:46`, `prod.yml:15`, `:50` | Mục `paths.include` của quy tắc không khớp tên tệp |
| Thiếu tái sinh định danh phiên | `login.php:22-26` | Quy tắc bắt mẫu có mặt nên khó bắt mẫu vắng mặt |
| Thiếu kiểm tra quyền sở hữu bình luận và đơn hàng | `comment_delete.php:18`, `shipment_detail.php` | Lỗi logic nghiệp vụ, cần hiểu ý định của ứng dụng |
| Tài khoản CSDL thừa quyền; bí mật đã lộ trong lịch sử kho mã nguồn | `init.sql:12-13`, toàn bộ lịch sử | Không có quy tắc đánh giá mức quyền SQL; công cụ chỉ quét bản làm việc hiện tại |

Dù nhận diện tốt mã nguy hiểm trong một tệp, một ngôn ngữ, phân tích tĩnh hạn chế trước bốn nhóm: thiếu kiểm soát, lỗi logic nghiệp vụ, thành phần hợp lệ gây lỗi, cùng khiếm khuyết cơ chế kiểm soát.

Nhóm thứ tư đáng chú ý nhất do làm sai lệch kết quả khác. Pipeline DevSecOps chỉ xử lý việc lặp lại để tập trung vào phần bỏ sót thay vì thay thế đọc mã hay rà soát thiết kế; chính pipeline cũng phải chịu kiểm chứng.

---
# KẾT LUẬN

Bám sát tám điều khoản chính sách, mỗi run pipeline DevSecOps năm stage vừa kiểm thử vừa lập hồ sơ tuân thủ: kiểm tra quy ước và chính sách khai báo, phân tích tĩnh qua hai công cụ độc lập, kiểm soát chuỗi cung ứng kèm SBOM, kiểm thử hành vi, tuân thủ lúc chạy, cùng stage CD xác minh phát hành có cơ chế quay lui.

Ba kết quả thực tiễn nhất đều nhờ kiểm chứng trực tiếp hệ thống đã triển khai thay vì mô tả.

Phát hiện đầu tiên: cổng báo đạt mà không kiểm tra do năm bước workflow qua `tee` không khai báo `shell`, khiến mã thoát luôn bằng 0. Do đó, ba cổng chính sách stage 1 và hai cổng stage 4 không chặn lỗi dù kết quả chứa FAIL; đối chiếu trạng thái bước với tệp kết quả giúp phát hiện điều pipeline bỏ sót. Khi khai báo `shell: bash` cho các bước dùng pipe, cổng chính sách triển khai và cổng quản trị đều báo thất bại trên cùng mã nguồn, cấu hình, còn các stage sau bị bỏ qua đúng thiết kế.

Quality gate đạt không đồng nghĩa an toàn: SonarQube Community đánh giá `security_rating` mức A và 0 lỗ hổng hai nhánh dù bộ quy tắc chỉ ra 12 điểm tiêm mã SQL, do thiếu phân tích luồng dữ liệu xuyên hàm, xuyên tệp để nối chuỗi truy vấn sang hàm bao tại `lib/db.php`; cổng chỉ chứng minh điều trong phạm vi quan sát.

Hiệu lực cổng phụ thuộc phạm vi kiểm tra: ban đầu, cổng chính sách lớp triển khai chỉ đọc compose phát triển nên bỏ sót hai tệp; khi mở rộng, quy tắc tìm thấy 9 vi phạm trên `prod.yml` và 13 trên `monitoring.yml`. Do không thấy vi phạm hay không đọc tệp đều báo đạt, phạm vi này phải được kiểm chứng riêng.

Ba kết quả trên phản ánh khiếm khuyết cơ chế kiểm soát thay vì ứng dụng. CS-07 xếp lỗi này nặng hơn thiếu cổng vì làm sai lệch kết quả cổng khác và tạo tin cậy sai lệch.

Về hạn chế, năm vấn đề Chương 4 mới phân tích tĩnh qua mã nguồn và cấu hình; đợt hai hoãn TDS-6 kèm ngoại lệ CS-08 thay vì kiểm chứng động như đợt đầu. Token mặc định workflow không đọc trường `protection` nhánh khiến CI chỉ kích hoạt một trong ba quy tắc quản trị. Stage CD mới phát hành lên runner thay vì máy chủ sản xuất, chưa thử nghiệm dưới tải thực dù chứng minh trình tự phát hành, xác minh, quay lui. Về pháp lý, báo cáo dẫn Nghị định 13/2023/NĐ-CP nhưng chưa đối chiếu Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15 áp dụng từ 01/01/2026.

Các hướng phát triển theo thứ tự ưu tiên:

- Chặn ở stage 2 bằng Semgrep sau đợt vá hai, thay TDS-6 bằng kiểm tra trực tiếp hàm nhật ký; cổng ngoại lệ sẽ đánh trượt stage 1 nếu trễ hạn `EX-2026-02` ngày 31/12/2026.
- Tự động đối chiếu trạng thái bước với tệp kết quả để phát hiện mất mã thoát thay vì rà soát thủ công.
- Cấp token quản trị riêng để ba quy tắc trong `repo_policy.rego` có hiệu lực ở CI.
- Thu hồi, thay thế bí mật trong lịch sử kho do công cụ quét chỉ đọc bản hiện tại.
- Mở rộng stage CD sang môi trường bền vững để kiểm chứng phát hành cùng cơ chế quay lui trên hệ thống có dữ liệu, chịu tải.

Danh mục minh chứng gộp nằm tại `report/phu-luc-ho-so-minh-chung.md` trong kho; mọi số liệu trong báo cáo đều dẫn thẳng tới tệp bằng chứng hoặc mã run tương ứng.

# TÀI LIỆU THAM KHẢO

[1] Chính phủ nước CHXHCN Việt Nam, *Nghị định số 13/2023/NĐ-CP ngày 17/4/2023 về bảo vệ dữ liệu cá nhân*, Hà Nội, 2023.

[2] Quốc hội nước CHXHCN Việt Nam, *Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15*, thông qua ngày 26/6/2025, hiệu lực từ 01/01/2026.

[3] European Parliament and Council, *Regulation (EU) 2016/679, General Data Protection Regulation*, Official Journal of the European Union, 2016.

[4] OWASP Foundation, *OWASP Top 10:2021, The Ten Most Critical Web Application Security Risks*, 2021.

[5] MITRE Corporation, *CWE, Common Weakness Enumeration, Version 4.x*.

[6] SonarSource, *SonarQube Server Documentation, Quality Gates and Analysis Parameters*.

[7] Semgrep Inc., *Semgrep Documentation, Writing Custom Rules and Taint Mode*.

[8] Grafana Labs, *Loki and Promtail Documentation, Pipeline Stages*.

[9] Docker Inc., *Docker Compose Specification and Dockerfile Best Practices*.

[10] PHP Group, *PHP Manual, Password Hashing and MySQLi Prepared Statements*.
