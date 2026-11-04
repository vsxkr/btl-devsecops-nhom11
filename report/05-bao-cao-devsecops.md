# BÁO CÁO BÀI TẬP LỚN HỌC PHẦN DEVSECOPS

**Đề tài:** Đánh giá an toàn ứng dụng và bảo vệ dữ liệu người dùng trên pipeline DevSecOps CI/CD của hệ thống InlaneWeb Logistics

| | |
| :--- | :--- |
| **Cơ sở đào tạo** | Học viện Công nghệ Bưu chính Viễn thông |
| **Học phần** | Thực hành DevOps / DevSecOps |
| **Giảng viên hướng dẫn** | TS. Phạm Hoàng Duy |
| **Nhóm thực hiện** | Nhóm 11, lớp M26CQAT01-B |
| **Kho mã nguồn** | `github.com/vsxkr/btl-devsecops-nhom11` |
| **Mốc mã nguồn khảo sát** | nhánh `main` tại `94004f3` (hệ thống khiếm khuyết) và nhánh `patched` tại `0c9cdfd` (bản vá) |
| **Thời gian** | Tháng 10 năm 2026 |

---

## PHÂN CÔNG NHIỆM VỤ

*Bảng: Phân công nhiệm vụ và vấn đề an toàn phụ trách*

| TT | Họ và tên | Mã học viên | Vấn đề an toàn phụ trách | Nhóm |
| :---: | :--- | :--- | :--- | :--- |
| 1 | Nguyễn Giang Nam (trưởng nhóm) | B26CHAT030 | Thiếu kiểm soát thay đổi mã nguồn | Quy trình |
| 2 | Nguyễn Đình Hải | B26CHAT010 | Tiêm mã SQL làm lộ dữ liệu cá nhân | Mã nguồn |
| 3 | Đào Xuân Mạnh | B26CHAT026 | Mật khẩu dạng rõ và bí mật gán cứng | Mã nguồn |
| 4 | Lê Đức Anh | B26CHAT003 | Cấu hình triển khai mất an toàn | Triển khai |
| 5 | Nguyễn Phương Mai | B26CHAT025 | Rò rỉ dữ liệu qua luồng nhật ký | Vận hành |

---

## DANH MỤC TỪ VIẾT TẮT

| Viết tắt | Tiếng Anh | Tiếng Việt |
| :--- | :--- | :--- |
| CI/CD | Continuous Integration / Continuous Delivery | Tích hợp và chuyển giao liên tục |
| SAST | Static Application Security Testing | Kiểm thử an toàn trên mã nguồn tĩnh |
| PaC | Policy as Code | Chính sách viết thành mã |
| SaC | Security as Code | Tiêu chí an toàn viết thành mã |
| CWE | Common Weakness Enumeration | Danh mục phân loại điểm yếu phần mềm |
| OWASP | Open Worldwide Application Security Project | Tổ chức về an toàn ứng dụng web |
| SQLi | SQL Injection | Tiêm mã truy vấn SQL |
| XSS | Cross-Site Scripting | Chèn mã kịch bản liên trang |
| PR | Pull Request | Pull request nhánh mã nguồn |
| GDPR | General Data Protection Regulation | Quy định bảo vệ dữ liệu chung của Liên minh châu Âu |
| NĐ 13 | | Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân |
| DLCN | Personal Data | Dữ liệu cá nhân |
| LogQL | Log Query Language | Ngôn ngữ truy vấn nhật ký của Loki |

---

# MỞ ĐẦU

**Bối cảnh và lý do chọn đề tài.** Khi chuyển sang mô hình phát hành liên tục, kiểm định an toàn truyền thống bằng rà soát thủ công không còn đáp ứng kịp tốc độ phát triển. Mã nguồn có thể hợp nhất nhiều lần mỗi ngày, trong khi rà soát thủ công kéo dài nhiều ngày. Hệ quả là an toàn dễ trở thành điểm nghẽn làm chậm pipeline, hoặc bị bỏ qua.

DevSecOps giải quyết mâu thuẫn này nhờ tích hợp kiểm tra an toàn vào pipeline tự động tại mọi stage: phát hiện lỗi ở stage nào, pipeline dừng ngay tại stage đó.

Không chỉ mô tả pipeline đã thiết lập, đề tài kiểm chứng pipeline có thực sự dừng khi gặp lỗi và mức độ bảo vệ dữ liệu cá nhân. Chương 3 ghi nhận hai kết quả thực nghiệm: ban đầu, quality gate báo lỗi nhưng pipeline không dừng; nhóm đã tìm nguyên nhân, hiệu chỉnh chặn lỗi, và xác nhận qua hai run tự động đều dừng chính xác tại quality gate. Đồng thời, SonarQube Community trong pipeline đánh giá an toàn mức A, không ghi nhận lỗ hổng trên cả mã khiếm khuyết lẫn mã đã vá, trong khi Semgrep phát hiện hàng chục vị trí tiêm mã. Kiểm chứng thực nghiệm xác thực được hiệu lực thực tế của từng cổng kiểm soát.

**Mục tiêu và phạm vi.** Đề tài đánh giá mức độ an toàn của ứng dụng InlaneWeb Logistics về bảo vệ dữ liệu người dùng từ viết mã đến vận hành, với bốn mục tiêu cụ thể:

- Mô tả ứng dụng và hai nghiệp vụ xử lý dữ liệu cá nhân.
- Đối chiếu môi trường triển khai theo yêu cầu an toàn tối thiểu.
- Mỗi thành viên chọn một vấn đề an toàn: cách phát hiện, xử lý, chính sách vi phạm, phase DevSecOps, minh chứng Policy as Code hoặc Security as Code và mã khắc phục.
- Phân tích nguyên nhân khiếm khuyết công cụ tự động bỏ sót.

Báo cáo khảo sát kho mã nguồn `btl-devsecops-nhom11` trên hai nhánh: `main` (commit `94004f3`, hệ thống khiếm khuyết) và `patched` (commit `0c9cdfd`, phiên bản đã vá). Kết quả quét mỗi nhánh lấy từ run GitHub Actions riêng biệt: `40748974196` cho `main` và `40748974200` cho `patched`.

**Phương pháp và nguồn minh chứng.** Nhóm dựa vào ba nguồn độc lập và chỉ khẳng định khi có ít nhất một nguồn chứng minh: mã nguồn đối chiếu số dòng từ tệp thực tế; tệp kết quả SonarQube và Semgrep tải từ mục Artifacts của hai run `40748974196` và `40748974200`; trạng thái từng run kiểm tra trên GitHub Actions. Khi dữ liệu mâu thuẫn, báo cáo ghi nhận sự bất đồng thay vì thiên lệch, thể hiện rõ tại mục Kết quả quét thực tế của Chương 3.

---

# CHƯƠNG 1. ỨNG DỤNG INLANEWEB VÀ DỮ LIỆU CÁ NHÂN CẦN BẢO VỆ

## 1.1 Giới thiệu ứng dụng

InlaneWeb Logistics là cổng thông tin vận tải biển phục vụ ba nhóm người dùng: khách hàng tra cứu vận đơn, nhân viên cập nhật đơn hàng và quản trị viên theo dõi báo cáo. Ứng dụng dùng PHP 8.2 trên máy chủ Apache, CSDL MariaDB 10.11 và triển khai bằng Docker. Mã nguồn theo kiến trúc front controller: mọi yêu cầu qua `InlaneWeb/web/src/index.php` đều phân tuyến tới các trình xử lý trong `pages`. Thư mục `lib` gồm hai thư viện: `db.php` truy vấn cơ sở dữ liệu và `layout.php` kết xuất giao diện.

Ứng dụng phục vụ huấn luyện, cài sẵn lỗ hổng để thực hành tiêm mã SQL. Điều này thể hiện qua chú thích "CO Y DE LO" tại `lib/db.php:5-8` và biểu ngữ "INTENTIONALLY VULNERABLE, TRAINING ONLY" trên giao diện tại `lib/layout.php:25`. Tác động của ranh giới thực nghiệm tới kết quả đánh giá được phân tích ở cuối Chương 2.

*Bảng: Các tuyến đường chính của ứng dụng*

| Tuyến | Trình xử lý | Chức năng |
| :--- | :--- | :--- |
| `/login`, `/logout` | `login.php`, `logout.php` | Xác thực, kết thúc phiên |
| `/account`, `/account/update` | `account.php`, `account_update.php` | Hồ sơ, vận đơn, cập nhật thư điện tử |
| `/ports`, `/ports/{mã}`, `/track`, `/api/track` | `ports.php`, `port_detail.php`, `track.php`, `track_api.php` | Tra cứu cảng biển và vận đơn |
| `/shipments/{id}`, `/shipments/{id}/comments`, `/comments/{id}/delete` | `shipment_detail.php`, `comment_add.php`, `comment_delete.php` | Chi tiết đơn hàng và bình luận |
| `/admin`, `/admin/console` | `admin_dashboard.php`, `admin_console.php` | Khu quản trị |
| `/health`, `/api/health` | Xử lý tại `index.php:53` | Điểm kiểm tra sức khỏe cho CI/CD |

## 1.2 Mô hình dữ liệu và phân loại mức độ nhạy cảm

Tệp `app/InlaneWeb/db/init.sql.template` khởi tạo hai cơ sở dữ liệu: `ilfreight` nghiệp vụ gồm năm bảng `users`, `ports`, `shipments`, `comments`, `news`; và `dev` gồm hai bảng `credentials`, `flags`. Việc đặt chung máy chủ và chia sẻ tài khoản truy cập gây rủi ro an toàn trực tiếp, do lỗ hổng tiêm mã SQL từ ứng dụng nghiệp vụ cho phép truy xuất trái phép sang `dev`.

*Bảng: Phân loại dữ liệu theo mức độ nhạy cảm*

| Bảng và trường | Phân loại theo NĐ 13 | Ghi chú hiện trạng |
| :--- | :--- | :--- |
| `users.username`, `users.email` | DLCN cơ bản | |
| `users.password` | Thông tin xác thực | Lưu dạng rõ tại `init.sql.template:26`, `:34-38` |
| `users.api_key` | Thông tin xác thực | Hiển thị thẳng trên trang hồ sơ tại `account.php:20` |
| `users.remember_token` | Thông tin xác thực | Khai báo tại `init.sql:30`, chưa dùng trong mã |
| `shipments.customer_id` | DLCN cơ bản, gián tiếp | Ranh giới phân quyền giữa các khách hàng |
| `comments.content` | Do người dùng cung cấp | |
| `dev.credentials` | Thông tin xác thực | Băm bằng MD5, xem `init.sql:120` |

Trọng tâm bảo vệ là thông tin xác thực gồm mật khẩu, khóa API và thẻ phiên. Khi lộ lọt, kẻ tấn công có thể mạo danh người dùng truy cập mọi dữ liệu cá nhân còn lại.

## 1.3 Nghiệp vụ thứ nhất: xác thực và quản lý phiên người dùng

### 1.3.1 Luồng xử lý hiện tại

Người dùng gửi biểu mẫu qua `POST /login` với hai trường `username` và `password`. Quy trình xử lý như sau:

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

Khi truy vấn trả về bản ghi hợp lệ, mã người dùng được lưu vào `$_SESSION['uid']`. Trong các yêu cầu kế tiếp, hàm `current_user()` tại `lib/layout.php:4-11` truy vấn lại người dùng từ CSDL theo `uid` phiên. Thao tác đăng xuất gọi hàm `session_destroy()` tại `pages/logout.php:3`. Đối chiếu luồng này với yêu cầu xác thực tối thiểu bộc lộ bốn điểm thiếu sót.

### 1.3.2 Đối chiếu với yêu cầu của một luồng xác thực đúng

*Bảng: Đối chiếu nghiệp vụ xác thực với yêu cầu tối thiểu*

| Yêu cầu | Hiện trạng | Vị trí |
| :--- | :--- | :--- |
| Mật khẩu phải băm một chiều, so sánh bằng `password_verify()` | So sánh chuỗi thuần trong câu lệnh SQL | `login.php:19` |
| Tham số đầu vào phải tách khỏi câu lệnh | Nối chuỗi trực tiếp | `login.php:19` |
| Tái sinh định danh phiên sau khi đăng nhập thành công | Không gọi `session_regenerate_id()` | `login.php:22-26` |
| Cookie phiên phải đặt cờ `HttpOnly` | Đặt `session.cookie_httponly = Off` | `web/php.ini:12` |

Ba thiếu sót đầu do thành viên 2 và thành viên 3 phân tích ở Chương 4. Thiếu sót thứ tư cho phép mã phía client truy cập cookie phiên, biến mọi lỗ hổng XSS thành nguy cơ chiếm đoạt phiên người dùng.

Khi đăng nhập, mật khẩu dạng rõ xuất hiện ở bốn điểm: thân yêu cầu HTTP, biến `$_POST`, câu lệnh SQL tại `login.php:19` và nhật ký lỗi truy vấn. Chuỗi lan truyền dài làm tăng rủi ro lộ lọt. Truy vấn tham số hóa kết hợp băm mật khẩu sẽ ngăn mật khẩu dạng rõ xuất hiện trong câu lệnh.

## 1.4 Nghiệp vụ thứ hai: tra cứu vận đơn và bình luận đơn hàng

### 1.4.1 Luồng xử lý

Sau đăng nhập, khách hàng vào tuyến `/account` xem danh sách vận đơn cá nhân lọc theo `customer_id`:

```php
// pages/account.php:39-42
$order = $_GET['order'] ?? 'id';
$sql = "SELECT tracking_no, port_code, status FROM shipments WHERE customer_id = "
     . intval($u['id']) . " ORDER BY $order";
```

Khách hàng truy cập `/shipments/{id}` để xem chi tiết và gửi bình luận qua yêu cầu `POST /shipments/{id}/comments`. Tuyến tiếp nhận và xóa bình luận lần lượt nằm tại `index.php:116-119` và `index.php:124-127`. Ngoài ra, tuyến `/api/track?tracking=...` tại `index.php:109` trả về trạng thái vận đơn dạng JSON, hỗ trợ tra cứu công khai không cần đăng nhập.

### 1.4.2 Ranh giới phân quyền và điểm yếu

Ranh giới phân quyền thứ nhất giữa các khách hàng nhằm đảm bảo khách hàng A không xem được vận đơn của khách hàng B. Tuyến `/account` đã cài đặt đúng qua `WHERE customer_id = intval($u['id'])`. Tuy nhiên, tham số `$order` nối trực tiếp vào `ORDER BY`, khiến giá trị `?order=` có chủ đích có thể truy xuất dữ liệu ngoài phạm vi `WHERE`. Semgrep ghi nhận luồng này với nguồn tại `account.php:39` và điểm thực thi tại `account.php:41`.

Ranh giới phân quyền thứ hai nằm giữa người viết và người xóa bình luận. Tuyến xóa tại `pages/comment_delete.php:18` dùng `DELETE FROM comments WHERE id = $comment_id` nhưng không kiểm tra quyền sở hữu của người đăng nhập, đồng thời không ràng buộc kiểu dữ liệu cho `$comment_id`.

Tuyến `/api/track` trả về trạng thái vận đơn mà không yêu cầu đăng nhập. Thiết kế này chỉ an toàn nếu mã khó đoán; dữ liệu mẫu từ `ILF1042CN` đến `ILF1046US` tại `init.sql:70-75` mang tính tuần tự, dễ bị duyệt vét.

---
# CHƯƠNG 2. BỐI CẢNH CHÍNH SÁCH VÀ MÔI TRƯỜNG TRIỂN KHAI

## 2.1 Chính sách an toàn thông tin của doanh nghiệp

Mọi cổng kiểm soát trong báo cáo này đều xuất phát từ một văn bản quản trị, không từ nhận định cảm tính. Công ty cổ phần Logistics Inlane ban hành chính sách `CS-ATTT-2026`, hiệu lực từ 01/11/2026, phạm vi gồm ứng dụng InlaneWeb, cơ sở dữ liệu khách hàng, hạ tầng container và chuỗi công cụ phát triển. Toàn văn chính sách đặt tại `policy/00-chinh-sach-attt.md` trong kho mã nguồn, để chính sách thay đổi theo cùng một quy trình kiểm soát phiên bản như mã nguồn.

Căn cứ ban hành là nghĩa vụ chứng minh tuân thủ. Theo Nghị định 13/2023/NĐ-CP Điều 26 và 27, tương ứng GDPR Điều 24 và 32, công ty là bên kiểm soát dữ liệu và phải chứng minh đã áp dụng biện pháp kỹ thuật, biện pháp quản lý phù hợp. Theo nghĩa vụ chứng minh, khi cơ quan quản lý hoặc chủ thể dữ liệu yêu cầu, công ty phải cung cấp bằng chứng thay vì lời cam kết. Vì vậy chính sách không dừng ở việc nêu yêu cầu. Mỗi điều khoản được gắn với một cổng kiểm soát tự động, và mỗi lượt chạy pipeline để lại một tệp bằng chứng kiểm chứng được.

*Bảng: Tám điều khoản chính sách và cổng kiểm soát thi hành tương ứng*

| Mã | Điều khoản | Tình huống làm phát sinh rủi ro | Cổng thi hành | Thành viên |
| :--- | :--- | :--- | :--- | :--- |
| CS-01 | Thay đổi vào nhánh phát hành phải qua pull request có người phê duyệt khác tác giả | Phát hành gấp ngoài giờ, một thành viên đẩy trực tiếp lên nhánh phát hành | `policy_guard.py`, `repo_policy.rego`, bảo vệ nhánh | Nam |
| CS-02 | Cấu hình triển khai phải qua cổng chính sách, và phạm vi kiểm tra phải phủ đúng tệp được triển khai | Thêm tệp compose riêng cho môi trường sản xuất, ngoài phạm vi kiểm tra | `compose_security.rego`, `docker_security.rego` | Đức Anh |
| CS-03 | Dữ liệu nhận từ người dùng không được ghép vào câu lệnh truy vấn | Khách tra cứu vận đơn bằng mã nhập tự do trên trang công khai | `policy-p4-sql-injection` | Hải |
| CS-04 | Bí mật chỉ đến từ nguồn quản lý bí mật, không có giá trị dự phòng dạng hằng | Triển khai lên máy mới, quên nạp biến môi trường, dịch vụ vẫn khởi động | `php-hardcoded-db-password-fallback`, Trivy, InSpec | Mạnh |
| CS-05 | Dữ liệu cá nhân chỉ truyền qua kênh đã khai báo; nhật ký không thuộc số này | Bật nhật ký tập trung, câu lệnh lỗi kèm mật khẩu đi vào kho nhật ký | TDS-2, TDS-6, pipeline stage che giấu dữ liệu | Mai |
| CS-06 | Tài khoản và tiến trình ở mức quyền tối thiểu, ảnh phải ghim phiên bản | Ứng dụng kết nối cơ sở dữ liệu bằng tài khoản quản trị toàn quyền | InSpec, `policy-p3-privileged-db-account-default` | Mạnh, Đức Anh |
| CS-07 | Cổng tự động phải chặn, không được chỉ báo cáo | Bước CI ghi vi phạm ra tệp nhưng vẫn báo trạng thái thành công | Đối chiếu mã thoát với nội dung tệp kết quả | Nam |
| CS-08 | Mọi ngoại lệ phải có lý do, người phê duyệt đích danh và thời hạn | Nhánh được miễn kiểm soát tạm thời rồi bị bỏ quên thu hồi | `policy/exceptions.json`, `ci/check_exceptions.py` | Nam |

Bốn phase của vòng đời DevSecOps nhận các điều khoản khác nhau: Plan và Code thi hành CS-01, CS-03, CS-04; Build và Test thi hành CS-02, CS-03, CS-04, CS-07; Release và Deploy thi hành CS-02, CS-06, CS-07; Operate và Monitor thi hành CS-05, CS-06, CS-08. Chương 4 đi theo đúng ánh xạ này: mỗi vấn đề an toàn được nêu kèm điều khoản bị vi phạm, tình huống nghiệp vụ làm nó phát sinh, và vị trí của nó trên workflow.

Chế tài cũng là một phần của chính sách. Pull request vi phạm bất kỳ điều khoản nào bị cổng tự động chặn và không hợp nhất được. Trường hợp phát hiện vi phạm sau khi đã phát hành, quy trình ứng phó sự cố yêu cầu xác định thay đổi gây ra và người phê duyệt trong 72 giờ theo CS-01 và CS-08, quay lui bản phát hành theo quy trình CD ở mục 3.5, và bổ sung một quy tắc mới vào bộ quy tắc nhằm chặn chính xác mẫu lỗi tương tự.

## 2.2 Kiến trúc triển khai

Hệ thống triển khai trên máy chủ riêng ảo thành hai cụm Docker Compose độc lập dùng chung mạng nội bộ. Cụm ứng dụng trong `docker-compose.prod.yml` (dự án `inlaneweb-prod`) gồm dịch vụ `db` (MariaDB), `web` (PHP-Apache), tạo mạng `inlaneweb_net` (bí danh `labnet`) tại dòng 59-62. Cụm giám sát trong `docker-compose.monitoring.yml` (dự án `inlaneweb-monitoring`) gồm `loki` lưu nhật ký, `promtail` thu thập, `grafana` hiển thị và `autoheal` tự khởi động container sự cố, tham gia mạng qua `external: true` tại dòng 77-80.

Tách hai cụm cho phép cập nhật ứng dụng độc lập, không gây gián đoạn giám sát. Tên dự án riêng biệt ngăn lệnh `docker compose down` của cụm này xóa nhầm container cụm kia. Dịch vụ web chỉ mở cổng trên giao diện vòng lặp nội bộ qua `"127.0.0.1:8088:80"` tại dòng 38; lưu lượng ngoài do Nginx Proxy Manager tiếp nhận, cấp chứng chỉ TLS. Cơ sở dữ liệu hoàn toàn không mở cổng ra ngoài máy chủ.

## 2.3 Đối chiếu với yêu cầu an toàn tối thiểu

*Bảng: Bảng kiểm yêu cầu an toàn tối thiểu của môi trường triển khai*

| # | Yêu cầu tối thiểu | Điều khoản | Kết quả | Dẫn chứng |
| :---: | :--- | :---: | :---: | :--- |
| 1 | Cơ sở dữ liệu không công bố cổng ra ngoài máy chủ | CS-02 | Đạt | `prod.yml`, dịch vụ `db` không có mục `ports` |
| 2 | Ứng dụng web chỉ lắng nghe trên giao diện nội bộ | CS-02 | Đạt | `prod.yml:38` |
| 3 | Dữ liệu cơ sở dữ liệu lưu trên volume bền vững | CS-02 | Đạt | `prod.yml:26-28`, `:64-66` |
| 4 | Dịch vụ có kiểm tra sức khỏe và tự phục hồi | CS-02 | Đạt | `prod.yml:21-25`, `:41-46`; `monitoring.yml:63-75` |
| 5 | Container không chạy bằng quyền `root` | CS-06 | Không đạt | `web/Dockerfile` và `db/Dockerfile` không có chỉ thị `USER` |
| 6 | Không gán cứng bí mật trong tệp cấu hình | CS-04 | Không đạt | `prod.yml:15`, `:50`; `monitoring.yml:46`; `init.sql:11` |
| 7 | Tài khoản cơ sở dữ liệu của ứng dụng có quyền tối thiểu | CS-06 | Không đạt | `prod.yml:49` dùng `root`; `init.sql:12-13` cấp `ALL PRIVILEGES` và `FILE` |
| 8 | Tài khoản quản trị cơ sở dữ liệu không đăng nhập từ mọi máy | CS-06 | Không đạt | `prod.yml:16` đặt `MYSQL_ROOT_HOST: "%"`; `init.sql:11` |
| 9 | Ảnh container ghim phiên bản, không dùng thẻ `latest` | CS-02 | Không đạt | `prod.yml:11`, `:31`; `monitoring.yml:64` |
| 10 | Không hiển thị lỗi hệ thống ra trình duyệt | CS-05 | Không đạt | `web/php.ini:6-7` đặt `display_errors = On` |
| 11 | Cookie phiên đặt cờ `HttpOnly` | CS-05 | Không đạt | `web/php.ini:12` đặt `session.cookie_httponly = Off` |
| 12 | Giao diện quản trị hệ giám sát không mở ra Internet | CS-02 | Không đạt | `monitoring.yml:43` công bố Grafana trên `0.0.0.0:3000` |
| 13 | Container thu thập nhật ký chạy với quyền hạn chế | CS-06 | Không đạt | `monitoring.yml:26` đặt `user: root` |
| 14 | Không gắn socket Docker với quyền ghi | CS-06 | Không đạt | `monitoring.yml:73` gắn `docker.sock` cho `autoheal` ở chế độ ghi |

Bốn yêu cầu đầu đạt chuẩn, mười yêu cầu còn lại không đạt. Yêu cầu số 12 là khiếm khuyết an toàn trọng yếu nhất: ứng dụng web nằm sau giao diện vòng lặp nội bộ, còn Grafana mở ra mọi giao diện mạng. Dịch vụ này hiển thị toàn bộ nhật ký gồm cả lệnh SQL thực thi thất bại, dẫn tới vấn đề an toàn phân tích tại mục 4.6.

## 2.4 Phân biệt lỗ hổng chủ ý với khiếm khuyết ngoài ý muốn

Do ứng dụng phục vụ bài thực hành tiêm mã SQL, một phần tiêu chí không đạt là có chủ ý: yêu cầu số 10 phục vụ khai thác dựa trên thông báo lỗi, yêu cầu số 7 hỗ trợ đọc ghi tệp qua quyền `FILE`, và không băm mật khẩu để minh họa hậu quả khai thác. Các khiếm khuyết này nằm trong mã ứng dụng, được ghi rõ trong mã nguồn và chỉ tác động trong môi trường thực hành.

Các yêu cầu số 5, 6, 9, 12, 13 và 14 phản ánh thiếu sót hạ tầng, không phục vụ nội dung thực hành nào. Riêng yêu cầu số 12 lan rộng hậu quả lỗ hổng có chủ ý ra ngoài môi trường thực hành. Mục tiêu thực hành không biện minh cho việc công bố Grafana ra Internet kèm mật khẩu quản trị trong kho mã nguồn công khai.

---
# CHƯƠNG 3. PIPELINE DEVSECOPS VÀ CÁC CỔNG KIỂM SOÁT BẮT BUỘC

## 3.1 Năm stage của pipeline

Pipeline khai báo trong `.github/workflows/devsecops-gate.yml`, kích hoạt khi đẩy mã lên `main`, `dev`, `patched`, khi mở pull request vào `main` và `dev`, hoặc khi chạy theo yêu cầu. Nguyên tắc thiết kế: mỗi stage là một cổng, cổng thất bại làm các stage sau bị bỏ qua và pull request không hợp nhất được.

*Bảng: Năm stage của pipeline, công việc và điều kiện chặn*

| Stage | Job | Công việc | Điều kiện chặn |
| :---: | :--- | :--- | :--- |
| 1 | `stage1_policy_guard`, `stage1_policy_as_code` | Quy ước commit và pull request, cổng CS-01, Conftest trên Dockerfile, Compose và cấu hình quản trị kho mã nguồn | Có bất kỳ `deny`, hoặc vi phạm quy ước, hoặc đẩy trực tiếp vào nhánh phát hành không có ngoại lệ còn hạn |
| 2 | `stage2_security_as_code` | SonarQube với quality gate, Semgrep với bộ quy tắc P1 đến P5 của nhóm cùng bốn bộ công khai, kiểm cú pháp PHP, cặp fixture hai chiều | Quality gate trả về `ERROR`, hoặc Semgrep có phát hiện mức ERROR |
| 3 | `stage3_supply_chain` | Sinh SBOM dạng CycloneDX cho hai ảnh nền, quét bí mật, cổng CVE | Có CVE mức CRITICAL trên ảnh nền |
| 4 | `stage4_test_driven_security` | Bộ test hành vi trên ứng dụng đang chạy, Compliance as Code bằng InSpec trên container | Một phép kiểm hành vi hoặc một phép kiểm tuân thủ thất bại |
| 5 | `stage5_cd_release` | Phát hành lên môi trường đích, xác minh sau phát hành, quay lui khi xác minh thất bại | Container không đạt trạng thái khỏe, hoặc phép kiểm sau phát hành thất bại |

Ràng buộc `needs` tạo trật tự: stage 2 cần cả hai job của stage 1, stage 3 cần job Policy as Code, stage 4 cần stage 2, và stage 5 cần cả stage 2, stage 3, stage 4. Job tổng kết chạy với `if: always()` và trả mã khác 0 khi bất kỳ job nào thất bại. Điều kiện để trạng thái của run phản ánh đúng trạng thái xấu nhất của các cổng là từng bước phải giữ được mã thoát, phần được phân tích ở mục 3.6.

Stage 5 chỉ chạy trên nhánh `patched`. Nhánh `main` được giữ ở trạng thái có khiếm khuyết để làm đối tượng đánh giá, nên không được phát hành. Điều kiện này viết thành `if: github.ref == 'refs/heads/patched'` ngay trong job, thay vì dựa vào quy ước giữa các thành viên.

## 3.2 Policy as Code tại stage 1

Stage 1 quản trị quy trình bằng mã: quy ước đặt tên commit và pull request mã hóa thành biểu thức chính quy cho máy kiểm tra, thay vì thỏa thuận giữa các thành viên. Ba biểu thức tạo ba cấp kiểm soát: commit theo Conventional Commits, pull request vào `dev` mang mã của một trong năm thành viên, và pull request vào `main` đánh số phiên bản phát hành.

Bản đầu của `ci/policy_guard.py` có một khiếm khuyết về phạm vi: hàm `validate_push_event()` chỉ đối chiếu định dạng thông điệp, không ngăn việc đẩy trực tiếp vào nhánh phát hành, trong khi điều khoản CS-01 cấm chính việc đó. Bản hiện tại bổ sung một cổng cho CS-01 kèm cơ chế ngoại lệ theo điều khoản CS-08:

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

Với SonarQube, pipeline dựng một máy chủ tạm trong máy ảo của runner, quét mã rồi hủy khi hoàn thành. Tiêu chí chấp nhận nằm trong `ci/sonarqube-quality-gate.json`, đặt năm điều kiện báo lỗi: `security_rating` lớn hơn 1, `reliability_rating` lớn hơn 1, `sqale_rating` lớn hơn 1, `security_hotspots_reviewed` nhỏ hơn 100, và `duplicated_lines_density` lớn hơn 10. Quản lý tiêu chí qua lịch sử kho mã nguồn xác lập bản chất Security as Code, thay cho một thiết lập trên giao diện.

Với Semgrep, pipeline chạy bốn bộ quy tắc công khai `p/owasp-top-ten`, `p/php`, `p/security-audit`, `p/cwe-top-25`, cùng hai tệp quy tắc của nhóm là `ci/semgrep-policy-php.yml` với tám quy tắc thuộc năm nhóm P1 đến P5, và `ci/semgrep-local-rules.yml` với hai quy tắc chống gán cứng bí mật. Cờ `--error` là bắt buộc: không có cờ này, Semgrep trả mã thoát 0 dù có phát hiện.

Quy tắc chống bí mật có giá trị dự phòng được viết lại để phủ cả bốn dạng cú pháp và cả ba nguồn biến môi trường:

```yaml
# ci/semgrep-local-rules.yml, quy tac php-hardcoded-db-password-fallback
pattern-either:
  - pattern: "getenv($NAME) ?: $FALLBACK"
  - pattern: "getenv($NAME) ?? $FALLBACK"
  - pattern: "$_ENV[$NAME] ?: $FALLBACK"
  - pattern: "$_SERVER[$NAME] ?? $FALLBACK"
```

Quy tắc thứ hai, `compose-hardcoded-mysql-root-password`, từng có một khiếm khuyết về phạm vi: mục `paths.include` chỉ liệt kê ba mẫu không khớp hai tệp compose thực sự dùng khi triển khai, nên quy tắc không chạy trên chúng. Phân tích đầy đủ khiếm khuyết này và cách khắc phục nằm ở mục 4.5.

## 3.4 Chuỗi cung ứng, Test-Driven Security và Compliance as Code

Stage 3 xử lý ba tác vụ trên hai ảnh nền `php:8.2-apache` và `mariadb:10.11`: sinh SBOM dạng CycloneDX nhằm kiểm kê thành phần hệ thống, quét bí mật trên toàn bộ `app/`, và đặt một cổng CVE. Cổng CVE là nơi dễ mất hiệu lực nhất: Trivy trả mã thoát 0 dù phát hiện lỗ hổng nếu thiếu `--exit-code 1`, và mã thoát đó còn bị mất lần nữa nếu kết quả đi qua một chuỗi lệnh pipe. Bước này do đó giữ mã thoát bằng `${PIPESTATUS[0]}` cho từng ảnh rồi so sánh tường minh.

Stage 4 chuyển từ việc đọc mã sang việc quan sát hành vi. Bộ test trong `tests/security/run.sh` dựng ứng dụng, chờ dịch vụ đạt trạng thái sẵn sàng, chạy sáu phép kiểm hành vi bên trong container, và kiểm một khẳng định không thực hiện được từ bên trong: luồng nhật ký của container không chứa nguyên văn câu lệnh truy vấn. Tiếp đó InSpec chạy trên container đang hoạt động để xác nhận trạng thái đang có hiệu lực, chứ không phải trạng thái được khai báo trong tệp. Đây là phần Compliance as Code: cùng một yêu cầu, nhưng đối tượng kiểm là hệ thống đang chạy.

## 3.5 CD tại stage 5: phát hành có xác minh và quay lui

Stage 5 là phần CD, chỉ chạy trên nhánh vá và chỉ sau khi cả ba stage trước đạt. Trình tự gồm năm bước, trong đó bước thứ tư là bước quyết định.

| Bước | Tác vụ | Kết quả |
| :---: | :--- | :--- |
| 1 | Ghi lại mốc đang chạy để có điểm quay lui | `evidence/ci-14-cd-rollback-point.txt` |
| 2 | Phát hành lên môi trường đích và chờ kiểm tra sức khỏe báo khỏe | `evidence/ci-15-cd-deploy.txt` |
| 3 | Xác minh sau phát hành bằng InSpec trên container vừa phát hành | `evidence/ci-16-cd-postdeploy-inspec.txt` |
| 4 | Quay lui khi xác minh thất bại, rồi trả mã khác 0 | `evidence/ci-17-cd-rollback.txt` |
| 5 | Kết luận phát hành khi xác minh đạt | `evidence/ci-18-cd-release-ok.txt` |

Điểm thiết kế đáng nêu là bước xác minh chạy lại đúng phép kiểm tuân thủ của stage 4, nhưng trên một đối tượng khác: container trong môi trường đích thay vì container trong môi trường kiểm thử. Chạy cùng một phép kiểm trên hai đối tượng khác nhau là cách duy nhất phát hiện sai lệch phát sinh trong chính quá trình phát hành.

Bước quay lui được khai báo với điều kiện `if: steps.verify.outcome == 'failure'`, nên nó chỉ chạy khi xác minh thất bại, và sau khi đưa môi trường về trạng thái trước phát hành, bước này trả mã khác 0 để run thất bại. Bản phát hành không đạt xác minh bị chặn hoàn toàn, không thể ghi nhận là thành công.

## 3.6 Hai khiếm khuyết của chính cơ chế chặn

Hai phát hiện quan trọng nhất của chương này thuộc về chính pipeline, không thuộc về ứng dụng. Điều khoản CS-07 xếp một cổng báo đạt mà không kiểm tra gì là vi phạm nặng hơn việc thiếu cổng, nên hai phát hiện được ghi nhận nguyên trạng.

Khiếm khuyết thứ nhất, ở bản pipeline đầu, biến quyết định việc chặn của quality gate được khai báo `ENFORCE_QUALITY_GATE: ${{ inputs.enforce_quality_gate || 'false' }}`. Ngữ cảnh `inputs` chỉ tồn tại khi kích hoạt thủ công, nên ở mọi run tự động biểu thức luôn trả về `'false'`. Trong khi đó `ci/sonarqube.py` đọc biến này với giá trị mặc định `"true"` ở cả hai vị trí, tức script vốn dừng an toàn. Việc ghi đè biến bằng một biểu thức luôn cho `'false'` đã biến quality gate thành cổng chỉ báo cáo. Cách sửa là không ghi đè biến đó.

Khiếm khuyết thứ hai nặng hơn và được nhóm phát hiện ngày 04/11/2026, khi đối chiếu trạng thái của từng bước với nội dung tệp kết quả do chính bước đó sinh ra. Năm bước trong tệp workflow chuyển kết quả qua `tee` mà không khai báo `shell`. GitHub Actions khi đó chạy `bash -e {0}`, cấu hình không bật `-o pipefail`, nên mã thoát của cả chuỗi lệnh là mã thoát của `tee` và luôn bằng 0. Ba cổng chính sách ở stage 1 và hai cổng ở stage 4 vì vậy không thực hiện chức năng ngăn chặn, trong khi tệp kết quả của chính chúng chứa các dòng FAIL. Phân tích đầy đủ, kèm bảng đối chiếu và mã thoát, nằm ở mục 4.2.

Cách sửa là khai báo `shell: bash` cho mọi bước có chuỗi lệnh pipe, vì GitHub Actions chạy shell này bằng `bash --noprofile --norc -eo pipefail {0}`. Đối chứng thực tế cho thấy sự thiếu nhất quán khi áp dụng một nguyên tắc đã biết: trong cùng tệp đó, cổng CVE đã giữ mã thoát bằng `${PIPESTATUS[0]}` và bước kiểm cú pháp PHP đã đối chiếu lại bằng `grep`.

## 3.7 Kết quả quét thực tế trên hai nhánh

Pipeline cho hai bộ số đối chứng: nhánh `main` mốc `94004f3` qua run `40748974196`, giữ trạng thái có khiếm khuyết; nhánh `patched` mốc `0c9cdfd` qua run `40748974200`, đã vá đợt một. Từng bộ số lấy từ `sonarqube/metrics.json`, `sonarqube/quality-gate.json` và `ci-05-semgrep.json` trong artifact `evidence-security-as-code` tương ứng.

*Bảng: Chỉ số SonarQube của hai nhánh*

| Chỉ số | `main` (`94004f3`) | `patched` (`0c9cdfd`) | Điều kiện cổng | Trạng thái |
| :--- | ---: | ---: | :--- | :---: |
| `reliability_rating` | 3 | 3 | Báo lỗi khi lớn hơn 1 | ERROR |
| `security_rating` | 1 | 1 | Báo lỗi khi lớn hơn 1 | OK |
| `sqale_rating` | 1 | 1 | Báo lỗi khi lớn hơn 1 | OK |
| `duplicated_lines_density` | 0,0 | 0,0 | Báo lỗi khi lớn hơn 10 | OK |
| `vulnerabilities` | 0 | 0 | | |
| `security_hotspots` | 0 | 0 | | |
| `bugs` và `code_smells` | 10 và 15 | 8 và 19 | | |
| Số tệp và số dòng mã | 24 và 734 | 24 và 876 | | |

SonarQube ghi nhận 25 phát hiện trên `main` và 27 trên `patched`, toàn bộ là lỗi lập trình và bảo trì: `Web:InputWithoutLabelCheck`, `Web:S6853`, `php:S100`, `php:S113`, `php:S2003`, `php:S121`. Không quy tắc nào thuộc nhóm an toàn. Trên cả hai nhánh, `vulnerabilities` bằng 0, `security_hotspots` bằng 0 và `security_rating` bằng 1, tức mức A, trong khi Semgrep phát hiện 12 vị trí tiêm mã SQL theo quy tắc của nhóm trên `main`. Quality gate báo lỗi vì `reliability_rating` bằng 3, không phải vì an toàn.

Nguyên nhân là bản SonarQube Community không phân tích luồng dữ liệu xuyên hàm và xuyên tệp, nên không nối được chuỗi truy vấn từ `pages` sang hàm bao trong `lib/db.php`. Hai hệ quả: quality gate đạt tiêu chí an toàn không đồng nghĩa mã an toàn, và SonarQube không thể hiện khác biệt giữa hai nhánh vì đều báo 0 lỗ hổng, trong khi Semgrep phản ánh đúng mức giảm từ 64 xuống 46 phát hiện.

*Bảng: Phân bố 64 phát hiện Semgrep trên nhánh `main`, run `40748974196`*

| Nhóm quy tắc | Số lượng | Phân loại | Nguồn quy tắc |
| :--- | :---: | :--- | :--- |
| `tainted-sql-string`, `policy-p4-sql-injection` | 19 và 12 | tiêm mã SQL, CWE-89, OWASP A03:2021 | công khai và nhóm |
| `policy-p2-client-supplied-identity` | 8 | định danh lấy từ client, OWASP A01:2021 | quy tắc của nhóm |
| `policy-p1-unrestricted-write` | 6 | ghi không kiểm quyền, OWASP A01:2021 | quy tắc của nhóm |
| `echoed-request` | 5 | XSS, CWE-79 | công khai `p/php` |
| `policy-p5-statement-logged-verbatim`, `policy-p4-error-detail-to-response` | 4 và 4 | ghi nhật ký nguyên văn, lộ chi tiết lỗi, OWASP A09 và A05 | quy tắc của nhóm |
| các quy tắc bí mật gán cứng và container chạy `root` | 6 | CWE-798 và CWE-250 | nhóm và công khai |

Trên `main`, cả 64 phát hiện đều ở mức ERROR và quy tắc tự viết kích hoạt đúng mục tiêu. Trên `patched`, tổng còn 46: `policy-p4-sql-injection` còn 8 và `tainted-sql-string` còn 14. Phần còn lại thuộc đợt vá thứ hai, có chủ sở hữu và lý do hoãn trong `patches/README.md`.

---
# CHƯƠNG 4. NĂM VẤN ĐỀ AN TOÀN THEO PHÂN CÔNG THÀNH VIÊN

## 4.1 Bảng tổng hợp và khuôn trình bày

Mỗi thành viên phụ trách đúng một vấn đề. Vấn đề được chọn theo tiêu chí ràng buộc nhiều lớp: nó vi phạm một điều khoản chính sách cụ thể, nó không tự bộc lộ trước công cụ tự động, và việc khắc phục bị nhiều điều kiện khác giới hạn.

*Bảng: Tổng hợp năm vấn đề an toàn của năm thành viên*

| Thành viên | Vấn đề | Nhóm | Phase | Điều khoản | Dạng chứng minh |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Nguyễn Giang Nam | Kiểm soát thay đổi được khai báo nhưng không có hiệu lực, và chính cổng kiểm chứng việc đó cũng không ngăn chặn | Quy trình | Plan, Code | CS-01, CS-07, CS-08 | Policy as Code |
| Nguyễn Đình Hải | Tiêm mã SQL qua hàm bao nội bộ, nên bộ quy tắc có sẵn và SonarQube đều không phát hiện | Mã nguồn | Code, Build | CS-03, CS-05 | Security as Code |
| Đào Xuân Mạnh | Bí mật không nằm trong kho mã nguồn nhưng vẫn nhận giá trị mặc định dạng hằng khi thiếu biến môi trường | Mã nguồn | Code, Build | CS-04, CS-06 | SaC và CaC |
| Lê Đức Anh | Cổng chính sách kiểm tra tệp compose không phải tệp dùng khi triển khai | Triển khai | Release, Deploy | CS-02, CS-06 | PaC và CaC |
| Nguyễn Phương Mai | Năm mắt xích hợp lý riêng lẻ hợp thành một kênh rò rỉ, và biện pháp che giấu xung đột với yêu cầu phát hiện tấn công | Vận hành | Operate, Monitor | CS-05, CS-08 | Test-Driven Security |

Năm vấn đề bao quát hai nhóm theo yêu cầu đề tài: ba vấn đề thuộc mã nguồn và quy trình phát triển, hai vấn đề thuộc triển khai và vận hành.

Mỗi mục dưới đây trình bày theo tám trường thống nhất: tình huống nghiệp vụ và điều khoản bị ràng buộc; vấn đề và nguyên nhân không tự bộc lộ; môi trường phải dựng để phát hiện; mã dùng để phát hiện; chứng minh hai chiều kèm mã thoát; ràng buộc trong quá trình khắc phục; cách xử lý và vị trí trên workflow; giới hạn kiểm chứng của cổng.

Báo cáo trích dẫn Nghị định 13/2023/NĐ-CP theo yêu cầu đề tài. Thực tế, Nghị định 13/2023 hết hiệu lực từ 01/01/2026, được thay thế bởi Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15 và Nghị định 356/2025/NĐ-CP hướng dẫn thi hành. Các nghĩa vụ pháp lý viện dẫn đều được văn bản mới kế thừa nhưng đổi số hiệu điều khoản. Do chưa đối chiếu trực tiếp văn bản gốc Luật 91/2025/QH15, báo cáo không dẫn số hiệu điều khoản cụ thể của luật này.

## 4.2 Thành viên 1, Nguyễn Giang Nam, B26CHAT030: kiểm soát thay đổi được khai báo nhưng không có hiệu lực thi hành

### 4.2.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Đợt phát hành hạ tầng giám sát diễn ra ngoài giờ làm việc. Một thành viên đưa nhanh cấu hình Loki và Grafana lên nhánh phát hành bằng thao tác đẩy trực tiếp thay vì mở pull request. Thay đổi này tác động tới luồng xử lý nhật ký, đồng nghĩa với tác động tới luồng dữ liệu cá nhân.

Điều khoản CS-01 yêu cầu mọi thay đổi vào nhánh phát hành phải có pull request, có một người phê duyệt khác tác giả, qua toàn bộ cổng kiểm soát tự động và truy vết được tác giả cùng lý do. Điều khoản CS-07 yêu cầu cổng tự động phải chặn chứ không chỉ báo cáo. Hai điều khoản này là nghĩa vụ chứng minh tuân thủ theo GDPR Điều 24 và 32(1), tương ứng Điều 26 và 27 Nghị định 13/2023/NĐ-CP. Thiếu pull request đồng nghĩa với thiếu hồ sơ phê duyệt, và nghĩa vụ giải trình trong 72 giờ không thể bù đắp bằng biện pháp kỹ thuật sau đó.

### 4.2.2 Vấn đề và nguyên nhân không tự bộc lộ

Kho mã nguồn khai báo ba lớp kiểm soát cho CS-01. Kiểm chứng thực tế cho thấy cả ba lớp đều không ngăn chặn được tình huống trên.

Lớp thứ nhất là `ci/policy_guard.py`. Tệp này kiểm tra định dạng thông điệp commit và tiêu đề pull request. Hàm `validate_push_event()` chỉ đối chiếu định dạng, không có đoạn mã nào từ chối một lần đẩy mã vì lý do đẩy trực tiếp vào nhánh phát hành.

Lớp thứ hai là bảo vệ nhánh phía GitHub. Truy vấn trực tiếp qua API ngày 04/11/2026, nhánh `main` trả về `protected: false`, nên thao tác đẩy trực tiếp và đẩy cưỡng bức đều được chấp nhận, không phụ thuộc vào số lượng script kiểm tra trong kho mã nguồn.

Lớp thứ ba là cổng kiểm soát quản trị trên CI, nơi phát sinh khiếm khuyết nghiêm trọng nhất. Bước chính sách lớp quản trị chạy đúng bộ quy tắc, ghi ra đúng kết luận vi phạm, rồi vẫn trả về trạng thái thành công. Nguyên nhân nằm ở một dòng:

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

### 4.2.3 Môi trường phải dựng để phát hiện

Phép kiểm chứng phải truy vấn đúng hệ thống đang nắm kiểm soát rồi giao cho một policy engine đánh giá dữ liệu trả về: truy vấn hệ thống danh tính, không căn cứ trên một khai báo tĩnh trong kho mã nguồn. Riêng lớp thứ ba cần một phép kiểm chứng thứ hai, đối chiếu trạng thái của bước trên CI với nội dung tệp kết quả do chính bước đó sinh ra.

*Bảng: Thành phần môi trường cần dựng cho phép kiểm chứng lớp quản trị*

| Thành phần | Bản dùng | Vai trò |
| :--- | :--- | :--- |
| GitHub REST API, endpoint `branches/{branch}` | token đọc cấu hình kho mã nguồn | Căn cứ duy nhất về trạng thái bảo vệ nhánh |
| Conftest, namespace `repo` | 0.71.1, bản ghim, đối chiếu mã băm | Công cụ thực thi chính sách khai báo |
| API Actions, endpoint `runs/{id}/jobs` và artifact của run | run thực tế | Đối chiếu trạng thái bước với nội dung tệp kết quả |

Trình tự bắt buộc gồm ba bước: tải Conftest bản ghim và đối chiếu mã băm; chạy `conftest verify -p policy/` để bộ test của quy tắc đạt trước; chỉ sau đó mới dùng quy tắc để đánh giá dữ liệu thực tế. Bước thứ hai mang tính bắt buộc, vì một quy tắc sai cú pháp vẫn chạy và vẫn trả về kết quả không có vi phạm.

### 4.2.4 Mã dùng để phát hiện

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

### 4.2.5 Chứng minh hai chiều

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

### 4.2.6 Ràng buộc trong quá trình khắc phục

Việc khắc phục vượt quá phạm vi một commit, do bốn ràng buộc tác động đồng thời.

Ràng buộc thẩm quyền: bật bảo vệ nhánh là thao tác trong phần thiết lập kho mã nguồn, và chỉ chủ kho mã nguồn có thẩm quyền thực hiện. Policy as Code ở đây chỉ kiểm chứng chứ không thi hành được kiểm soát, nên bản vá có một phần kỹ thuật và một phần hành chính.

Ràng buộc phạm vi token: khối `permissions` của `GITHUB_TOKEN` không có khóa `administration`. Lần thử khai báo `administration: read` làm cả tệp workflow không phân tích được, và GitHub tạo một run thất bại với 0 job, run `41810605290`. Hệ quả là trường `protection` của một nhánh không đọc được bằng token mặc định của workflow, nên trong CI chỉ quy tắc thứ nhất còn hiệu lực.

Ràng buộc độ tin cậy của điểm thi hành: hook `.githooks/commit-msg` chạy trên máy lập trình viên, và bản trước trả về 0 kèm một dòng cảnh báo khi máy không có Python, tức bỏ qua kiểm tra mà vẫn báo thành công. Lập trình viên cũng có thể vô hiệu hóa hook bằng `git commit --no-verify`.

Ràng buộc giữa chính sách và phương pháp đánh giá: nhánh `main` giữ hệ thống ở trạng thái có khiếm khuyết để làm đối tượng đánh giá, trong khi CS-01 yêu cầu mọi thay đổi vào nhánh phát hành phải qua pull request. Giải pháp là một ngoại lệ có hồ sơ và có thời hạn theo CS-08 thay vì nới lỏng chính sách một cách tùy tiện.

### 4.2.7 Cách xử lý và vị trí trên workflow

Bản vá gồm bốn thay đổi theo thứ tự hiệu lực giảm dần: khai báo `shell: bash` cho mọi bước có chuỗi lệnh pipe để ba cổng ở stage 1 và hai cổng ở stage 4 thực thi ngăn chặn; bổ sung `ci/check_branch_payload.py` kiểm tra cấu trúc phản hồi API trước khi đánh giá; chỉ đánh giá những nhánh vừa thuộc diện chính sách vừa thực sự tồn tại; và chuyển hook sang fail-closed.

*Bảng: Bốn lớp thi hành của cùng một điều khoản chính sách*

| Lớp | Nơi thi hành | Phase | Cơ chế |
| :--- | :--- | :--- | :--- |
| Phản hồi sớm | máy lập trình viên | Code | hook `commit-msg`, fail-closed |
| Quy ước thay đổi và cổng CS-01 | CI | Code | `policy_guard.py` chạy trên payload sự kiện, có cơ chế ngoại lệ theo thời hạn |
| Quản trị kho mã nguồn | CI | Plan, Code | `repo_policy.rego` đánh giá JSON lấy từ API |
| Chặn hợp nhất | GitHub | Plan | bảo vệ nhánh, kiểm chứng được nhưng không thi hành được từ mã |

Một điều khoản chính sách cần nhiều điểm thi hành, và điểm thi hành càng gần người viết mã càng cho phản hồi nhanh, đồng thời càng ít tin cậy. Lớp duy nhất thực sự ngăn được một lần hợp nhất không đạt lại nằm ngoài kho mã nguồn, do đó lớp này phải được kiểm chứng liên tục bằng lớp thứ ba, và lớp thứ ba phải tự chứng minh được khả năng ngăn chặn của chính nó.

### 4.2.8 Giới hạn kiểm chứng của cổng

Chính sách quản trị chỉ đọc được trạng thái cấu hình. Cổng không xác minh được một thành viên có thực sự dùng xác thực hai yếu tố, cũng không xác minh được người phê duyệt pull request có đọc mã hay chỉ phê duyệt hình thức. Phần đó thuộc phạm vi quản trị nhân sự. Kết quả kiểm chứng còn phụ thuộc phạm vi token như nêu ở mục 4.2.6, nên phạm vi token là một phần của phép kiểm chứng, không phải chi tiết kỹ thuật phụ.

## 4.3 Thành viên 2, Nguyễn Đình Hải, B26CHAT010: tiêm mã SQL đi qua hàm bao nội bộ

### 4.3.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Khách hàng tra cứu vận đơn và tra cứu cảng biển trên trang công khai, không cần đăng nhập. Hai luồng này nhận chuỗi nhập tự do rồi hiển thị kết quả lấy từ cơ sở dữ liệu chứa dữ liệu cá nhân của người nhận hàng.

Điều khoản CS-03 cấm ghép dữ liệu nhận từ người dùng vào câu lệnh truy vấn dưới mọi hình thức. Điều khoản CS-05 yêu cầu dữ liệu cá nhân chỉ rời khỏi hệ thống theo đường đã khai báo. Căn cứ pháp lý là GDPR Điều 5(1)(f) và 32, tương ứng Điều 26 và 27 Nghị định 13/2023/NĐ-CP.

### 4.3.2 Vấn đề và nguyên nhân không tự bộc lộ

Vấn đề không dừng ở một lỗ hổng tiêm mã SQL thông thường. Điểm thực thi câu lệnh không phải `mysqli_query` mà hàm bao `query()` của dự án trong `lib/db.php`, và chuỗi nhiễm đi từ `$_GET` trong tệp trang qua biến trung gian rồi vào hàm bao ở tệp khác.

```php
// pages/ports.php:12, 24, 27
$q = $_GET['q'] ?? '';
$sql = "SELECT code, city, country, volume FROM ports WHERE code LIKE '%$q%'";
$res = query($sql);   // diem thuc thi nam o lib/db.php, khong phai o day
```

Bảng kết quả hiển thị bốn cột, nên một truy vấn `UNION SELECT` bốn cột trích xuất được dữ liệu mọi bảng mà tài khoản kết nối đọc được, gồm bảng `users` chứa mật khẩu dạng rõ và khóa API. Hai cấu hình khác gia tăng thiệt hại: ứng dụng kết nối bằng tài khoản `root` toàn quyền theo `prod.yml:49`, và lỗi SQL xuất trực tiếp ra phản hồi HTTP theo `lib/db.php:48-49`.

Hai biến thể phức tạp hơn nằm ở hai tệp khác. Tệp `pages/track_api.php` trả về JSON và không in kết quả truy vấn ra trang, nên khai thác theo thời gian vẫn thành công mà không để lại dấu vết hiển thị trên giao diện. Tệp `pages/shipment_detail.php` thiếu kiểm tra quyền sở hữu, nên một người dùng đã đăng nhập đọc được đơn hàng của chủ thể dữ liệu khác mà không cần tiêm mã.

Nguyên nhân không tự bộc lộ là tên hàm bao. Bộ quy tắc công khai `p/php` và SonarQube Community đều không liên kết được source với sink khi sink là một hàm do dự án tự định nghĩa ở tệp khác. Trên cả hai nhánh, SonarQube ghi `vulnerabilities` bằng 0, `security_hotspots` bằng 0 và `security_rating` bằng 1, tức mức A.

### 4.3.3 Môi trường phải dựng để phát hiện

Môi trường gồm Semgrep 1.182.1 bật taint mode với bộ quy tắc tự viết; SonarQube Community dựng tạm trong CI làm đối chứng, cùng mã nguồn và cùng lượt chạy; một cặp fixture PHP gồm bản vi phạm và bản đã vá; và cơ sở dữ liệu có dữ liệu mẫu của hai người dùng khác nhau để kiểm tra quyền sở hữu.

Việc đặt hai công cụ trên cùng một lượt chạy là có chủ đích. Đặt hai công cụ cạnh nhau làm rõ giới hạn của từng lớp: Semgrep báo 12 vị trí tiêm mã SQL trong khi SonarQube báo 0 lỗ hổng trên cùng mã nguồn và cùng lượt chạy.

### 4.3.4 Mã dùng để phát hiện

Quy tắc tự viết khai báo nguồn không tin cậy, điểm thực thi và bộ khử nhiễm. Điểm then chốt là dòng khai báo `query(...)` làm sink, do bộ quy tắc tiêu chuẩn không nhận diện hàm bao nội bộ của dự án.

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

### 4.3.5 Chứng minh hai chiều

Cặp fixture chạy ngay trong pipeline tại bước chứng minh cặp fixture hai chiều, kết quả ở `evidence/ci-06-fixture-vulnerable.txt` và `evidence/ci-07-fixture-patched.txt`. Bước này so sánh hai mã thoát bằng biến tường minh thay vì dựa vào mã thoát của chuỗi lệnh pipe:

```
ban co y sai: exit=1 (ky vong 1)
ban da va    : exit=0 (ky vong 0)
```

Đối chứng âm nằm trong cùng lượt chạy: trên cùng mã nguồn, SonarQube báo 0 lỗ hổng và `security_rating` mức A, trong khi quy tắc tự viết báo vi phạm ở 12 vị trí trên nhánh `main`. Số phát hiện giảm còn 8 trên nhánh `patched`, phần còn lại thuộc đợt vá thứ hai có chủ đích.

### 4.3.6 Ràng buộc trong quá trình khắc phục

Ràng buộc thứ nhất là thứ tự vá. Phép kiểm TDS-6 khẳng định luồng nhật ký không chứa nguyên văn câu lệnh truy vấn. Để khẳng định được điều đó phải có một truy vấn lỗi thực tế. Vá hết các điểm còn lại trong cùng một đợt làm phép kiểm mất đối tượng kiểm chứng: nó sẽ báo đạt vì không còn gì để kiểm, đúng loại đạt giả đã phát sinh ba lần trong quá trình xây dựng bộ kiểm thử. Danh sách hoãn có chủ sở hữu và lý do trong `patches/README.md`.

Ràng buộc thứ hai là bản chất của hai biến thể. Tham số hóa truy vấn không khắc phục được `shipment_detail.php`, vì thiếu sót ở đó là thiếu điều kiện chủ sở hữu trong logic nghiệp vụ. Bản vá phải thêm điều kiện `WHERE customer_id = ?` và một phép kiểm riêng, TDS-3, chứng minh người này không đọc được dữ liệu người khác.

Ràng buộc thứ ba là tầng quyền. Chừng nào ứng dụng còn kết nối bằng `root` với quyền `FILE`, một lỗ hổng tiêm mã SQL còn lại ở bất kỳ đâu vẫn cho phép đọc ghi tệp trên máy chủ cơ sở dữ liệu. Việc hạ quyền thuộc mục 4.4 và 4.5, nên bản vá của ba thành viên phải phối hợp theo thứ tự.

### 4.3.7 Cách xử lý và vị trí trên workflow

Quy tắc chạy ở stage 2 với cờ `--error`, nên một phát hiện mức ERROR làm bước thất bại và chặn pull request. Bản vá dùng `mysqli_prepare` với tham số ràng buộc, bổ sung điều kiện chủ sở hữu, và giữ lại một điểm lỗi có chủ đích làm đối tượng cho TDS-6 đến khi phép kiểm đó được thay bằng phép kiểm trực tiếp trên hàm ghi nhật ký.

### 4.3.8 Giới hạn kiểm chứng của cổng

Taint mode không lần được vết luồng dữ liệu qua một biến siêu toàn cục ghi ở tệp khác, cũng không lần được chuỗi truy vấn tạo bởi thao tác ghép mảng qua `implode`. Quy tắc cũng không chứng minh được dữ liệu chưa từng bị trích xuất trước thời điểm vá; khẳng định đó cần nhật ký truy cập đầy đủ từ ngày hệ thống lên mạng, điều mà hệ thống hiện chưa có.

## 4.4 Thành viên 3, Đào Xuân Mạnh, B26CHAT026: bí mật có giá trị dự phòng dạng hằng và mật khẩu dạng rõ

### 4.4.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Đội vận hành triển khai ứng dụng lên một máy chủ mới. Quy trình yêu cầu nạp biến môi trường từ nguồn quản lý bí mật trước khi khởi động, nhưng bước đó bị bỏ qua. Dịch vụ vẫn khởi động bình thường, ứng dụng vẫn kết nối được cơ sở dữ liệu, và không có cảnh báo nào.

Điều khoản CS-04 yêu cầu bí mật chỉ đến từ nguồn quản lý bí mật, không có giá trị dự phòng dạng hằng, và ứng dụng phải dừng khi thiếu bí mật. Điều khoản CS-06 yêu cầu tài khoản dịch vụ ở mức quyền tối thiểu. Căn cứ pháp lý là GDPR Điều 5(1)(f), 25 và 32(1)(a).

### 4.4.2 Vấn đề và nguyên nhân không tự bộc lộ

Do `.env` nằm trong `.gitignore`, trình quét bí mật không có chuỗi tĩnh nào để phát hiện. Khiếm khuyết thực tế nằm ở cơ chế nhận giá trị mặc định dạng hằng khi thiếu biến môi trường, cho phép container khởi động bằng một mật khẩu đã công khai trong kho mã nguồn.

Ba lớp liên hoàn. Lớp thứ nhất là toán tử dự phòng trong `lib/db.php`, nhận chuỗi hằng làm giá trị khi biến môi trường rỗng. Lớp thứ hai là tài khoản mặc định `root` toàn quyền, kèm quyền `FILE`, theo `prod.yml:49` và `init.sql.template:11-14`. Lớp thứ ba là mật khẩu người dùng lưu dạng rõ trong bảng `users`.

Riêng lớp thứ nhất chỉ là một cấu hình sai. Kết hợp với lỗ hổng tiêm mã SQL ở mục 4.3, bộ ba này cho phép đọc ghi tệp trên máy chủ cơ sở dữ liệu, và lộ toàn bộ mật khẩu người dùng ngay tại bản ghi chứ không cần phá băm.

Nguyên nhân không tự bộc lộ là nơi khiếm khuyết biểu hiện. Đọc tệp cấu hình chỉ thấy một chuỗi tham chiếu biến môi trường, hoàn toàn hợp lệ. Khiếm khuyết chỉ bộc lộ trong môi trường thực thi, ở trường hợp biến môi trường không được nạp, tức ở một trạng thái mà phân tích tĩnh không quan sát.

### 4.4.3 Môi trường phải dựng để phát hiện

Môi trường gồm ba thành phần. Hai lần khởi tạo cùng một tệp compose, một lần có biến môi trường và một lần không, nhằm quan sát hành vi nhận giá trị dự phòng. Trivy secret scan chạy trên toàn bộ `app/` làm đối chứng âm, để chứng minh lớp quét bí mật không đủ. InSpec chạy trên container đang hoạt động để đọc giá trị đang có hiệu lực thay vì giá trị được khai báo.

Thành phần thứ ba là thành phần quyết định: phép kiểm phải đọc trạng thái runtime, nơi khiếm khuyết thực sự bộc lộ.

### 4.4.4 Mã dùng để phát hiện

Quy tắc nhận diện mẫu toán tử dự phòng, phủ cả `?:` và `??`, trên cả `getenv`, `$_ENV` và `$_SERVER`:

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

### 4.4.5 Chứng minh hai chiều

Chiều vi phạm: quy tắc báo vi phạm trên `lib/db.php` ở trạng thái hiện tại. Chiều đạt: quy tắc không báo vi phạm sau khi đổi sang bắt buộc có biến môi trường và thoát sớm khi thiếu.

Đối chứng âm trên cùng mã nguồn và cùng lượt chạy: Trivy secret scan ghi kết quả vào `evidence/ci-09-trivy-secret.txt` và không phát hiện bí mật nào trong `app/`. Hai kết quả trái dấu trên cùng một đối tượng là bằng chứng rằng quét bí mật và kiểm tra cấu hình xử lý hai mục tiêu độc lập, không thay thế nhau.

Phép kiểm tuân thủ ở stage 4 kiểm giá trị đang có hiệu lực trên container, kết quả tại `evidence/ci-13-inspec.txt`. Trước khi sửa, hai cổng ở stage 4 cũng mất mã thoát theo cơ chế nêu ở mục 4.2, nên kết quả này chỉ trở thành một cổng thật sau bản vá đó.

### 4.4.6 Ràng buộc trong quá trình khắc phục

Bỏ giá trị dự phòng làm container không khởi động được khi thiếu biến, nên phải sửa cả entrypoint và tài liệu dựng, đồng thời bổ sung một thông điệp lỗi nêu rõ biến bị thiếu.

Áp dụng hàm băm yêu cầu di trú dữ liệu đồng bộ với `login.php`. Nếu làm đơn phương, toàn bộ tài khoản hiện hành mất quyền đăng nhập. Thứ tự đúng là thêm cột băm, ghi song song khi người dùng đăng nhập thành công, rồi mới bỏ cột mật khẩu dạng rõ.

Hạ quyền tài khoản cơ sở dữ liệu làm một số truy vấn hiện có thất bại, vì chúng đang dựa vào quyền rộng của `root`. Mỗi truy vấn thất bại phải được xem lại, thay vì cấp thêm quyền tùy tiện.

### 4.4.7 Cách xử lý và vị trí trên workflow

Quy tắc chạy ở stage 2, phép kiểm tuân thủ chạy ở stage 4 trên container thực tế, và lặp lại ở stage 5 sau khi phát hành. Thứ tự vá gồm bốn bước: tạo tài khoản quyền tối thiểu, đổi chuỗi kết nối sang tài khoản đó, bắt buộc có biến môi trường và thoát sớm khi thiếu, băm mật khẩu kèm di trú dữ liệu.

### 4.4.8 Giới hạn kiểm chứng của cổng

Quy tắc chỉ nhận diện được dạng mã đã khai báo. Một bí mật truyền qua tệp cấu hình sinh lúc chạy, hoặc đọc từ một dịch vụ cấu hình từ xa, nằm ngoài phạm vi. Phép kiểm tuân thủ xác nhận trạng thái tại một thời điểm, không xác nhận bí mật chưa từng bị dùng trước đó, và không thu hồi được bí mật đã lộ trong lịch sử kho mã nguồn.

## 4.5 Thành viên 4, Lê Đức Anh, B26CHAT003: cổng chính sách kiểm tra không đúng tệp được triển khai

### 4.5.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Đội vận hành cần một tệp compose riêng cho môi trường thật, với biến môi trường và cổng khác môi trường phát triển. Tệp mới được thêm vào kho mã nguồn dưới tên `docker-compose.prod.yml`, và một tệp nữa cho cụm giám sát. Phạm vi kiểm tra của cổng chính sách không được cập nhật theo.

Điều khoản CS-02 yêu cầu cấu hình triển khai phải qua cổng chính sách trước khi phát hành, và phạm vi kiểm tra phải phủ đúng tệp được dùng khi triển khai. Điều khoản CS-06 yêu cầu quyền tối thiểu và bề mặt tiếp xúc nhỏ nhất. Căn cứ pháp lý là GDPR Điều 32(1)(b).

### 4.5.2 Vấn đề và nguyên nhân không tự bộc lộ

Cổng chính sách, bộ quy tắc rego và kết quả đạt đều tồn tại, nhưng tệp thuộc phạm vi kiểm tra không phải tệp dùng khi triển khai. Mục `paths.include` của quy tắc Semgrep cục bộ chỉ liệt kê ba mẫu `**/docker-compose.yml`, `**/compose.yml` và `**/compose.yaml`. Hai tệp chứa mật khẩu gán cứng là `docker-compose.prod.yml` và `docker-compose.monitoring.yml` không khớp mẫu nào, nên quy tắc không chạy trên chúng.

Bên dưới lớp che lấp đó là ba nhóm khiếm khuyết thực tế. Container chạy bằng `root` do hai Dockerfile thiếu chỉ thị `USER`. Tệp compose thiếu `cap_drop`, `no-new-privileges` và `read_only`. Ảnh dùng thẻ `latest` tại `prod.yml:11`, `:31` và `monitoring.yml:64`, nên hai lần triển khai có thể chạy hai bản khác nhau dù mã nguồn không đổi.

Nguyên nhân không tự bộc lộ nằm ở hình thức của kết quả. Một cổng báo đạt vì không tìm thấy vi phạm và một cổng báo đạt vì không đọc đến tệp nào cho ra cùng một dòng kết luận. Một kết quả đạt trong trường hợp thứ hai gây rủi ro cao hơn trường hợp không có cổng, vì nó tạo ra sự tin cậy sai lệch. Điều khoản CS-07 xếp đây là vi phạm nặng hơn việc thiếu cổng.

### 4.5.3 Môi trường phải dựng để phát hiện

Môi trường gồm Conftest chạy trên toàn bộ tệp compose có trong kho mã nguồn, kể cả tệp của môi trường thật và tệp của cụm giám sát; một container dựng thực tế để InSpec đọc trạng thái đang có hiệu lực; và phép đối chiếu giữa khai báo trong tệp với kết quả `docker inspect`.

Phép kiểm chứng quyết định là phép kiểm chứng về chính phạm vi: chạy cổng trước và sau khi mở rộng `paths.include` trên cùng mã nguồn, rồi so sánh số vi phạm. Nếu phạm vi đúng từ đầu, hai lượt cho cùng kết quả; nếu phạm vi sai, số vi phạm tăng từ 0 lên giá trị thực tế.

### 4.5.4 Mã dùng để phát hiện

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

### 4.5.5 Chứng minh hai chiều

Bộ quy tắc rego cho hai kết quả trái dấu trên cặp fixture: báo vi phạm trên `fixtures/docker-compose.insecure.yml` và không báo vi phạm trên `fixtures/docker-compose.hardened.yml`, kèm mã thoát 1 và 0.

Chứng minh về phạm vi kiểm tra đặt cạnh nhau hai lượt trên cùng mã nguồn. Với phạm vi cũ, `docker-compose.prod.yml` không được đọc đến và cổng báo đạt. Với phạm vi đã mở rộng, Conftest đo được 9 vi phạm và 2 cảnh báo trên đúng tệp đó trong run `41810794218`: hai bí mật dạng hằng, tài khoản ứng dụng là `root`, bốn thiếu sót `cap_drop` và `no-new-privileges` trên hai dịch vụ, và hai ảnh ghim theo thẻ `latest`. Sau khi vá cả chín, cùng cổng đó báo 0 vi phạm trong run `41812598120`. Phần tăng từ 0 lên 9 rồi về 0 là số đo của chính phạm vi kiểm tra, không phải của mã nguồn, vì mã nguồn ở hai lượt đầu không đổi.

Ở stage 1, kết quả của cổng chính sách lớp triển khai nằm trong `evidence/ci-02-compose.txt`. Trước bản vá nêu ở mục 4.2, tệp này ghi 9 failures cho `prod.yml` và 13 cho `monitoring.yml` trong khi bước vẫn trả về trạng thái thành công. Sau bản vá, nội dung tệp và trạng thái bước khớp nhau.

### 4.5.6 Ràng buộc trong quá trình khắc phục

Bật `read_only` làm Apache không ghi được thư mục tạm, nên phải khai báo thêm `tmpfs` duy nhất cho các thư mục bắt buộc ghi.

Ghim ảnh theo mã băm làm quy trình cập nhật phải đổi: mỗi lần nâng phiên bản là một pull request có người phê duyệt, thay vì một lần khởi động lại container. Nhờ đó, hai lần triển khai từ cùng mã nguồn cho cùng một kết quả.

Hạ `cap_drop` xuống `ALL` làm một số dịch vụ giám sát mất quyền đọc thông tin tiến trình trên máy chủ, nên phải cấp lại từng năng lực cần thiết thay vì mở toàn bộ.

Ràng buộc trình tự: phạm vi kiểm tra phải được sửa trước khi vá nội dung, vì vá nội dung trước làm mất khả năng chứng minh cổng từng không đọc đến tệp đó.

### 4.5.7 Cách xử lý và vị trí trên workflow

Cổng chính sách chạy ở stage 1, trước khi dựng ảnh. Phép kiểm tuân thủ chạy ở stage 4 sau khi container hoạt động, và lặp lại ở stage 5 ngay sau khi phát hành, trước khi bản phát hành được chấp nhận. Ba vị trí này kiểm ba đối tượng khác nhau: tệp khai báo, container trong môi trường kiểm thử, và container trong môi trường đích.

### 4.5.8 Giới hạn kiểm chứng của cổng

Conftest chỉ kiểm tra tệp khai báo, không kiểm soát được các lệnh người vận hành nhập thủ công trên máy chủ. Phép kiểm tuân thủ xác nhận một thời điểm, nên một thay đổi sau đó vẫn nằm ngoài tầm nếu không có cổng chạy định kỳ khi vận hành. Đây là lý do mục 5.4 bổ sung một vòng lặp kiểm tra khi vận hành chứ không chỉ khi phát hành.

## 4.6 Thành viên 5, Nguyễn Phương Mai, B26CHAT025: kênh rò rỉ dữ liệu cá nhân qua luồng nhật ký

### 4.6.1 Tình huống nghiệp vụ và điều khoản bị ràng buộc

Để quan sát sự cố nhanh hơn, công ty dựng hệ giám sát tập trung và đưa toàn bộ nhật ký container vào đó. Quyết định này hợp lý về vận hành. Hệ quả ngoài dự kiến là mật khẩu dạng rõ của người dùng đi vào kho nhật ký, nơi có nhiều người truy cập hơn cơ sở dữ liệu.

Điều khoản CS-05 yêu cầu dữ liệu cá nhân chỉ rời khỏi hệ thống theo đường đã khai báo, và nhật ký không thuộc số đó. Điều khoản CS-08 yêu cầu lưu đủ sự kiện kiểm toán để thông báo vi phạm trong 72 giờ. Căn cứ pháp lý là GDPR Điều 5(1)(c), 33 và 34, tương ứng Điều 23 và 26 Nghị định 13/2023/NĐ-CP.

### 4.6.2 Vấn đề và nguyên nhân không tự bộc lộ

Kênh rò rỉ gồm năm mắt xích, mỗi mắt xích riêng lẻ đều là một lựa chọn kỹ thuật hợp lý.

Mắt xích thứ nhất, `pages/login.php:19` ghép mật khẩu vào câu lệnh truy vấn. Mắt xích thứ hai, hàm `query()` trong `lib/db.php:40-50` truyền toàn văn câu lệnh cho bộ ghi nhật ký khi truy vấn thất bại. Mắt xích thứ ba, Promtail không có pipeline stage che giấu dữ liệu nên chuyển nguyên văn dòng nhật ký. Mắt xích thứ tư, Loki lưu và cho truy vấn tự do, còn Grafana mở trên mọi giao diện mạng theo `monitoring.yml:43`. Mắt xích thứ năm, không có sự kiện kiểm toán khi đăng nhập thất bại, nên hệ thống không ghi nhận được số lần việc này đã xảy ra.

Một mật khẩu chứa dấu nháy đơn làm truy vấn thất bại, và toàn văn câu lệnh kèm mật khẩu đi hết năm mắt xích. Không công cụ nào trong pipeline phát hiện được, vì kênh này trải qua PHP và YAML ở hai tệp khác nhau, và không mắt xích nào là một mẫu mã nguy hiểm.

### 4.6.3 Môi trường phải dựng để phát hiện

Môi trường gồm ngăn xếp giám sát dựng đầy đủ với Promtail, Loki và Grafana; một truy vấn lỗi thực tế lấy từ đợt vá thứ hai chưa vá, làm đối tượng kiểm chứng; và một truy vấn LogQL chạy trước và sau khi bổ sung pipeline stage che giấu dữ liệu.

Về phương pháp, phép kiểm phải là phép kiểm hành vi trên hệ thống đang chạy, không phải phép kiểm trên mã nguồn. Khẳng định cần chứng minh là một khẳng định phủ định về nội dung luồng nhật ký, và nó chỉ kiểm được bằng cách kích hoạt một lỗi thật rồi đọc lại luồng.

### 4.6.4 Mã dùng để phát hiện

Phép kiểm TDS-6 chạy trong `tests/security/run.sh`: kích hoạt một truy vấn lỗi, sau đó khẳng định luồng nhật ký của container không chứa nguyên văn câu lệnh và không chứa giá trị mật khẩu. Bản vá phía giám sát đặt một pipeline stage thay thế giá trị nhạy cảm trong `patches/monitoring/promtail-config.hardened.yml`, và chuyển việc tương quan sang quy tắc Loki để không cần giữ lại dữ liệu gốc.

### 4.6.5 Chứng minh hai chiều

Chiều vi phạm: TDS-6 thất bại trên cấu hình gốc, kèm trích đoạn dòng nhật ký chứa giá trị nhạy cảm. Chiều đạt: TDS-6 đạt trên cấu hình đã che giấu, và cùng một truy vấn LogQL không còn trả về kết quả nào. Mã thoát của cả hai lượt được ghi trong `evidence/ci-12-tds.txt`.

Chuỗi phát hiện được kiểm chứng tiếp ở mục 5.3: tám yêu cầu tiêm mã SQL gửi vào ứng dụng đã vá, độ trễ từ tấn công tới đích nhận cảnh báo đạt mức 15,1, 20,9 và 24,6 giây qua ba lượt độc lập, ghi tại `evidence/35-chuoi-phat-hien-do-tre.txt`.

### 4.6.6 Ràng buộc trong quá trình khắc phục

Ràng buộc nặng nhất là xung đột giữa hai điều khoản của chính sách. Che giấu quá rộng làm quy tắc tương quan mất chính trường dữ liệu cần để nhận diện tấn công, vi phạm CS-08. Che giấu quá hẹp vẫn để lại rò rỉ, vi phạm CS-05. Giải pháp là tách hai nhiệm vụ: Promtail chỉ che giá trị nhạy cảm và giữ lại nhãn phân loại cùng địa chỉ nguồn, còn việc tương quan chuyển sang quy tắc Loki làm trên nhãn thay vì trên nội dung.

Ràng buộc đích nhận cảnh báo: cấu hình gốc gửi cảnh báo tới điểm cuối `alertmanager:9093` không tồn tại, nên dù phát hiện đúng, kết quả vẫn không đến được người tiếp nhận, và nghĩa vụ thông báo trong 72 giờ vẫn không thực hiện được.

Ràng buộc hiệu lực của chính cổng: hai bước ở stage 4 từng mất mã thoát theo cơ chế ở mục 4.2, nên phép kiểm TDS-6 có kết quả nhưng không có hiệu lực chặn. Bản vá ở mục 4.2 là điều kiện cần để kết quả của mục này trở thành một cổng.

### 4.6.7 Cách xử lý và vị trí trên workflow

Pipeline stage che giấu dữ liệu nằm trong Promtail khi vận hành, phép kiểm TDS-6 đặt ở stage 4 trong pipeline, và quy tắc tương quan Loki là ví dụ cụ thể của việc bổ sung quy tắc trong quá trình vận hành, trình bày ở mục 5.4.

### 4.6.8 Giới hạn kiểm chứng của cổng

Phép kiểm chỉ khẳng định về đường nhật ký đã biết, tức luồng đi qua Promtail. Nhật ký do Apache hoặc MariaDB ghi trực tiếp ra tệp trong container nằm ngoài phạm vi. Phép kiểm cũng không chứng minh được dữ liệu đã lưu trong Loki trước thời điểm che giấu đã bị xóa hết; việc đó cần một lần rà soát và xóa có hồ sơ riêng theo nghĩa vụ tại GDPR Điều 17.

---
# CHƯƠNG 5. GIÁM SÁT, ỨNG PHÓ VÀ VÒNG ĐỜI QUY TẮC

## 5.1 Kiến trúc nhật ký và nhận diện vector tấn công

Hệ thống giám sát thu thập nhật ký từ Docker qua socket, lọc hai container `ilfreight_web` và `ilfreight_db` theo `promtail-config.yml:17-23`, chia thành hai luồng: lỗi ứng dụng gắn nhãn `log_category: app_exception` (dòng 42-48) và lưu lượng HTTP gắn nhãn `log_category: http_traffic` (dòng 51-56). Cơ chế phân tách giúp đặt chính sách lưu trữ và cảnh báo riêng cho từng loại. Phía ứng dụng, cơ chế bắt lỗi toàn cục tại `index.php:13-33` gồm `set_exception_handler`, `set_error_handler` và `register_shutdown_function`, bảo đảm mọi lỗi đều được ghi nhận.

Promtail đồng thời gắn nhãn phân loại vector tấn công ngay khi thu thập, qua biểu thức chính quy so khớp dòng nhật ký.

*Bảng: Bốn nhóm vector tấn công được nhận diện tự động*

| Nhãn `vuln_category` | Mức | Dấu hiệu nhận biết chính | Dòng |
| :--- | :--- | :--- | :---: |
| `sqli` | critical | `union select`, `sleep(`, `or 1=1`, `information_schema`, `load_file(`, `sqlmap` | 58-66 |
| `traversal_lfi` | high | `../`, `%2e%2e%2f`, `/etc/passwd`, `php://filter` | 68-76 |
| `xss` | warning | `<script`, `onerror=`, `javascript:`, `document.cookie` | 78-86 |
| `command_injection` | critical | `; cat`, `&& ls`, `/bin/sh`, `powershell`, `cmd.exe` | 88-96 |

Bên cạnh bốn nhóm trên, nhóm thứ năm `error_based_leak` tại dòng 98-106 nhận diện phản hồi chứa lỗi SQL hoặc mã 4xx và 5xx. Phương pháp này có giới hạn kỹ thuật: việc so khớp chuỗi bị vượt qua bằng kỹ thuật mã hóa đơn giản, đồng thời báo sai khi người dùng nhập chuỗi trùng mẫu. Do đó cơ chế này chỉ hỗ trợ quan sát và điều tra sau sự cố, không ngăn chặn chủ động.

## 5.2 Tự động phục hồi dịch vụ

Dịch vụ `autoheal` theo dõi container gắn nhãn `autoheal: "true"` để khởi động lại khi gặp sự cố, theo cấu hình `AUTOHEAL_INTERVAL=10` và `AUTOHEAL_START_PERIOD=20` tại `monitoring.yml:68-70`. Container web kiểm tra sức khỏe qua `/health` mỗi 10 giây, cho phép lỗi ba lần liên tiếp theo `prod.yml:41-46`, tức phát hiện lỗi sau 30 giây. Điểm cuối `index.php:53-90` còn kiểm tra cơ sở dữ liệu qua `mysqli_ping` và trả mã 503 khi mất kết nối, giúp nhận diện trường hợp web chạy nhưng mất kết nối dữ liệu.

Giải pháp có một đánh đổi về an toàn: để khởi động lại container khác, `autoheal` gắn socket Docker ở chế độ ghi theo `monitoring.yml:73`, tương đương đặc quyền `root` trên máy chủ, trong khi vẫn dùng ảnh thẻ `latest` từ bên thứ ba. Nếu bản cập nhật thượng nguồn bị can thiệp, kẻ tấn công kiểm soát được toàn bộ máy chủ. Rủi ro chuỗi cung ứng này phải cân nhắc so với lợi ích tự phục hồi, và là một trong các điểm mà vòng lặp ở mục 5.4 theo dõi.

## 5.3 Chuỗi tấn công đến cảnh báo và độ trễ phát hiện

Biện pháp ở Chương 4 được triển khai trên nhánh vá và kiểm chứng qua vận hành thực tế. Cụm giám sát được chỉnh để khép kín quy trình từ tấn công đến cảnh báo: Promtail chỉ che giấu dữ liệu trước khi lưu, việc tương quan chuyển sang quy tắc Loki, và bổ sung Alertmanager cùng đích nhận cảnh báo. Khi gửi tám yêu cầu tiêm mã SQL vào ứng dụng đã vá, luồng xử lý đi tuần tự qua Apache, Promtail, Loki đếm địa chỉ nguồn bằng `| json`, Alertmanager, tới đích nhận để thông báo người trực. Độ trễ từ tấn công tới đích ghi nhận 15,1, 20,9 và 24,6 giây qua ba lượt độc lập, do chu kỳ đánh giá mười lăm giây của Loki và khoảng chờ gộp mười giây của Alertmanager quyết định.

Một đợt gửi kích hoạt hai mức cảnh báo: mức thông tin để đối chiếu và mức nghiêm trọng báo người trực, theo kiến trúc cảnh báo hai chuỗi song song. Cơ chế che giấu dữ liệu được kiểm chứng: gửi yêu cầu chứa mật khẩu, không nhật ký nào trong Loki còn lưu mật khẩu nguyên văn. Ở cấu hình gốc, quy tắc trỏ tới một Alertmanager không tồn tại khiến chuỗi phát hiện bị đứt tại mắt xích cuối.

## 5.4 Vòng đời quy tắc và tự động vá khi vận hành

Ba mục trên trình bày việc phát hiện trong một bản phát hành đã có. Mục này trình bày cơ chế hệ thống tự đưa phát hiện mới trở lại đầu pipeline, phần tương ứng với CD trong DevSecOps.

Vòng lặp khi vận hành gồm ba việc, khai báo trong `.github/workflows/auto-remediate.yml`, chạy theo lịch hằng tuần và chạy được theo yêu cầu.

*Bảng: Ba việc của vòng lặp vận hành và cơ chế tương ứng*

| Tác vụ | Cơ chế | Kết quả |
| :--- | :--- | :--- |
| Theo dõi chuỗi cung ứng sau khi phát hành | Trivy quét hai ảnh nền ở mức CRITICAL và HIGH, so sánh với mốc cơ sở trong `sbom/cve-baseline.json` | `evidence/cve-watch.txt` |
| Tự động vá | Khi có CVE chưa từng xuất hiện, `ci/cve_watch.py` cập nhật mốc cơ sở, sinh mô tả bản vá và mở một pull request vào nhánh vá | `evidence/auto-remediate-pr-body.md` |
| Bổ sung quy tắc | Một mẫu tấn công quan sát được trong Loki trở thành một quy tắc Semgrep hoặc một quy tắc tương quan mới, quay lại stage 2 và trở thành cổng chặn cho lần sau | tệp quy tắc trong `ci/` và nhật ký của run |

Điểm quan trọng về thiết kế: pull request do vòng lặp này sinh ra vẫn phải đi qua toàn bộ cổng kiểm soát như mọi pull request khác. Việc tự động hóa nằm ở khâu phát hiện và khâu soạn thay đổi, không nằm ở khâu phê duyệt. Điều khoản CS-01 không có ngoại lệ cho một tác nhân tự động.

Vòng lặp này xử lý một giới hạn mà bốn stage đầu không xử lý được: một lỗ hổng công bố sau ngày phát hành không vi phạm cổng nào tại thời điểm phát hành, nên không có vòng lặp định kỳ thì nó không bao giờ bị phát hiện. Mỗi lần vòng lặp chạy là một lần hệ thống đối chiếu lại trạng thái hiện tại với tri thức mới nhất về lỗ hổng.

## 5.5 Tổng hợp những gì công cụ không phát hiện được

*Bảng: Khiếm khuyết công cụ không phát hiện và nguyên nhân*

| Khiếm khuyết | Vị trí | Nguyên nhân công cụ không báo |
| :--- | :--- | :--- |
| Mật khẩu lưu dạng rõ trong cơ sở dữ liệu | `init.sql.template:26`, `:34-38` | Thuộc dữ liệu, không ở mã; tệp SQL không được quét |
| Quality gate chỉ báo cáo ở bản đầu, và cổng báo thành công trong khi tệp kết quả của chính nó chứa dòng FAIL | biểu thức `enforce_quality_gate`, năm bước có chuỗi lệnh pipe | Không công cụ nào tự kiểm cấu hình của chính pipeline, cũng không đối chiếu trạng thái bước với tệp kết quả |
| Kênh rò rỉ mật khẩu ra Grafana | 5 tệp, 2 ngôn ngữ | Kênh trải qua PHP và YAML, không công cụ nào phân tích xuyên lớp |
| Bí mật trong compose của môi trường thật và của cụm giám sát | `monitoring.yml:46`, `prod.yml:15`, `:50` | Mục `paths.include` của quy tắc không khớp tên tệp |
| Thiếu tái sinh định danh phiên | `login.php:22-26` | Quy tắc bắt mẫu có mặt nên khó bắt mẫu vắng mặt |
| Thiếu kiểm tra quyền sở hữu bình luận và đơn hàng | `comment_delete.php:18`, `shipment_detail.php` | Lỗi logic nghiệp vụ, cần hiểu ý định của ứng dụng |
| Tài khoản cơ sở dữ liệu thừa quyền, và bí mật đã lộ trong lịch sử kho mã nguồn | `init.sql.template:12-13`, toàn bộ lịch sử | Không có quy tắc nào đánh giá mức quyền SQL; công cụ chỉ quét bản làm việc hiện tại |

Các khiếm khuyết trên có một đặc tính chung. Phân tích tĩnh nhận diện hiệu quả mã nguy hiểm trong một tệp và một ngôn ngữ, nhưng hạn chế trước bốn nhóm: thiếu một biện pháp kiểm soát, lỗi logic nghiệp vụ, khiếm khuyết từ tổ hợp các thành phần riêng lẻ vốn hợp lệ, và khiếm khuyết của chính cơ chế kiểm soát.

Nhóm thứ tư là nhóm đáng chú ý nhất, vì nó làm sai lệch kết quả của mọi nhóm còn lại. Hệ quả thực tiễn: pipeline DevSecOps không thay được việc đọc mã và rà soát thiết kế, chỉ xử lý phần việc lặp lại để con người tập trung vào phần công cụ tự động chưa làm được, và bản thân pipeline cũng phải nằm trong diện bị kiểm chứng.

---
# KẾT LUẬN

Nhóm xây dựng và vận hành một pipeline DevSecOps năm stage bằng công cụ nguồn mở: kiểm tra quy ước phát triển cùng cổng chính sách khai báo, phân tích tĩnh qua hai công cụ độc lập, kiểm soát chuỗi cung ứng kèm SBOM, kiểm thử hành vi và tuân thủ trên hệ thống đang chạy, và một stage CD có xác minh sau phát hành kèm cơ chế quay lui. Toàn bộ cổng đều bắt nguồn từ tám điều khoản của một văn bản chính sách doanh nghiệp, nên mỗi run pipeline vừa là một lần kiểm thử vừa là một lần tạo hồ sơ chứng minh tuân thủ.

Ba kết quả có giá trị thực tiễn cao nhất đều đến từ việc kiểm chứng trực tiếp hệ thống đã triển khai, không từ việc mô tả.

Kết quả thứ nhất, và là phát hiện quan trọng nhất của đề tài, là một cổng có thể báo đạt trong khi không kiểm tra gì. Năm bước trong tệp workflow chuyển kết quả qua `tee` mà không khai báo `shell`, nên mã thoát của cả chuỗi lệnh là mã thoát của `tee` và luôn bằng 0. Ba cổng chính sách ở stage 1 và hai cổng ở stage 4 vì vậy không thực hiện chức năng ngăn chặn trong khi pipeline được giả định có cơ chế chặn, dù tệp kết quả của chính chúng chứa các dòng FAIL. Phát hiện này đến từ một phép đối chiếu đơn giản mà không công cụ nào trong pipeline tự làm: so sánh trạng thái của một bước với nội dung tệp kết quả do chính bước đó sinh ra. Sau khi khai báo `shell: bash` cho mọi bước có chuỗi lệnh pipe, cùng mã nguồn và cùng cấu hình cho ra kết quả trái ngược: cổng chính sách lớp triển khai và cổng quản trị đều trả về trạng thái thất bại, và các stage sau bị bỏ qua đúng thiết kế.

Kết quả thứ hai là một quality gate đạt không đồng nghĩa mã nguồn an toàn. Bản SonarQube Community đánh giá `security_rating` mức A và ghi nhận 0 lỗ hổng trên cả hai nhánh, trong khi bộ quy tắc tự viết của nhóm phát hiện 12 vị trí tiêm mã SQL. Nguyên nhân là bản này không phân tích luồng dữ liệu xuyên hàm và xuyên tệp, nên không nối được chuỗi truy vấn từ tệp trang sang hàm bao trong `lib/db.php`. Hiện tượng này khẳng định một cổng chỉ chứng minh được điều nằm trong phạm vi quan sát của nó.

Kết quả thứ ba là hiệu lực của một cổng phụ thuộc vào phạm vi kiểm tra của nó. Cổng chính sách lớp triển khai từng chỉ đọc một tệp compose của môi trường phát triển, trong khi hai tệp thực sự dùng khi triển khai nằm ngoài phạm vi. Sau khi mở rộng phạm vi, cùng bộ quy tắc đó phát hiện 9 vi phạm trên `prod.yml` và 13 trên `monitoring.yml`. Một cổng báo đạt vì không tìm thấy vi phạm và một cổng báo đạt vì không đọc đến tệp nào cho ra cùng một dòng kết luận, nên phạm vi kiểm tra phải được kiểm chứng tách riêng.

Ba kết quả trên có một điểm chung: chúng đều là khiếm khuyết của chính cơ chế kiểm soát, không phải của ứng dụng. Điều khoản CS-07 trong chính sách xếp loại khiếm khuyết này nặng hơn việc thiếu cổng, vì nó làm sai lệch kết quả của mọi cổng còn lại và tạo ra sự tin cậy sai lệch.

Về hạn chế, phân tích năm vấn đề ở Chương 4 dựa trên mã nguồn và cấu hình, trong khi kiểm chứng động chỉ áp dụng cho bản vá đợt một. Đợt vá thứ hai được hoãn có chủ đích để giữ đối tượng kiểm chứng cho phép kiểm TDS-6, và việc hoãn này được ghi thành một ngoại lệ có thời hạn theo điều khoản CS-08 thay vì để ngầm hiểu. Trường `protection` của một nhánh không đọc được bằng token mặc định của workflow, nên trong CI chỉ một trong ba quy tắc quản trị còn hiệu lực. Stage CD phát hành lên một môi trường đích tạm dựng trong máy ảo của runner, không phải lên máy chủ sản xuất, nên nó chứng minh được trình tự phát hành, xác minh và quay lui, nhưng chưa chứng minh được hành vi của hệ thống dưới tải thực. Về pháp lý, báo cáo trích dẫn Nghị định 13/2023/NĐ-CP theo yêu cầu đề tài nhưng chưa đối chiếu Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15, văn bản thay thế nghị định từ 01/01/2026.

Các hướng phát triển theo thứ tự ưu tiên:

- Đưa kết quả Semgrep thành điều kiện chặn tại stage 2, sau khi hoàn thành đợt vá thứ hai và thay phép kiểm TDS-6 bằng một phép kiểm trực tiếp trên hàm ghi nhật ký. Ngoại lệ `EX-2026-02` hết hạn ngày 31/12/2026, và chính cổng kiểm hồ sơ ngoại lệ sẽ làm stage 1 thất bại nếu công việc chưa hoàn tất trước thời hạn.
- Bổ sung một phép kiểm định kỳ về tính toàn vẹn của cổng: đối chiếu tự động trạng thái từng bước với nội dung tệp kết quả của bước đó, để khiếm khuyết dạng mất mã thoát không cần đến một lần rà soát thủ công mới phát hiện được.
- Dùng một token có quyền quản trị kho mã nguồn cho riêng cổng quản trị, để cả ba quy tắc trong `repo_policy.rego` đều có hiệu lực trong CI.
- Thu hồi và thay thế mọi bí mật từng xuất hiện trong lịch sử kho mã nguồn, vì công cụ quét chỉ đọc bản làm việc hiện tại.
- Mở rộng stage CD sang một môi trường đích bền vững, để phép xác minh sau phát hành và cơ chế quay lui được kiểm chứng trên hệ thống có dữ liệu và có tải.

---

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

---

# PHỤ LỤC. HỒ SƠ MINH CHỨNG

Mọi số liệu trong báo cáo đều lấy từ một trong các nguồn dưới đây. Quy chuẩn thu thập minh chứng hình ảnh được lưu riêng tại `docs/` trong kho mã nguồn, không thuộc phạm vi báo cáo.

*Bảng: Danh mục minh chứng*

| TT | Minh chứng | Vị trí |
| :---: | :--- | :--- |
| 1 | Chính sách an toàn thông tin, tám điều khoản CS-01 đến CS-08, và hồ sơ ngoại lệ có thời hạn | `policy/00-chinh-sach-attt.md`, `policy/exceptions.json`, `ci/check_exceptions.py` |
| 2 | Pipeline năm stage có chặn, và vòng lặp vận hành theo dõi CVE | `.github/workflows/devsecops-gate.yml`, `auto-remediate.yml`, `ci/cve_watch.py` |
| 3 | Policy as Code: quy ước commit, cổng CS-01, chính sách khai báo và bộ test của chính chính sách | `ci/policy_guard.py`, `.githooks/commit-msg`, `policy/*.rego`, `policy/*_test.rego` |
| 4 | Kiểm cấu trúc phản hồi API trước khi đánh giá chính sách | `ci/check_branch_payload.py` |
| 5 | Security as Code: tiêu chí quality gate và quy tắc tự viết | `ci/sonarqube-quality-gate.json`, `ci/semgrep-policy-php.yml`, `ci/semgrep-local-rules.yml` |
| 6 | Test-Driven Security, Compliance as Code và cặp fixture đạt chuẩn với vi phạm | `tests/security/run.sh`, `compliance/`, `fixtures/` |
| 7 | Trạng thái bảo vệ nhánh qua API, cùng ba kịch bản của cổng CS-01 kèm mã thoát | `evidence/api/branch-*-slim.json`, `evidence/20-policy-guard-cs01.txt` |
| 8 | Kết quả quét của hai nhánh | Artifact `evidence-security-as-code` của run `40748974196` và `40748974200` |
| 9 | Cổng không chặn trước khi sửa, và chặn đúng chức năng sau khi sửa | Artifact `evidence-policy-as-code` của run `40748974196` và `41810794218` |
| 10 | Tệp workflow không phân tích được do khóa `permissions` không tồn tại | run `41810605290`, 0 job |
| 11 | Danh sách khiếm khuyết đã vá, cổng phát hiện và chủ sở hữu | `patches/README.md` |

Kết quả quét được tái lập qua artifact `evidence-security-as-code` của run tương ứng, giải nén rồi mở `sonarqube/report.html`. Dạng máy đọc gồm `sonarqube/metrics.json`, `sonarqube/quality-gate.json`, `sonarqube/issues.json` và `ci-05-semgrep.json`. Phép kiểm hai chiều của cổng chính sách được tái lập qua artifact `evidence-policy-as-code`, đối chiếu nội dung `ci-01-dockerfile.txt`, `ci-02-compose.txt` và `ci-03-branch-protection.txt` với trạng thái từng bước trên trang của run.
