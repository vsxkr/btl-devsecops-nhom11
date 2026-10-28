# BÁO CÁO BÀI TẬP LỚN HỌC PHẦN DEVSECOPS

**Đề tài:** Đánh giá an toàn ứng dụng và bảo vệ dữ liệu người dùng trên dây chuyền DevSecOps CI/CD của hệ thống InlaneWeb Logistics

| | |
| :--- | :--- |
| **Cơ sở đào tạo** | Học viện Công nghệ Bưu chính Viễn thông |
| **Học phần** | Thực hành DevOps / DevSecOps |
| **Giảng viên hướng dẫn** | TS. Phạm Hoàng Duy |
| **Nhóm thực hiện** | Nhóm 11, lớp M26CQAT01-B |
| **Kho mã nguồn** | `github.com/wtfwhoyouare/PTIT-DevOps-SonarQube` |
| **Mốc mã nguồn khảo sát** | `660e75c` (quét công cụ) và `eb3f6c7` (hiện trạng) |
| **Thời gian** | Tháng 10 năm 2026 |

---

## PHÂN CÔNG NHIỆM VỤ

*Bảng: Phân công nhiệm vụ và vấn đề an toàn phụ trách*

| TT | Họ và tên | Mã học viên | Vấn đề an toàn phụ trách | Nhóm |
| :---: | :--- | :--- | :--- | :--- |
| 1 | Nguyễn Giang Nam (trưởng nhóm) | *(cần điền)* | Thiếu kiểm soát thay đổi mã nguồn | Quy trình |
| 2 | Nguyễn Đình Hải | *(cần điền)* | Tiêm mã SQL làm lộ dữ liệu cá nhân | Mã nguồn |
| 3 | Đào Xuân Mạnh | B26CHAT026 | Mật khẩu dạng rõ và bí mật gán cứng | Mã nguồn |
| 4 | Lê Đức Anh | *(cần điền)* | Cấu hình triển khai mất an toàn | Triển khai |
| 5 | Nguyễn Phương Mai | *(cần điền)* | Rò rỉ dữ liệu qua đường nhật ký | Vận hành |

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
| PR | Pull Request | Yêu cầu hợp nhất nhánh mã nguồn |
| GDPR | General Data Protection Regulation | Quy định bảo vệ dữ liệu chung của Liên minh châu Âu |
| NĐ 13 | | Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân |
| DLCN | Personal Data | Dữ liệu cá nhân |
| LogQL | Log Query Language | Ngôn ngữ truy vấn nhật ký của Loki |

---

# MỞ ĐẦU

**Bối cảnh và lý do chọn đề tài.** Khi một nhóm phát triển chuyển sang mô hình phát hành liên tục, khâu kiểm định an toàn theo lối cũ, tức rà soát thủ công một lần trước khi phát hành, không còn theo kịp tốc độ. Mỗi ngày có thể có vài lần hợp nhất mã nguồn, trong khi một đợt rà soát thủ công mất nhiều ngày. Hệ quả là khâu an toàn hoặc trở thành nút thắt làm chậm cả dây chuyền, hoặc bị bỏ qua.

Mô hình DevSecOps giải quyết mâu thuẫn này bằng cách đưa việc kiểm tra an toàn vào chính dây chuyền tự động, ở mọi chặng. Nguyên tắc cốt lõi là phát hiện lỗi ở chặng nào thì dây chuyền phải dừng ngay tại chặng đó.

Đề tài không dừng ở việc mô tả một dây chuyền đã dựng. Nhóm đặt câu hỏi ngược lại: dây chuyền nhóm đã dựng có thực sự dừng khi gặp lỗi không, và những dữ liệu cá nhân nào của người dùng thực sự được bảo vệ. Quá trình kiểm chứng cho một kết quả đáng chú ý được trình bày tại mục Khiếm khuyết trọng yếu của Chương 3: cổng chất lượng báo lỗi nhưng không dừng dây chuyền. Việc tự tìm ra và phân tích khiếm khuyết này có giá trị thực tiễn cao hơn một bản mô tả không có phản biện.

**Mục tiêu và phạm vi.** Mục tiêu tổng quát là đánh giá mức độ an toàn của ứng dụng InlaneWeb Logistics dưới góc độ bảo vệ dữ liệu người dùng, trên toàn bộ vòng đời từ viết mã đến vận hành. Bốn mục tiêu cụ thể gồm:

- Mô tả ứng dụng và phân tích hai nghiệp vụ có xử lý dữ liệu cá nhân.
- Mô tả môi trường triển khai và đối chiếu với các yêu cầu an toàn tối thiểu.
- Mỗi thành viên xác định một vấn đề an toàn, trình bày cách phát hiện, cách xử lý, chính sách bị vi phạm, pha DevSecOps tương ứng, kèm minh chứng Policy as Code hoặc Security as Code và mã nguồn khắc phục.
- Chỉ ra những khiếm khuyết mà công cụ tự động không phát hiện được, kèm lý giải nguyên nhân.

Phạm vi khảo sát là kho mã `PTIT-DevOps-SonarQube` tại hai mốc: `660e75c` là mốc có đầy đủ kết quả quét của lần chạy `39756107853`, và `eb3f6c7` là hiện trạng nhánh `main`.

**Phương pháp và nguồn minh chứng.** Nhóm sử dụng ba nguồn minh chứng độc lập và chỉ khẳng định một nội dung khi có ít nhất một nguồn chứng minh được: mã nguồn đọc trực tiếp với mọi số dòng lấy từ tệp thật trong kho, tệp kết quả SonarQube và Semgrep tải từ phần Artifacts của lần chạy `39756107853`, và ảnh chụp màn hình GitHub Actions lưu trong `docs/images`. Khi ba nguồn mâu thuẫn nhau, báo cáo ghi nhận mâu thuẫn thay vì chọn một bên, trường hợp cụ thể trình bày ở mục Kết quả quét thực tế của Chương 3.

---

# CHƯƠNG 1. ỨNG DỤNG INLANEWEB VÀ DỮ LIỆU CÁ NHÂN CẦN BẢO VỆ

## 1.1 Giới thiệu ứng dụng

InlaneWeb Logistics là cổng thông tin vận tải biển, phục vụ ba nhóm người dùng: khách hàng tra cứu vận đơn của mình, nhân viên cập nhật trạng thái đơn hàng, và quản trị viên xem báo cáo tổng hợp. Ứng dụng viết bằng PHP 8.2 chạy trên Apache, cơ sở dữ liệu MariaDB 10.11, đóng gói bằng Docker. Mã nguồn tổ chức theo mô hình front controller: toàn bộ yêu cầu đi qua `InlaneWeb/web/src/index.php` rồi phân tuyến tới các trình xử lý trong thư mục `pages`. Thư mục `lib` chứa hai thư viện dùng chung là `db.php` lo truy vấn cơ sở dữ liệu và `layout.php` lo dựng giao diện.

Cần nêu rõ ngay từ đầu rằng đây là ứng dụng huấn luyện được cố ý cài lỗ hổng để phục vụ việc học kỹ thuật tiêm mã SQL. Điều này được ghi công khai trong mã nguồn: `lib/db.php:5-8` chú thích "CO Y DE LO", và giao diện có dải băng "INTENTIONALLY VULNERABLE, TRAINING ONLY" tại `lib/layout.php:25`. Ý nghĩa của ranh giới này đối với kết quả đánh giá được phân tích tại mục cuối Chương 2.

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

Hệ thống tạo hai cơ sở dữ liệu tại `InlaneWeb/db/init.sql`. Cơ sở dữ liệu `ilfreight` phục vụ nghiệp vụ, gồm năm bảng `users`, `ports`, `shipments`, `comments` và `news`. Cơ sở dữ liệu `dev` gồm hai bảng `credentials` và `flags`. Việc đặt hai cơ sở dữ liệu trên cùng một máy chủ và truy cập bằng cùng một tài khoản có ý nghĩa an toàn trực tiếp, vì một lỗi tiêm mã SQL ở ứng dụng nghiệp vụ cho phép đọc sang cơ sở dữ liệu `dev`.

*Bảng: Phân loại dữ liệu theo mức độ nhạy cảm*

| Bảng và trường | Phân loại theo NĐ 13 | Ghi chú hiện trạng |
| :--- | :--- | :--- |
| `users.username`, `users.email` | DLCN cơ bản | |
| `users.password` | Thông tin xác thực | Lưu dạng rõ, xem `init.sql:26` và `:34-38` |
| `users.api_key` | Thông tin xác thực | Hiển thị thẳng trên trang hồ sơ tại `account.php:20` |
| `users.remember_token` | Thông tin xác thực | Khai báo tại `init.sql:30`, chưa dùng trong mã |
| `shipments.customer_id` | DLCN cơ bản, gián tiếp | Ranh giới phân quyền giữa các khách hàng |
| `comments.content` | Do người dùng cung cấp | |
| `dev.credentials` | Thông tin xác thực | Băm bằng MD5, xem `init.sql:120` |

Trọng tâm cần bảo vệ của hệ thống là nhóm thông tin xác thực, gồm mật khẩu, khóa API và thẻ phiên. Nếu nhóm dữ liệu này bị lộ, kẻ tấn công có thể mạo danh người dùng và từ đó truy cập toàn bộ dữ liệu cá nhân còn lại.

## 1.3 Nghiệp vụ thứ nhất: xác thực và quản lý phiên người dùng

### 1.3.1 Luồng xử lý hiện tại

Người dùng gửi biểu mẫu `POST /login` với hai trường `username` và `password`. Trình xử lý thực hiện như sau:

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

Nếu truy vấn trả về một bản ghi, định danh người dùng được ghi vào `$_SESSION['uid']`. Ở mỗi yêu cầu sau đó, hàm `current_user()` tại `lib/layout.php:4-11` đọc lại bản ghi người dùng từ cơ sở dữ liệu theo giá trị `uid` trong phiên. Thao tác đăng xuất gọi `session_destroy()` tại `pages/logout.php:3`. Đối chiếu luồng này với yêu cầu tối thiểu của một cơ chế xác thực cho thấy bốn điểm còn thiếu.

### 1.3.2 Đối chiếu với yêu cầu của một luồng xác thực đúng

*Bảng: Đối chiếu nghiệp vụ xác thực với yêu cầu tối thiểu*

| Yêu cầu | Hiện trạng | Vị trí |
| :--- | :--- | :--- |
| Mật khẩu phải băm một chiều, so sánh bằng `password_verify()` | So sánh chuỗi thuần trong câu lệnh SQL | `login.php:19` |
| Tham số đầu vào phải tách khỏi câu lệnh | Nối chuỗi trực tiếp | `login.php:19` |
| Tái sinh định danh phiên sau khi đăng nhập thành công | Không gọi `session_regenerate_id()` | `login.php:22-26` |
| Cookie phiên phải đặt cờ `HttpOnly` | Đặt `session.cookie_httponly = Off` | `web/php.ini:12` |

Ba điểm đầu thuộc phần việc của thành viên 2 và thành viên 3, được phân tích tại Chương 4. Điểm thứ tư cho phép mã kịch bản phía trình duyệt đọc được cookie phiên, khiến một lỗi XSS bất kỳ có thể chuyển thành chiếm phiên người dùng.

Một lần đăng nhập làm mật khẩu dạng rõ đi qua bốn vị trí: thân yêu cầu HTTP, biến `$_POST`, chuỗi câu lệnh SQL tại `login.php:19`, và đường nhật ký nếu truy vấn thất bại. Đây là chuỗi lan truyền dài hơn mức cần thiết. Nếu dùng truy vấn tham số hóa và băm mật khẩu, mật khẩu dạng rõ sẽ không bao giờ xuất hiện trong chuỗi câu lệnh.

## 1.4 Nghiệp vụ thứ hai: tra cứu vận đơn và bình luận đơn hàng

### 1.4.1 Luồng xử lý

Khách hàng đã đăng nhập mở `/account` để xem danh sách vận đơn của mình, danh sách được lọc theo `customer_id`:

```php
// pages/account.php:39-42
$order = $_GET['order'] ?? 'id';
$sql = "SELECT tracking_no, port_code, status FROM shipments WHERE customer_id = "
     . intval($u['id']) . " ORDER BY $order";
```

Từ danh sách, khách hàng mở `/shipments/{id}` để xem chi tiết và các bình luận, rồi gửi bình luận mới qua `POST /shipments/{id}/comments`. Tuyến thêm bình luận khai báo tại `index.php:116-119`, tuyến xóa bình luận tại `index.php:124-127`. Ngoài ra, tuyến `/api/track?tracking=...` tại `index.php:109` trả về trạng thái vận đơn dưới dạng JSON, phục vụ tra cứu công khai không cần đăng nhập.

### 1.4.2 Ranh giới phân quyền và điểm yếu

Ranh giới phân quyền thứ nhất nằm giữa các khách hàng, theo đó khách hàng A không được xem vận đơn của khách hàng B. Ranh giới này cài đặt đúng ở `/account` nhờ mệnh đề `WHERE customer_id = intval($u['id'])`. Tuy nhiên tham số sắp xếp `$order` lại nối thẳng vào mệnh đề `ORDER BY`, nên một giá trị `?order=` dựng khéo cho phép đọc dữ liệu ngoài phạm vi mệnh đề `WHERE`. Semgrep ghi nhận đúng luồng này, nguồn tại `account.php:39` và điểm thực thi tại `account.php:41`.

Ranh giới phân quyền thứ hai nằm giữa người viết và người xóa bình luận. Tuyến xóa tại `pages/comment_delete.php:18` xây dựng câu lệnh `DELETE FROM comments WHERE id = $comment_id` mà không kiểm tra bình luận có thuộc về người đang đăng nhập hay không, đồng thời không ràng buộc kiểu dữ liệu của `$comment_id`.

Tuyến `/api/track` không yêu cầu đăng nhập nhưng trả về trạng thái vận đơn theo mã tra cứu. Thiết kế này chấp nhận được nếu mã vận đơn đủ khó đoán, nhưng với dữ liệu mẫu hiện tại từ `ILF1042CN` đến `ILF1046US` tại `init.sql:70-75` thì mã có quy luật rõ ràng và có thể duyệt tuần tự.

---

# CHƯƠNG 2. MÔI TRƯỜNG TRIỂN KHAI VÀ YÊU CẦU AN TOÀN TỐI THIỂU

## 2.1 Kiến trúc triển khai

Hệ thống chạy trên một máy chủ riêng ảo, tổ chức thành hai cụm Docker Compose độc lập dùng chung một mạng nội bộ. Cụm ứng dụng khai báo trong `docker-compose.prod.yml` với tên dự án `inlaneweb-prod`, gồm `db` chạy MariaDB và `web` chạy PHP-Apache, tạo mạng `inlaneweb_net` với bí danh `labnet` tại dòng 59-62. Cụm giám sát khai báo trong `docker-compose.monitoring.yml` với tên dự án `inlaneweb-monitoring`, gồm `loki` lưu nhật ký, `promtail` thu thập, `grafana` hiển thị và `autoheal` khởi động lại container hỏng, tham gia cùng mạng ở chế độ `external: true` tại dòng 77-80.

Việc tách hai cụm cho phép cập nhật ứng dụng mà không làm gián đoạn hệ giám sát và ngược lại. Hai tên dự án khác nhau cũng tránh được tình huống lệnh `docker compose down` của cụm này xóa nhầm container của cụm kia. Ứng dụng web chỉ mở cổng trên giao diện vòng lặp nội bộ với khai báo `"127.0.0.1:8088:80"` tại dòng 38, lưu lượng từ bên ngoài đi qua Nginx Proxy Manager là nơi cấp chứng chỉ TLS. Cơ sở dữ liệu không công bố cổng nào ra máy chủ.

## 2.2 Đối chiếu với yêu cầu an toàn tối thiểu

*Bảng: Bảng kiểm yêu cầu an toàn tối thiểu của môi trường triển khai*

| # | Yêu cầu tối thiểu | Kết quả | Dẫn chứng |
| :---: | :--- | :---: | :--- |
| 1 | Cơ sở dữ liệu không công bố cổng ra ngoài máy chủ | Đạt | `prod.yml`, dịch vụ `db` không có mục `ports` |
| 2 | Ứng dụng web chỉ lắng nghe trên giao diện nội bộ | Đạt | `prod.yml:38` |
| 3 | Dữ liệu cơ sở dữ liệu lưu trên volume bền vững | Đạt | `prod.yml:26-28`, `:64-66` |
| 4 | Dịch vụ có kiểm tra sức khỏe và tự phục hồi | Đạt | `prod.yml:21-25`, `:41-46`; `monitoring.yml:63-75` |
| 5 | Container không chạy bằng quyền `root` | Không đạt | `web/Dockerfile` và `db/Dockerfile` không có chỉ thị `USER` |
| 6 | Không gán cứng bí mật trong tệp cấu hình | Không đạt | `prod.yml:15`, `:50`; `monitoring.yml:46`; `init.sql:11` |
| 7 | Tài khoản cơ sở dữ liệu của ứng dụng có quyền tối thiểu | Không đạt | `prod.yml:49` dùng `root`; `init.sql:12-13` cấp `ALL PRIVILEGES` và `FILE` |
| 8 | Tài khoản quản trị cơ sở dữ liệu không đăng nhập từ mọi máy | Không đạt | `prod.yml:16` đặt `MYSQL_ROOT_HOST: "%"`; `init.sql:11` |
| 9 | Ảnh container ghim phiên bản, không dùng thẻ `latest` | Không đạt | `prod.yml:11`, `:31`; `monitoring.yml:64` |
| 10 | Không hiển thị lỗi hệ thống ra trình duyệt | Không đạt | `web/php.ini:6-7` đặt `display_errors = On` |
| 11 | Cookie phiên đặt cờ `HttpOnly` | Không đạt | `web/php.ini:12` đặt `session.cookie_httponly = Off` |
| 12 | Giao diện quản trị hệ giám sát không mở ra Internet | Không đạt | `monitoring.yml:43` công bố Grafana trên `0.0.0.0:3000` |
| 13 | Container thu thập nhật ký chạy với quyền hạn chế | Không đạt | `monitoring.yml:26` đặt `user: root` |
| 14 | Không gắn socket Docker với quyền ghi | Không đạt | `monitoring.yml:73` gắn `docker.sock` cho `autoheal` ở chế độ ghi |

Bốn yêu cầu đầu đạt, mười yêu cầu còn lại không đạt. Yêu cầu số 12 đáng chú ý nhất. Trong khi ứng dụng web được đóng cẩn thận sau giao diện vòng lặp nội bộ, Grafana lại được công bố trực tiếp ra mọi giao diện mạng, mà đây chính là nơi hiển thị toàn bộ nhật ký hệ thống, bao gồm cả nội dung câu lệnh SQL thất bại. Tình trạng này là nền của vấn đề được phân tích tại mục cuối Chương 4.

## 2.3 Phân biệt lỗ hổng chủ ý với khiếm khuyết ngoài ý muốn

Vì ứng dụng được dựng làm bài thực hành tiêm mã SQL, một phần các điểm trong bảng kiểm trên là chủ ý. Yêu cầu số 10 không đạt nhằm phục vụ kỹ thuật khai thác dựa trên thông báo lỗi, yêu cầu số 7 không đạt nhằm phục vụ kỹ thuật đọc ghi tệp qua quyền `FILE`, và việc không băm mật khẩu nhằm minh họa hậu quả. Những điểm này nằm trong mã ứng dụng, có chú thích rõ trong nguồn, và chỉ gây hậu quả bên trong môi trường thực hành.

Các yêu cầu số 5, 6, 9, 12, 13 và 14 thì khác. Chúng không phục vụ bài học tiêm mã SQL nào, mà là thiếu sót thật ở lớp hạ tầng. Riêng yêu cầu số 12 còn mở rộng hậu quả của các lỗ hổng chủ ý ra ngoài phạm vi môi trường thực hành. Phân biệt này quan trọng khi đánh giá, vì không thể lấy tính chất thực hành của ứng dụng để biện minh cho việc công bố Grafana ra Internet kèm mật khẩu quản trị nằm trong kho mã công khai.

---

# CHƯƠNG 3. DÂY CHUYỀN DEVSECOPS VÀ CƠ CHẾ DỪNG KHI CÓ LỖI

## 3.1 Bốn chặng của dây chuyền

Dây chuyền khai báo trong `.github/workflows/devsecops-pipeline.yml`, kích hoạt khi đẩy mã lên nhánh `main` hoặc `dev`, hoặc khi mở yêu cầu hợp nhất vào hai nhánh đó, theo khai báo tại dòng 5-17.

*Bảng: Bốn chặng của dây chuyền và điều kiện kích hoạt*

| Chặng | Công việc | Điều kiện chạy | Dòng |
| :--- | :--- | :--- | :---: |
| 1 | `branch_policy_guard`, kiểm tra quy ước nhánh, commit và PR | Mọi sự kiện | 29 |
| 2 | `analyze` chạy SonarQube và `semgrep` chạy Semgrep | PR vào `dev`, hoặc đẩy lên `dev` | 44, 162 |
| 3 | `production_smoke_test`, dựng ảnh Docker và chạy thử | PR vào `main`, hoặc đẩy lên `main` | 211 |
| 4 | `production_deploy_monitoring` và `production_deploy_web` | Đẩy lên `main` | 438, 593 |

Thiết kế này đặt hai cổng theo hai hướng hợp nhất khác nhau. Mã nguồn đi vào `dev` phải qua phân tích tĩnh, còn mã nguồn đi vào `main` phải qua chạy thử tích hợp. Ràng buộc `needs` tại các dòng 213, 440 và 596 bảo đảm các chặng chạy tuần tự.

## 3.2 Policy as Code tại chặng 1

Chặng 1 chạy `ci/policy_guard.py`. Đây là chính sách quản trị quy trình được viết thành mã, theo đó quy ước đặt tên commit và yêu cầu hợp nhất được mã hóa thành biểu thức chính quy mà máy kiểm tra được, thay vì tồn tại dưới dạng thỏa thuận miệng giữa các thành viên.

```python
# ci/policy_guard.py:23-38
COMMIT_REGEX = re.compile(
    r"^(Merge\s.+|Revert\s.+|(release|RELEASE):\s+v[0-9]+\.[0-9]+\.[0-9]+.*"
    r"|(feat|fix|sec|ci|docs|refactor|test|chore|style|perf|revert|release)"
    r"(\([a-zA-Z0-9_\-\.\/]+\))?:\s.+)", re.IGNORECASE)

PR_DEV_REGEX = re.compile(
    r"^\[(namng|haind|manhdx|anhld|mainp)\]\s+"
    r"(feat|fix|sec|ci|docs|refactor|test|chore|style|perf|revert)"
    r"(\([a-zA-Z0-9_\-\.\/]+\))?:\s.+", re.IGNORECASE)
```

Biểu thức thứ ba là `PR_MAIN_REGEX` tại dòng 35-38, yêu cầu tiêu đề PR vào `main` có dạng `release: vX.Y.Z`. Ba biểu thức tương ứng ba cấp kiểm soát: commit theo chuẩn Conventional Commits, PR vào `dev` mở đầu bằng tên nhánh của một trong năm thành viên trong danh sách cố định, và PR vào `main` là một bản phát hành có đánh số phiên bản. Cùng đoạn mã này chạy lại ở máy lập trình viên qua móc `.githooks/commit-msg`, nên lỗi đặt tên bị chặn ngay trước khi commit được tạo.

Giới hạn của cơ chế này cần được nêu rõ. Hàm `validate_push_event()` chỉ kiểm tra định dạng thông điệp commit, không có đoạn mã nào từ chối việc đẩy thẳng lên `main` hay `dev`. Việc cấm đẩy thẳng hiện phụ thuộc vào thiết lập bảo vệ nhánh phía GitHub, nằm ngoài kho mã, nên không thuộc phạm vi Policy as Code và không được kiểm chứng trong báo cáo này.

## 3.3 Security as Code tại chặng 2

Chặng 2 chạy song song hai công cụ phân tích tĩnh có cơ chế khác nhau.

Với SonarQube, dây chuyền khởi tạo một máy chủ tạm thời ngay trong máy ảo chạy dây chuyền theo khai báo tại dòng 104-110, quét mã rồi hủy. Tiêu chí chấp nhận được viết thành tệp `ci/sonarqube-quality-gate.json`. Đây chính là Security as Code, vì ngưỡng an toàn nằm trong kho mã và mọi thay đổi đều được theo dõi qua lịch sử Git. Tệp này đặt năm điều kiện báo lỗi: `security_rating` lớn hơn 1 tương ứng có lỗ hổng an toàn dưới mức A, `reliability_rating` lớn hơn 1 tương ứng có lỗi ảnh hưởng độ tin cậy, `sqale_rating` lớn hơn 1 tương ứng nợ kỹ thuật vượt ngưỡng, `security_hotspots_reviewed` nhỏ hơn 100 tương ứng còn điểm cần rà soát chưa xử lý, và `duplicated_lines_density` lớn hơn 10 tương ứng trùng lặp mã vượt 10 phần trăm.

Với Semgrep, dây chuyền chạy bốn bộ luật công khai gồm `p/owasp-top-ten`, `p/php`, `p/security-audit` và `p/cwe-top-25`, cộng thêm một tệp luật tự viết, theo khai báo tại dòng 186-195. Tệp `ci/semgrep-local-rules.yml` chứa hai luật, đều nhằm vào việc gán cứng bí mật:

```yaml
# ci/semgrep-local-rules.yml:2-14 (CWE-798: Use of Hard-coded Credentials)
- id: php-hardcoded-db-password-fallback
  languages: [php]
  severity: ERROR
  message: A database password has a hardcoded fallback. Require a secret from the environment instead.
  patterns:
    - pattern: "getenv('DB_PASS') ?: $FALLBACK"
    - metavariable-regex: { metavariable: $FALLBACK, regex: ^['"].+['"]$ }
```

Luật thứ hai là `compose-hardcoded-mysql-root-password`, bắt biến môi trường `MYSQL_ROOT_PASSWORD` có giá trị không phải là tham chiếu bí mật.

Luật thứ hai có một khiếm khuyết. Mục `paths.include` tại dòng 26-30 chỉ liệt kê ba mẫu tên tệp là `**/docker-compose.yml`, `**/compose.yml` và `**/compose.yaml`. Hai tệp đang thực sự chứa mật khẩu gán cứng là `docker-compose.prod.yml` và `docker-compose.monitoring.yml` không khớp mẫu nào, nên luật không bao giờ chạy trên chúng. Kết quả quét trình bày ở mục sau xác nhận điều này, vì luật chỉ kích hoạt trên `InlaneWeb/docker-compose.yml`. Cách sửa được trình bày tại phần của thành viên 3 ở Chương 4.

## 3.4 Khiếm khuyết trọng yếu: cổng chất lượng không dừng dây chuyền

Đây là phát hiện quan trọng nhất của chương, và nhóm trình bày như một kết quả kiểm chứng thay vì che đi. Biến môi trường quyết định cổng chất lượng có chặn hay không được khai báo như sau:

```yaml
# .github/workflows/devsecops-pipeline.yml:55
ENFORCE_QUALITY_GATE: ${{ inputs.enforce_quality_gate || 'false' }}
```

Ngữ cảnh `inputs` trong GitHub Actions chỉ tồn tại khi dây chuyền được kích hoạt thủ công bằng `workflow_dispatch`. Với sự kiện đẩy mã hoặc mở yêu cầu hợp nhất, tức toàn bộ các lần chạy tự động, `inputs.enforce_quality_gate` không có giá trị nên biểu thức luôn trả về chuỗi `'false'`. Giá trị này được đọc ở bước kiểm tra cuối:

```python
# ci/sonarqube.py:433-439
if status["quality_gate"] == "ERROR":
    if os.environ.get("ENFORCE_QUALITY_GATE", "true").lower() == "true":
        print("Quality Gate FAILED. Reports were exported before this check.", file=sys.stderr)
        return 1
    print("Quality Gate FAILED; report-only mode explicitly selected.")
else:
    print("Quality Gate PASSED.")
return 0
```

Khi cổng chất lượng ở trạng thái `ERROR` và biến `ENFORCE_QUALITY_GATE` khác `true`, hàm chỉ in một dòng thông báo rồi trả về giá trị 0, tức báo thành công. Công việc của chặng 2 kết thúc với trạng thái thành công và các chặng sau không bị chặn.

Semgrep cũng không chặn, vì hai lý do độc lập. Lệnh quét tại dòng 187-195 không có cờ `--error`, và tệp `ci/semgrep_report.py` chỉ kết thúc bất thường khi bản thân quá trình quét gặp lỗi, không phải khi tìm thấy phát hiện.

Hệ quả là toàn bộ chặng 2 hiện hoạt động ở chế độ chỉ báo cáo. Nguyên tắc dừng dây chuyền ngay tại chặng phát hiện lỗi chưa được thực hiện. Ba ảnh chụp màn hình dưới đây là minh chứng trực tiếp cho kết luận này.

![Tóm tắt lần chạy 39756107853 cho thấy cổng chất lượng ở trạng thái ERROR và chế độ thực thi chỉ báo cáo, trong khi trạng thái chung của lần chạy vẫn là thành công](images/h01-run-summary.png)

![Danh sách các bước của công việc SonarQube, bước Enforce pipeline result kết thúc thành công dù cổng chất lượng đã báo lỗi](images/h02-sonar-job-steps.png)

![Công việc Semgrep kết thúc thành công sau khi ghi nhận 19 phát hiện ở mức ERROR](images/h03-semgrep-job.png)

Cách khắc phục chỉ cần sửa một dòng, đủ để cổng chất lượng chặn ở mọi lần chạy tự động mà vẫn cho phép tắt chặn có chủ ý khi chạy thủ công:

```yaml
# .github/workflows/devsecops-pipeline.yml:55 (đề xuất sửa)
ENFORCE_QUALITY_GATE: ${{ inputs.enforce_quality_gate != 'false' }}
```

Với Semgrep, cần bổ sung cờ `--error` vào lệnh quét để quá trình kết thúc bất thường khi có phát hiện ở mức ERROR.

Nhóm chưa áp dụng hai thay đổi này vào nhánh `main`, vì bật chặn sẽ làm mọi yêu cầu hợp nhất vào `dev` thất bại ngay lập tức, do kho mã hiện có 19 phát hiện mức ERROR và cổng chất lượng đang ở trạng thái ERROR. Việc bật chặn cần đi kèm kế hoạch xử lý các phát hiện đó và cần sự thống nhất của cả nhóm.

## 3.5 Kết quả quét thực tế tại mốc `660e75c`

*Bảng: Chỉ số SonarQube tại mốc `660e75c`*

| Chỉ số | Giá trị | Điều kiện cổng | Trạng thái |
| :--- | ---: | :--- | :---: |
| `reliability_rating` | 3 | Lớn hơn 1 thì báo lỗi | ERROR |
| `security_rating` | 1 | Lớn hơn 1 thì báo lỗi | OK |
| `sqale_rating` | 1 | Lớn hơn 1 thì báo lỗi | OK |
| `duplicated_lines_density` | 0,0 | Lớn hơn 10 thì báo lỗi | OK |
| `vulnerabilities` | 0 | | |
| `security_hotspots` | 0 | | |
| `bugs` và `code_smells` | 10 và 10 | | |
| Số tệp PHP phân tích và số dòng mã | 16 và 408 | | |

SonarQube ghi nhận 20 phát hiện, gồm 1 mức CRITICAL, 10 mức MAJOR và 9 mức MINOR. Toàn bộ thuộc nhóm lỗi lập trình và khả năng bảo trì, cụ thể là các quy tắc `php:S121` về thiếu dấu ngoặc nhọn, `php:S100` về quy ước đặt tên hàm, `php:S2003` về việc dùng `require` thay vì `require_once`, cùng `Web:S6853` và `Web:InputWithoutLabelCheck` về nhãn biểu mẫu.

![Danh sách đầy đủ 20 phát hiện của SonarQube tại mốc 660e75c](images/h04-sonar-issues.png)

Có một kết quả cần được giải thích thay vì bỏ qua. SonarQube báo `vulnerabilities` bằng 0, `security_hotspots` bằng 0 và `security_rating` bằng 1 tương ứng mức A, trên một kho mã mà Semgrep tìm thấy 11 vị trí tiêm mã SQL. Cổng chất lượng có báo lỗi, nhưng báo lỗi vì chỉ số độ tin cậy, hoàn toàn không phải vì an toàn.

Nguyên nhân là bản SonarQube Community dùng trong dây chuyền không có khả năng phân tích luồng dữ liệu xuyên hàm và xuyên tệp. Trong ứng dụng này, chuỗi SQL được xây ở các tệp trong thư mục `pages` rồi truyền sang hàm `query()` ở `lib/db.php` mới thực thi, tạo thành một luồng xuyên tệp mà bản Community không lần được. Kết luận rút ra là cổng chất lượng ở trạng thái đạt không đồng nghĩa với mã nguồn an toàn, và một dây chuyền chỉ dùng một công cụ thì không đủ.

*Bảng: Phân bố 19 phát hiện của Semgrep tại mốc `660e75c`*

| Nhóm luật | Số lượng | Phân loại | Vị trí tiêu biểu |
| :--- | :---: | :--- | :--- |
| `tainted-sql-string` | 11 | CWE-89, tiêm mã SQL | `login.php:19`, `ports.php:24` |
| `echoed-request` | 4 | CWE-79, XSS | `comment_add.php:29`, `track_api.php:31` |
| `missing-user`, `missing-user-entrypoint` | 2 | CWE-250 và CWE-269, container chạy quyền root | `db/Dockerfile:15`, `:16` |
| `php-hardcoded-db-password-fallback` | 1 | CWE-798, bí mật gán cứng | `lib/db.php:17` |
| `compose-hardcoded-mysql-root-password` | 1 | CWE-798, bí mật gán cứng | `docker-compose.yml:15` |

Toàn bộ 19 phát hiện đều ở mức ERROR, và hai luật tự viết của nhóm đều kích hoạt đúng mục tiêu. Số dòng của phát hiện tại `lib/db.php:17` tương ứng mốc `660e75c`. Ở hiện trạng `eb3f6c7`, dòng này đã dịch xuống dòng 19 do tệp `lib/logger.php` được thêm vào và `db.php` phải nạp tệp đó.

---

# CHƯƠNG 4. NĂM VẤN ĐỀ AN TOÀN THEO PHÂN CÔNG THÀNH VIÊN

## 4.1 Bảng tổng hợp

*Bảng: Tổng hợp năm vấn đề an toàn của năm thành viên*

| Thành viên | Vấn đề | Nhóm | Pha DevSecOps | Căn cứ pháp lý | Dạng |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Nguyễn Giang Nam | Thiếu kiểm soát thay đổi mã nguồn | Quy trình | Plan, Code | NĐ 13 Điều 26, 27; GDPR Art. 24, 32(1) | PaC |
| Nguyễn Đình Hải | Tiêm mã SQL làm lộ DLCN | Mã nguồn | Code, Build | NĐ 13 Điều 26, 27; GDPR Art. 5(1)(f), 32 | SaC |
| Đào Xuân Mạnh | Mật khẩu dạng rõ và bí mật gán cứng | Mã nguồn | Code, Build | NĐ 13 Điều 26, 27; GDPR Art. 5(1)(f), 25, 32(1)(a) | SaC |
| Lê Đức Anh | Cấu hình triển khai mất an toàn | Triển khai | Release, Deploy | NĐ 13 Điều 26, 27; GDPR Art. 32(1)(b) | PaC |
| Nguyễn Phương Mai | Rò rỉ DLCN qua đường nhật ký | Vận hành | Operate, Monitor | NĐ 13 Điều 23, 26; GDPR Art. 5(1)(c), 33, 34 | SaC |

Năm vấn đề phủ đủ hai nhóm mà đề bài yêu cầu, trong đó ba vấn đề thuộc mã nguồn và quy trình phát triển, hai vấn đề thuộc triển khai và vận hành.

Về căn cứ pháp lý, đề bài nêu Nghị định 13/2023/NĐ-CP và nhóm trích dẫn theo đúng yêu cầu đó. Cần ghi nhận thêm rằng Nghị định 13/2023 đã hết hiệu lực từ ngày 01/01/2026, được thay thế bằng Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15 cùng Nghị định 356/2025/NĐ-CP hướng dẫn thi hành. Các nghĩa vụ mà báo cáo viện dẫn, gồm việc áp dụng biện pháp kỹ thuật và quản lý để bảo vệ dữ liệu và việc thông báo vi phạm trong 72 giờ, đều được kế thừa trong văn bản mới, song số hiệu điều khoản đã thay đổi. Nhóm chưa đối chiếu được số hiệu điều khoản của Luật 91/2025/QH15 với văn bản gốc nên không trích dẫn số hiệu cụ thể của luật này.

## 4.2 Thành viên 1, Nguyễn Giang Nam: thiếu kiểm soát thay đổi mã nguồn

**Mô tả vấn đề.** Một hệ thống xử lý dữ liệu cá nhân cần chứng minh được rằng mọi thay đổi mã nguồn đều có nguồn gốc, có người chịu trách nhiệm và có qua rà soát. Nếu bất kỳ ai cũng đẩy được mã thẳng lên nhánh phát hành với thông điệp tùy ý, thì khi xảy ra sự cố rò rỉ dữ liệu sẽ không truy được thay đổi nào gây ra sự cố, do ai thực hiện và đã được ai phê duyệt.

**Cách phát hiện.** Đọc lịch sử Git và đối chiếu với mã nguồn của chặng 1, nhóm phát hiện hai điểm. Trước khi có `ci/policy_guard.py`, không tồn tại ràng buộc nào về thông điệp commit. Ngay cả hiện nay, hàm `validate_push_event()` cũng chỉ kiểm tra định dạng thông điệp chứ không từ chối việc đẩy thẳng lên nhánh được bảo vệ.

**Chính sách bị vi phạm.** Trường hợp này vi phạm nghĩa vụ áp dụng biện pháp quản lý để bảo vệ dữ liệu cá nhân theo Điều 26 Nghị định 13/2023/NĐ-CP, và nghĩa vụ ban hành quy định nội bộ về bảo vệ dữ liệu cá nhân theo Điều 27. Theo GDPR, tương ứng Điều 24 về trách nhiệm của bên kiểm soát dữ liệu bao gồm khả năng chứng minh sự tuân thủ, và Điều 32(1) về biện pháp tổ chức phù hợp. Vấn đề thuộc pha Plan và Code, phát hiện tại chặng 1.

**Cách xử lý và minh chứng Policy as Code.** Chính sách được viết thành mã trong `ci/policy_guard.py` và chạy ở hai nơi, gồm móc `commit-msg` tại máy lập trình viên và chặng 1 của dây chuyền:

```python
# ci/policy_guard.py:47-60
def validate_commit_message(msg: str) -> tuple[bool, str]:
    first_line = msg.strip().splitlines()[0] if msg.strip() else ""
    if not first_line:
        return False, "Tiêu đề commit không được để trống."
    if COMMIT_REGEX.match(first_line):
        return True, ""
    return False, (
        f"Tiêu đề commit '{first_line}' vi phạm chuẩn Conventional Commits.\n"
        "Cú pháp bắt buộc: <loại>(<phạm_vi>): <mô tả>"
    )
```

Đây là Policy as Code đúng nghĩa, vì quy ước làm việc của nhóm tồn tại dưới dạng mã nguồn trong kho, mọi thay đổi được theo dõi qua lịch sử Git, và việc tuân thủ được thực thi tự động chứ không dựa vào nhắc nhở.

**Giới hạn.** Móc `.githooks/commit-msg` thoát với mã 0 nếu máy lập trình viên không cài Python, tức bỏ qua kiểm tra trong im lặng. Chặng 1 trên máy chủ vẫn bắt được trường hợp này nên đây là suy giảm có kiểm soát, song vẫn cần ghi nhận để người dùng không hiểu nhầm rằng móc cục bộ luôn chạy.

## 4.3 Thành viên 2, Nguyễn Đình Hải: tiêm mã SQL làm lộ dữ liệu cá nhân

**Mô tả vấn đề.** Toàn bộ truy vấn của ứng dụng được xây dựng bằng cách nối chuỗi dữ liệu người dùng vào câu lệnh SQL, không dùng truy vấn tham số hóa. Semgrep xác định 11 vị trí như vậy. Tuyến tra cứu cảng biển là một ví dụ:

```php
// pages/ports.php:12, 24
$q = $_GET['q'] ?? '';
$sql = "SELECT code, city, country, volume FROM ports WHERE code LIKE '%$q%'";
```

Bảng kết quả hiển thị 4 cột, nên một truy vấn ghép `UNION SELECT` với 4 cột cho phép đọc bất kỳ bảng nào mà tài khoản cơ sở dữ liệu có quyền, bao gồm bảng `users` chứa mật khẩu dạng rõ và khóa API, và cả cơ sở dữ liệu `dev`. Mức độ nghiêm trọng bị khuếch đại bởi hai yếu tố cấu hình: ứng dụng kết nối bằng tài khoản `root` toàn quyền theo `prod.yml:49`, và lỗi SQL được in thẳng ra trang theo `lib/db.php:48-49`, giúp kẻ tấn công dò cấu trúc dữ liệu nhanh chóng.

**Cách phát hiện.** Semgrep với bộ luật `p/owasp-top-ten` và `p/php`, quy tắc `php.lang.security.injection.tainted-sql-string`. Công cụ xác định được cả nguồn dữ liệu và điểm thực thi:

```
Vị trí: InlaneWeb/web/src/pages/ports.php:24
Nguồn:  12: $q = $_GET['q'] ?? '';
Đích:   24: $sql = "SELECT code, city, country, volume FROM ports WHERE code LIKE '%$q%'";
Phân loại: A01:2017 Injection, CWE-89
```

*Bảng: Mười một vị trí tiêm mã SQL do Semgrep phát hiện*

| Tệp và dòng | Nguồn dữ liệu | Loại câu lệnh |
| :--- | :--- | :--- |
| `pages/login.php:19` | `$_POST['username']`, `$_POST['password']` | SELECT |
| `pages/ports.php:24` | `$_GET['q']` | SELECT |
| `pages/port_detail.php:19` | `$_GET['code']` | SELECT |
| `pages/news.php:17` | `$_GET['id']` | SELECT |
| `pages/account.php:41` | `$_GET['order']` | SELECT, mệnh đề ORDER BY |
| `pages/account_update.php:20` | `$_POST['email']` | UPDATE |
| `pages/comment_add.php:19` | `$_POST['content']` | INSERT |
| `pages/comment_delete.php:18` | `$_GET['comment_id']` | DELETE |
| `pages/shipment_detail.php:15`, `:30` | `$_GET['id']` | SELECT |
| `pages/track_api.php:18` | `$_GET['tracking']` | SELECT |

**Chính sách bị vi phạm.** Trường hợp này vi phạm nghĩa vụ áp dụng biện pháp kỹ thuật bảo vệ dữ liệu cá nhân theo Điều 26 và Điều 27 Nghị định 13/2023/NĐ-CP. Theo GDPR, tương ứng Điều 5(1)(f) về nguyên tắc toàn vẹn và bảo mật, và Điều 32 về an toàn của hoạt động xử lý. Vấn đề thuộc pha Code và Build, phát hiện tại chặng 2.

**Cách xử lý và minh chứng Security as Code.** Biện pháp xử lý là chuyển sang truy vấn tham số hóa. Bổ sung hàm sau vào `lib/db.php`:

```php
/** query_safe(): truy van tham so hoa, du lieu nguoi dung tach khoi cau lenh. */
function query_safe(string $sql, string $types = '', array $params = []): array
{
    $stmt = mysqli_prepare(db(), $sql);
    if ($stmt === false) {
        return [];
    }
    if ($types !== '') {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    mysqli_stmt_execute($stmt);
    $res  = mysqli_stmt_get_result($stmt);
    $rows = $res ? mysqli_fetch_all($res, MYSQLI_ASSOC) : [];
    mysqli_stmt_close($stmt);
    return $rows;
}
```

Tuyến tra cứu cảng được viết lại thành:

```php
// pages/ports.php (sau khi sua)
$rows = query_safe(
    "SELECT code, city, country, volume FROM ports WHERE code LIKE ?",
    's', ['%' . $q . '%']);
```

Dữ liệu người dùng đi vào máy chủ cơ sở dữ liệu như một tham số, không còn là một phần của câu lệnh, nên ký tự nháy đơn mất khả năng thay đổi cấu trúc truy vấn. Minh chứng Security as Code là tiêu chí `security_rating` trong `ci/sonarqube-quality-gate.json` kết hợp với bộ luật Semgrep, cả hai đều nằm trong kho mã và chạy tự động trên mọi thay đổi.

**Giới hạn.** Như đã trình bày ở Chương 3, SonarQube Community không phát hiện được nhóm lỗi này. Nếu dây chuyền chỉ có SonarQube thì 11 vị trí nêu trên đã lọt hoàn toàn. Đây là căn cứ để nhóm chạy song song hai công cụ phân tích tĩnh có cơ chế khác nhau.

## 4.4 Thành viên 3, Đào Xuân Mạnh: mật khẩu dạng rõ và bí mật gán cứng

### 4.4.1 Mô tả vấn đề

Vấn đề gồm hai phần liên quan nhau, cùng thuộc nhóm quản lý thông tin xác thực.

Phần thứ nhất liên quan tới việc mật khẩu người dùng được lưu dạng rõ. Bảng `users` khai báo cột `password` kèm chú thích thừa nhận cách làm sai:

```sql
-- db/init.sql:23-38 (trich)
    password       VARCHAR(255) NOT NULL,   -- luu cleartext (bad practice CO Y)

INSERT INTO users (username, password, email, role, api_key) VALUES
('admin',   'p@ssw0rd',    'admin@ilfreight.local',  'admin',    'ILF-ADM-9f3c1a77e2b04d55'),
('jsmith',  'Spring2024!', 'jsmith@ilfreight.local', 'customer', 'ILF-CUS-1b2c3d4e5f60718'),
```

Hệ quả trực tiếp là bất kỳ đường rò rỉ nào tới bảng `users`, dù là một lỗi tiêm mã SQL, một bản sao lưu bị lộ hay một người có quyền đọc cơ sở dữ liệu, đều làm lộ mật khẩu ở dạng dùng được ngay. Vì người dùng thường dùng lại mật khẩu trên nhiều dịch vụ, thiệt hại lan sang cả các hệ thống khác, vượt ra ngoài phạm vi hệ thống này.

Mật khẩu dạng rõ còn khiến việc xác thực phải so sánh chuỗi trong câu lệnh SQL tại `login.php:19`, tức mật khẩu bị ghép vào chuỗi truy vấn. Đây chính là mắt xích đầu tiên của chuỗi rò rỉ được phân tích ở phần của thành viên 5.

Phần thứ hai liên quan tới bí mật gán cứng trong mã nguồn và cấu hình. Cùng một mật khẩu cơ sở dữ liệu xuất hiện ở bốn vị trí trong kho mã:

*Bảng: Các vị trí gán cứng thông tin xác thực*

| Vị trí | Nội dung | Vai trò |
| :--- | :--- | :--- |
| `web/src/lib/db.php:19` | `$pass = getenv('DB_PASS') ?: 'password';` | Giá trị dự phòng khi thiếu biến môi trường |
| `docker-compose.prod.yml:15` | `MYSQL_ROOT_PASSWORD: password` | Mật khẩu khởi tạo máy chủ cơ sở dữ liệu |
| `docker-compose.prod.yml:50` | `DB_PASS: password` | Mật khẩu ứng dụng dùng để kết nối |
| `db/init.sql:11` | `CREATE USER ... IDENTIFIED BY 'password'` | Mật khẩu tài khoản quản trị cơ sở dữ liệu |

Giá trị dự phòng tại `db.php:19` nguy hiểm hơn vẻ ngoài của nó. Toán tử `?:` khiến ứng dụng không báo lỗi khi thiếu biến môi trường mà lặng lẽ dùng mật khẩu mặc định. Một môi trường triển khai bị cấu hình thiếu sẽ chạy có vẻ bình thường trong khi đang dùng thông tin xác thực công khai trong kho mã.

### 4.4.2 Cách phát hiện

Nhóm phát hiện vấn đề này theo hai cách bổ sung cho nhau.

Cách thứ nhất là luật Semgrep tự viết. Nhóm phải viết luật riêng vì các bộ luật công khai không bắt được mẫu `getenv(...) ?: 'chuỗi'` đặc thù của PHP. Luật đặt tại `ci/semgrep-local-rules.yml:2-14`, nội dung đã trình bày ở Chương 3. Kết quả quét tại mốc `660e75c` xác nhận luật kích hoạt đúng mục tiêu:

```
Phat hien 4: ci.php-hardcoded-db-password-fallback  [ERROR]
Vi tri: InlaneWeb/web/src/lib/db.php:17
Noi dung: $pass = getenv('DB_PASS') ?: 'password';
Phan loai: A07:2021 Identification and Authentication Failures, CWE-798
```

Cách thứ hai là rà soát thủ công lược đồ cơ sở dữ liệu. Việc mật khẩu được lưu dạng rõ nằm ở phần dữ liệu chứ không nằm ở phần mã, nên không công cụ phân tích tĩnh nào trong dây chuyền phát hiện được. Nhóm phát hiện bằng cách đọc tệp `init.sql`. Đây là một minh họa cụ thể cho yêu cầu của đề bài về việc chỉ ra giới hạn của công cụ.

### 4.4.3 Chính sách bị vi phạm và pha DevSecOps

Theo Nghị định 13/2023/NĐ-CP, trường hợp này vi phạm Điều 26 về nghĩa vụ áp dụng biện pháp kỹ thuật bảo vệ dữ liệu cá nhân ngay từ đầu và trong suốt quá trình xử lý, và Điều 27 về bảo vệ dữ liệu cá nhân cơ bản, trong đó có yêu cầu kiểm tra an ninh mạng đối với hệ thống phục vụ xử lý dữ liệu trước khi đưa vào xử lý.

Theo GDPR, trường hợp này vi phạm Điều 32(1)(a) về yêu cầu áp dụng biện pháp giả danh hóa và mã hóa dữ liệu cá nhân ở mức phù hợp với rủi ro, trong đó lưu mật khẩu dạng rõ là vi phạm trực tiếp. Trường hợp này cũng vi phạm Điều 25 về bảo vệ dữ liệu ngay từ khâu thiết kế và theo mặc định, vì việc chọn lược đồ cơ sở dữ liệu không băm mật khẩu là một quyết định ở khâu thiết kế, và Điều 5(1)(f) về nguyên tắc toàn vẹn và bảo mật.

Vấn đề thuộc pha Code và Build, phát hiện tại chặng 2. Mật khẩu dạng rõ được đưa vào từ khâu thiết kế lược đồ thuộc pha Code, còn bí mật gán cứng trong tệp Compose nằm ở ranh giới giữa pha Code và pha Release.

### 4.4.4 Cách xử lý

Để xử lý phần thứ nhất, nhóm chuyển sang băm mật khẩu. PHP cung cấp sẵn `password_hash()` và `password_verify()`, dùng thuật toán bcrypt theo mặc định. Hàm xác thực được viết lại kết hợp cả hai biện pháp là băm mật khẩu và truy vấn tham số hóa:

```php
/** authenticate(): mat khau khong bao gio duoc ghep vao chuoi cau lenh SQL. */
function authenticate(string $username, string $password): ?array
{
    $stmt = mysqli_prepare(db(),
        'SELECT id, username, role, password_hash FROM users WHERE username = ? LIMIT 1');
    if ($stmt === false) { return null; }
    mysqli_stmt_bind_param($stmt, 's', $username);
    mysqli_stmt_execute($stmt);
    $row = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));
    mysqli_stmt_close($stmt);

    if ($row === null || !password_verify($password, $row['password_hash'])) {
        return null;              // khong phan biet sai ten hay sai mat khau
    }
    unset($row['password_hash']);
    return $row;
}
```

Trình xử lý đăng nhập dùng hàm trên, đồng thời tái sinh định danh phiên để chống kỹ thuật cố định phiên:

```php
// pages/login.php (sau khi sua)
$user = authenticate($_POST['username'] ?? '', $_POST['password'] ?? '');
if ($user !== null) {
    session_regenerate_id(true);
    $_SESSION['uid'] = $user['id'];
    header('Location: /account'); exit;
}
$error = 'Sai tên đăng nhập hoặc mật khẩu.';
```

Lược đồ cơ sở dữ liệu đổi cột `password VARCHAR(255)` thành `password_hash CHAR(60) NOT NULL`, đủ chứa chuỗi 60 ký tự có tiền tố `$2y$` do `password_hash()` sinh ra, và dữ liệu mẫu được nạp bằng giá trị băm thay vì chuỗi gốc.

Để xử lý phần thứ hai, nhóm đưa bí mật ra khỏi kho mã. Giá trị dự phòng bị loại bỏ, và khi thiếu biến môi trường thì ứng dụng dừng ngay thay vì chạy với mật khẩu mặc định:

```php
// lib/db.php (sau khi sua)
$pass = getenv('DB_PASS');
if ($pass === false || $pass === '') {
    throw new RuntimeException('Thieu cau hinh bat buoc: DB_PASS');
}
```

Tệp Compose nhận bí mật từ môi trường thay vì chứa giá trị:

```yaml
# docker-compose.prod.yml (sau khi sua)
  db:
    environment: { MYSQL_ROOT_PASSWORD: "${MYSQL_ROOT_PASSWORD:?Thieu}", MYSQL_ROOT_HOST: "localhost" }
  web:
    environment: { DB_USER: "${DB_USER:?Thieu}", DB_PASS: "${DB_PASS:?Thieu}" }
```

Cú pháp `${BIEN:?thông báo}` khiến lệnh khởi động thất bại kèm thông báo rõ ràng nếu thiếu biến, áp dụng đúng nguyên tắc để hệ thống báo lỗi ngay và rõ thay vì chạy tiếp với giá trị mặc định không an toàn.

### 4.4.5 Minh chứng Security as Code

Tiêu chí an toàn của vấn đề này tồn tại dưới dạng mã trong kho và chạy tự động trên mọi thay đổi. Luật `php-hardcoded-db-password-fallback` tại `ci/semgrep-local-rules.yml:2-14` bắt mẫu gán cứng trong mã PHP, còn luật `compose-hardcoded-mysql-root-password` tại dòng 16-34 bắt mật khẩu gán cứng trong tệp Compose. Để luật thứ hai bao phủ được cả hai tệp Compose đang thực sự chứa bí mật, cần sửa mục `paths.include`:

```yaml
# ci/semgrep-local-rules.yml:26-30 (de xuat sua)
    paths:
      include:
        - "**/docker-compose*.yml"
        - "**/compose*.yml"
        - "**/compose*.yaml"
```

Với mẫu `docker-compose*.yml`, luật sẽ khớp cả `docker-compose.prod.yml:15` và `docker-compose.monitoring.yml:46`, là hai vị trí hiện đang lọt.

### 4.4.6 Giới hạn của công cụ đối với vấn đề này

Có ba điểm công cụ không phát hiện được, cần nêu rõ.

- **Mật khẩu lưu dạng rõ trong lược đồ cơ sở dữ liệu.** Không công cụ nào trong dây chuyền báo. SonarQube không quét tệp SQL trong cấu hình hiện tại, còn Semgrep không có luật nào nhận biết được rằng một cột tên `password` kiểu `VARCHAR(255)` đang chứa giá trị chưa băm.
- **Mật khẩu quản trị Grafana tại `monitoring.yml:46`.** Vị trí này lọt vì khiếm khuyết `paths.include` nêu trên, và vì luật chỉ nhằm vào khóa `MYSQL_ROOT_PASSWORD`.
- **Giá trị của bí mật đã lộ.** Công cụ chỉ báo rằng có bí mật gán cứng, không biết bí mật đó đã lộ ra kho mã công khai và cần được thu hồi. Xử lý triệt để đòi hỏi đổi toàn bộ mật khẩu đã từng xuất hiện trong lịch sử Git, vì lịch sử vẫn giữ giá trị cũ ngay cả sau khi tệp được sửa.

## 4.5 Thành viên 4, Lê Đức Anh: cấu hình triển khai mất an toàn

### 4.5.1 Mô tả vấn đề

Bảng kiểm ở Chương 2 liệt kê mười yêu cầu không đạt ở lớp hạ tầng. Thành viên 4 phụ trách nhóm vấn đề về quyền hạn và bề mặt tiếp xúc của container, tập trung vào ba điểm.

Điểm thứ nhất là container chạy bằng quyền `root`. Tệp `InlaneWeb/web/Dockerfile` không có chỉ thị `USER` nào nên tiến trình Apache chạy với quyền `root` trong container, và `InlaneWeb/db/Dockerfile` cũng ở tình trạng tương tự. Khi kết hợp với một lỗ hổng cho phép thực thi lệnh, quyền `root` trong container làm tăng đáng kể khả năng kẻ tấn công thoát ra máy chủ.

Điểm thứ hai là tài khoản cơ sở dữ liệu toàn quyền. Ứng dụng kết nối bằng `root` theo `prod.yml:49`, và tài khoản này được cấp quyền rộng nhất có thể:

```sql
-- db/init.sql:11-14
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
GRANT FILE ON *.* TO 'root'@'%';
```

Ba yếu tố ở đây cộng hưởng với nhau. Khai báo `'root'@'%'` cho phép kết nối từ mọi máy, `ALL PRIVILEGES ON *.*` cho phép đọc cả cơ sở dữ liệu `dev`, và `GRANT FILE` cho phép đọc ghi tệp trên máy chủ cơ sở dữ liệu. Một lỗi tiêm mã SQL với tài khoản như vậy không chỉ đọc được dữ liệu mà còn ghi được tệp.

Điểm thứ ba là ảnh container không ghim phiên bản. Các dịch vụ dùng thẻ `latest` tại `prod.yml:11`, `:31` và `monitoring.yml:64`. Hệ quả là hai lần triển khai cách nhau có thể chạy hai phiên bản khác nhau mà không ai chủ động thay đổi gì, khiến sự cố khó tái hiện và khiến một bản cập nhật có lỗ hổng có thể tự động vào môi trường thật.

### 4.5.2 Cách phát hiện và chính sách bị vi phạm

Semgrep phát hiện điểm thứ nhất qua hai luật của bộ `p/security-audit`:

```
Phat hien 1: dockerfile.security.missing-user-entrypoint  [ERROR]
Vi tri: InlaneWeb/db/Dockerfile:15 | ENTRYPOINT ["fix-perms-entrypoint.sh"]
Phan loai: A04:2021 Insecure Design, CWE-269

Phat hien 2: dockerfile.security.missing-user  [ERROR]
Vi tri: InlaneWeb/db/Dockerfile:16 | CMD ["mariadbd"]
Phan loai: A04:2021 Insecure Design, CWE-250
```

Điểm thứ hai và điểm thứ ba được phát hiện bằng rà soát thủ công. Công cụ `ci/validate_configs.py` chạy trong dây chuyền không phát hiện được, vì tệp này chỉ gọi `yaml.safe_load` và `json.load` để kiểm tra cú pháp của 8 tệp cấu hình, hoàn toàn không có tiêu chí an toàn nào.

Trường hợp này vi phạm Điều 26 và Điều 27 Nghị định 13/2023/NĐ-CP về biện pháp kỹ thuật bảo vệ dữ liệu, trong đó Điều 27 yêu cầu kiểm tra an ninh mạng đối với hệ thống và thiết bị phục vụ xử lý dữ liệu cá nhân trước khi xử lý. Theo GDPR, tương ứng Điều 32(1)(b) về bảo đảm tính bảo mật, toàn vẹn, sẵn sàng và khả năng phục hồi của hệ thống xử lý. Vấn đề thuộc pha Release và Deploy, liên quan chặng 3 và chặng 4.

### 4.5.3 Cách xử lý và minh chứng Policy as Code

Biện pháp xử lý gồm ba phần. Sửa Dockerfile để tiến trình chạy bằng tài khoản không đặc quyền, cụ thể là thêm `RUN chown -R www-data:www-data /var/www/html` rồi `USER www-data`. Tạo tài khoản cơ sở dữ liệu riêng cho ứng dụng theo nguyên tắc quyền tối thiểu. Ghim phiên bản ảnh container theo digest thay cho thẻ `latest`.

```sql
-- db/init.sql: tai khoan rieng cho ung dung
CREATE USER IF NOT EXISTS 'ilf_app'@'%' IDENTIFIED BY '${APP_DB_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE ON ilfreight.* TO 'ilf_app'@'%';
-- Khong cap FILE, khong cap GRANT OPTION, khong cap quyen tren CSDL dev
```

Về minh chứng Policy as Code, các yêu cầu trên được viết thành một kiểm tra tự động chạy trong dây chuyền thay vì chỉ là ghi chú trong tài liệu. Dưới đây là chính sách triển khai dạng mã, bổ sung vào `ci/validate_configs.py`:

```python
RULES = [
    ("R1 gan cung bi mat",      lambda s: [k for k, v in (s.get("environment") or {}).items()
                                           if re.search(r"(PASSWORD|PASS|SECRET|TOKEN)$", k, re.I)
                                           and not str(v).startswith("${")]),
    ("R2 cong bo ra moi giao dien", lambda s: [p for p in (s.get("ports") or [])
                                           if str(p).startswith("0.0.0.0:")]),
    ("R3 anh khong ghim",       lambda s: [s["image"]] if str(s.get("image", "")).endswith(":latest") else []),
    ("R4 docker.sock ghi duoc", lambda s: [v for v in (s.get("volumes") or [])
                                           if "/var/run/docker.sock" in str(v) and not str(v).endswith(":ro")]),
    ("R5 chay bang root",       lambda s: ["user: root"] if str(s.get("user", "")) == "root" else []),
]

def validate_deployment_policy(compose_path: str) -> int:
    doc = yaml.safe_load(open(compose_path, encoding="utf-8"))
    violations = 0
    for name, svc in (doc.get("services") or {}).items():
        for label, check in RULES:
            for hit in check(svc):
                print(f"[VI PHAM] {label} | dich vu {name}: {hit}", file=sys.stderr)
                violations += 1
    return violations
```

Chạy hàm này trên hai tệp Compose hiện tại cho ra đúng các vi phạm đã liệt kê trong bảng kiểm ở Chương 2: quy tắc R1 bắt `prod.yml:15`, `:50` và `monitoring.yml:46`; R2 bắt `monitoring.yml:43`; R3 bắt ba vị trí; R4 bắt `monitoring.yml:73`; R5 bắt `monitoring.yml:26`. Đặt kiểm tra này vào chặng 3 với điều kiện dừng khi `violations` lớn hơn 0, dây chuyền sẽ không triển khai được cấu hình vi phạm chính sách, đúng nguyên tắc dừng ngay tại chặng phát hiện lỗi.

## 4.6 Thành viên 5, Nguyễn Phương Mai: rò rỉ dữ liệu cá nhân qua đường nhật ký

### 4.6.1 Mô tả vấn đề

Đây là vấn đề do chính đợt bổ sung hệ giám sát tạo ra, và không công cụ nào trong dây chuyền phát hiện được. Hệ giám sát được thêm vào để tăng khả năng quan sát, nhưng lại mở một đường đưa dữ liệu nhạy cảm ra ngoài. Chuỗi rò rỉ gồm năm mắt xích, mỗi mắt xích đều hợp lý nếu xét riêng.

Mắt xích thứ nhất nằm ở `pages/login.php:19`, nơi mật khẩu người dùng được ghép vào chuỗi câu lệnh SQL.

Mắt xích thứ hai xuất hiện khi truy vấn thất bại, mà chỉ cần tên đăng nhập chứa một dấu nháy đơn là đủ. Hàm `query()` gọi bộ ghi nhật ký và truyền nguyên văn câu lệnh:

```php
// lib/db.php:40-50
function query(string $sql)
{
    $conn = db();
    $res = mysqli_query($conn, $sql);
    if ($res === false) {
        $err = mysqli_error($conn);
        InlaneLogger::logSqlError($sql, $err, mysqli_errno($conn));
        echo '<div class="sql-error"><strong>SQL Error:</strong> ' . $err . '</div>';
    }
    return $res;
}
```

Mắt xích thứ ba nằm ở bộ ghi nhật ký, nơi nguyên văn câu lệnh được đưa vào trường `failed_query` của bản ghi JSON rồi ghi ra luồng lỗi chuẩn:

```php
// lib/logger.php:68-79
public static function logSqlError(string $query, string $errorMessage, int $errorCode = 0): void
{
    self::emit('APP-EXCEPTION', [
        'level'         => 'error',
        'type'          => 'database_query_failure',
        'error_message' => $errorMessage,
        'failed_query'  => $query,          // chua mat khau dang ro
        'uri'           => $_SERVER['REQUEST_URI'] ?? '/',
    ], true);
}
```

Mắt xích thứ tư nằm ở Promtail, được cấu hình bóc đúng trường này ra khỏi JSON và đẩy sang Loki:

```yaml
# monitoring/promtail/promtail-config.yml:27-39 (trich)
      - json:
          expressions:
            level: level
            message: message
            failed_query: failed_query      # boc truong chua mat khau
            uri: uri
```

Mắt xích thứ năm nằm ở Grafana, nơi đọc Loki và được công bố trên `0.0.0.0:3000` theo `monitoring.yml:43`, tức mở ra mọi giao diện mạng của máy chủ, với mật khẩu quản trị gán cứng tại dòng 46 của chính tệp đang nằm trong kho mã công khai.

Kết quả là mật khẩu người dùng nhập ở biểu mẫu đăng nhập đi tới một bảng điều khiển truy cập được từ Internet. Không mắt xích nào trong năm mắt xích trên tự nó là lỗi nghiêm trọng, hậu quả chỉ xuất hiện khi ghép chúng lại.

### 4.6.2 Cách phát hiện

Không công cụ nào trong dây chuyền báo vấn đề này. SonarQube báo `vulnerabilities` bằng 0. Semgrep không có luật nào coi hàm ghi nhật ký là điểm thực thi nhạy cảm, vì các bộ luật công khai tập trung vào tiêm mã chứ không vào việc ghi dữ liệu nhạy cảm ra nhật ký.

Nhóm phát hiện bằng cách lần theo đường đi của một trường dữ liệu qua nhiều lớp hệ thống, từ biểu mẫu HTML, qua mã PHP, qua cấu hình thu thập nhật ký, tới cấu hình công bố cổng mạng. Phương pháp này đòi hỏi đọc đồng thời mã ứng dụng và cấu hình hạ tầng, là việc mà công cụ phân tích tĩnh hiện nay không làm được do chúng chỉ làm việc trong phạm vi từng tệp hoặc từng ngôn ngữ.

### 4.6.3 Chính sách bị vi phạm và pha DevSecOps

Theo Nghị định 13/2023/NĐ-CP, trường hợp này vi phạm Điều 26 về nghĩa vụ áp dụng biện pháp bảo vệ dữ liệu cá nhân trong suốt quá trình xử lý, vì việc đưa thông tin xác thực vào hệ thống nhật ký công khai là vi phạm nghĩa vụ đó. Trường hợp này cũng liên quan Điều 23 về nghĩa vụ thông báo vi phạm quy định bảo vệ dữ liệu cá nhân cho Bộ Công an trong thời hạn 72 giờ kể từ khi xảy ra vi phạm, theo Mẫu số 03 của Nghị định, trong đó thông báo sau thời hạn phải kèm lý do chậm trễ. Hệ thống hiện chưa có quy trình nào đáp ứng nghĩa vụ này.

Theo GDPR, trường hợp này vi phạm Điều 5(1)(c) về nguyên tắc tối thiểu hóa dữ liệu, vì việc ghi toàn văn câu lệnh SQL vượt xa mức cần thiết cho mục đích chẩn đoán lỗi. Điều 33 và Điều 34 quy định nghĩa vụ thông báo vi phạm cho cơ quan giám sát trong 72 giờ và cho chủ thể dữ liệu khi rủi ro ở mức cao.

Vấn đề trải trên hai pha. Ba mắt xích đầu thuộc pha Code, còn mắt xích thứ tư và thứ năm thuộc pha Operate và Monitor. Đây là nguyên nhân khiến vấn đề lọt qua mọi cổng kiểm tra, vì mỗi pha chỉ nhìn thấy một nửa và không nửa nào tự nó sai.

### 4.6.4 Cách xử lý và minh chứng Security as Code

Biện pháp thứ nhất là lọc dữ liệu nhạy cảm ngay tại nguồn ghi nhật ký. Đây là biện pháp quan trọng nhất vì nó chặn ở mắt xích sớm nhất:

```php
// lib/logger.php: bo sung; logSqlError() goi redactQuery($query) thay vi $query
private static function redactQuery(string $query): string
{
    $query = preg_replace(
        "/\b(password|passwd|pass|api_key|remember_token|token|secret)\b\s*(=|LIKE)\s*'[^']*'/i",
        '$1 $2 \'[DA CHE]\'', $query);
    return mb_strlen($query) > 500 ? mb_substr($query, 0, 500) . '...[cat bot]' : $query;
}
```

Biện pháp thứ hai là đóng Grafana sau proxy, bằng cách sửa `monitoring.yml:43` thành `"127.0.0.1:3000:3000"` và cho phép truy cập qua Nginx Proxy Manager có xác thực, giống cách ứng dụng web đã làm.

Biện pháp thứ ba là đưa mật khẩu quản trị Grafana ra khỏi kho mã, dùng cú pháp `${GRAFANA_ADMIN_PASSWORD:?...}` như đã trình bày ở phần của thành viên 3. Mật khẩu hiện tại đã nằm trong lịch sử Git của kho công khai nên phải coi là đã lộ và bắt buộc phải đổi, không chỉ chuyển sang biến môi trường.

Biện pháp thứ tư là xây dựng quy trình ứng phó sự cố rò rỉ dữ liệu cá nhân, gồm người chịu trách nhiệm, các bước xác minh phạm vi ảnh hưởng, và mẫu thông báo gửi Bộ Công an trong 72 giờ theo Điều 23.

Về minh chứng Security as Code, để lỗi tương tự không tái diễn, nhóm đề xuất một luật Semgrep tự viết coi hàm ghi nhật ký là điểm thực thi nhạy cảm:

```yaml
# ci/semgrep-local-rules.yml: luat de xuat bo sung
  - id: php-sql-query-into-logger
    languages: [php]
    severity: ERROR
    message: Cau lenh SQL duoc ghi nguyen van vao nhat ky, co the chua thong tin xac thuc.
    patterns:
      - pattern: InlaneLogger::logSqlError($SQL, ...)
      - pattern-not: InlaneLogger::logSqlError(self::redactQuery(...), ...)
    metadata:
      cwe: "CWE-532: Insertion of Sensitive Information into Log File"
      owasp: "A09:2021 Security Logging and Monitoring Failures"
```

Luật này bắt mọi lời gọi ghi nhật ký truyền thẳng câu lệnh SQL chưa qua hàm che dữ liệu, và sẽ báo lỗi ở cả ba vị trí hiện tại trong `lib/db.php` là các dòng 46, 61 và 90.

---

# CHƯƠNG 5. GIÁM SÁT, PHÁT HIỆN VÀ ỨNG PHÓ

## 5.1 Kiến trúc nhật ký và nhận diện vector tấn công

Hệ giám sát thu thập nhật ký trực tiếp từ Docker qua socket, lọc giữ lại hai container `ilfreight_web` và `ilfreight_db` theo `promtail-config.yml:17-23`, rồi phân thành hai luồng: luồng lỗi ứng dụng gắn nhãn `log_category: app_exception` tại dòng 42-48, và luồng lưu lượng HTTP gắn nhãn `log_category: http_traffic` tại dòng 51-56. Cách tách này cho phép đặt chính sách lưu trữ và cảnh báo khác nhau cho hai loại nhật ký. Phía ứng dụng, bộ bắt lỗi toàn cục đăng ký tại `index.php:13-33` gồm `set_exception_handler`, `set_error_handler` và `register_shutdown_function`, nhờ đó không có lỗi nào biến mất khỏi nhật ký.

Promtail còn gắn nhãn phân loại tấn công ngay tại khâu thu thập, dựa trên biểu thức chính quy so khớp nội dung dòng nhật ký.

*Bảng: Bốn nhóm vector tấn công được nhận diện tự động*

| Nhãn `vuln_category` | Mức | Dấu hiệu nhận biết chính | Dòng |
| :--- | :--- | :--- | :---: |
| `sqli` | critical | `union select`, `sleep(`, `or 1=1`, `information_schema`, `load_file(`, `sqlmap` | 58-66 |
| `traversal_lfi` | high | `../`, `%2e%2e%2f`, `/etc/passwd`, `php://filter` | 68-76 |
| `xss` | warning | `<script`, `onerror=`, `javascript:`, `document.cookie` | 78-86 |
| `command_injection` | critical | `; cat`, `&& ls`, `/bin/sh`, `powershell`, `cmd.exe` | 88-96 |

Ngoài bốn nhóm trên còn nhóm thứ năm là `error_based_leak` tại dòng 98-106, nhận diện phản hồi chứa thông báo lỗi SQL hoặc mã trạng thái 4xx và 5xx. Giới hạn của cách làm này cần được nêu rõ: việc nhận diện dựa trên so khớp mẫu chuỗi nên có thể bị vượt qua bằng các kỹ thuật mã hóa đơn giản, và có thể báo nhầm khi người dùng vô tình nhập chuỗi khớp mẫu. Cơ chế này hữu ích cho việc quan sát và điều tra sau sự cố, không phải là biện pháp ngăn chặn.

## 5.2 Tự động phục hồi dịch vụ

Dịch vụ `autoheal` theo dõi trạng thái sức khỏe của các container có nhãn `autoheal: "true"` và khởi động lại container không khỏe, với `AUTOHEAL_INTERVAL=10` và `AUTOHEAL_START_PERIOD=20` tại `monitoring.yml:68-70`. Container web kiểm tra sức khỏe qua điểm cuối `/health` mỗi 10 giây, cho phép thất bại 3 lần liên tiếp theo `prod.yml:41-46`, tức phát hiện sự cố sau khoảng 30 giây. Điểm cuối này tại `index.php:53-90` còn kiểm tra kết nối cơ sở dữ liệu bằng `mysqli_ping` và trả mã 503 khi mất kết nối, nhờ đó một container web còn sống nhưng mất kết nối cơ sở dữ liệu vẫn bị phát hiện.

Cần ghi nhận một đánh đổi về an toàn ở đây. Để khởi động lại container khác, `autoheal` được gắn socket Docker với quyền ghi theo `monitoring.yml:73`, mà quyền này tương đương quyền `root` trên máy chủ, trong khi container `autoheal` lại dùng ảnh thẻ `latest` của bên thứ ba. Một bản cập nhật bị can thiệp ở thượng nguồn sẽ kiểm soát được toàn bộ máy chủ. Đây là rủi ro chuỗi cung ứng cần được cân nhắc so với lợi ích tự phục hồi.

## 5.3 Chuỗi tấn công đến cảnh báo và độ trễ phát hiện

Các biện pháp khắc phục ở Chương 4 được triển khai trên một nhánh vá và kiểm chứng bằng cách chạy hệ thống thật. Cụm giám sát được sửa để khép kín chuỗi từ tấn công đến cảnh báo: Promtail chỉ còn che dữ liệu trước khi lưu, việc tương quan chuyển sang luật của Loki, và bổ sung hai dịch vụ còn thiếu là Alertmanager cùng một đích nhận cảnh báo. Gửi tám yêu cầu mang đặc trưng tiêm mã SQL vào ứng dụng đã vá, chuỗi chạy tuần tự qua Apache, Promtail, Loki đếm theo địa chỉ nguồn bằng truy vấn `| json`, Alertmanager, tới đích nhận ghi một dòng cho người trực. Độ trễ từ lúc tấn công tới khi cảnh báo tới đích đo được là 15,1 rồi 20,9 rồi 24,6 giây qua ba lần chạy độc lập, bị giới hạn bởi chu kỳ đánh giá luật mười lăm giây của Loki và khoảng chờ gộp mười giây của Alertmanager.

Cùng một loạt kích hoạt đồng thời hai mức cảnh báo, một mức thông tin để đối chiếu và một mức nghiêm trọng để gọi người trực, đúng kiến trúc hai chuỗi của tài liệu môn học. Phần che dữ liệu được kiểm trực tiếp: khi gửi một yêu cầu chứa mật khẩu, không dòng nhật ký nào trong Loki còn chứa mật khẩu nguyên văn. Cấu hình gốc trỏ bộ luật tới một Alertmanager không tồn tại, nên chuỗi phát hiện của bản gốc đứt ở mắt xích cuối.

## 5.4 Tổng hợp những gì công cụ không phát hiện được

*Bảng: Khiếm khuyết công cụ không phát hiện và nguyên nhân*

| Khiếm khuyết | Vị trí | Nguyên nhân công cụ không báo |
| :--- | :--- | :--- |
| Mật khẩu lưu dạng rõ trong cơ sở dữ liệu | `init.sql:26`, `:34-38` | Nằm ở dữ liệu chứ không ở mã, tệp SQL không được quét |
| Cổng chất lượng không chặn | `devsecops-pipeline.yml:55` | Không công cụ nào tự kiểm tra cấu hình của chính dây chuyền |
| Chuỗi rò rỉ mật khẩu ra Grafana | 5 tệp, 2 ngôn ngữ | Chuỗi trải qua PHP và YAML, không công cụ nào phân tích xuyên lớp |
| Mật khẩu Grafana gán cứng | `monitoring.yml:46` | Mục `paths.include` của luật không khớp tên tệp |
| Mật khẩu CSDL trong Compose sản xuất | `prod.yml:15`, `:50` | Cùng nguyên nhân với trường hợp trên |
| Thiếu tái sinh định danh phiên | `login.php:22-26` | Lỗi do thiếu một lời gọi, luật phân tích tĩnh bắt mẫu có mặt nên khó bắt mẫu vắng mặt |
| Thiếu kiểm tra quyền sở hữu bình luận | `comment_delete.php:18` | Lỗi logic nghiệp vụ, cần hiểu ý định của ứng dụng |
| Tài khoản cơ sở dữ liệu thừa quyền | `init.sql:12-13` | Không có luật nào đánh giá mức quyền SQL |
| Bí mật đã lộ trong lịch sử Git | Toàn bộ lịch sử | Công cụ quét bản làm việc hiện tại, không quét lịch sử |

Chín khiếm khuyết trên có một mẫu chung. Công cụ phân tích tĩnh mạnh ở việc nhận ra mẫu mã nguồn nguy hiểm trong phạm vi một tệp và một ngôn ngữ, nhưng yếu ở ba loại vấn đề: lỗi do thiếu một biện pháp, lỗi logic nghiệp vụ, và lỗi hình thành từ sự kết hợp của nhiều thành phần mà riêng lẻ đều hợp lệ.

Hệ quả thực tiễn là một dây chuyền DevSecOps không thay thế được việc đọc mã và rà soát thiết kế. Dây chuyền xử lý phần việc lặp đi lặp lại để con người tập trung vào phần việc mà máy chưa làm được.

---

# KẾT LUẬN

Nhóm đã dựng và vận hành một dây chuyền DevSecOps bốn chặng trên nền công cụ nguồn mở, gồm kiểm tra quy ước phát triển, phân tích tĩnh bằng hai công cụ có cơ chế khác nhau, chạy thử tích hợp, triển khai tự động lên máy chủ thật và giám sát nhật ký tập trung. Nhóm cũng phân tích năm vấn đề an toàn theo phân công, phủ đủ hai nhóm mã nguồn và triển khai vận hành, mỗi vấn đề đều có vị trí cụ thể trong mã, cách phát hiện, căn cứ pháp lý và mã nguồn khắc phục.

Hai kết quả mà nhóm đánh giá là có giá trị nhất đều mang tính phủ định, và đều đến từ việc kiểm chứng chính công trình của mình.

Kết quả thứ nhất cho thấy dây chuyền của nhóm chưa dừng khi gặp lỗi. Chương 3 chỉ ra một dòng cấu hình khiến toàn bộ chặng phân tích tĩnh hoạt động ở chế độ chỉ báo cáo, có ba ảnh chụp màn hình làm chứng. Nguyên tắc cốt lõi của DevSecOps chưa được thực hiện, dù hình thức bên ngoài của dây chuyền đã đầy đủ.

Kết quả thứ hai cho thấy cổng chất lượng ở trạng thái đạt không đồng nghĩa với mã nguồn an toàn. SonarQube Community báo `security_rating` ở mức A và không có lỗ hổng nào, trên một kho mã có 11 vị trí tiêm mã SQL mà Semgrep tìm ra. Chương 5 tổng hợp chín khiếm khuyết thật mà công cụ hoàn toàn im lặng.

Một kết quả thứ ba mang tính khẳng định đến từ việc kiểm chứng động trên nhánh vá: bộ kiểm thử theo hướng hành vi chuyển từ sáu phép kiểm thất bại sang sáu phép kiểm đạt, các cổng chính sách và quét tĩnh chuyển từ báo lỗi sang sạch, và chuỗi phát hiện khép kín với độ trễ mười lăm đến hai mươi lăm giây. Nhờ đó các đề xuất ở Chương 4 được chạy thử và đo trong môi trường thật, như trình bày ở mục 5.3.

Về hạn chế, phần phân tích năm vấn đề ở Chương 4 dựa trên mã nguồn và cấu hình, còn việc kiểm chứng động được thực hiện cho các biện pháp khắc phục trên nhánh vá như trình bày ở mục 5.3, chưa phủ hết mọi trường hợp khai thác. Nhóm giữ lại một đợt vá thứ hai có chủ đích để bộ kiểm thử còn đối tượng đo. Dây chuyền cũng chưa có phân tích thành phần phần mềm bên thứ ba và chưa đo độ bao phủ kiểm thử. Về pháp lý, nhóm trích dẫn Nghị định 13/2023/NĐ-CP theo yêu cầu của đề bài nhưng chưa đối chiếu được với Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15 đã thay thế nghị định này từ ngày 01/01/2026.

Hướng phát triển tiếp theo được sắp xếp theo thứ tự ưu tiên:

- Bật chế độ chặn của cổng chất lượng theo đề xuất ở Chương 3, kèm kế hoạch xử lý 19 phát hiện hiện có. Đây là việc cần làm trước tiên vì nếu không có nó thì mọi cổng kiểm tra khác chỉ mang tính hình thức.
- Áp dụng chính sách triển khai dạng mã vào chặng 3, và bổ sung luật che dữ liệu nhật ký vào bộ luật Semgrep nội bộ.
- Khắc phục chuỗi rò rỉ dữ liệu qua đường nhật ký, đồng thời đổi toàn bộ bí mật đã xuất hiện trong lịch sử Git.
- Bổ sung phân tích thành phần phần mềm bên thứ ba và kiểm thử động vào dây chuyền.

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

# PHỤ LỤC. HƯỚNG DẪN CHỤP ẢNH VÀ HỒ SƠ MINH CHỨNG

Bốn ảnh minh chứng phải được chụp lại từ lần chạy dây chuyền gần nhất, không dùng lại ảnh của các lần chạy cũ, để số liệu trên ảnh khớp với số liệu đã dẫn trong Chương 3. Quy ước chung khi chụp: dùng trình duyệt ở chế độ cửa sổ tối đa, độ phân giải tối thiểu 1600 pixel chiều ngang, mức thu phóng 100 phần trăm; chỉ cắt lấy vùng nội dung chính và giữ lại thanh địa chỉ khi địa chỉ là một phần của bằng chứng; lưu định dạng PNG đúng tên tệp nêu dưới đây vào thư mục `docs/images`; che các giá trị bí mật nếu vô tình lọt vào khung hình; không chỉnh sửa nội dung ảnh ngoài việc cắt khung và che bí mật.

*Bảng: Hướng dẫn chụp từng ảnh minh chứng*

| Tên tệp | Mở ở đâu | Khung hình bắt buộc thấy rõ |
| :--- | :--- | :--- |
| `h01-run-summary.png` | Trang tóm tắt lần chạy, mục Summary | Trạng thái chung của lần chạy, dòng `Quality Gate: ERROR`, dòng `Gate enforcement: report-only`, mã commit được quét |
| `h02-sonar-job-steps.png` | Công việc SonarQube SAST and Quality Gate | Toàn bộ danh sách bước, thấy rõ bước `Enforce pipeline result` kèm dấu hoàn thành, và dấu trạng thái thành công của cả công việc |
| `h03-semgrep-job.png` | Công việc Semgrep Security SAST | Danh sách bước và dấu trạng thái thành công, kèm thời gian chạy |
| `h04-sonar-issues.png` | Tệp `report.html` trong artifact SonarQube, bảng Issues | Dòng tiêu đề nêu tổng số phát hiện, đủ các cột Mức độ, Phân loại, Vị trí, Rule ID, Chi tiết vi phạm |

Hai ảnh đầu là minh chứng quan trọng nhất của báo cáo, vì chúng cho thấy cổng chất lượng báo lỗi nhưng lần chạy vẫn kết thúc thành công. Khi chụp, cần bảo đảm trạng thái báo lỗi của cổng và trạng thái thành công của công việc cùng nằm trong một khung hình, vì nếu tách thành hai ảnh thì sức thuyết phục giảm đáng kể.

Toàn bộ hồ sơ minh chứng của báo cáo được liệt kê dưới đây.

*Bảng: Danh mục minh chứng*

| TT | Minh chứng | Vị trí |
| :---: | :--- | :--- |
| 1 | Dây chuyền DevSecOps bốn chặng | `.github/workflows/devsecops-pipeline.yml` |
| 2 | Policy as Code, quy ước commit và PR | `ci/policy_guard.py`, `.githooks/commit-msg` |
| 3 | Security as Code, tiêu chí cổng chất lượng | `ci/sonarqube-quality-gate.json` |
| 4 | Security as Code, luật Semgrep tự viết | `ci/semgrep-local-rules.yml` |
| 5 | Kiểm tra cú pháp tệp cấu hình | `ci/validate_configs.py`, `tests/test_validate_configs.py` |
| 6 | Cấu hình triển khai và thu thập nhật ký | `InlaneWeb/docker-compose.prod.yml`, `docker-compose.monitoring.yml`, `monitoring/promtail/promtail-config.yml` |
| 7 | Lược đồ cơ sở dữ liệu và bản ghi kỹ thuật khai thác | `InlaneWeb/db/init.sql`, `InlaneWeb/writeup.md` |
| 8 | Kết quả SonarQube và Semgrep của lần chạy `39756107853` | Phần Artifacts của lần chạy trong kho mã |
| 9 | Ảnh chụp màn hình dây chuyền | `docs/images` |

Để tái lập kết quả quét, mở trang lần chạy `39756107853` trong kho mã, tải hai tệp nén ở mục Artifacts, giải nén rồi mở tệp `report.html` trong mỗi tệp nén. Tệp `summary.md` chứa cùng nội dung ở dạng văn bản. Mọi số liệu về chỉ số SonarQube và phân bố phát hiện Semgrep trong Chương 3 đều lấy từ hai nguồn này.
