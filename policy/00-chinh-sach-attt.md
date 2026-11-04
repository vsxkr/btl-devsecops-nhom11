# Chính sách an toàn thông tin, Công ty cổ phần Logistics Inlane

| Hạng mục | Nội dung |
| :--- | :--- |
| Mã hiệu | CS-ATTT-2026 |
| Phiên bản | 1.0, hiệu lực từ 01/11/2026 |
| Phạm vi | Ứng dụng InlaneWeb, cơ sở dữ liệu khách hàng, hạ tầng container và chuỗi công cụ phát triển |
| Người phê duyệt | Giám đốc công nghệ |
| Rà soát | Sáu tháng một lần, hoặc ngay khi có sự cố liên quan dữ liệu cá nhân |

## 1. Bối cảnh và lý do ban hành

Inlane vận hành cổng tra cứu vận đơn cho khách hàng doanh nghiệp và khách lẻ.
Hệ thống lưu họ tên, số điện thoại, địa chỉ nhận hàng, lịch sử đơn hàng và
thông tin đăng nhập. Theo Nghị định 13/2023/NĐ-CP Điều 26 và 27, tương ứng
GDPR Điều 24 và 32, công ty là bên kiểm soát dữ liệu và có nghĩa vụ chứng minh
đã áp dụng biện pháp kỹ thuật và quản lý phù hợp. Nghĩa vụ chứng minh là điểm
quan trọng: khi cơ quan quản lý hoặc khách hàng yêu cầu, công ty phải đưa ra
bằng chứng chứ không phải lời cam kết.

Chính sách này do đó không dừng ở việc nêu yêu cầu. Mỗi điều khoản được gắn
với một cổng kiểm soát tự động trong pipeline, và mỗi lần chạy pipeline để lại
một tệp bằng chứng. Phần mềm không qua được cổng thì không được phát hành.

## 2. Tám điều khoản bắt buộc

| Mã | Điều khoản | Tình huống nghiệp vụ phát sinh rủi ro | Cổng thi hành | Bằng chứng |
| :--- | :--- | :--- | :--- | :--- |
| CS-01 | Mọi thay đổi mã nguồn vào nhánh phát hành phải đi qua pull request, có một người phê duyệt khác tác giả, và truy vết được tác giả cùng lý do | Phát hành gấp ngoài giờ, một thành viên đẩy thẳng cấu hình lên nhánh phát hành | `ci/policy_guard.py`, `policy/repo_policy.rego`, bảo vệ nhánh phía GitHub | `evidence/ci-03-branch-protection.txt` |
| CS-02 | Cấu hình triển khai phải qua cổng chính sách trước khi phát hành, và phạm vi kiểm tra phải phủ đúng tệp được dùng khi triển khai | Đội vận hành thêm một tệp compose riêng cho môi trường thật, nằm ngoài phạm vi kiểm tra của cổng | `policy/compose_security.rego`, `policy/docker_security.rego` | `evidence/ci-01-dockerfile.txt`, `evidence/ci-02-compose.txt` |
| CS-03 | Dữ liệu nhận từ người dùng không được ghép vào câu lệnh truy vấn dưới mọi hình thức | Khách hàng tra cứu vận đơn bằng mã đơn nhập tự do trên trang công khai | Quy tắc `policy-p4-sql-injection` trong `ci/semgrep-policy-php.yml` | `evidence/ci-05-semgrep.json` |
| CS-04 | Bí mật chỉ đến từ nguồn quản lý bí mật, không có giá trị dự phòng dạng hằng, và ứng dụng phải dừng khi thiếu bí mật | Triển khai lên máy mới, quên nạp biến môi trường, dịch vụ vẫn khởi động bằng mật khẩu mặc định | Quy tắc `php-hardcoded-db-password-fallback`, Trivy secret scan, InSpec | `evidence/ci-09-trivy-secret.txt`, `evidence/ci-13-inspec.txt` |
| CS-05 | Dữ liệu cá nhân chỉ rời khỏi hệ thống theo đường đã khai báo; nhật ký, thông điệp lỗi và bản xuất dữ liệu không phải đường trong số đó | Bật nhật ký tập trung để quan sát sự cố, câu lệnh lỗi kèm mật khẩu đi vào kho nhật ký | Phép kiểm TDS-2, TDS-6, chặng che giấu dữ liệu trong Promtail | `evidence/ci-12-tds.txt` |
| CS-06 | Tài khoản dịch vụ và tiến trình chạy ở mức quyền tối thiểu; container không chạy bằng `root` và ảnh phải ghim phiên bản | Ứng dụng kết nối cơ sở dữ liệu bằng tài khoản quản trị toàn quyền cho tiện | InSpec trên container đang chạy, `policy-p3-privileged-db-account-default` | `evidence/ci-13-inspec.txt` |
| CS-07 | Cổng tự động phải chặn, không được chỉ báo cáo; một cổng báo đạt mà không kiểm tra gì là vi phạm nặng hơn việc thiếu cổng | Một bước CI ghi kết quả vi phạm ra tệp nhưng vẫn báo thành công do mã thoát bị mất | Đối chiếu mã thoát với nội dung tệp kết quả, bước tổng kết cổng | `evidence/ci-00-conftest-verify.txt`, Step Summary của mỗi run |
| CS-08 | Mọi ngoại lệ đối với chính sách phải có hồ sơ: lý do, người phê duyệt dích danh và thời hạn. Hết hạn là hết hiệu lực | Một nhánh được miễn kiểm soát tạm thời rồi không ai nhớ để thu hồi | `policy/exceptions.json` và kiểm tra thời hạn trong `ci/policy_guard.py` | Nhật ký của stage 1 trong mỗi run |

## 3. Trách nhiệm

| Vai trò | Trách nhiệm theo chính sách này |
| :--- | :--- |
| Giám đốc công nghệ | Phê duyệt chính sách, phê duyệt ngoại lệ theo CS-08 |
| Trưởng nhóm phát triển | Bảo đảm cổng kiểm soát hoạt động đúng, rà soát hiệu lực cổng hằng tháng theo CS-07 |
| Lập trình viên | Tuân thủ CS-01, CS-03, CS-04 trong từng pull request |
| Kỹ sư vận hành | Tuân thủ CS-02, CS-06; giữ phạm vi kiểm tra của cổng khớp với cấu hình thật |
| Phụ trách giám sát | Tuân thủ CS-05, CS-08; bảo đảm đủ sự kiện kiểm toán để thông báo vi phạm trong 72 giờ |

## 4. Chế tài và xử lý vi phạm

Pull request vi phạm bất kỳ điều khoản nào bị cổng tự động chặn và không hợp
nhất được. Trường hợp phát hiện vi phạm sau khi đã phát hành, quy trình ứng phó
sự cố được kích hoạt: xác định thay đổi gây ra và người phê duyệt trong 72 giờ
theo CS-01 và CS-08, quay lui bản phát hành theo quy trình CD, và bổ sung một
quy tắc mới vào bộ quy tắc để lần sau cổng chặn được đúng mẫu đó.

## 5. Liên hệ với vòng đời DevSecOps

| Phase | Điều khoản được thi hành |
| :--- | :--- |
| Plan, Code | CS-01, CS-03, CS-04 |
| Build, Test | CS-02, CS-03, CS-04, CS-07 |
| Release, Deploy | CS-02, CS-06, CS-07 |
| Operate, Monitor | CS-05, CS-06, CS-08 |
