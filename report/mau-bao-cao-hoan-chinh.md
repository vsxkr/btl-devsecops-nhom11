# Mẫu báo cáo hoàn chỉnh, dùng để kiểm tra nhiệm vụ từng thành viên

Tệp này không phải bản nộp. Đây là bộ khung đầy đủ của báo cáo cuối cùng: thứ tự
mục, hạn mức trang, và với mỗi thành viên là vấn đề phụ trách, môi trường phải
dựng, công cụ, mã phải viết, minh chứng phải tạo ra. Dùng để thống nhất phân công
trước khi viết.

Ký hiệu trạng thái dùng trong toàn tệp:

- `[CO]` đã có trong kho mã và đã có minh chứng kiểm chứng được.
- `[KIEM CHUNG LAI]` đã có nội dung nhưng số liệu thuộc kho mã nguồn cũ hoặc đã lệch, phải thu thập lại trên `vsxkr/btl-devsecops-nhom11`.
- `[VIET]` chưa có, phải viết mới.

---

## PHẦN A. KHUNG BÁO CÁO VÀ HẠN MỨC TRANG

| Mục | Nội dung chính | Trang | Trạng thái | Người phụ trách |
| :--- | :--- | :---: | :---: | :--- |
| Trang bìa, phân công, từ viết tắt | Bảng phân công có đủ 5 mã học viên | 3,0 | `[KIEM CHUNG LAI]` | Nam |
| MỞ ĐẦU | Mục tiêu, phạm vi, phương pháp đánh giá và thu thập minh chứng | 1,0 | `[CO]` | Nam |
| Chương 1. Ứng dụng InlaneWeb và dữ liệu cá nhân | Mô hình dữ liệu, hai nghiệp vụ, phân loại mức nhạy cảm | 3,0 | `[CO]` | Hải |
| Chương 2. Bối cảnh chính sách và môi trường triển khai | **2.1 Chính sách ATTT của doanh nghiệp, mới, một trang**; 2.2 kiến trúc; 2.3 bảng kiểm an toàn tối thiểu | 3,5 | `[VIET]` mục 2.1 | Nam |
| Chương 3. Pipeline DevSecOps và các cổng kiểm soát bắt buộc | **Năm stage, có stage CD mới**, PaC, SaC, cổng chất lượng | 4,0 | `[KIEM CHUNG LAI]` | Mạnh |
| Chương 4. Năm vấn đề an toàn | Năm mục theo khuôn tám trường, mỗi mục 2,4 trang | 12,0 | xem Phần C | mỗi người một mục |
| Chương 5. Giám sát, ứng phó và vòng đời quy tắc | Nhật ký, độ trễ phát hiện, **tự động vá và bổ sung quy tắc khi vận hành, mới** | 2,5 | `[VIET]` phần vòng đời quy tắc | Mai |
| KẾT LUẬN, TÀI LIỆU THAM KHẢO | Bỏ câu khẳng định triển khai tự động lên máy chủ thực tế | 1,0 | `[KIEM CHUNG LAI]` | Nam |
| **Tổng** | | **30,0** | | |

Phụ lục hướng dẫn thu thập minh chứng hình ảnh chuyển sang `docs/`, không nộp. Số trang trống do
ngắt trang hiện chiếm 5,04 trang, phải điều chỉnh để đủ hạn mức.

---

## PHẦN B. BẢNG NHIỆM VỤ TỪNG THÀNH VIÊN

Mỗi thành viên phụ trách đúng một vấn đề. Vấn đề đó ràng buộc nhiều lớp kiểm soát, nên việc khắc phục đòi hỏi xử lý đồng thời nhiều điều kiện.

| Thành viên | Mã học viên | Mục | Vấn đề phụ trách, dạng phức hợp | Điều khoản | Phase | Công cụ chính | Dạng chứng minh |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| Nguyễn Giang Nam | B26CHAT030 | 4.2 | Kiểm soát thay đổi được khai báo nhưng không có hiệu lực thi hành, và chính cổng kiểm soát việc đó cũng không ngăn chặn | CS-01, CS-07 | Plan, Code | GitHub REST API, conftest, rego, so sánh mã thoát | Policy as Code |
| Nguyễn Đình Hải | B26CHAT010 | 4.3 | Tiêm mã SQL đi qua hàm bao `query()`, nên bộ quy tắc có sẵn và SonarQube đều không phát hiện | CS-03, CS-05 | Code, Build | Semgrep taint mode, quy tắc tự viết, SonarQube làm đối chứng | Security as Code |
| Đào Xuân Mạnh | B26CHAT026 | 4.4 | Bí mật không nằm trong kho mã nhưng vẫn nhận giá trị mặc định dạng hằng khi thiếu biến môi trường, nên công cụ quét bí mật không phát hiện được | CS-04, CS-06 | Code, Build | Semgrep quy tắc `?:`, Trivy secret làm đối chứng âm, InSpec trên container trong môi trường thực thi | SaC và CaC |
| Lê Đức Anh | B26CHAT003 | 4.5 | Cổng chính sách kiểm tra tệp compose không phải tệp dùng khi triển khai, nên cấu hình triển khai thực tế chưa từng được kiểm tra | CS-02, CS-06 | Release, Deploy | conftest, rego, InSpec docker resource, đối chiếu khai báo với hiệu lực | PaC và CaC |
| Nguyễn Phương Mai | B26CHAT025 | 4.6 | Năm mắt xích hợp lý riêng lẻ hợp thành một kênh rò rỉ dữ liệu cá nhân, và biện pháp che giấu dữ liệu lại làm mất khả năng phát hiện tấn công | CS-05, CS-08 | Operate, Monitor | Promtail pipeline stage, Loki query, phép kiểm TDS-6 | Test-Driven Security |

### Danh mục mã nguồn và tệp minh chứng bắt buộc nộp vào kho mã nguồn

| Thành viên | Mã phải viết | Tệp minh chứng phải sinh ra | Fixture đạt chuẩn và vi phạm |
| :--- | :--- | :--- | :--- |
| Nam | `policy/repo_policy.rego`; sửa `shell: bash` cho các bước bị che mã thoát | `evidence/ci-03-branch-protection.txt`, `evidence/api/branch-main-slim.json` thu thập lại trên kho mã nguồn mới | `fixtures/branch-protection-compliant.json` so với phản hồi API thực tế |
| Hải | quy tắc `policy-p4-sql-injection` trong `ci/semgrep-policy-php.yml`, khai báo `query()` là sink | `evidence/semgrep-*.json`; kết quả SonarQube 0 lỗ hổng làm đối chứng | `fixtures/php/*vuln.php` so với `*patched.php` |
| Mạnh | quy tắc `policy-p3-hardcoded-credential-fallback`, `policy-p3-privileged-db-account-default` | `evidence/trivy-secret-*.txt` không phát hiện; `evidence/inspec-*.json` giá trị hiệu lực | hai lần khởi tạo môi trường, một lần có biến môi trường và một lần không |
| Đức Anh | `policy/compose_security.rego`; sửa `paths.include` để phủ `docker-compose.prod.yml` và `docker-compose.monitoring.yml` | `evidence/ci-02-compose.txt`, `evidence/inspec-container-*.json` | `fixtures/docker-compose.insecure.yml` so với `hardened.yml` |
| Mai | chặng che giấu dữ liệu trong Promtail, quy tắc tương quan Loki, phép kiểm TDS-6 | `evidence/tds-*.txt`; truy vấn Loki trước và sau khi che | một truy vấn lỗi thực tế ở đợt 2 làm đối tượng kiểm chứng |

---

## PHẦN C. CHƯƠNG 4, KHUÔN TÁM TRƯỜNG CHO TỪNG THÀNH VIÊN

Mọi mục dùng chung tám trường sau. Bản đầy đủ của mục 4.2 đã viết, xem
`report/mau-4.2-nam.md`.

1. Tình huống nghiệp vụ và điều khoản chính sách bị ràng buộc
2. Vấn đề và nguyên nhân không tự bộc lộ
3. Môi trường phải dựng để phát hiện
4. Mã dùng để phát hiện
5. Chứng minh hai chiều
6. Ràng buộc trong quá trình khắc phục
7. Cách xử lý và vị trí trên workflow
8. Giới hạn kiểm chứng của cổng kiểm soát

---

### 4.2 Nguyễn Giang Nam, B26CHAT030

**Vấn đề.** Kho mã nguồn khai báo ba lớp kiểm soát thay đổi: regex thông điệp commit
trong `ci/policy_guard.py`, git hook `commit-msg`, và bảo vệ nhánh trên GitHub.
Kiểm chứng thực tế cho thấy cả ba đều không có hiệu lực, và cổng dùng để phát hiện điều đó cũng
không chặn.

| Trường | Nội dung | Trạng thái |
| :--- | :--- | :---: |
| 1. Nghiệp vụ, chính sách | Thay đổi mã của hệ thống xử lý dữ liệu cá nhân phải truy được nguồn gốc và người phê duyệt. CS-01 yêu cầu mọi thay đổi đi qua pull request có rà soát, CS-07 yêu cầu cổng tự động phải chặn chứ không chỉ báo cáo | `[CO]` |
| 2. Vấn đề | `validate_push_event()` chỉ kiểm định dạng thông điệp, không chặn đẩy trực tiếp; hook trả về `exit 0` khi không tìm thấy python; `main` của kho mới vẫn `protected: false`. Nghiêm trọng hơn: ba cổng stage 1 in ra kết luận vi phạm trong tệp kết quả của chính nó nhưng bước vẫn ghi nhận trạng thái thành công, vì `conftest ... \| tee` làm mất mã thoát dưới shell mặc định `bash -e {0}` không bật `-o pipefail` | `[CO]` |
| 3. Môi trường | Kho mã thật trên GitHub, token đọc `administration`, conftest 0.71.1 ghim theo mã băm, hai nhánh để đối chiếu | `[CO]` |
| 4. Mã phát hiện | `policy/repo_policy.rego` ba quy tắc `deny`, đọc phản hồi `repos/{owner}/{repo}/branches/{branch}` thay vì căn cứ trên khai báo tĩnh trong kho mã nguồn | `[CO]` |
| 5. Chứng minh hai chiều | Quy tắc báo vi phạm trên phản hồi API thực tế, không báo vi phạm trên `fixtures/branch-protection-compliant.json`. Bảng đối chiếu trạng thái bước so với nội dung tệp kết quả, lấy từ run `40748974196` và `40748974200` | `[CO]` |
| 6. Ràng buộc | Bật bảo vệ nhánh làm chính pipeline không đẩy được kết quả; sửa `shell` cho một bước làm lộ ra vi phạm của các cổng khác và khiến cả job chuyển sang trạng thái thất bại; tên check bắt buộc phải khớp chuỗi tên job | `[CO]` |
| 7. Xử lý, vị trí workflow | Bốn lớp: hook cục bộ, `policy_guard.py` khi push, rego khi chạy pipeline, bảo vệ nhánh phía dịch vụ. Sửa bằng `shell: bash` hoặc `${PIPESTATUS[0]}` | `[CO]` |
| 8. Không chứng minh được | Rego kiểm tra trạng thái cấu hình chứ không đánh giá chất lượng rà soát; hook bỏ qua được bằng `--no-verify`; không chứng minh được người phê duyệt đã đọc mã | `[CO]` |

---

### 4.3 Nguyễn Đình Hải, B26CHAT010

**Vấn đề phức hợp.** Vấn đề không dừng ở một lỗ hổng tiêm mã SQL thông thường. Điểm thực thi thực tế không
phải `mysqli_query` mà hàm bao `query()` của dự án trong `lib/db.php`, nên bộ
bộ quy tắc có sẵn `p/php` và SonarQube Community đều không liên kết được source với sink.
Hệ quả là lỗ hổng tồn tại trong khi báo cáo công cụ ghi 0 lỗ hổng.

| Trường | Nội dung phải viết | Trạng thái |
| :--- | :--- | :---: |
| 1. Nghiệp vụ, chính sách | Tra cứu vận đơn và tra cứu cảng là hai điểm nhận dữ liệu từ người dùng không xác thực. CS-03 cấm ghép chuỗi vào câu lệnh truy vấn, CS-05 yêu cầu dữ liệu cá nhân chỉ ra khỏi hệ thống theo đường đã khai báo | `[VIET]` |
| 2. Vấn đề | Chuỗi nhiễm đi từ `$_GET` qua biến trung gian, vào `query()` ở tệp khác. `pages/track_api.php` không in kết quả ra trang nên khai thác theo thời gian vẫn thành công mà không để lại dấu vết hiển thị trên giao diện; `pages/shipment_detail.php` thiếu kiểm quyền sở hữu nên đọc được đơn của chủ thể dữ liệu khác | `[KIEM CHUNG LAI]` |
| 3. Môi trường | Semgrep 1.182.1 bật taint mode; SonarQube Community dựng bằng docker làm đối chứng; cặp fixture php; cơ sở dữ liệu có dữ liệu mẫu của hai người dùng khác nhau | `[KIEM CHUNG LAI]` |
| 4. Mã phát hiện | Quy tắc `policy-p4-sql-injection` khai báo `pattern-sources` là `$_GET`, `$_POST`, `$_COOKIE` và `pattern-sinks` là `query(...)`, kèm `pattern-sanitizers` cho truy vấn tham số hóa. Đây là phần mã phải tự viết, vì không bộ quy tắc công khai nào biết tên hàm bao của dự án | `[VIET]` |
| 5. Chứng minh hai chiều | Quy tắc tự viết báo vi phạm tại 11 vị trí đợt 2, không báo vi phạm trên tệp đã vá. Đối chứng âm: trên cùng mã nguồn, `p/php` và SonarQube báo 0, kèm ảnh bảng điều khiển và mã thoát | `[KIEM CHUNG LAI]` |
| 6. Ràng buộc | Vá hết 11 điểm cùng lúc làm phép kiểm TDS-6 mất đối tượng kiểm chứng, nên phải vá theo hai đợt có chủ đích. Ngoài ra, `shipment_detail.php` cần bổ sung kiểm tra quyền sở hữu, đây là thay đổi logic nghiệp vụ chứ không phải tham số hóa truy vấn | `[CO]` |
| 7. Xử lý, vị trí workflow | Quy tắc chạy ở stage 2, chặn pull request. Vá bằng `mysqli_prepare` và thêm điều kiện chủ sở hữu, kèm phép kiểm TDS-3 chứng minh người này không đọc được dữ liệu người khác | `[VIET]` |
| 8. Không chứng minh được | Taint mode không theo được luồng đi qua biến siêu toàn cục ghi ở tệp khác, cũng không theo được chuỗi dựng bằng nối mảng. Không chứng minh được dữ liệu chưa từng bị rút ra trước khi vá | `[VIET]` |

---

### 4.4 Đào Xuân Mạnh, B26CHAT026

**Vấn đề phức hợp.** Bí mật không nằm trong kho mã, `.env` đã nằm trong
`.gitignore`, nên trình quét bí mật không có gì để tìm. Khiếm khuyết nằm ở chỗ
khác: khi biến môi trường thiếu, mã nhận một giá trị mặc định dạng hằng, và container vẫn
khởi động bình thường bằng mật khẩu mặc định đã công khai. Khiếm khuyết chỉ bộc lộ trong môi trường
thực thi, không bộc lộ khi đọc tệp.

| Trường | Nội dung phải viết | Trạng thái |
| :--- | :--- | :---: |
| 1. Nghiệp vụ, chính sách | Ứng dụng kết nối cơ sở dữ liệu chứa dữ liệu cá nhân. CS-04 yêu cầu bí mật chỉ đến từ nơi quản lý bí mật và không có giá trị dự phòng, CS-06 yêu cầu tài khoản dịch vụ ở mức quyền tối thiểu | `[VIET]` |
| 2. Vấn đề | Ba lớp cộng hưởng: `lib/db.php` dùng toán tử `?:` nhận chuỗi hằng làm giá trị dự phòng; tài khoản mặc định là `root` toàn quyền kèm `GRANT FILE`; `init.sql.template` lưu mật khẩu người dùng dạng rõ. Riêng lớp thứ nhất chỉ là cấu hình sai; kết hợp với tiêm mã SQL của mục 4.3, lỗ hổng cho phép đọc ghi tệp trên máy chủ cơ sở dữ liệu | `[KIEM CHUNG LAI]` |
| 3. Môi trường | Hai lần khởi tạo cùng một compose, một lần có biến môi trường và một lần không, nhằm quan sát hành vi nhận giá trị dự phòng. Trivy secret scan làm đối chứng âm. InSpec chạy trên container đang hoạt động để đọc giá trị đang có hiệu lực | `[VIET]` |
| 4. Mã phát hiện | Quy tắc `policy-p3-hardcoded-credential-fallback` nhận diện dạng `getenv(...) ?: "..."` và `?? "..."`; quy tắc `policy-p3-privileged-db-account-default` nhận diện giá trị mặc định `root`; phép kiểm InSpec xác nhận tài khoản ứng dụng dùng không phải `root` | `[VIET]` |
| 5. Chứng minh hai chiều | Quy tắc báo vi phạm trên `lib/db.php` hiện tại, không báo vi phạm sau khi đổi sang bắt buộc có biến môi trường và thoát sớm nếu thiếu. Đối chứng: Trivy secret scan trên cùng kho mã trả về không phát hiện, chứng minh vì sao lớp quét bí mật không đủ | `[VIET]` |
| 6. Ràng buộc | Bỏ giá trị dự phòng làm container không khởi động được nếu thiếu biến, phải đổi cả entrypoint và tài liệu dựng. Băm mật khẩu phải di trú dữ liệu và sửa `login.php`, nếu chỉ băm ở một phía, toàn bộ người dùng hiện có không đăng nhập được. Hạ quyền tài khoản làm một số truy vấn hiện có thất bại | `[VIET]` |
| 7. Xử lý, vị trí workflow | Quy tắc chạy stage 2, phép kiểm InSpec chạy stage 4 trên container thực tế. Vá theo thứ tự: thêm tài khoản quyền tối thiểu, đổi chuỗi kết nối, bắt buộc biến môi trường, băm mật khẩu kèm di trú | `[VIET]` |
| 8. Không chứng minh được | Quy tắc chỉ nhận diện được dạng mã đã khai báo, không thấy bí mật truyền qua tệp cấu hình sinh lúc chạy. InSpec xác nhận trạng thái hiện tại chứ không xác nhận bí mật chưa từng bị dùng | `[VIET]` |

---

### 4.5 Lê Đức Anh, B26CHAT003

**Vấn đề phức hợp.** Cổng chính sách, bộ quy tắc rego và kết quả đạt đều tồn tại, nhưng tệp thuộc phạm vi kiểm tra không phải tệp dùng khi triển khai.
`paths.include` của bộ quy tắc cục bộ không phủ `docker-compose.prod.yml` và
`docker-compose.monitoring.yml`. Cấu hình triển khai thực tế chưa từng được kiểm tra, và một
kết quả đạt ở đây gây rủi ro cao hơn trường hợp không có cổng, vì nó tạo ra
sự tin cậy sai lệch.

| Trường | Nội dung phải viết | Trạng thái |
| :--- | :--- | :---: |
| 1. Nghiệp vụ, chính sách | Môi trường vận hành chứa cơ sở dữ liệu cá nhân. CS-02 yêu cầu cấu hình triển khai phải qua cổng chính sách trước khi phát hành, CS-06 yêu cầu quyền tối thiểu và bề mặt tiếp xúc nhỏ nhất | `[VIET]` |
| 2. Vấn đề | Ba nhóm: container chạy `root` do thiếu `USER` trong hai Dockerfile; compose thiếu `cap_drop`, `no-new-privileges`, `read_only`; ảnh dùng thẻ `latest` nên hai lần triển khai chạy hai bản khác nhau. Nguyên nhân che lấp các vi phạm trên là phạm vi kiểm tra sai của cổng | `[KIEM CHUNG LAI]` |
| 3. Môi trường | conftest chạy trên toàn bộ tệp compose có trong kho, kể cả prod và monitoring; container được dựng thực tế để InSpec đọc trạng thái hiệu lực; so sánh khai báo trong tệp với kết quả `docker inspect` | `[VIET]` |
| 4. Mã phát hiện | `policy/compose_security.rego` và `docker_security.rego`; phép kiểm InSpec dùng `docker_container` và `docker_image` để xác nhận `User` không rỗng, `CapDrop` có `ALL`, ảnh ghim theo digest | `[KIEM CHUNG LAI]` |
| 5. Chứng minh hai chiều | Quy tắc báo vi phạm trên `fixtures/docker-compose.insecure.yml`, không báo vi phạm trên `hardened.yml`. Chứng minh phạm vi đo: thực thi cổng trước và sau khi sửa `paths.include`, số vi phạm tăng từ 0 lên giá trị thực tế, kèm mã thoát | `[VIET]` |
| 6. Ràng buộc | Bật `read_only` làm Apache không ghi được thư mục tạm, phải thêm `tmpfs`; ghim digest làm quy trình cập nhật phải đổi; hạ `cap_drop` xuống `ALL` làm một số dịch vụ giám sát mất quyền đọc tiến trình trên máy chủ | `[VIET]` |
| 7. Xử lý, vị trí workflow | Cổng chạy stage 1 trước khi dựng ảnh, phép kiểm InSpec chạy stage 4 sau khi container hoạt động, và lặp lại ở stage CD trước khi cho phát hành | `[VIET]` |
| 8. Không chứng minh được | conftest kiểm tra tệp khai báo, không kiểm soát được các lệnh người vận hành nhập thủ công; InSpec xác nhận một thời điểm, không chặn thay đổi sau đó nếu không có cổng lúc vận hành | `[VIET]` |

---

### 4.6 Nguyễn Phương Mai, B26CHAT025

**Vấn đề phức hợp.** Năm mắt xích, mỗi mắt xích riêng lẻ đều là lựa chọn kỹ
thuật hợp lý, hợp lại thành một đường đưa mật khẩu dạng rõ của người dùng vào
hệ thống nhật ký tập trung. Khó nhất không phải phát hiện mà là xử lý: che giấu dữ
liệu trong nhật ký làm mất chính trường dữ liệu mà quy tắc tương quan cần để
phát hiện tấn công, dẫn tới xung đột giữa hai yêu cầu của chính sách.

| Trường | Nội dung phải viết | Trạng thái |
| :--- | :--- | :---: |
| 1. Nghiệp vụ, chính sách | Đăng nhập và bình luận đơn hàng đều đi qua nhật ký tập trung. CS-05 yêu cầu dữ liệu cá nhân chỉ ra theo đường đã khai báo và nhật ký không phải một đường trong đó, CS-08 yêu cầu lưu đủ sự kiện kiểm toán để thông báo vi phạm trong 72 giờ | `[VIET]` |
| 2. Vấn đề | Mắt xích 1, `login.php` ghép mật khẩu vào câu lệnh. Mắt xích 2, `query()` truyền toàn văn câu lệnh cho bộ ghi nhật ký khi lỗi. Mắt xích 3, Promtail không có chặng che. Mắt xích 4, Loki lưu và cho truy vấn tự do. Mắt xích 5, không có sự kiện kiểm toán khi đăng nhập thất bại, nên hệ thống không ghi nhận được số lần xảy ra | `[KIEM CHUNG LAI]` |
| 3. Môi trường | Ngăn xếp giám sát được dựng đầy đủ: Promtail, Loki, Grafana. Một truy vấn lỗi thực tế từ đợt 2 chưa vá làm đối tượng kiểm chứng. Truy vấn LogQL chạy trước và sau khi bổ sung chặng che giấu dữ liệu | `[KIEM CHUNG LAI]` |
| 4. Mã phát hiện | Phép kiểm TDS-6 dạng hành vi: kích hoạt một truy vấn lỗi, rồi khẳng định luồng nhật ký không chứa nguyên văn câu lệnh và không chứa giá trị mật khẩu. Kèm chặng `replace` trong `promtail-config.hardened.yml` và quy tắc tương quan Loki | `[KIEM CHUNG LAI]` |
| 5. Chứng minh hai chiều | TDS-6 thất bại trên cấu hình hiện tại, kèm trích đoạn dòng nhật ký chứa giá trị nhạy cảm; đạt trên cấu hình đã che, kèm cùng một truy vấn LogQL nhưng không còn kết quả. Ghi mã thoát của cả hai lần | `[KIEM CHUNG LAI]` |
| 6. Ràng buộc | Che giấu quá rộng làm quy tắc tương quan mất dữ liệu nhận diện tấn công, vi phạm CS-08; che giấu quá hẹp vẫn còn rò rỉ. Cảnh báo hiện gửi tới điểm cuối `alertmanager:9093` không tồn tại, nên kết quả phát hiện không đến được người tiếp nhận. Ngoài ra, stage 4 bị SKIPPED trong cả hai run nên kết quả TDS hiện chỉ có từ chạy cục bộ, phải chạy lại trên pipeline | `[CO]` |
| 7. Xử lý, vị trí workflow | Chặng che giấu dữ liệu ở Promtail khi vận hành, phép kiểm TDS-6 ở stage 4 trong pipeline, và quy tắc tương quan là ví dụ của việc bổ sung quy tắc trong quá trình vận hành ở Chương 5 | `[VIET]` |
| 8. Không chứng minh được | Phép kiểm chỉ khẳng định về đường nhật ký đã biết, không khẳng định được về nhật ký của Apache hay MariaDB ghi trực tiếp ra tệp. Không chứng minh được dữ liệu đã lưu trong Loki trước khi che đã bị xoá hết | `[VIET]` |

---

## PHẦN D. HAI PHẦN MỚI PHẢI VIẾT

### D.1 Mục 2.1, Chính sách an toàn thông tin của doanh nghiệp, một trang

Bản báo cáo trước đây trình bày trực tiếp phần công cụ mà chưa nêu căn cứ quản trị giải thích nhu cầu đặt cổng kiểm soát. Viết dưới góc nhìn quản lý, một trang, tám điều khoản,
mỗi điều khoản sau đó được một cổng trong pipeline thi hành. Tệp nguồn:
`policy/00-chinh-sach-attt.md`, trích vào báo cáo dưới dạng bảng.

| Mã | Điều khoản | Chính sách nội bộ | Cổng thi hành | Thành viên |
| :--- | :--- | :---: | :--- | :--- |
| CS-01 | Mọi thay đổi mã nguồn đi qua pull request có rà soát và truy được người phê duyệt | P1 | `repo_policy.rego`, bảo vệ nhánh | Nam |
| CS-02 | Cấu hình triển khai phải qua cổng chính sách trước khi phát hành | P1 | `compose_security.rego`, `docker_security.rego` | Đức Anh |
| CS-03 | Dữ liệu từ người dùng không được ghép vào câu lệnh truy vấn | P4 | `policy-p4-sql-injection` | Hải |
| CS-04 | Bí mật chỉ đến từ nơi quản lý bí mật, không có giá trị dự phòng | P3 | `policy-p3-hardcoded-credential-fallback` | Mạnh |
| CS-05 | Dữ liệu cá nhân chỉ ra khỏi hệ thống theo đường đã khai báo | P5 | TDS-2, TDS-6, chặng che Promtail | Mai, Hải |
| CS-06 | Tài khoản và tiến trình ở mức quyền tối thiểu | P3 | InSpec, `policy-p3-privileged-db-account-default` | Mạnh, Đức Anh |
| CS-07 | Cổng tự động phải chặn, không được chỉ báo cáo | P1 | so sánh mã thoát, cổng chất lượng | Nam |
| CS-08 | Lưu đủ sự kiện kiểm toán để thông báo vi phạm trong 72 giờ | P5 | quy tắc tương quan Loki | Mai |

Mục này đồng thời xác định tình huống phát sinh khiếm khuyết: mỗi điều khoản
đi kèm một tình huống nghiệp vụ cụ thể, và mục tương ứng ở Chương 4 chỉ ra lỗi
nằm ở đâu trên workflow.

### D.2 Stage CD và vòng đời quy tắc khi vận hành

Bảng bốn stage ở mục 3.1 hiện đã lệch với tệp workflow thật và phải viết lại
thành năm stage. Stage CD mở rộng phạm vi kiểm soát sang chu trình phát hành và vận hành.

| Stage | Tên | Nội dung thực thi | Điều kiện chặn | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| 1 | Policy as Code | conftest trên Dockerfile, compose, cấu hình kho mã | có bất kỳ `deny` | `[KIEM CHUNG LAI]` mã thoát bị che |
| 2 | Security as Code | Semgrep với quy tắc tự viết, Trivy secret, SonarQube | có phát hiện mức cao | `[CO]` |
| 3 | Build và SBOM | dựng ảnh, sinh CycloneDX, cổng CVE | CVE nghiêm trọng | `[CO]` |
| 4 | Test-Driven Security và Compliance as Code | TDS trên ứng dụng đang hoạt động, InSpec trên container | phép kiểm thất bại | `[KIEM CHUNG LAI]` bị SKIPPED cả hai run |
| 5 | **CD: phát hành, xác minh, phục hồi** | triển khai lên môi trường đích; chạy lại InSpec sau khi triển khai; tự động quay lui nếu phép kiểm thất bại; mở pull request vá tự động khi có CVE mới; bổ sung quy tắc mới vào bộ quy tắc khi phát hiện vector tấn công mới | phép kiểm sau triển khai thất bại | `[VIET]` |

Ba nhiệm vụ của stage 5 gồm giám sát, tự động vá, và bổ sung quy tắc trong quá trình vận hành. Vòng đời quy tắc viết ở Chương 5: từ một mẫu tấn
công quan sát được trong Loki, sinh ra một quy tắc Semgrep hoặc một quy tắc tương quan
mới, quy tắc đó quay lại stage 2 và trở thành cổng chặn cho lần sau.

---

## PHẦN E. VIỆC PHẢI LÀM TRƯỚC KHI VIẾT

Mọi số liệu trong Chương 3 và Chương 4 phụ thuộc vào kết quả chạy pipeline. Các
việc dưới đây phải xong trước, nếu không, báo cáo sẽ dẫn lại số liệu của kho mã nguồn cũ.

| TT | Việc | Tệp | Người | Chặn mục nào |
| :---: | :--- | :--- | :--- | :--- |
| 1 | Thêm `shell: bash` hoặc `${PIPESTATUS[0]}` cho các bước bị che mã thoát | `.github/workflows/devsecops-gate.yml` dòng 65, 73, 83, 105, 138, 248, 251, 259, 262, 286, 295 | Nam | 3.1, 4.2 |
| 2 | Lặp đúng các nhánh tồn tại, bổ sung kiểm tra cấu trúc phản hồi API | cùng tệp, dòng 95-106 | Nam | 4.2 |
| 3 | Sửa `paths.include` để phủ compose của prod và monitoring | `ci/semgrep-local-rules.yml` | Đức Anh | 4.5 |
| 4 | Bỏ emoji trong đầu ra | `ci/policy_guard.py`, `.githooks/commit-msg` | Nam | toàn bộ |
| 5 | Thu thập lại `evidence/api/*.json` trên kho mã nguồn mới | `evidence/api/` | Nam | 4.2 |
| 6 | Chạy lại pipeline để stage 4 không bị SKIPPED | toàn bộ | Mai | 4.4, 4.5, 4.6, Chương 5 |
| 7 | Viết `policy/00-chinh-sach-attt.md` | mới | Nam | 2.1 và cả Chương 4 |
| 8 | Điền bốn mã học viên còn thiếu | `report/05-bao-cao-devsecops.md` dòng 23-27 | Nam | trang phân công |
| 9 | Bỏ câu khẳng định triển khai tự động lên máy chủ thực tế nếu không làm stage 5 | phần KẾT LUẬN | Nam | kết luận |
