# Bản mẫu một mục Chương 4 theo khuôn tám trường

> Bản mẫu chuẩn hóa cấu trúc mục 4.2, dùng để áp dụng đồng bộ cho bốn thành viên còn lại. Mọi số liệu
> và kết quả lệnh lấy từ tệp bằng chứng hoặc từ run thực tế, ghi nguồn tại chỗ.

---

## 4.2 Thành viên 1, Nguyễn Giang Nam, B26CHAT030: kiểm soát thay đổi được khai báo nhưng không có hiệu lực thi hành

### 4.2.1 Tình huống nghiệp vụ và điều khoản chính sách bị ràng buộc

Đợt phát hành hạ tầng giám sát diễn ra ngoài giờ làm việc. Một thành viên đưa
nhanh cấu hình Loki và Grafana lên nhánh phát hành bằng thao tác đẩy trực tiếp
thay vì mở pull request. Thay đổi này tác động tới luồng xử lý nhật ký, đồng
nghĩa với tác động tới luồng dữ liệu cá nhân.

Chính sách nội bộ ràng buộc tình huống này tại hai điều khoản. CS-01 về quản trị
thay đổi yêu cầu mọi thay đổi vào nhánh phát hành phải có pull request, có một
người phê duyệt khác tác giả, qua toàn bộ cổng kiểm soát tự động, và truy vết
được tác giả cùng lý do. CS-07 về ứng phó sự cố yêu cầu trong 72 giờ kể từ khi có nghi vấn rò rỉ phải xác định được thay đổi nào gây ra và ai đã phê duyệt. Hai điều
khoản này là nghĩa vụ chứng minh tuân thủ theo GDPR Điều 24 và 32(1), tương ứng
Điều 26 và 27 Nghị định 13/2023/NĐ-CP. Thiếu pull request đồng nghĩa với thiếu hồ sơ phê duyệt, và nghĩa vụ ở CS-07 không thể bù lại bằng biện pháp kỹ thuật nào sau
đó.

### 4.2.2 Vấn đề và nguyên nhân không tự bộc lộ

Kho mã nguồn khai báo ba lớp kiểm soát cho CS-01. Kiểm chứng thực tế cho thấy cả
ba lớp đều không ngăn chặn được tình huống trên.

Lớp thứ nhất là `ci/policy_guard.py`. Tệp này kiểm tra định dạng thông điệp commit
(`COMMIT_REGEX`, dòng 23-26) và tiêu đề pull request (dòng 29-38). Hàm
`validate_push_event()` (dòng 64) chỉ đối chiếu định dạng, không có đoạn mã nào
từ chối một lần đẩy mã vì lý do đẩy trực tiếp vào nhánh phát hành.

Lớp thứ hai là bảo vệ nhánh phía GitHub. Truy vấn trực tiếp qua API ngày
04/11/2026, nhánh `main` trả về `protected: false`, nên thao tác đẩy trực tiếp và
đẩy cưỡng bức đều được chấp nhận, không phụ thuộc vào số lượng script kiểm tra trong kho mã nguồn.

Lớp thứ ba là cổng kiểm soát quản trị trên CI, nơi phát sinh khiếm khuyết nghiêm trọng nhất. Bước `Chinh sach lop quan tri, bao ve nhanh` chạy đúng bộ quy tắc, ghi ra
đúng kết luận vi phạm, rồi vẫn trả về trạng thái thành công. Nguyên nhân nằm ở
một dòng:

```yaml
# .github/workflows/devsecops-gate.yml:104-105
./conftest test "branch-${b}.json" -p policy/ --namespace repo --no-color \
  | tee -a evidence/ci-03-branch-protection.txt
```

Bước `run` không khai báo `shell`, nên GitHub Actions dùng `bash -e {0}`, cấu hình mặc định này không bật `-o pipefail`. Mã thoát của cả chuỗi lệnh pipe là mã thoát của `tee`,
luôn bằng 0. Conftest trả về 1 nhưng bước vẫn ghi nhận trạng thái thành công.

Khiếm khuyết này không tự bộc lộ vì ba nguyên nhân đồng thời: đây là tình trạng
thiếu một kiểm soát chứ không phải một đoạn mã sai, nên phân tích tĩnh không có
mẫu nào để đối chiếu; đối tượng cần kiểm tra là trạng thái của hệ thống lưu trữ
kho mã nguồn, không nằm trong bản sao làm việc; và biểu hiện của nó là trạng thái
thành công, dạng tín hiệu không ai đặt nghi vấn.

### 4.2.3 Môi trường phải dựng để phát hiện

Phép kiểm chứng phải truy vấn đúng hệ thống đang nắm kiểm soát rồi giao cho một
policy engine đánh giá dữ liệu trả về, theo đúng cách tài liệu lab Conftest yêu
cầu đối với kiểm soát danh tính: truy vấn hệ thống danh tính, không căn cứ trên
một khai báo tĩnh trong Dockerfile. Riêng lớp thứ ba còn cần một phép kiểm chứng
thứ hai: đối chiếu trạng thái của bước trên CI với nội dung tệp kết quả do chính
bước đó sinh ra.

*Bảng: Thành phần môi trường cần dựng cho phép kiểm chứng lớp quản trị*

| Thành phần | Bản dùng | Vai trò |
| :--- | :--- | :--- |
| GitHub REST API, endpoint `branches/{branch}` | token đọc cấu hình kho mã nguồn | Căn cứ duy nhất về trạng thái bảo vệ nhánh |
| Conftest, namespace `repo` | 0.71.1, bản ghim, đối chiếu mã băm | Công cụ thực thi chính sách khai báo |
| `policy/repo_policy.rego` và `repo_policy_test.rego` | 3 quy tắc, 4 ca test | Chính sách và bộ test của chính chính sách |
| `fixtures/branch-protection-compliant.json` | trong kho mã nguồn | Mẫu cấu hình đạt chuẩn, dùng cho kịch bản đối chứng đạt |
| API Actions, endpoint `runs/{id}/jobs` và artifact của run | run thực tế | Đối chiếu trạng thái bước với nội dung tệp kết quả |

Trình tự bắt buộc gồm ba bước: tải Conftest bản ghim và đối chiếu mã băm; chạy
`conftest verify -p policy/` để bộ test của quy tắc đạt trước; chỉ sau đó mới
dùng quy tắc để đánh giá dữ liệu thực tế. Bước thứ hai mang tính bắt buộc, vì một quy
tắc sai cú pháp vẫn chạy và vẫn trả về kết quả không có vi phạm.

### 4.2.4 Mã dùng để phát hiện

Chính sách quản trị viết thành ba quy tắc khai báo: nhánh không có bảo vệ, nhánh
có bảo vệ nhưng không bắt buộc status check, và nhánh thiếu đúng cổng kiểm soát
cần có trong danh sách status check bắt buộc.

```rego
# policy/repo_policy.rego:22-33
required_check_patterns := {"Policy Guard", "SonarQube", "Semgrep"}

deny contains msg if {
	not input.protected == true
	msg := sprintf("GOVERNANCE: branch '%s' has no protection rule; direct pushes and force pushes are possible regardless of what the in-repo policy script checks.", [input.name])
}

deny contains msg if {
	input.protected == true
	input.protection.required_status_checks.enforcement_level == "off"
	msg := sprintf("GOVERNANCE: branch '%s' is protected but required status checks are off, so a failing pipeline does not block a merge.", [input.name])
}
```

Phép kiểm chứng tính toàn vẹn của cổng kiểm soát không biểu diễn được bằng rego, do
đối tượng của nó là chính pipeline. Phép kiểm chứng đó gồm một lệnh đọc trạng
thái bước và một lệnh đọc tệp kết quả của bước đó trong artifact cùng run.

### 4.2.5 Chứng minh hai chiều

Kịch bản vi phạm và kịch bản đạt chuẩn của bộ quy tắc, tại
`evidence/11-repo-branch-main-thucte.txt` và
`evidence/13-repo-branch-compliant.txt`:

```
$ conftest test <trang thai that cua nhanh main> -p policy/ --namespace repo
FAIL - GOVERNANCE: branch 'main' has no protection rule; direct pushes and
       force pushes are possible regardless of what the in-repo policy script checks.
3 tests, 2 passed, 0 warnings, 1 failure, 0 exceptions        exit=1

$ conftest test fixtures/branch-protection-compliant.json -p policy/ --namespace repo
3 tests, 3 passed, 0 warnings, 0 failures, 0 exceptions       exit=0
```

Cùng một bộ quy tắc cho hai mã thoát khác nhau trên hai đầu vào khác nhau, nên
kết quả không đạt ở kịch bản vi phạm là một phát hiện chứ không phải một lỗi của
công cụ.

Để chứng minh khiếm khuyết của chính cổng kiểm soát, báo cáo đối chiếu song song hai nguồn minh chứng trong cùng một run. Bảng dưới lấy từ run `40748974196` (nhánh `main`, mốc
`94004f3`) và artifact `evidence-policy-as-code` của chính run đó.

*Bảng: Trạng thái bước trên CI đối chiếu với nội dung tệp kết quả của chính bước đó*

| Bước trong stage 1 | Tệp kết quả do bước sinh ra | Nội dung tệp | Trạng thái bước |
| :--- | :--- | :--- | :---: |
| Chính sách lớp build, Dockerfile | `ci-01-dockerfile.txt` | 4 dòng FAIL cho mỗi Dockerfile, dòng tổng kết `4 failures` | success |
| Chính sách lớp triển khai, Compose | `ci-02-compose.txt` | 10 dòng FAIL trở lên cho mỗi tệp compose | success |
| Chính sách lớp quản trị, bảo vệ nhánh | `ci-03-branch-protection.txt` | 2 dòng FAIL, mỗi lần chạy ghi `1 failure` | success |

Toàn bộ job `[CHANG 1] Policy as Code` trả về trạng thái thành công trong cả hai
run `40748974196` và `40748974200`. Ba cổng kiểm soát trên không thực hiện chức
năng ngăn chặn trong suốt thời gian pipeline được coi là có ngăn chặn.

Đối chứng nằm ngay trong cùng tệp workflow: bước cổng CVE giữ mã thoát bằng
`${PIPESTATUS[0]}` (dòng 260-263) và bước kiểm tra cú pháp PHP đối chiếu lại bằng
`grep` (dòng 140), nên hai bước đó thực thi ngăn chặn đúng chức năng và cùng trả
về trạng thái thất bại trong cả hai run. Khiếm khuyết vì vậy không xuất phát từ việc hiểu sai công cụ mà từ việc áp dụng không nhất quán một nguyên tắc đã biết.

### 4.2.6 Ràng buộc trong quá trình khắc phục

Việc khắc phục khiếm khuyết này vượt quá phạm vi một commit, do bốn ràng buộc tác động đồng thời.

Ràng buộc về quyền. Bật bảo vệ nhánh là thao tác trong phần thiết lập kho mã
nguồn và chỉ chủ kho mã nguồn có thẩm quyền thực hiện. Policy as Code ở đây chỉ kiểm chứng
chứ không thi hành được kiểm soát, nên bản vá có một phần kỹ thuật và một phần
hành chính, phần hành chính phải có người chịu trách nhiệm theo tên.

Ràng buộc về độ tin cậy của điểm thi hành. Hook `.githooks/commit-msg` chạy trên
máy lập trình viên, và khi máy không có Python, hook ghi cảnh báo rồi trả về 0
(dòng 18-20), tức bỏ qua kiểm tra mà vẫn báo thành công. Lập trình viên cũng có
thể vô hiệu hóa hook bằng `git commit --no-verify`. Lớp cục bộ vì vậy chỉ giữ vai trò phản hồi sớm.

Ràng buộc về tính đúng của phép kiểm chứng. Vòng lặp của bước quản trị đọc hai
nhánh `main` và `dev`, trong khi kho mã nguồn hiện chỉ có `main` và `patched`.
Bản ghi cho `dev` vì vậy là một phản hồi không có nhánh, và tệp kết quả ghi
`branch 'null'`. Quy tắc vẫn kết luận vi phạm trên một đối tượng không tồn tại,
nên trước khi dựa vào kết quả phải bổ sung một phép kiểm tra cấu trúc dữ liệu đầu
vào.

Ràng buộc giữa chính sách và chính bài thực hành. Nhánh `main` giữ hệ thống ở
trạng thái có khiếm khuyết để làm đối tượng đánh giá, trong khi điều khoản CS-01 yêu cầu mọi
thay đổi vào nhánh phát hành phải qua pull request và qua toàn bộ cổng kiểm soát.
Giải pháp là một ngoại lệ có hồ sơ và có thời hạn theo CS-08, ghi rõ nhánh nào
được miễn, miễn đến khi nào, ai duyệt, thay vì nới lỏng chính sách một cách tùy
tiện.

### 4.2.7 Cách xử lý và vị trí trên workflow

Bản vá gồm ba thay đổi theo thứ tự hiệu lực giảm dần. Khai báo `shell: bash` cho
các bước có chuỗi lệnh pipe, hoặc giữ mã thoát bằng `${PIPESTATUS[0]}` như hai
bước đã làm đúng, để ba cổng kiểm soát ở stage 1 thực thi ngăn chặn. Sửa vòng lặp
đọc đúng các nhánh đang tồn tại và bổ sung phép kiểm tra cấu trúc dữ liệu. Bật
bảo vệ nhánh trên GitHub với ba status check bắt buộc đúng như fixture của kịch
bản đạt chuẩn mô tả.

*Bảng: Bốn lớp thi hành của cùng một điều khoản chính sách*

| Lớp | Nơi thi hành | Phase | Cổng kiểm soát | Cơ chế |
| :--- | :--- | :--- | :--- | :--- |
| Phản hồi sớm | máy lập trình viên | Code | hook `commit-msg` | `policy_guard.py`, suy giảm tính năng có kiểm soát |
| Quy ước thay đổi | CI | Code | `stage1_policy_guard` | cùng tệp trên, chạy trên payload sự kiện |
| Quản trị kho mã nguồn | CI | Plan, Code | `stage1_policy_as_code` | `repo_policy.rego` đánh giá JSON lấy từ API |
| Chặn hợp nhất | GitHub | Plan | bảo vệ nhánh | thiết lập ngoài kho mã nguồn, kiểm chứng được nhưng không thi hành được từ mã |

Một điều khoản chính sách cần nhiều điểm thi hành, và điểm thi hành càng gần
người viết mã càng cho phản hồi nhanh, đồng thời càng ít tin cậy. Lớp duy nhất thực sự ngăn
được một lần hợp nhất không đạt lại nằm ngoài kho mã nguồn, do đó lớp này phải được kiểm chứng liên tục bằng lớp thứ ba, và lớp thứ ba phải tự chứng minh được khả
năng ngăn chặn của chính nó.

### 4.2.8 Giới hạn kiểm chứng của cổng kiểm soát

Chính sách quản trị chỉ đọc được trạng thái cấu hình. Chính sách không xác minh
được một thành viên có thực sự dùng xác thực hai yếu tố, cũng không xác minh được
người phê duyệt pull request có đọc mã hay chỉ phê duyệt hình thức. Phần đó thuộc
phạm vi quản trị nhân sự.

Kết quả kiểm chứng còn phụ thuộc phạm vi token. Trường `protection` chỉ được trả
về đầy đủ cho token có quyền quản trị kho mã nguồn; với token mặc định của
workflow ở mức `contents: read`, chỉ quy tắc thứ nhất còn hiệu lực. Phạm vi
token vì vậy là một phần của phép kiểm chứng, không phải chi tiết kỹ thuật phụ.
