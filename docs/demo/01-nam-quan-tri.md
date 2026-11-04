# Nguyễn Giang Nam, B26CHAT030, trưởng nhóm

**Chính sách:** quản trị thay đổi và P3
**Nhóm lỗi:** vận hành
**Pha DevSecOps:** Plan, Code
**Điều khoản:** GDPR Điều 32, tương ứng Luật 91/2025/QH15 về biện pháp bảo vệ dữ liệu

## Vấn đề

Hai kiểm soát được tuyên bố là có, nhưng đo ra thì không có hiệu lực.

**Một.** `ci/policy_guard.py` chỉ kiểm định dạng thông điệp commit và tiêu đề pull
request. Hàm `validate_push_event()` không có đoạn mã nào từ chối việc đẩy thẳng
lên `main` hay `dev`. Việc cấm đẩy thẳng phụ thuộc bảo vệ nhánh phía GitHub, và đo
thực tế thì **cả `main` và `dev` đều `protected: false`**.

**Hai.** `devsecops-pipeline.yml:55` của bản cũ gán
`ENFORCE_QUALITY_GATE` bằng biểu thức lấy từ `inputs`. Vì `inputs` chỉ tồn tại với
sự kiện `workflow_dispatch`, giá trị luôn là chuỗi `false`. Trong khi đó
`ci/sonarqube.py` đọc biến này với mặc định `"true"` ở cả dòng 393 và 434, tức
script vốn được viết theo hướng chặn. Workflow mới là chỗ tắt nó đi.

## Cách phát hiện, chiều đỏ

```
conftest test evidence/api/branch-main-slim.json -p policy/ --namespace repo
```

Kết quả mong đợi:

```
FAIL - GOVERNANCE: branch 'main' has no protection rule; direct pushes and force
       pushes are possible regardless of what the in-repo policy script checks.
3 tests, 2 passed, 0 warnings, 1 failure
exit=1
```

Chạy lại với `branch-dev-slim.json` để thấy nhánh `dev` cũng vậy.

JSON này lấy từ hệ thống sở hữu kiểm soát, đúng cách lab Conftest dạy ở phụ lục
A.5: MFA là kiểm soát danh tính nên phải hỏi hệ thống danh tính, không kiểm bằng
một nhãn tự khai trong Dockerfile.

```
curl -H "Authorization: Bearer $GH_TOKEN" \
  https://api.github.com/repos/vsxkr/btl-devsecops-nhom11/branches/main
```

## Chiều xanh

```
conftest test fixtures/branch-protection-compliant.json -p policy/ --namespace repo
# 3 tests, 3 passed, 0 failures   exit=0
```

Fixture này là hình dạng cấu hình đạt. Bật thật trên GitHub là một thao tác trong
Settings, và cần chính Nam làm vì chỉ chủ repo có quyền.

## Bằng chứng mạnh nhất, cổng tự nó không chặn

Đây là phát hiện quan trọng nhất của Nam, và nó nói về chính pipeline.

Ba cổng chính sách ở stage 1 ghi ra kết luận vi phạm trong tệp kết quả của chính
nó, rồi vẫn trả về trạng thái thành công. Nguyên nhân là một dòng:

```yaml
./conftest test "branch-${b}.json" -p policy/ --namespace repo --no-color   | tee -a evidence/ci-03-branch-protection.txt
```

Bước `run` không khai báo `shell`, nên GitHub Actions dùng `bash -e {0}`, bản này
không bật `-o pipefail`. Mã thoát của cả chuỗi lệnh pipe là mã thoát của `tee`,
luôn bằng 0.

Cách chứng minh: đặt cạnh nhau trạng thái bước và nội dung tệp kết quả do chính
bước đó sinh ra, lấy từ artifact `evidence-policy-as-code` của cùng run.

| Lượt đo | Trạng thái nhánh `main` | Kết quả Conftest | Trạng thái bước |
| :--- | :--- | :--- | :---: |
| run `40748974196` | `protected: false` | 1 failure | success, sai |
| run `41810794218` | `protected: false` | 1 failure | failure, đúng |
| run `41812598120` | `protected: true` | 0 failure | success, đúng |

Lượt thứ hai là lượt phải nhấn khi demo: cùng trạng thái hệ thống, cùng bộ quy
tắc, nhưng trạng thái bước đổi dấu. Khác biệt duy nhất là một dòng khai báo
`shell: bash`.

Đối chứng nằm ngay trong cùng tệp workflow: cổng CVE giữ mã thoát bằng
`${PIPESTATUS[0]}` và bước kiểm cú pháp PHP đối chiếu lại bằng `grep`, nên hai
bước đó chặn đúng chức năng. Nói rõ với thầy: đây không phải hiểu sai công cụ,
mà là áp dụng không nhất quán một nguyên tắc đã biết.

## Bằng chứng thứ hai, chính sách chặn sai và cách xử lý

Cổng CS-01 từ chối một commit của chính nhóm trong run `41812598120`:

```
[LOI] VI PHAM QUY UOC DAT TEN COMMIT
- Commit [42279bd]: "sec(deploy,sonar): va cau hinh trien khai thuc te..."
```

Lý do: biểu thức chỉ nhận một scope, không nhận danh sách cách nhau bởi dấu
phẩy. Nhưng lịch sử kho mã đã có `feat(report,telemetry): ...` từ trước, tức quy
tắc đang từ chối một dạng nhóm dùng thật.

Cách xử lý: mở rộng biểu thức, rồi thêm `tests/test_policy_guard.py` giữ cả hai
chiều, trong đó có chiều mà bộ test cũ không có là "dạng hợp lệ phải được chấp
nhận". Bộ test này chạy **trước** khi cổng được dùng, cùng nguyên tắc với
`conftest verify`.

Thông điệp khi demo: một cổng từ chối đầu vào hợp lệ cũng là một cổng sai, và
cách xử lý là sửa quy tắc rồi thêm phép kiểm, không phải tắt cổng.

## Bằng chứng thứ ba, ngoại lệ có thời hạn

Nhánh `main` phải giữ trạng thái có khiếm khuyết để làm đối tượng đánh giá, trong
khi CS-01 cấm đẩy trực tiếp. Giải pháp là một bản ghi trong
`policy/exceptions.json` đủ bốn trường, có thời hạn. Ba kịch bản trong
`evidence/20-policy-guard-cs01.txt`:

| Kịch bản | Kết luận | Mã thoát |
| :--- | :--- | :---: |
| Ngoại lệ `EX-2026-01` còn hạn đến 31/12/2026 | đạt, ghi rõ người phê duyệt | 0 |
| Cùng lần đẩy đó, ngoại lệ hết hạn | chặn, nêu tên ngoại lệ và lý do | 1 |
| Thay đổi đến từ pull request đã hợp nhất | đạt, không cần ngoại lệ | 0 |

Thêm nữa, `ci/check_exceptions.py` làm stage 1 thất bại nếu trong tệp còn một
ngoại lệ đã hết hạn, nên không ai phải nhớ đi thu hồi.

## Bản vá

`.github/workflows/devsecops-gate.yml` không đặt `ENFORCE_QUALITY_GATE`, nên
`sonarqube.py` dùng mặc định `"true"` và cổng chặn trở lại. Việc ghi nhận trạng
thái mà không chặn chuyển sang `security-baseline.yml`, một workflow riêng có tên
nói rõ nó không chặn.

## Điều cổng của Nam không chứng minh được

Chính sách quản trị chỉ đọc được **trạng thái cấu hình**. Nó không biết một thành
viên có thực sự dùng xác thực hai yếu tố hay không, cũng không biết người phê duyệt
pull request có thật sự đọc mã hay chỉ bấm approve. Phần đó thuộc quy trình con
người, không thuộc phạm vi mã.

## Câu thầy có thể hỏi

**Policy as Code khác gì một script kiểm tra?** `policy_guard.py` là mã thủ tục
kiểm quy ước đặt tên, tức quản trị quy trình. Policy as Code theo nghĩa tài liệu
môn học là chính sách khai báo trên cấu hình, do một engine chính sách đánh giá,
đặt tại đúng điểm thi hành. Nhóm có cả hai, và đã tách tên gọi cho đúng.
