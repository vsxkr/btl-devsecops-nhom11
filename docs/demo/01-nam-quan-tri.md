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
  https://api.github.com/repos/wtfwhoyouare/PTIT-DevOps-SonarQube/branches/main
```

## Chiều xanh

```
conftest test fixtures/branch-protection-compliant.json -p policy/ --namespace repo
# 3 tests, 3 passed, 0 failures   exit=0
```

Fixture này là hình dạng cấu hình đạt. Bật thật trên GitHub là một thao tác trong
Settings, và cần chính Nam làm vì chỉ chủ repo có quyền.

## Bằng chứng mạnh nhất, chính sách đã chặn thật một lần

Run `39984469804` ngày 23/10 lúc 16:09, đẩy lên `refs/heads/main`:

```
LOI VI PHAM CHINH SACH DAT TEN COMMIT (CONVENTIONAL COMMITS)
Commit [a3ff9cb]: "release: v1.0.1 - Trien khai ha tang giam sat Loki va Grafana..."
##[error]Process completed with exit code 1.
```

Job `[STAGE 1] Policy Guard` thất bại, và **năm job sau bị skipped**. Sau đó commit
`a9b4259` lúc 23:11 sửa chính `COMMIT_REGEX` để cho phép tiêu đề release.

Đây là vòng đời Policy-as-Code đầy đủ: chính sách chặn, chính sách bắt sai, chính
sách được sửa bằng cách sửa mã chính sách, tất cả có dấu vết trong Git. Nói rõ với
thầy rằng đây là **cảnh báo sai**, và cách xử lý một cảnh báo sai là sửa luật chứ
không phải tắt cổng.

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
