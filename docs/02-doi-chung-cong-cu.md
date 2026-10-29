# Đối chứng từng cổng trên từng lớp khiếm khuyết

Mốc chấm số 3 của `SonarQube and juice shop Lab.docx` yêu cầu:

> *"Student documents which violations each tool caught, and explains the gaps
> (edition limits, entropy, no taint analysis)."*

Bảng dưới đây đo từ artifact thật, không suy luận. Ký hiệu: **✓** cổng bắt được,
**–** cổng không áp dụng cho lớp này, **✗** cổng áp dụng được nhưng **không** bắt.

## Số liệu gốc

| Nguồn | Kết quả |
|---|---|
| SonarQube Community, run `40748974196`, nhánh `main` tại `94004f3` | 25 vấn đề: 15 `CODE_SMELL`, 10 `BUG`, **0 `VULNERABILITY`** |
| Semgrep, cùng run, cùng mốc | 64 phát hiện |
| Giao của hai tập | **rỗng**, không một phát hiện nào trùng nhau |

Luật mà SonarQube báo: `Web:InputWithoutLabelCheck` 9 lần, `php:S100` 6 lần,
`Web:S6853` 4 lần, `php:S113` 4 lần, `php:S2003` 1 lần, `php:S121` 1 lần. Tức là ô
nhập thiếu nhãn, quy ước đặt tên, dòng trống cuối tệp, và thiếu cặp ngoặc nhọn.

Lý do nằm trong chính tài liệu môn học:

> *"SonarSource states that Community Build does not support taint analysis, which
> is how injection flaws such as SQL injection and XSS are found. These are
> Developer Edition features."*

Trên một ứng dụng có 12 điểm nối chuỗi vào câu truy vấn, công cụ được cài đặt đúng
theo yêu cầu của đề chỉ báo về **trợ năng và quy ước đặt tên**. Kết quả này trả
lời trực tiếp yêu cầu số 3 của bài tập nhóm và phần phân tích của bài tập lớn.

## Bảng đối chứng

| Lớp khiếm khuyết | SonarQube CE | Semgrep | Conftest | InSpec | TDS | Trivy |
|---|---|---|---|---|---|---|
| Chèn mã truy vấn, 12 điểm | ✗ | ✓ 12 | – | – | gián tiếp | – |
| Lỗi CSDL ra phản hồi HTTP | ✗ | ✓ 4 | – | – | ✓ TDS-5 | – |
| Bí mật gán cứng trong mã PHP | ✗ | ✓ 1 | – | – | – | ✗ |
| Bí mật gán cứng trong compose | – | ✓ 1 trên 4 nơi | **✓ 4 trên 4** | ✓ | – | ✗ |
| Tài khoản CSDL đặc quyền | ✗ | ✓ 1 | ✓ | – | – | – |
| Dockerfile thiếu `USER` | – | ✓ 2 | ✓ | ✓ | – | ✓ |
| Dockerfile thiếu `HEALTHCHECK` | – | ✗ | ✓ | – | – | ✓ |
| Dockerfile thiếu nhãn OCI provenance | – | ✗ | **✓ chỉ luật nhóm** | – | – | ✗ |
| Cổng công bố ra mọi giao diện | – | ✗ | ✓ | ✓ | – | ✗ |
| Mount `docker.sock` ghi được | – | ✗ | ✓ | ✓ | – | ✗ |
| Container chạy bằng root | – | ✗ | ✓ | ✓ | – | ✗ |
| Thiếu `cap_drop` và `no-new-privileges` | – | ✗ | ✓ | ✓ | – | ✗ |
| Ảnh không ghim phiên bản | – | ✗ | ✓ | – | – | ✗ |
| Mật khẩu người dùng lưu dạng rõ | ✗ | ✗ | – | – | **✓ chỉ TDS-4** | – |
| Quyền được xoá không được thực thi | ✗ | ✗ | – | – | **✓ chỉ TDS-1** | – |
| Bản xuất lộ thông tin xác thực | ✗ | ✗ | – | – | **✓ chỉ TDS-2** | – |
| Phân quyền ngang ở bản xuất | ✗ | ✗ | – | – | **✓ chỉ TDS-3** | – |
| Nhật ký chứa nguyên văn câu lệnh | ✗ | ✓ luật cú pháp | – | – | **✓ TDS-6 đo đầu cuối** | – |
| Nhánh `main` và `dev` không được bảo vệ | – | – | **✓ chỉ luật nhóm** | – | – | – |
| Bí mật đọc được qua `docker inspect` | – | – | ✗ sau khi vá | **✓ chỉ InSpec** | – | – |
| CRLF làm container không khởi động | ✗ | ✗ | ✗ | ✗ | **✓ chỉ việc chạy thật** | ✗ |
| Thiếu sự kiện kiểm toán khi đăng nhập thất bại | ✗ | ✗ | ✗ | ✗ | ✗ | – |
| CVE ảnh nền, 145 mức HIGH và CRITICAL | – | – | – | – | – | **✓ chỉ Trivy** |

## Đọc bảng theo cột

| Cổng | Số lớp khiếm khuyết nó là cổng **duy nhất** bắt được |
|---|---|
| Test-Driven Security | **5** |
| Trivy | 1 |
| InSpec | 1 |
| Chính sách riêng của nhóm | 2 |
| Việc chạy thật, không cổng nào | 1 |
| SonarQube Community | **0** |

## Kết luận

1. SonarQube Community không phải là cổng an toàn mà là cổng chất lượng mã. Trên
   dự án này nó không là cổng duy nhất bắt được bất kỳ lớp khiếm khuyết nào, và nó
   xếp loại 0 vấn đề là `VULNERABILITY`. Dùng nó làm cổng an toàn duy nhất là một
   nhận định sai về năng lực công cụ, không phải một lỗi cấu hình.

2. Năm lớp khiếm khuyết chỉ test hành vi bắt được đều là vi phạm dữ liệu cá nhân
   trực tiếp: mật khẩu dạng rõ, quyền được xoá không được thực thi, bản xuất lộ
   thông tin xác thực, phân quyền ngang, nhật ký ghi quá mức. Không công cụ phân
   tích tĩnh nào thấy chúng, vì mã nguồn chạy đúng ý định của người viết. Điều này
   tương ứng với nội dung mục *"What static analysis cannot prove"*.

3. Một lớp khiếm khuyết không cổng nào bắt được, chỉ phát hiện khi chạy thật: kết
   thúc dòng CRLF làm container không khởi động trên Windows. Conftest đọc nội
   dung cấu hình chứ không đọc byte kết thúc dòng, Semgrep đọc cây cú pháp, Trivy
   đọc gói và CVE. Trong 150 lần chạy pipeline của nhóm không lần nào bắt được, vì
   runner Linux checkout ra LF.

4. Một lớp khiếm khuyết không một cổng **tĩnh hay hành vi** nào bắt được: ứng dụng
   không phát sự kiện kiểm toán khi đăng nhập thất bại. Nó được phát hiện khi viết
   luật tương quan cho Loki và nhận ra không có dữ liệu nào để đếm. Việc thiết kế
   một phép kiểm rồi thấy nó không có đầu vào là một đường phát hiện mà không công
   cụ phân tích nào cung cấp.

## Cổng thứ bảy: chuỗi telemetry đo được (bậc 3)

Sáu cổng trong bảng trên đều kết thúc ở một phán quyết tĩnh hoặc một phép kiểm
hành vi: chúng nói **có lỗi** hay **không có lỗi** tại một thời điểm. Chúng không
đo được đại lượng vận hành là thời gian từ khi bị tấn công thật tới khi người trực
nhận được tin.

Cụm giám sát đã vá là cổng duy nhất trả lời câu đó. `tests/security/detect_latency.sh`
chạy một loạt tám yêu cầu mang đặc trưng SQL injection vào ứng dụng đã vá rồi đo
cả chuỗi: Apache ghi log JSON → Promtail che dữ liệu → Loki đếm theo từng nguồn
bằng `| json` → luật `SqliProbeBurstFromSingleSource` vượt ngưỡng → Alertmanager →
alert sink. Đo qua ba lần chạy độc lập, **độ trễ phát hiện 15,1 / 20,9 / 24,6
giây**, bị giới hạn bởi chu kỳ đánh giá luật 15 giây và `group_wait` 10 giây của
Alertmanager. Cùng chuỗi đó kích **hai mức** cùng lúc, `SqliProbeObserved` mức
info để đối chiếu và `SqliProbeBurstFromSingleSource` mức critical để gọi người
trực, đúng kiến trúc hai chuỗi của lab Telemetry.

Cổng này cũng là nơi ba lớp khiếm khuyết chỉ lộ khi chạy được khép kín: sự kiện
kiểm toán khi đăng nhập thất bại (kết luận thứ tư) nay được ứng dụng phát ra và luật
`CredentialStuffingObserved` đếm được; loạt tấn công theo nguồn được tương quan;
và bí mật trong luồng log bị Promtail thay bằng `[REDACTED_CREDENTIAL]` **trước
khi** bất kỳ byte nào được lưu: kiểm bằng cách gửi một mật khẩu rồi xác nhận
không dòng Loki nào còn chứa nó (GDPR Điều 5(1)(c)). Bằng chứng đầu-cuối, kèm cả
chiều đỏ (ruler bản gốc trỏ tới một `alertmanager` không tồn tại nên cảnh báo
không tới đâu), ở `evidence/35-chuoi-phat-hien-do-tre.txt`.

Ba lỗi cấu hình chỉ lộ ra khi dựng cụm thật: stage `labels` của Promtail không
đặt giá trị hằng, stage `replace` chỉ chạy khi có nhóm bắt, và `relabel keep` lọc
container quá muộn, được ghi ở `patches/monitoring/README.md`. Chúng là ví dụ
sống cho luận điểm xuyên suốt: một phép kiểm không chạm được vào thứ cần đo trông
giống hệt một phép kiểm đạt.
