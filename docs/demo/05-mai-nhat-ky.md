# Nguyễn Phương Mai, B26CHAT025

**Chính sách:** P5, nhật ký và telemetry
**Nhóm lỗi:** vận hành
**Pha DevSecOps:** Monitor
**Điều khoản:** GDPR Điều 5(1)(c) về tối giản dữ liệu, Điều 5(1)(e), Điều 32, Điều 33 và 34 về thông báo sự cố, CWE-532

## Vấn đề

Ba khiếm khuyết nối thành một chuỗi, và chuỗi đó đứt ở cả hai đầu.

**Một, nhật ký ghi quá nhiều.** `lib/logger.php` hàm `logSqlError()` ghi
`failed_query` là **nguyên văn câu lệnh truy vấn**, cộng `error_message`, `file`,
`uri`. Với `pages/login.php:19` câu lệnh đó chứa chuỗi người dùng vừa nhập, tức tên
đăng nhập và mật khẩu đi thẳng vào luồng nhật ký. Promtail trích `failed_query`
thành nhãn rồi lưu nguyên, **không có chặng che nào**: trong
`monitoring/promtail/promtail-config.yml` không có stage `replace` hay `drop`.

**Hai, cảnh báo không tới được đâu cả.** `monitoring/loki/loki-config.yml:30` trỏ
ruler tới `http://alertmanager:9093`, nhưng **không tệp compose nào có dịch vụ tên
alertmanager**. Chín luật cảnh báo vẫn được đánh giá rồi gửi vào một host không tồn
tại. Lab Telemetry nhấn mạnh rằng dashboard chỉ hiện sự kiện, còn cảnh báo phải tới
được nơi người hoặc script xử lý được.

**Ba, không phát hiện được dò quét.** Cả chín luật đều là `rate(...) > 0` với
`for: 5s`, không nhóm theo nguồn và không có ngưỡng. Lab dùng kiến trúc hai chuỗi:
luật mức thấp đánh dấu từng request, luật mức cao đếm theo từng IP trong một cửa sổ
thời gian, kèm khoảng `ignore` chống lặp. Hệ quả là một lần thăm dò sinh một cảnh
báo, còn một trăm lần thăm dò sinh một trăm cảnh báo, và không có cảnh báo nào nói
rằng đó là cùng một nguồn.

Thêm một khiếm khuyết liên quan: **ứng dụng không phát sự kiện xác thực nào**, nên
không đếm được số lần đăng nhập thất bại và do đó không phát hiện được dò quét thông
tin đăng nhập. Đây đúng là mục "missing audit events" trong bảng P5 của tài liệu.

## Cách phát hiện, chiều đỏ

```
bash tests/security/run.sh
# TDS-6  GDPR Art. 5(1)(c)  nhat ky khong duoc chua nguyen van cau lenh
```

Bộ điều phối đánh một mốc vào luồng nhật ký, chạy bộ test (trong đó `TDS-5` kích
một lỗi SQL), rồi đếm số dòng có trường `failed_query` sau mốc đó. Trên cấu hình
hiện tại số đó lớn hơn 0 nên test thất bại, và nó in ra một dòng mẫu đã cắt ngắn.

Chứng minh phần cảnh báo đứt đích:

```
grep -n alertmanager_url app/InlaneWeb/monitoring/loki/loki-config.yml
grep -c alertmanager app/InlaneWeb/docker-compose.monitoring.yml
```

Dòng đầu cho thấy ruler trỏ tới alertmanager, dòng sau trả về 0.

## Bản vá và chiều xanh

**Che dữ liệu trước khi lưu.** `patches/monitoring/promtail-config.hardened.yml` có
ba chặng `replace` đặt **trước** mọi chặng gán nhãn, nên không có bản sao nào của
payload được giữ lại:

```
      - replace:
          expression: '"failed_query":"([^"]*)"'
          replace: '[REDACTED_BY_PIPELINE]'
```

Deck "OpSec Telemetry Hygiene" của mon học ghi đúng yêu cầu này: *Log Scrubbing
Pipelines, filters log streams automatically before storage to scrub PII, PCI data,
and tokens, Regex Masking Rules*.

**Cảnh báo tới được đích.** `patches/monitoring/alertmanager.yml` và
`patches/monitoring/alert-sink.py` dựng đích nhận ghi một dòng đọc được cho mỗi
cảnh báo, đúng mẫu alert sink của lab. Thêm `inhibit_rules` để cảnh báo mức
`critical` của một nguồn dập cảnh báo mức `info` của cùng nguồn đó.

**Tương quan theo nguồn.** `patches/monitoring/loki-alert-rules.hardened.yml` dùng
`sum by (client_ip)` trên trường bóc tách lúc truy vấn qua `| json`, nên đếm được
theo từng địa chỉ mà không tạo nhãn có lực tính cao trong Loki. Mỗi luật có mã MITRE:
T1190 cho khai thác ứng dụng công khai, T1110.004 cho dò quét thông tin đăng nhập,
T1083 cho dò tìm tệp, T1059 cho thực thi lệnh.

Kiểm chính sách trên bản monitoring đã sửa:

```
conftest test patches/monitoring/docker-compose.monitoring.hardened.yml -p policy/ --namespace compose
# 13 tests, 10 passed, 3 warnings, 0 failures   exit=0
```

## Điều Mai cần nói rõ, và nó là điểm phân tích hay nhất của nhóm

Trường `failed_query` vừa là **nguồn phát hiện tấn công** vừa là **chỗ rò rỉ dữ liệu
cá nhân**. Chính nó cho phép luật `HttpErrorBasedResponseLeak` nhận ra khai thác dựa
trên thông điệp lỗi, và chính nó đưa mật khẩu người dùng vào Loki.

Hai mục tiêu này xung đột, và cách giải không phải chọn một bên. Cách giải là ghi
**siêu dữ liệu sự kiện** thay vì ghi **nội dung**: actor, event, target, outcome,
cộng một mã sự kiện để đối chiếu. Dấu hiệu tấn công vẫn còn, vì vẫn biết ai gửi,
gửi tới đâu, kết quả thế nào, trong khi dữ liệu cá nhân không còn được lưu. Đó đúng
là cách tài liệu môn học mô tả phần vá P5.

## Điều cổng của Mai không chứng minh được

Phát hiện dựa trên nhật ký chỉ thấy những gì **đã được ghi**. Một kẻ tấn công không
gây lỗi SQL nào, ví dụ khai thác thành công kiểu boolean hoặc time-based, sẽ không
để lại dòng `failed_query` nào và vì vậy không bị luật nào bắt. Tầng này không thay
được việc sửa lỗi ở tầng mã.

Ngoài ra toàn bộ nửa đo lường tài nguyên của lab Telemetry, gồm Prometheus,
node-exporter và cAdvisor cùng các luật `for:` chuyển Pending sang Firing, **chưa
được dựng**. Nhóm có nửa nhật ký, chưa có nửa số đo. Cần nói rõ thay vì để trống.
