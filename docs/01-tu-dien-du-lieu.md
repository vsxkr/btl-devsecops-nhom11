# Từ điển dữ liệu, đo từ lược đồ thật

Sinh bằng truy vấn `information_schema.columns` trên CSDL `ilfreight` đang chạy,
không gõ tay. Thang phân loại bốn mức lấy theo bước 1 của Rapid Risk Assessment
trong `3.Threat Modeling and Risk Management in DevSecOps Architecture.docx`:
Public, Internal, Confidential, Restricted.

| Bảng | Cột | Kiểu | Mức nhạy cảm | Loại dữ liệu | Điều khoản liên quan |
|---|---|---|---|---|---|
| `comments` | `id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `comments` | `shipment_id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `comments` | `user_id` | `int(11)` | **Internal** | Lien ket toi chu the du lieu | GDPR Art. 4(1) |
| `comments` | `content` | `text` | **Confidential** | Du lieu ca nhan do chu the nhap | GDPR Art. 5(1)(c), Art. 17 |
| `comments` | `created_at` | `datetime` | **Internal** | Sieu du lieu | GDPR Art. 5(1)(e) |
| `legacy_service_accounts` | `id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `legacy_service_accounts` | `username` | `varchar(100)` | **Confidential** | Du lieu ca nhan, dinh danh | GDPR Art. 4(1), Art. 17 |
| `legacy_service_accounts` | `password_hash` | `varchar(64)` | **Restricted** | Thong tin xac thuc | GDPR Art. 32 |
| `legacy_service_accounts` | `api_key` | `varchar(64)` | **Restricted** | Thong tin xac thuc | GDPR Art. 32 |
| `news` | `id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `news` | `title` | `varchar(200)` | **Public** | Du lieu tra cuu cong khai | - |
| `news` | `body` | `text` | **Public** | Du lieu tra cuu cong khai | - |
| `news` | `published_at` | `datetime` | **Public** | Sieu du lieu | - |
| `ports` | `id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `ports` | `code` | `varchar(10)` | **Public** | Du lieu tra cuu cong khai | - |
| `ports` | `city` | `varchar(100)` | **Public** | Du lieu tra cuu cong khai | - |
| `ports` | `country` | `varchar(100)` | **Public** | Du lieu tra cuu cong khai | - |
| `ports` | `volume` | `decimal(6,2)` | **Public** | Du lieu tra cuu cong khai | - |
| `privacy_requests` | `id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `privacy_requests` | `user_id` | `int(11)` | **Internal** | Lien ket toi chu the du lieu | GDPR Art. 4(1) |
| `privacy_requests` | `kind` | `varchar(20)` | **Internal** | Du lieu nghiep vu | - |
| `privacy_requests` | `reason` | `text` | **Confidential** | Du lieu ca nhan do chu the nhap | GDPR Art. 5(1)(c) |
| `privacy_requests` | `status` | `varchar(20)` | **Internal** | Du lieu nghiep vu | - |
| `privacy_requests` | `created_at` | `datetime` | **Internal** | Sieu du lieu | GDPR Art. 5(1)(e) |
| `shipments` | `id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `shipments` | `tracking_no` | `varchar(30)` | **Internal** | Du lieu nghiep vu | - |
| `shipments` | `port_code` | `varchar(10)` | **Public** | Du lieu tra cuu cong khai | - |
| `shipments` | `status` | `varchar(40)` | **Internal** | Du lieu nghiep vu | - |
| `shipments` | `customer_id` | `int(11)` | **Internal** | Lien ket toi chu the du lieu | GDPR Art. 4(1) |
| `users` | `id` | `int(11)` | **Public** | Du lieu tra cuu cong khai | - |
| `users` | `username` | `varchar(100)` | **Confidential** | Du lieu ca nhan, dinh danh | GDPR Art. 4(1), Art. 17 |
| `users` | `password` | `varchar(255)` | **Restricted** | Thong tin xac thuc | GDPR Art. 32, Art. 5(1)(f) |
| `users` | `email` | `varchar(150)` | **Confidential** | Du lieu ca nhan, dinh danh | GDPR Art. 4(1), Art. 15, Art. 17 |
| `users` | `role` | `varchar(20)` | **Internal** | Thuoc tinh phan quyen | GDPR Art. 25 |
| `users` | `api_key` | `varchar(64)` | **Restricted** | Thong tin xac thuc | GDPR Art. 32 |
| `users` | `remember_token` | `varchar(64)` | **Restricted** | Thong tin xac thuc | GDPR Art. 32 |

## Tổng hợp

| Mức nhạy cảm | Số cột |
|---|---|
| Restricted | 5 |
| Confidential | 5 |
| Internal | 10 |
| Public | 16 |
| **Tổng** | **36** |
