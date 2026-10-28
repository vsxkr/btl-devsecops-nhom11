<?php
/**
 * profile_update.vulnerable.php  (DIEM BAT DAU, CO Y SAI)
 *
 * Moi chinh sach P1 den P5 bi vi pham dung mot lan, co nhan o cuoi dong.
 * Tuong duong routes/updateProfile.ts cua lab SonarQube (Appendix A.1), nhung
 * viet bang PHP va mysqli de dung duoc helper thuc te cua InlaneWeb.
 */

require_once __DIR__ . '/../../app/InlaneWeb/web/src/lib/db.php';

// P2 RBAC: dinh danh doi tuong lay tu dau vao client, khong tu phien
$userId = $_GET['user_id'];

// P4 kiem tra dau vao: noi chuoi truc tiep vao truy van tho
$sql = "SELECT id, username, email FROM users WHERE id = $userId";
$row = query_one($sql);

// P1 least privilege: du lieu client di vao cau lenh ghi, khong co danh sach
// truong duoc phep, nen client co the chen them cot can sua
$email = $_POST['email'];
exec_write("UPDATE users SET email = '$email' WHERE id = $userId");

// P3 quan ly bi mat: khoa API co gia tri du phong la chuoi hang
$apiKey = getenv('ILF_API_KEY') ?: 'ILF-ADM-9f3c1a77e2b04d55';

// P3 least privilege o tang ket noi: tai khoan CSDL dac quyen theo mac dinh
$dbUser = getenv('DB_USER') ?: 'root';

// P5 nhat ky: du lieu nguoi dung vua nhap di thang vao nhat ky
error_log('profile update for ' . $_POST['email']);

// P4 ve sinh loi: noi dung loi cua tang CSDL di ra phan hoi HTTP
echo mysqli_error(db());
