<?php
/**
 * profile_update.patched.php  (BAN DA VA)
 *
 * Moi chinh sach duoc xu ly theo cach ap dung duoc vao ung dung that:
 *   P1  danh sach truong duoc phep, va chi sua ban ghi cua chinh chu the
 *   P2  dinh danh lay tu phien da xac thuc, tra 401 khi khong co phien
 *   P3  bi mat chi den tu moi truong, khong co gia tri du phong
 *   P4  cau lenh chuan bi truoc, va client chi nhan thong diep chung kem ma su kien
 *   P5  nhat ky chi ghi actor, event, target, outcome
 */

require_once __DIR__ . '/../../app/InlaneWeb/web/src/lib/db.php';
require_once __DIR__ . '/../../app/InlaneWeb/web/src/lib/layout.php';

// P2: dinh danh den tu phien da xac thuc
$session = current_user();
if ($session === null) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthenticated']);
    return;
}
$userId = (int) $session['id'];

// P3: bi mat khong co gia tri du phong; thieu cau hinh thi dung han
$apiKey = getenv('ILF_API_KEY');
if ($apiKey === false || $apiKey === '') {
    throw new RuntimeException('ILF_API_KEY chua duoc cau hinh');
}

// P4: cau lenh chuan bi truoc voi tham so rang buoc
$conn = db();
$read = mysqli_prepare($conn, 'SELECT id, username, email FROM users WHERE id = ?');
mysqli_stmt_bind_param($read, 'i', $userId);
mysqli_stmt_execute($read);
$row = mysqli_fetch_assoc(mysqli_stmt_get_result($read));

// P1: danh sach truong duoc phep, va khoa WHERE lay tu phien chu khong tu client
$newEmail = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
if ($newEmail === false || $newEmail === null) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid email address']);
    return;
}
$write = mysqli_prepare($conn, 'UPDATE users SET email = ? WHERE id = ?');
mysqli_stmt_bind_param($write, 'si', $newEmail, $userId);
$ok = mysqli_stmt_execute($write);

// P5: chi ghi su kien, khong ghi noi dung nguoi dung nhap va khong ghi cau lenh
error_log(json_encode([
    'actor'   => $userId,
    'event'   => 'profile.update',
    'target'  => 'users:' . $userId,
    'outcome' => $ok ? 'success' : 'failure',
]));

// P4: chi tiet loi o lai phia may chu, client nhan ma su kien de doi chieu
if (!$ok) {
    $eventId = bin2hex(random_bytes(6));
    error_log('[' . $eventId . '] mysqli_errno=' . mysqli_errno($conn));
    http_response_code(500);
    echo json_encode([
        'status'  => 'error',
        'message' => 'An internal error occurred',
        'eventId' => $eventId,
    ]);
    return;
}

echo json_encode(['status' => 'success', 'email' => $newEmail]);
