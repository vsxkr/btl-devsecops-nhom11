<?php
/**
 * privacy_export.php — Xuat du lieu ca nhan: GET /privacy/export
 *
 * BAN VA. Ba thay doi so voi ban cu:
 *
 * 1. P2, GDPR Dieu 5(1)(f): dinh danh chi lay tu PHIEN DA XAC THUC. Ban cu uu
 *    tien `$_GET['user_id']` nen moi nguoi dung da dang nhap deu xuat duoc du
 *    lieu cua nguoi khac bang /privacy/export?user_id=1
 *
 * 2. GDPR Dieu 15 va Dieu 5(1)(c): quyen truy cap cua chu the du lieu KHONG bao
 *    gom thong tin xac thuc. Ban xuat bo cac cot `password`, `api_key` va
 *    `remember_token`, va chi liet ke dung nhung truong thuoc ve chu the.
 *
 * 3. P4: moi truy van dung tham so rang buoc.
 */

$u = current_user();
if ($u === null) {
    header('Location: /login');
    exit;
}

// Dinh danh den tu phien, khong nhan tu client.
$userId = (int) $u['id'];

// Neu client co y truyen user_id khac thi tu choi han, de hanh vi ro rang thay
// vi am tham bo qua tham so.
if (isset($_GET['user_id']) && (int) $_GET['user_id'] !== $userId) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status'  => 'error',
        'message' => 'Chi xuat duoc du lieu cua chinh tai khoan dang dang nhap.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// Danh sach truong duoc phep xuat. Khong co cot xac thuc nao trong danh sach.
$profile = query_one_p(
    'SELECT id, username, email, role FROM users WHERE id = ?',
    'i',
    [$userId]
);

$comments = query_p(
    'SELECT id, shipment_id, content, created_at FROM comments WHERE user_id = ?',
    'i',
    [$userId]
);

$requests = query_p(
    'SELECT id, kind, reason, status, created_at FROM privacy_requests WHERE user_id = ?',
    'i',
    [$userId]
);

header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="inlaneweb-personal-data.json"');

echo json_encode([
    'exported_at'      => gmdate('Y-m-d\TH:i:s\Z'),
    'subject_id'       => $userId,
    'profile'          => $profile,
    'comments'         => $comments,
    'privacy_requests' => $requests,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
