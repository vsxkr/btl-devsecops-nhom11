<?php
/**
 * privacy_export.php — Xuat du lieu ca nhan: GET /privacy/export
 *
 * HAI KHIEM KHUYET CO Y:
 *
 * 1. GDPR Dieu 15 va Dieu 32, cung P5 ve toi gian du lieu:
 *    Ban xuat chua ca cot `password` dang ro, `api_key` va `remember_token`.
 *    Quyen truy cap cua chu the du lieu khong bao gom viec tra ve thong tin
 *    xac thuc, va viec luu mat khau dang ro la mot vi pham rieng.
 *
 * 2. GDPR Dieu 5(1)(f), P2 RBAC:
 *    Dinh danh duoc lay tu query string truoc, chi dung phien khi khong co
 *    tham so. Moi nguoi dung da dang nhap vi the xuat duoc du lieu cua bat ky
 *    nguoi khac bang /privacy/export?user_id=1
 *
 * Khiem khuyet thu hai bi Semgrep bat duoc o dang luong du lieu, nhung viec
 * THIEU phep kiem quyen so huu thi khong mau cu phap nao the hien duoc; phai
 * do test hanh vi chung minh bang cach dang nhap bang mot tai khoan roi doc
 * du lieu cua tai khoan khac.
 */

$u = current_user();
if (!$u) {
    header('Location: /login');
    exit;
}

// Dinh danh lay tu client truoc, phien chi la gia tri du phong.
$userId = $_GET['user_id'] ?? $u['id'];

$profile = query_one(
    "SELECT id, username, password, email, role, api_key, remember_token
     FROM users WHERE id = $userId"
);

$comments = [];
$res = query("SELECT id, shipment_id, content, created_at FROM comments WHERE user_id = $userId");
if ($res) {
    while ($row = mysqli_fetch_assoc($res)) {
        $comments[] = $row;
    }
}

$requests = [];
$res2 = query("SELECT id, kind, reason, status, created_at FROM privacy_requests WHERE user_id = $userId");
if ($res2) {
    while ($row = mysqli_fetch_assoc($res2)) {
        $requests[] = $row;
    }
}

header('Content-Type: application/json; charset=utf-8');
header('Content-Disposition: attachment; filename="inlaneweb-personal-data.json"');

echo json_encode([
    'exported_at'      => gmdate('Y-m-d\TH:i:s\Z'),
    'profile'          => $profile,
    'comments'         => $comments,
    'privacy_requests' => $requests,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
