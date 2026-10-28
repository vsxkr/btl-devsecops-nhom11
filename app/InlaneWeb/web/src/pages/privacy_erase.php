<?php
/**
 * privacy_erase.php — Yeu cau xoa du lieu ca nhan.
 *   GET  /privacy/erase   hien form
 *   POST /privacy/erase   tiep nhan yeu cau
 *
 * KHIEM KHUYET CO Y, GDPR Dieu 17 (quyen duoc xoa):
 * Trang nay chi GHI NHAN yeu cau vao bang privacy_requests roi tra loi rang
 * yeu cau "da duoc tiep nhan". Khong co ban ghi nao bi xoa hay an danh hoa.
 *
 * Day la loai khiem khuyet ma phan tich tinh KHONG THE phat hien, vi ma nguon
 * chay dung y dinh cua nguoi viet va khong co mau cu phap nao dang nghi. Chi
 * mot test hanh vi doi chieu trang thai co so du lieu truoc va sau yeu cau moi
 * cho thay du lieu van con nguyen.
 */

$u = current_user();
if (!$u) {
    header('Location: /login');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    render_header('Xoá dữ liệu cá nhân');
    echo '<div class="card"><h1>Yêu cầu xoá dữ liệu cá nhân</h1>'
        . '<p class="muted">Theo Nghị định về bảo vệ dữ liệu cá nhân, bạn có quyền '
        . 'yêu cầu xoá dữ liệu của mình khỏi hệ thống.</p>'
        . '<form method="post" action="/privacy/erase">'
        . '<p>Tài khoản: <strong>' . htmlspecialchars($u['username']) . '</strong></p>'
        . '<label>Lý do (không bắt buộc)<br><input type="text" name="reason" size="48"></label>'
        . '<p><button type="submit">Gửi yêu cầu xoá</button></p>'
        . '</form></div>';
    render_footer();
    exit;
}

$reason = $_POST['reason'] ?? '';
$uid    = intval($u['id']);

// Chi ghi nhan yeu cau. Khong xoa, khong an danh hoa.
$sql = "INSERT INTO privacy_requests (user_id, kind, reason, status)
        VALUES ($uid, 'erasure', '$reason', 'received')";
exec_write($sql);

render_header('Xoá dữ liệu cá nhân');
echo '<div class="card"><h1>Đã tiếp nhận yêu cầu</h1>'
    . '<p>Yêu cầu xoá dữ liệu cá nhân của bạn đã được ghi nhận và sẽ được xử lý '
    . 'theo quy trình nội bộ.</p>'
    . '<p class="muted"><a href="/account">← Về hồ sơ</a></p></div>';
render_footer();
