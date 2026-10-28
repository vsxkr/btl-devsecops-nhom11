<?php
/**
 * privacy_erase.php — Yeu cau xoa du lieu ca nhan.
 *   GET  /privacy/erase   hien form
 *   POST /privacy/erase   thuc hien xoa
 *
 * BAN VA, GDPR Dieu 17 (quyen duoc xoa).
 *
 * Ban cu chi GHI NHAN yeu cau vao bang privacy_requests roi tra loi rang yeu cau
 * "da duoc tiep nhan", trong khi khong ban ghi nao bi xoa. Phan tich tinh khong
 * the phat hien dieu do, vi ma nguon chay dung y dinh cua nguoi viet.
 *
 * Ban nay thuc hien dung ba viec:
 *   1. Xoa du lieu do chu the tao ra: binh luan.
 *   2. An danh hoa ban ghi nguoi dung thay vi xoa cung, vi `comments.user_id` va
 *      cac ban ghi nghiep vu khac tham chieu toi id nay. Day la lua chon co chu
 *      dich: GDPR cho phep an danh hoa khi toan ven tham chieu hoac nghia vu luu
 *      tru khong cho phep xoa cung.
 *   3. Xoa thong tin xac thuc: mat khau, khoa API, ma ghi nho dang nhap.
 *
 * Ban ghi trong privacy_requests duoc GIU lai voi trang thai completed, vi do la
 * ban ghi kiem toan chung minh yeu cau da duoc thuc hien, va no khong con chua
 * du lieu nhan dang sau khi an danh hoa.
 */

$u = current_user();
if ($u === null) {
    header('Location: /login');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    render_header('Xoá dữ liệu cá nhân');
    echo '<div class="card"><h1>Yêu cầu xoá dữ liệu cá nhân</h1>'
        . '<p class="muted">Theo quy định về bảo vệ dữ liệu cá nhân, bạn có quyền '
        . 'yêu cầu xoá dữ liệu của mình khỏi hệ thống. Thao tác này không thể hoàn tác.</p>'
        . '<form method="post" action="/privacy/erase">'
        . '<p>Tài khoản: <strong>' . htmlspecialchars($u['username'], ENT_QUOTES, 'UTF-8') . '</strong></p>'
        . '<div class="form-row"><label for="erase-reason">Lý do (không bắt buộc)</label>'
        . '<input id="erase-reason" type="text" name="reason" size="48"></div>'
        . '<p><button class="btn" type="submit">Gửi yêu cầu xoá</button></p>'
        . '</form></div>';
    render_footer();
    exit;
}

$reason = (string) ($_POST['reason'] ?? '');
$uid    = (int) $u['id'];

// 1. Ghi nhan yeu cau truoc, de co dau vet kiem toan ngay ca khi buoc sau loi.
exec_write_p(
    'INSERT INTO privacy_requests (user_id, kind, reason, status) VALUES (?, ?, ?, ?)',
    'isss',
    [$uid, 'erasure', $reason, 'processing']
);

// 2. Xoa du lieu do chu the tao ra.
exec_write_p('DELETE FROM comments WHERE user_id = ?', 'i', [$uid]);

// 3. An danh hoa ban ghi nguoi dung va xoa thong tin xac thuc.
exec_write_p(
    'UPDATE users
        SET username       = ?,
            email          = ?,
            password       = ?,
            api_key        = NULL,
            remember_token = NULL
      WHERE id = ?',
    'sssi',
    [
        'erased_' . $uid,
        sprintf('erased-%d@anonymized.invalid', $uid),
        '',
        $uid,
    ]
);

// 4. Danh dau yeu cau da hoan tat va ket thuc phien.
exec_write_p(
    'UPDATE privacy_requests SET status = ? WHERE user_id = ? AND status = ?',
    'sis',
    ['completed', $uid, 'processing']
);

$_SESSION = [];
session_destroy();

render_header('Xoá dữ liệu cá nhân');
echo '<div class="card"><h1>Đã xoá dữ liệu cá nhân</h1>'
    . '<p>Dữ liệu nhận dạng của bạn đã được xoá hoặc ẩn danh hoá, và thông tin '
    . 'xác thực đã được loại bỏ. Phiên đăng nhập đã kết thúc.</p>'
    . '<p class="muted"><a href="/">← Về trang chủ</a></p></div>';
render_footer();
