<?php
/**
 * login.php — Dang nhap.
 *
 * BAN VA. Bon thay doi so voi ban cu:
 *
 * 1. P4, GDPR Dieu 32: cau lenh chuan bi truoc voi tham so rang buoc. Ban cu noi
 *    chuoi ca `username` lan `password` vao truy van, nen vua co the vuot xac thuc
 *    bang `admin'-- -` vua doc duoc du lieu tung ky tu bang dieu kien boolean.
 *
 * 2. P3, GDPR Dieu 32 va Dieu 5(1)(f): mat khau duoc kiem bang password_verify
 *    tren gia tri da bam, thay cho so sanh chuoi dang ro trong cau lenh SQL.
 *
 * 3. An toan phien: session_regenerate_id sau khi dang nhap thanh cong, de mot
 *    ma phien lay truoc do khong con dung duoc (session fixation).
 *
 * 4. P5: phat su kien xac thuc co cau truc, nho do dem duoc so lan that bai theo
 *    tung dia chi nguon va phat hien duoc do quet thong tin dang nhap. Su kien chi
 *    ghi ten dang nhap duoc yeu cau va ket qua, khong ghi mat khau.
 */

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = (string) ($_POST['username'] ?? '');
    $password = (string) ($_POST['password'] ?? '');

    $row = query_one_p(
        'SELECT id, username, role, password FROM users WHERE username = ? LIMIT 1',
        's',
        [$username]
    );

    $ok = false;
    if ($row !== null && is_string($row['password']) && $row['password'] !== '') {
        $ok = password_verify($password, $row['password']);
        // Ho tro chuyen doi dan: neu ban ghi con la mat khau dang ro thi van cho
        // dang nhap mot lan roi bam lai ngay. Buoc nay se bo sau khi di tru xong.
        if (!$ok && hash_equals($row['password'], $password)) {
            $ok = true;
            exec_write_p(
                'UPDATE users SET password = ? WHERE id = ?',
                'si',
                [password_hash($password, PASSWORD_DEFAULT), (int) $row['id']]
            );
        }
    }

    InlaneLogger::logAuthEvent($username, $ok ? 'success' : 'failure');

    if ($ok && $row !== null) {
        session_regenerate_id(true);
        $_SESSION['uid'] = (int) $row['id'];
        header('Location: /account');
        exit;
    }

    // Thong diep chung, khong cho biet ten dang nhap co ton tai hay khong.
    $error = 'Sai tên đăng nhập hoặc mật khẩu.';
}

render_header('Đăng nhập');
?>
<div class="card" style="max-width:440px;margin:0 auto;">
    <h1>Đăng nhập</h1>
    <?php if ($error) flash($error, 'error'); ?>
    <form action="/login" method="post">
        <div class="form-row">
            <label for="login-username">Tên đăng nhập</label>
            <input id="login-username" type="text" name="username" autofocus>
        </div>
        <div class="form-row">
            <label for="login-password">Mật khẩu</label>
            <input id="login-password" type="password" name="password">
        </div>
        <button class="btn" type="submit" style="width:100%">Đăng nhập</button>
    </form>
    <p class="muted" style="margin-top:16px">Tài khoản demo: <code>jsmith / Spring2024!</code></p>
</div>
<?php
render_footer();
