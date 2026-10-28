<?php
/**
 * compliance_test.php — Test-Driven Security cho InlaneWeb.
 *
 * Can cu: Hands-on_guide_updated.docx, Phase 4 va moc cham so 3:
 *   "Tests fail on the original code for the right reason and pass after
 *    patching; tests assert behaviour, not implementation."
 *
 * Moi test khang dinh HANH VI dung theo mot dieu khoan phap ly, khong khang
 * dinh cach hien thuc. Vi vay test khong doc ma nguon, chi goi HTTP va doc
 * trang thai co so du lieu.
 *
 * Chay BEN TRONG container web (co PHP va mysqli):
 *   docker compose exec -T web php /tests/security/compliance_test.php
 *
 * Ma thoat: 0 khi tat ca dat, 1 khi co test that bai.
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
//  Ha tang test toi gian: khong phu thuoc goi ngoai nao
// ---------------------------------------------------------------------------

const APP_HOST = '127.0.0.1';
const APP_PORT = 80;

$GLOBALS['tds_results'] = [];

function tds_assert(string $id, string $clause, string $claim, bool $ok, string $detail = ''): void
{
    $GLOBALS['tds_results'][] = [
        'id' => $id, 'clause' => $clause, 'claim' => $claim,
        'ok' => $ok, 'detail' => $detail,
    ];
    printf("  [%s] %-7s %-26s %s\n", $ok ? 'DAT ' : 'LOI ', $id, $clause, $claim);
    if (!$ok && $detail !== '') {
        printf("          -> %s\n", $detail);
    }
}

/**
 * Client HTTP bang socket tho. Khong dung extension curl de test chay duoc
 * tren moi ban PHP, va de kiem soat duoc cookie phien.
 */
function http_request(string $method, string $path, array $form = [], ?string $cookie = null): array
{
    $body = $form ? http_build_query($form) : '';
    $req = sprintf("%s %s HTTP/1.1\r\n", $method, $path)
        . sprintf("Host: %s\r\n", APP_HOST)
        . "Connection: close\r\n"
        . "User-Agent: tds-compliance-test/1.0\r\n";
    if ($cookie !== null) {
        $req .= sprintf("Cookie: %s\r\n", $cookie);
    }
    if ($body !== '') {
        $req .= "Content-Type: application/x-www-form-urlencoded\r\n"
            . sprintf("Content-Length: %d\r\n", strlen($body));
    }
    $req .= "\r\n" . $body;

    $fp = @stream_socket_client(
        sprintf('tcp://%s:%d', APP_HOST, APP_PORT),
        $errno, $errstr, 10
    );
    if (!$fp) {
        throw new RuntimeException(sprintf('khong ket noi duoc ung dung: %s (%d)', $errstr, $errno));
    }
    fwrite($fp, $req);
    $raw = stream_get_contents($fp);
    fclose($fp);

    $split = strpos($raw, "\r\n\r\n");
    $head = $split === false ? $raw : substr($raw, 0, $split);
    $payload = $split === false ? '' : substr($raw, $split + 4);

    preg_match('#^HTTP/1\.[01] (\d{3})#', $head, $m);
    $status = isset($m[1]) ? (int) $m[1] : 0;

    $cookies = [];
    foreach (explode("\r\n", $head) as $line) {
        if (stripos($line, 'Set-Cookie:') === 0) {
            $kv = trim(explode(';', substr($line, 11))[0]);
            $cookies[] = $kv;
        }
    }

    // Body co the o dang chunked vi HTTP/1.1
    if (stripos($head, 'Transfer-Encoding: chunked') !== false) {
        $decoded = '';
        $pos = 0;
        while ($pos < strlen($payload)) {
            $nl = strpos($payload, "\r\n", $pos);
            if ($nl === false) { break; }
            $len = hexdec(trim(substr($payload, $pos, $nl - $pos)));
            if ($len === 0) { break; }
            $decoded .= substr($payload, $nl + 2, (int) $len);
            $pos = $nl + 2 + (int) $len + 2;
        }
        $payload = $decoded;
    }

    return ['status' => $status, 'head' => $head, 'body' => $payload, 'cookies' => $cookies];
}

function app_login(string $username, string $password): string
{
    $r = http_request('POST', '/login', ['username' => $username, 'password' => $password]);
    foreach ($r['cookies'] as $c) {
        if (stripos($c, 'PHPSESSID=') === 0) {
            return $c;
        }
    }
    // Phien da ton tai truoc khi dang nhap: lay cookie tu lan goi dau
    throw new RuntimeException(sprintf(
        'dang nhap that bai cho %s, status=%d', $username, $r['status']
    ));
}

function db_conn(): mysqli
{
    $conn = mysqli_connect(
        getenv('DB_HOST') ?: 'db',
        getenv('DB_USER') ?: 'root',
        getenv('DB_PASS') ?: 'password',
        getenv('DB_NAME') ?: 'ilfreight'
    );
    if (!$conn) {
        throw new RuntimeException('khong ket noi duoc CSDL: ' . mysqli_connect_error());
    }
    return $conn;
}

function db_one(mysqli $c, string $sql): ?array
{
    $res = mysqli_query($c, $sql);
    if ($res === false) {
        throw new RuntimeException('truy van test that bai: ' . mysqli_error($c));
    }
    $row = mysqli_fetch_assoc($res);
    return $row ?: null;
}

// ---------------------------------------------------------------------------
//  Chuan bi: tao mot chu the du lieu rieng cho test
// ---------------------------------------------------------------------------

const SUBJECT_USER = 'tds_subject';
const SUBJECT_PASS = 'TdsP@ssw0rd2026';
const SUBJECT_MAIL = 'tds_subject@ilfreight.local';

$conn = db_conn();
mysqli_query($conn, "DELETE FROM privacy_requests WHERE user_id IN (SELECT id FROM users WHERE username = '" . SUBJECT_USER . "')");
mysqli_query($conn, "DELETE FROM comments WHERE user_id IN (SELECT id FROM users WHERE username = '" . SUBJECT_USER . "')");
mysqli_query($conn, "DELETE FROM users WHERE username = '" . SUBJECT_USER . "'");
mysqli_query($conn, sprintf(
    "INSERT INTO users (username, password, email, role, api_key) VALUES ('%s', '%s', '%s', 'customer', 'ILF-TDS-0000000000000001')",
    SUBJECT_USER, SUBJECT_PASS, SUBJECT_MAIL
));
$subject = db_one($conn, "SELECT id FROM users WHERE username = '" . SUBJECT_USER . "'");
$subjectId = (int) $subject['id'];
mysqli_query($conn, sprintf(
    "INSERT INTO comments (shipment_id, user_id, content) VALUES (1, %d, 'binh luan cua chu the du lieu test')",
    $subjectId
));
$adminRow = db_one($conn, "SELECT id FROM users WHERE username = 'admin'");
$adminId = (int) $adminRow['id'];

echo "Test-Driven Security, InlaneWeb\n";
echo str_repeat('-', 78) . "\n";
printf("chu the du lieu test: id=%d username=%s\n", $subjectId, SUBJECT_USER);
echo str_repeat('-', 78) . "\n";

// ---------------------------------------------------------------------------
//  TDS-4  Luu tru mat khau   GDPR Dieu 32, PCI DSS 8.3.1
// ---------------------------------------------------------------------------
$seed = db_one($conn, "SELECT password FROM users WHERE username = 'jsmith'");
tds_assert(
    'TDS-4',
    'GDPR Art. 32',
    'mat khau khong duoc luu dang ro',
    $seed !== null && $seed['password'] !== 'Spring2024!',
    $seed === null ? 'khong tim thay nguoi dung jsmith' : sprintf('cot password chua dung chuoi dang ro: %s', $seed['password'])
);

// ---------------------------------------------------------------------------
//  TDS-5  Ve sinh loi        GDPR Dieu 32, PCI DSS 6.2.4
// ---------------------------------------------------------------------------
// Dung endpoint CONG KHAI /ports, la trang di qua helper query() cua ung dung.
// Hai lan thu truoc deu cho ket qua DAT GIA:
//   /shipments/1'   co chan dang nhap  -> chuyen huong, khong truy van nao chay
//   /api/track      goi mysqli_query truc tiep va CO Y nuot loi -> khong in gi
// Mot phep kiem khong cham duoc vao duong can kiem thi khong ket luan duoc gi.
$bad = http_request('GET', '/ports?q=1%27');
$leaks = [];
foreach (['SQL Error', 'mysqli', 'syntax', 'SQL syntax', 'MariaDB server version'] as $needle) {
    if (stripos($bad['body'], $needle) !== false) {
        $leaks[] = $needle;
    }
}
if ($bad['status'] === 302 || stripos($bad['head'], 'Location: /login') !== false) {
    $leaks[] = sprintf('phep kiem khong cham duoc vao ma, bi chuyen huong, status=%d', $bad['status']);
}
tds_assert(
    'TDS-5',
    'GDPR Art. 32',
    'phan hoi loi khong duoc lo noi bo',
    $leaks === [],
    sprintf('phan hoi chua: %s', implode(', ', $leaks))
);

// ---------------------------------------------------------------------------
//  TDS-2  Toi gian du lieu   GDPR Dieu 15 va Dieu 32, Art. 5(1)(c)
// ---------------------------------------------------------------------------
$cookie = app_login(SUBJECT_USER, SUBJECT_PASS);
$exp = http_request('GET', '/privacy/export', [], $cookie);
$forbidden = [];
foreach (['password', 'api_key', 'remember_token'] as $field) {
    if (stripos($exp['body'], '"' . $field . '"') !== false) {
        $forbidden[] = $field;
    }
}
if (stripos($exp['body'], SUBJECT_PASS) !== false) {
    $forbidden[] = 'gia tri mat khau dang ro';
}
tds_assert(
    'TDS-2',
    'GDPR Art. 15, Art. 5(1)(c)',
    'ban xuat khong duoc chua thong tin xac thuc',
    $forbidden === [],
    sprintf('ban xuat chua: %s', implode(', ', $forbidden))
);

// ---------------------------------------------------------------------------
//  TDS-3  Phan quyen ngang   GDPR Dieu 5(1)(f) va Dieu 32
// ---------------------------------------------------------------------------
$other = http_request('GET', '/privacy/export?user_id=' . $adminId, [], $cookie);
$leakedOther = false;
$decoded = json_decode($other['body'], true);
if (is_array($decoded) && isset($decoded['profile']['id'])) {
    $leakedOther = ((int) $decoded['profile']['id']) === $adminId;
}
tds_assert(
    'TDS-3',
    'GDPR Art. 5(1)(f)',
    'khong doc duoc du lieu cua chu the khac',
    !$leakedOther && ($other['status'] >= 400 || !$leakedOther),
    sprintf('status=%d va ban xuat tra ve profile id=%s cua nguoi khac', $other['status'], $decoded['profile']['id'] ?? '?')
);

// ---------------------------------------------------------------------------
//  TDS-1  Quyen duoc xoa     GDPR Dieu 17
// ---------------------------------------------------------------------------
$er = http_request('POST', '/privacy/erase', ['reason' => 'test quyen duoc xoa'], $cookie);
$still = db_one($conn, sprintf("SELECT email FROM users WHERE id = %d", $subjectId));
$stillIdentifiable = $still !== null && $still['email'] === SUBJECT_MAIL;
$cmt = db_one($conn, sprintf("SELECT COUNT(*) AS n FROM comments WHERE user_id = %d", $subjectId));
$commentsLeft = (int) ($cmt['n'] ?? 0);
tds_assert(
    'TDS-1',
    'GDPR Art. 17',
    'yeu cau xoa phai xoa hoac an danh hoa',
    !$stillIdentifiable && $commentsLeft === 0,
    sprintf(
        'status=%d, email van con nhan dang duoc: %s, so binh luan con lai: %d',
        $er['status'],
        $stillIdentifiable ? 'co' : 'khong',
        $commentsLeft
    )
);

// ---------------------------------------------------------------------------
//  Don dep va tong ket
// ---------------------------------------------------------------------------
mysqli_query($conn, sprintf("DELETE FROM privacy_requests WHERE user_id = %d", $subjectId));
mysqli_query($conn, sprintf("DELETE FROM comments WHERE user_id = %d", $subjectId));
mysqli_query($conn, sprintf("DELETE FROM users WHERE id = %d", $subjectId));

$total = count($GLOBALS['tds_results']);
$failed = count(array_filter($GLOBALS['tds_results'], static fn (array $r): bool => !$r['ok']));
echo str_repeat('-', 78) . "\n";
printf("%d test, %d dat, %d that bai\n", $total, $total - $failed, $failed);
exit($failed === 0 ? 0 : 1);
