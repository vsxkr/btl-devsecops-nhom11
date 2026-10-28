<?php
/**
 * db.php — Ket noi database va helper query.
 *
 * BAN VA. Ba thay doi so voi ban cu:
 *
 * 1. P3, GDPR Dieu 32 va PCI DSS 8.6.2: khong con gia tri du phong dang chuoi
 *    hang cho thong tin xac thuc. Thieu cau hinh thi dung han, thay vi am tham
 *    chay bang root/password.
 *
 * 2. P4, GDPR Dieu 32: khong in noi dung loi cua tang CSDL ra phan hoi HTTP.
 *    Client chi nhan mot thong diep chung kem ma su kien, chi tiet o lai phia
 *    may chu.
 *
 * 3. Them bo tro giup cau lenh chuan bi truoc, de cac trang chuyen dan sang
 *    tham so rang buoc thay cho noi chuoi.
 */

require_once __DIR__ . '/logger.php';

function db(): mysqli
{
    static $conn = null;
    if ($conn === null) {
        $host = getenv('DB_HOST');
        $user = getenv('DB_USER');
        $pass = getenv('DB_PASS');
        $name = getenv('DB_NAME');

        // Fail closed: thieu bat ky bien nao thi dung, khong doan gia tri.
        foreach (['DB_HOST' => $host, 'DB_USER' => $user, 'DB_PASS' => $pass, 'DB_NAME' => $name] as $k => $v) {
            if ($v === false || $v === '') {
                throw new RuntimeException(sprintf('Thieu bien cau hinh %s', $k));
            }
        }

        mysqli_report(MYSQLI_REPORT_OFF);
        $conn = mysqli_connect((string) $host, (string) $user, (string) $pass, (string) $name);
        if (!$conn) {
            $eventId = InlaneLogger::logSqlError(
                'CONNECT',
                'connection failure',
                mysqli_connect_errno()
            );
            http_response_code(503);
            die('Dich vu tam thoi khong san sang. Ma su kien: ' . $eventId);
        }
    }
    return $conn;
}

/** In thong diep loi chung, khong tiet lo noi bo. */
function db_error_notice(string $eventId): void
{
    echo '<div class="sql-error"><strong>Loi xu ly:</strong> yeu cau khong hoan tat. '
        . 'Ma su kien: <code>' . htmlspecialchars($eventId, ENT_QUOTES, 'UTF-8') . '</code></div>';
}

/** query() — chay SELECT, tra ve mysqli_result hoac FALSE. */
function query(string $sql)
{
    $conn = db();
    $res = mysqli_query($conn, $sql);
    if ($res === false) {
        $eventId = InlaneLogger::logSqlError($sql, mysqli_error($conn), mysqli_errno($conn));
        db_error_notice($eventId);
    }
    return $res;
}

/** exec_write() — chay INSERT/UPDATE/DELETE/CREATE. */
function exec_write(string $sql): bool
{
    $conn = db();
    $ok = mysqli_query($conn, $sql);
    if ($ok === false) {
        $eventId = InlaneLogger::logSqlError($sql, mysqli_error($conn), mysqli_errno($conn));
        db_error_notice($eventId);
        return false;
    }
    return true;
}

/** exec_multi() — chay nhieu cau lenh ngan bang dau cham phay. */
function exec_multi(string $sql): array
{
    $conn = db();
    $out = [];
    if (mysqli_multi_query($conn, $sql)) {
        do {
            if ($res = mysqli_store_result($conn)) {
                while ($row = mysqli_fetch_assoc($res)) {
                    $out[] = $row;
                }
                mysqli_free_result($res);
            }
        } while (mysqli_more_results($conn) && mysqli_next_result($conn));
    }
    if ($err = mysqli_error($conn)) {
        $eventId = InlaneLogger::logSqlError($sql, $err, mysqli_errno($conn));
        db_error_notice($eventId);
    }
    return $out;
}

/** Lay 1 row tien loi. */
function query_one(string $sql): ?array
{
    $res = query($sql);
    if ($res && mysqli_num_rows($res) > 0) {
        return mysqli_fetch_assoc($res);
    }
    return null;
}

// ---------------------------------------------------------------------------
//  Cau lenh chuan bi truoc. Day la cach dung dung cho moi truy van co tham so.
//  $types theo quy uoc mysqli: i so nguyen, d so thuc, s chuoi, b blob.
// ---------------------------------------------------------------------------

/** Tra ve mang cac dong, hoac mang rong khi loi. */
function query_p(string $sql, string $types = '', array $params = []): array
{
    $conn = db();
    $stmt = mysqli_prepare($conn, $sql);
    if ($stmt === false) {
        $eventId = InlaneLogger::logSqlError($sql, mysqli_error($conn), mysqli_errno($conn));
        db_error_notice($eventId);
        return [];
    }
    if ($types !== '') {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    if (!mysqli_stmt_execute($stmt)) {
        $eventId = InlaneLogger::logSqlError($sql, mysqli_stmt_error($stmt), mysqli_stmt_errno($stmt));
        db_error_notice($eventId);
        mysqli_stmt_close($stmt);
        return [];
    }
    $res = mysqli_stmt_get_result($stmt);
    $rows = [];
    if ($res instanceof mysqli_result) {
        while ($row = mysqli_fetch_assoc($res)) {
            $rows[] = $row;
        }
        mysqli_free_result($res);
    }
    mysqli_stmt_close($stmt);
    return $rows;
}

/** Tra ve mot dong hoac null. */
function query_one_p(string $sql, string $types = '', array $params = []): ?array
{
    $rows = query_p($sql, $types, $params);
    return $rows[0] ?? null;
}

/** Chay cau lenh ghi co tham so, tra ve so dong bi anh huong hoac -1 khi loi. */
function exec_write_p(string $sql, string $types = '', array $params = []): int
{
    $conn = db();
    $stmt = mysqli_prepare($conn, $sql);
    if ($stmt === false) {
        $eventId = InlaneLogger::logSqlError($sql, mysqli_error($conn), mysqli_errno($conn));
        db_error_notice($eventId);
        return -1;
    }
    if ($types !== '') {
        mysqli_stmt_bind_param($stmt, $types, ...$params);
    }
    if (!mysqli_stmt_execute($stmt)) {
        $eventId = InlaneLogger::logSqlError($sql, mysqli_stmt_error($stmt), mysqli_stmt_errno($stmt));
        db_error_notice($eventId);
        mysqli_stmt_close($stmt);
        return -1;
    }
    $n = mysqli_stmt_affected_rows($stmt);
    mysqli_stmt_close($stmt);
    return (int) $n;
}
