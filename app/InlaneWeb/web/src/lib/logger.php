<?php
/**
 * lib/logger.php — Bộ thu thập nhật ký ứng dụng InlaneWeb (Application Error & Exception Logger)
 */

class InlaneLogger
{
    /**
     * Xuất nhật ký có cấu trúc theo định dạng JSON tương thích 100% với Promtail
     */
    private static function emit(string $channel, array $data, bool $isError = true): void
    {
        $payload = array_merge([
            'source'    => 'inlaneweb_app',
            'channel'   => $channel,
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        ], $data);

        $line = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($line === false) {
            $line = sprintf('[%s] %s', $channel, serialize($data));
        }

        // Xuất ra stderr để Docker capture và Promtail bóc tách
        file_put_contents($isError ? 'php://stderr' : 'php://stdout', $line . PHP_EOL);
    }

    /**
     * 1. Thu thập toàn bộ ngoại lệ và chuỗi nguyên nhân (Root Cause Analysis)
     */
    public static function logException(\Throwable $e, array $context = []): void
    {
        $causes = [];
        $curr = $e;
        $depth = 0;
        while ($curr !== null && $depth < 10) {
            $causes[] = [
                'depth'   => $depth,
                'class'   => get_class($curr),
                'message' => $curr->getMessage(),
                'code'    => $curr->getCode(),
                'file'    => $curr->getFile(),
                'line'    => $curr->getLine(),
            ];
            $curr = $curr->getPrevious();
            $depth++;
        }

        $rootCause = !empty($causes) ? $causes[count($causes) - 1]['message'] : $e->getMessage();

        self::emit('APP-EXCEPTION', [
            'level'       => 'error',
            'type'        => 'unhandled_exception',
            'class'       => get_class($e),
            'message'     => $e->getMessage(),
            'root_cause'  => $rootCause,
            'file'        => $e->getFile(),
            'line'        => $e->getLine(),
            'cause_chain' => $causes,
            'stack_trace' => explode("\n", $e->getTraceAsString()),
            'context'     => $context,
        ], true);
    }

    /**
     * Rút gọn câu truy vấn thành DẤU VÂN TAY: mọi hằng chuỗi và hằng số bị thay
     * bằng dấu hỏi. Nhờ vậy vẫn nhóm được các lỗi cùng loại để điều tra, nhưng
     * không còn lưu dữ liệu người dùng vừa nhập.
     */
    private static function fingerprint(string $query): string
    {
        $q = preg_replace("/'(?:[^'\\\\]|\\\\.)*'/", '?', $query);
        $q = preg_replace('/"(?:[^"\\\\]|\\\\.)*"/', '?', (string) $q);
        $q = preg_replace('/\b\d+\b/', '?', (string) $q);
        $q = preg_replace('/\s+/', ' ', (string) $q);
        return trim(substr((string) $q, 0, 200));
    }

    /**
     * 2. Thu thập lỗi truy vấn cơ sở dữ liệu.
     *
     * BẢN VÁ P5, GDPR Điều 5(1)(c) về tối giản dữ liệu và CWE-532.
     *
     * Bản cũ ghi `failed_query` là nguyên văn câu lệnh, cộng `error_message` của
     * MariaDB. Cả hai đều mang dữ liệu người dùng vừa nhập: với trang đăng nhập
     * thì đó là tên đăng nhập và mật khẩu, còn thông điệp lỗi của MariaDB nhúng
     * luôn đoạn chuỗi gây lỗi. Promtail đẩy nguyên các trường đó sang Loki.
     *
     * Bản này ghi siêu dữ liệu sự kiện theo khuôn actor, event, target, outcome,
     * kèm một mã sự kiện để đối chiếu khi người dùng báo lỗi, và một dấu vân tay
     * câu lệnh đã bỏ hết hằng. Dấu hiệu tấn công vẫn còn vì vẫn biết ai gọi, gọi
     * tới đâu, loại câu lệnh nào thất bại và mã lỗi là gì.
     */
    public static function logSqlError(string $query, string $errorMessage, int $errorCode = 0): string
    {
        $eventId = bin2hex(random_bytes(6));
        self::emit('APP-EXCEPTION', [
            'level'                 => 'error',
            'type'                  => 'database_query_failure',
            'event_id'              => $eventId,
            'actor'                 => $_SESSION['uid'] ?? null,
            'event'                 => 'db.query.failure',
            'target'                => $_SERVER['SCRIPT_NAME'] ?? 'unknown',
            'outcome'               => 'failure',
            'error_code'            => $errorCode,
            'statement_fingerprint' => self::fingerprint($query),
            'uri'                   => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH),
        ], true);
        return $eventId;
    }

    /**
     * Su kien xac thuc.
     *
     * BAN VA cho khoang trong "missing audit events" trong bang P5 cua tai lieu
     * mon hoc. Ban cu khong phat su kien nao khi dang nhap that bai, nen khong
     * dem duoc so lan that bai theo tung dia chi nguon, va vi vay khong luat canh
     * bao nao phat hien duoc do quet thong tin dang nhap.
     *
     * Chi ghi ten dang nhap DUOC YEU CAU va ket qua. Khong ghi mat khau, khong
     * ghi cau lenh. Dia chi nguon do Apache ghi o dong log rieng cua no.
     */
    public static function logAuthEvent(string $requestedUser, string $outcome): void
    {
        self::emit('AUTH-EVENT', [
            'level'        => $outcome === 'success' ? 'info' : 'warning',
            'type'         => 'authentication',
            'auth_event'   => 'login',
            'auth_outcome' => $outcome,
            'event'        => 'auth.login.' . $outcome,
            'target'       => substr($requestedUser, 0, 64),
            'outcome'      => $outcome,
            'uri'          => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH),
        ], $outcome !== 'success');
    }

    /**
     * 3. Thu thập lỗi PHP runtime (Notice, Warning, Deprecated)
     */
    public static function logPhpError(int $errno, string $errstr, string $errfile, int $errline): void
    {
        if ($errno === E_ERROR || $errno === E_CORE_ERROR || $errno === E_COMPILE_ERROR || $errno === E_USER_ERROR) {
            $level = 'error';
        } elseif ($errno === E_WARNING || $errno === E_CORE_WARNING || $errno === E_COMPILE_WARNING || $errno === E_USER_WARNING) {
            $level = 'warning';
        } else {
            $level = 'notice';
        }

        self::emit('APP-EXCEPTION', [
            'level'    => $level,
            'type'     => 'php_runtime_error',
            'errno'    => $errno,
            'message'  => $errstr,
            'file'     => $errfile,
            'line'     => $errline,
        ], $level === 'error');
    }

    /**
     * 4. Thu thập lỗi nghiêm trọng tại thời điểm shutdown (Out of memory, syntax, fatal crash)
     */
    public static function logShutdown(): void
    {
        $lastError = error_get_last();
        if ($lastError !== null && in_array($lastError['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE], true)) {
            self::emit('APP-EXCEPTION', [
                'level'   => 'fatal',
                'type'    => 'fatal_shutdown_error',
                'errno'   => $lastError['type'],
                'message' => $lastError['message'],
                'file'    => $lastError['file'],
                'line'    => $lastError['line'],
                'uri'     => $_SERVER['REQUEST_URI'] ?? '/',
            ], true);
        }
    }
}
