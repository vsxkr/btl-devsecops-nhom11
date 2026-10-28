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
     * 2. Thu thập lỗi truy vấn cơ sở dữ liệu
     */
    public static function logSqlError(string $query, string $errorMessage, int $errorCode = 0): void
    {
        self::emit('APP-EXCEPTION', [
            'level'         => 'error',
            'type'          => 'database_query_failure',
            'error_code'    => $errorCode,
            'error_message' => $errorMessage,
            'failed_query'  => $query,
            'file'          => $_SERVER['SCRIPT_FILENAME'] ?? 'unknown',
            'uri'           => $_SERVER['REQUEST_URI'] ?? '/',
        ], true);
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
