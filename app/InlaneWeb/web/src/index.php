<?php
/**
 * index.php — Front controller / router.
 * Map cac route "giong that" (URL sach) toi handler tuong ung.
 */
session_start();

require_once __DIR__ . '/lib/logger.php';
require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/layout.php';

// 1. Kích hoạt cơ chế bắt trọn vẹn Cause Exceptions & Mọi lỗi hệ thống (Application Logging)
set_exception_handler(function (\Throwable $e): void {
    InlaneLogger::logException($e, ['request_uri' => $_SERVER['REQUEST_URI'] ?? '']);
    http_response_code(500);
    if (!headers_sent()) {
        header('Content-Type: text/html; charset=utf-8');
    }
    echo '<div class="sql-error"><strong>Application Unhandled Exception:</strong> '
        . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</div>';
    exit(1);
});

set_error_handler(function (int $errno, string $errstr, string $errfile, int $errline): bool {
    if (!(error_reporting() & $errno)) {
        return false;
    }
    InlaneLogger::logPhpError($errno, $errstr, $errfile, $errline);
    return false;
});

// Bắt các lỗi nghiêm trọng gây crash / halt tiến trình tại thời điểm shutdown
register_shutdown_function([InlaneLogger::class, 'logShutdown']);

// Lay path (bo query string), bo dau '/' cuoi
$uri  = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = rtrim($uri, '/');
if ($path === '') { $path = '/'; }
$method = $_SERVER['REQUEST_METHOD'];

// Helper: dispatch toi file handler trong /pages
function page(string $file): void
{
    require __DIR__ . '/pages/' . $file;
    exit;
}

// ---------------------------------------------------------------------------
//  ROUTING
// ---------------------------------------------------------------------------

// Healthcheck endpoint cho CI/CD Smoke Test & Container Orchestration
if ($path === '/health' || $path === '/api/health') {
    header('Content-Type: application/json; charset=utf-8');
    $db_ok = false;
    $db_err = '';
    try {
        $conn = db();
        if ($conn && @mysqli_ping($conn)) {
            $db_ok = true;
        } else {
            $test = @mysqli_query($conn, 'SELECT 1');
            if ($test !== false) {
                $db_ok = true;
            }
        }
    } catch (\Throwable $e) {
        $db_err = $e->getMessage();
    }

    if ($db_ok) {
        http_response_code(200);
        echo json_encode([
            'status' => 'UP',
            'application' => 'InlaneWeb Logistics Portal',
            'database' => 'CONNECTED',
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } else {
        http_response_code(503);
        echo json_encode([
            'status' => 'DOWN',
            'application' => 'InlaneWeb Logistics Portal',
            'database' => 'DISCONNECTED',
            'error' => $db_err,
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
    exit;
}

// Auth
if ($path === '/login')  { page('login.php'); }
if ($path === '/logout') { page('logout.php'); }

// Trang chu & noi dung
if ($path === '/')     { page('home.php'); }
if ($path === '/news') { page('news.php'); }

// Cang bien
if ($path === '/ports') { page('ports.php'); }                       // ?q=  -> UNION
if (preg_match('#^/ports/(.+)$#', $path, $m)) {                      // /ports/{code} -> Error
    $_GET['code'] = urldecode($m[1]);
    page('port_detail.php');
}

// Tra cuu van don (JSON API) -> Time-based
if ($path === '/track')     { page('track.php'); }
if ($path === '/api/track') { page('track_api.php'); }

// Tai khoan
if ($path === '/account')        { page('account.php'); }            // Error-based
if ($path === '/account/update') { page('account_update.php'); }     // UPDATE inject

// Quyen cua chu the du lieu ca nhan
if ($path === '/privacy/erase')  { page('privacy_erase.php'); }      // GDPR Art. 17
if ($path === '/privacy/export') { page('privacy_export.php'); }     // GDPR Art. 15

// Binh luan don hang
if (preg_match('#^/shipments/(\d+)/comments$#', $path, $m)) {        // INSERT inject
    $_GET['shipment_id'] = $m[1];
    page('comment_add.php');
}
if (preg_match('#^/shipments/([^/]+)$#', $path, $m)) {               // chi tiet don hang
    $_GET['id'] = urldecode($m[1]);
    page('shipment_detail.php');
}
if (preg_match('#^/comments/(.+)/delete$#', $path, $m)) {            // DELETE inject
    $_GET['comment_id'] = urldecode($m[1]);
    page('comment_delete.php');
}

// Khu quan tri
if ($path === '/admin')                 { page('admin_dashboard.php'); }
if ($path === '/admin/reports/export')  { page('admin_report_export.php'); } // CREATE inject
if ($path === '/admin/console')         { page('admin_console.php'); }       // Stacked

// Tai bao cao -> OOB
if ($path === '/reports/download') { page('report_download.php'); }

// ---------------------------------------------------------------------------
//  404
// ---------------------------------------------------------------------------
http_response_code(404);
render_header('Không tìm thấy');
echo '<div class="card"><h1>404</h1><p>Không tìm thấy trang: <code>'
    . htmlspecialchars($path) . '</code></p><p><a href="/">Về trang chủ</a></p></div>';
render_footer();
