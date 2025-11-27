<?php
// === WP Backdoor Deep Scanner — output satu-per-baris ===
// Ekstensi sesuai perintah kamu
// wp-backdoor-fullscan-deep.php
// Read-only, high-sensitivity WP backdoor + HTML/TXT deep scanner.
// Browser usage: https://site/wp-backdoor-fullscan-deep.php?key=RAHASIASENPAI
// CLI usage: php wp-backdoor-fullscan-deep.php
// DOES NOT MODIFY OR DELETE FILES.

//////////// CONFIG ////////////
$BROWSER_KEY        = 'RAHASIASENPAI';    // required for browser access
$EXTS               = ['php','php3','php4','php5','php7','php8','phtml','inc','txt','html','htm'];
$MAX_FILES          = 200000;             // safety cap on number of files scanned
$MAX_TOTAL_BYTES    = 4 * 1024 * 1024 * 1024; // 4 GB total read cap
$SLEEP_EVERY        = 2000;
$SLEEP_US           = 15000;              // 15 ms
$SCORE_THRESHOLD    = 1;                  // >=1 marks candidate
$ext_allow = ['php','phtml','php5','phar','txt','inc'];

$patterns = [
    'eval\s*\(',
    'base64_decode',
    'gzinflate',
    'gzuncompress',
    'str_rot13',
    'shell_exec',
    'exec\s*\(',
    'system\s*\(',
    'passthru',
    'assert\s*\(',
    'preg_replace\s*\(.*e',
    'file_put_contents',
    'move_uploaded_file',
    '\$_POST',
    '\$_GET',
    '\$_REQUEST',
    'curl_exec'
];

// Heuristics & patterns (broader; includes HTML/TXT patterns)
$PATTERNS = [
    // PHP obfuscation & eval combos
    '/eval\s*\(\s*base64_decode\s*\(/i',
    '/eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/i',
    '/gzinflate\s*\(\s*base64_decode\s*\(/i',
    '/base64_decode\s*\(/i',
    '/gzinflate\s*\(/i',
    '/gzuncompress\s*\(/i',
    '/str_rot13\s*\(/i',
    // dangerous code execution
    '/\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(/i',
    '/\bassert\s*\(/i',
    '/\bcreate_function\s*\(/i',
    '/file_put_contents\s*\(/i',
    '/curl_exec\s*\(/i',
    '/fsockopen\s*\(/i',
    // remote include / file_get_contents remote (php)
    '/(include|require|include_once|require_once)[^\n;]*https?:\/\//i',
    '/fopen\s*\(\s*[\'"]https?:\/\//i',
    '/file_get_contents\s*\(\s*[\'"]https?:\/\//i',
    // preg /e obfuscation
    '/preg_replace\s*\(\s*[\'"].+\/e[\'"]/i',
    // hex escapes common in obf
    '/(\\\\x[0-9A-Fa-f]{2}){6,}/',
    // Long continuous base64-like blobs (in any file)
    '/[A-Za-z0-9+\/\s]{200,}={0,2}/',
    // common backdoor function names / comments
    '/(backdoor|webshell|phpshell|c99|r57|shell_exec|web-socket)/i'

// cloaking and bot-detection logic
    'ua_googlebot' => '/HTTP_USER_AGENT[^;]{0,120}Googlebot/i',
    'server_ua_google' => '/\$_SERVER\[[\'"]HTTP_USER_AGENT[\'"]\].*Googlebot/i',
    'dns_or_ip_check' => '/(dns_get_record|gethostbyaddr|gethostbyname|checkdnsrr)\s*\(/i',
    'header_location_redirect' => '/header\s*\(\s*[\'"]Location:/i',
    'wp_redirect' => '/\bwp_redirect\s*\(/i',
    'curl_remote' => '/(curl_exec|curl_multi_exec)\s*\(/i',
    'file_get_contents_remote' => '/file_get_contents\s*\([^\)]*http/i',
    'conditional_bot_check' => '/if\s*\(.*(bot|Googlebot|is_bot|is_googlebot).*?\)/i'
];

// HTML/TXT specific suspicious snippets (deep scan)
$HTML_PATTERNS = [
    // base64 inside script or data URIs
    '/data:text\/javascript;base64,[A-Za-z0-9+\/=]{40,}/i',
    '/<script[^>]*>[^<]{0,200}(?:base64|gzinflate|unescape|atob|fromCharCode)[\s\S]{0,200}<\/script>/i',
    // hidden iframe or iframe to external
    '/<iframe[^>]+src=[\'"]?https?:\/\/[^\'" >]+[\'" >][^>]*>/i',
    '/<iframe[^>]+style=[\'"][^\'"]*(display\s*:\s*none|visibility\s*:\s*hidden)[^\'"]*[\'"][^>]*>/i',
    // meta refresh redirect
    '/<meta[^>]*http-equiv=[\'"]?refresh[\'"]?[^>]*content=[\'"]?[0-9]+;\s*url=https?:\/\//i',
    // form posting to absolute external domains (phishing)
    '/<form[^>]*action=[\'"]\s*https?:\/\//i',
    // suspicious obfuscated comments/tokens
    '/<!--\s*(base64|obfuscated|malicious|injected)\s*-->/i',
    // long non-alnum sequences inside html (indicating embedded blob)
    '/[^\x20-\x7E]{100,}/'
];

// filename heuristics (random-looking names, typical disguises)
$NAME_TOKENS = '/(^|[\/\._\-])((prv[a-z0-9]{2,}|tmp[a-z0-9]{1,}|cache_|error_|stats_|\.cache_|\.local_|\.wp-admin_|wp-admin_|wp-login_|xmlrpc|xmlrpcs|wp-cron|backdoor|webshell|shell|sx|mrec|hidden|adminer|phpinfo)|([a-z0-9]{4,}\d+[a-z0-9]{1,}\.(php|phtml|inc|txt|html|htm)$))/i';

function scan_dir_deep($dir, $ext_allow, $patterns, &$result) {
    $items = scandir($dir);
    foreach ($items as $i) {
        if ($i === '.' || $i === '..') continue;

        $path = $dir . '/' . $i;

        if (is_dir($path)) {
            scan_dir_deep($path, $ext_allow, $patterns, $result);
            continue;
        }

        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (!in_array($ext, $ext_allow)) continue;

        $content = @file_get_contents($path);
        if (!$content) continue;

        foreach ($patterns as $p) {
            if (preg_match("/$p/i", $content)) {
                $result[] = $path;
                break;
            }
        }
    }
}

$result = [];
scan_dir_deep(__DIR__, $ext_allow, $patterns, $result);

echo "<h2>🔥 Hasil Deep Scan</h2>";

if (empty($result)) {
    echo "<div style='color:green;font-size:20px;font-weight:bold;'>✔ Tidak ada backdoor ditemukan.</div>";
} else {
    echo "<pre style='font-size:16px;line-height:1.4;'>";
    foreach ($result as $r) {
        echo $r . "\n"; // <=== SATU PER BARIS 🔥
    }
    echo "</pre>";
}

// ===== CEK CLOAKING FILE =====
echo "<hr><h3>📌 Cek file cloaking</h3>";

$cloak = __DIR__ . "/cloaking.php";
echo file_exists($cloak)
    ? "✔ <b>cloaking.php</b> ditemukan."
    : "❌ <b>cloaking.php</b> tidak ditemukan.";
?>
