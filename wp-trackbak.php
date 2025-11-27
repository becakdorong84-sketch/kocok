<?php
/**
 * WP Scanner — Simple Paths Output (Read-only)
 * + CLOAKING DETECTOR (added)
 * + Sorted output (added)
 */

@set_time_limit(0);
error_reporting(0);

// =====================
// CONFIG
// =====================
$CONFIG = [
    'KEY' => 'RAHASIASENPAI',
    'ALERT_EMAIL' => 'you@example.com',
    'LOG_FILE' => __DIR__ . '/wp-scanner-simple-log.json',
    'ALLOWED_IPS' => [],
    'SCAN_UPLOADS' => true,
];

// AUTH
if (!isset($_GET['key']) || $_GET['key'] !== $CONFIG['KEY']) {
    http_response_code(403);
    exit('ACCESS DENIED');
}

if (!empty($CONFIG['ALLOWED_IPS'])) {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!in_array($remote, $CONFIG['ALLOWED_IPS'], true)) {
        http_response_code(403);
        exit('ACCESS DENIED');
    }
}

$ROOT = rtrim(__DIR__, DIRECTORY_SEPARATOR);
$TARGETS = [
    $ROOT . '/wp-content',
    $ROOT . '/wp-admin',
    $ROOT . '/wp-includes',
];

// =======================
// SIGNATURES — NORMAL + CLOAKING
// =======================
$PATTERNS = [

    // ——— Normal Malware
    '/\beval\s*\(/i',
    '/base64_decode\s*\(/i',
    '/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i',
    '/(assert|preg_replace\s*\(.*\/e)/i',
    '/(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
    '/file_put_contents\s*\([^)]*\.php/i',
    '/(include|require)[^;]{0,120}\$_(GET|POST|REQUEST|COOKIE)/i',
    '/file_get_contents\s*\(.*http/i',
    '/curl_exec\s*\(/i',

    // ——— Cloaking Detector (baru)
    '/Googlebot/i',
    '/bot|crawler|spider/i',
    '/strpos\s*\(\s*\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT[\'"]\s*\]/i',
    '/if\s*\(.*HTTP_USER_AGENT.*Google/i',
    '/if\s*\(.*(country|geo|IP|REMOTE_ADDR).*?\)/i',
    '/header\s*\(\s*[\'"]Location:/i',
    '/\$_SERVER\s*\[\s*[\'"]HTTP_REFERER[\'"]\s*\]/i',
    '/\$_SERVER\s*\[\s*[\'"]HTTP_X_FORWARDED_FOR[\'"]\s*\]/i'
];

// Load log
$log = [];
if (file_exists($CONFIG['LOG_FILE'])) {
    $j = @file_get_contents($CONFIG['LOG_FILE']);
    $log = $j ? json_decode($j, true) : [];
    if (!is_array($log)) $log = [];
}

function scan_targets($targets, $patterns, $root) {
    $out = [];
    foreach ($targets as $t) {
        if (!is_dir($t)) continue;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($t, RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if (!$file->isFile()) continue;

            $fname = $file->getFilename();
            if (!preg_match('/\.php[0-9]*$/i', $fname)) continue;

            $path = $file->getPathname();
            if (strpos($path, DIRECTORY_SEPARATOR . '.') !== false) continue;

            $content = @file_get_contents($path);
            if ($content === false) continue;

            foreach ($patterns as $rx) {
                if (@preg_match($rx, $content)) {
                    $rel = str_replace($root, '', $path);
                    if ($rel === '' || $rel[0] !== '/') $rel = '/' . ltrim($rel, '/\\');
                    $out[$path] = $rel;
                    break;
                }
            }
        }
    }
    return $out;
}

$results = scan_targets($TARGETS, $PATTERNS, $ROOT);

// ——— Sorting Output (baru)
asort($results);

// NEW hits
$new_hits = [];
foreach ($results as $abs => $rel) {
    $id = md5($abs);
    if (!isset($log[$id])) {
        $log[$id] = time();
        $new_hits[] = $rel;
    }
}

@file_put_contents($CONFIG['LOG_FILE'], json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// Notify by email
if (!empty($new_hits) && !empty($CONFIG['ALERT_EMAIL'])) {
    $subject = '⚠ WP Scanner - NEW suspicious files';
    $body = "New suspicious or cloaking files:\n\n" . implode("\n", $new_hits) . "\n\nRoot: $ROOT\nTime: " . date('c');
    @mail($CONFIG['ALERT_EMAIL'], $subject, $body);
}

// UI
header("Content-Type: text/html; charset=utf-8");
$plain = implode("\n", array_values($results));
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WP Scanner — Simple Paths</title>
<style>
body{background:#0b1220;color:#dfe7ff;font-family:Segoe UI, Roboto, Arial; padding:16px;}
.output{background:#071021;padding:12px; border-radius:6px; min-height:220px; max-height:560px; overflow:auto; font-family:monospace; font-size:13px; line-height:1.35;}
</style>
</head>
<body>

<h1>WP Scanner — Sorted Output</h1>
<div>Found: <?=count($results)?> | New: <?=count($new_hits)?></div>

<div class="output">
<?php
if (empty($results)) echo "No suspicious files found.\n";
else foreach ($results as $rel) echo htmlspecialchars($rel)."\n";
?>
</div>

</body>
</html>
