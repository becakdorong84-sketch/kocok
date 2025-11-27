<?php
/**
 * WP Scanner — Simple Paths Output (Read-only)
 * - Outputs only file paths (one per line)
 * - Scans: wp-content, wp-admin, wp-includes (recursively)
 * - Logs hits to avoid duplicate email alerts
 *
 * IMPORTANT:
 * 1) CHANGE the CONFIG['KEY'] and CONFIG['ALERT_EMAIL'] before use.
 * 2) Protect this script (move outside webroot or protect with .htaccess) after use.
 */

@set_time_limit(0);
error_reporting(0);

// =====================
// CONFIG - MUST CHANGE
// =====================
$CONFIG = [
    'KEY' => 'GANTI_DENGAN_KUNCI_YANG_SULIT',    // <-- CHANGE THIS to a strong secret
    'ALERT_EMAIL' => 'you@example.com',         // <-- CHANGE THIS to your email
    'LOG_FILE' => __DIR__ . '/wp-scanner-simple-log.json',
    'ALLOWED_IPS' => [],                        // optional: ['1.2.3.4'] to restrict
    'SCAN_UPLOADS' => true,                     // scan wp-content/uploads as well
];

// AUTH
if (!isset($_GET['key']) || $_GET['key'] !== $CONFIG['KEY']) {
    http_response_code(403);
    exit('ACCESS DENIED');
}

// optional IP allowlist
if (!empty($CONFIG['ALLOWED_IPS'])) {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!in_array($remote, $CONFIG['ALLOWED_IPS'], true)) {
        http_response_code(403);
        exit('ACCESS DENIED - IP NOT ALLOWED');
    }
}

// Root & targets
$ROOT = rtrim(__DIR__, DIRECTORY_SEPARATOR);
$TARGETS = [
    $ROOT . DIRECTORY_SEPARATOR . 'wp-content',
    $ROOT . DIRECTORY_SEPARATOR . 'wp-admin',
    $ROOT . DIRECTORY_SEPARATOR . 'wp-includes',
];

// Simple signature patterns (broad but effective)
$PATTERNS = [
    '/\beval\s*\(/i',
    '/base64_decode\s*\(/i',
    '/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i',
    '/\b(assert|preg_replace\s*\(.*\/e[\'"]?)/i',
    '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
    '/file_put_contents\s*\([^)]*\.php/i',
    '/(include|require)[^;]{0,120}\$_(GET|POST|REQUEST|COOKIE)/i',
    '/file_get_contents\s*\([^\)]*http/i',
    '/(curl_exec|curl_multi_exec)\s*\(/i',
    '/str_rot13\s*\(/i',
    '/\b(pack|chr|ord)\s*\(/i',
    '/\bgoto\b/i',
    '/\$_FILES\b|move_uploaded_file\s*\(/i',
    '/[\'"][A-Za-z0-9\/+=]{160,}[\'"]/',     // long base64-ish
    '/[\'"][0-9A-Fa-f]{160,}[\'"]/',         // long hex blob
    '/HTTP_USER_AGENT[^;]{0,120}Googlebot/i',
    '/if\s*\(.*(bot|Googlebot|is_bot|is_googlebot).*?\)/i'
];

// load log (ids of previous hits)
$log = [];
if (file_exists($CONFIG['LOG_FILE'])) {
    $j = @file_get_contents($CONFIG['LOG_FILE']);
    $log = $j ? json_decode($j, true) : [];
    if (!is_array($log)) $log = [];
}

// scan function
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
            // skip hidden files
            if (strpos($path, DIRECTORY_SEPARATOR . '.') !== false) continue;

            $content = @file_get_contents($path);
            if ($content === false) continue;

            foreach ($patterns as $rx) {
                if (@preg_match($rx, $content)) {
                    $rel = str_replace($root, '', $path);
                    // ensure leading slash
                    if ($rel === '' || $rel[0] !== '/' ) $rel = '/' . ltrim($rel, '/\\');
                    $out[$path] = $rel;
                    break;
                }
            }
        }
    }
    return $out;
}

// run scan
$results = scan_targets($TARGETS, $PATTERNS, $ROOT);

// determine new hits and update log
$new_hits = [];
foreach ($results as $abs => $rel) {
    $id = md5($abs);
    if (!isset($log[$id])) {
        $log[$id] = time();
        $new_hits[] = $rel;
    }
}

// save log
@file_put_contents($CONFIG['LOG_FILE'], json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// send email if new hits
if (!empty($new_hits) && !empty($CONFIG['ALERT_EMAIL'])) {
    $subject = '⚠ WP Scanner - New suspicious files on ' . ($_SERVER['HTTP_HOST'] ?? 'site');
    $body = "New suspicious files detected:\n\n" . implode("\n", $new_hits) . "\n\nScan root: $ROOT\nTime: " . date('c') . "\n\nNote: This scanner outputs only file paths. Remove scanner after cleanup.";
    @mail($CONFIG['ALERT_EMAIL'], $subject, $body);
}

// Output: plain text UI and HTML copy-friendly UI
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
.wrap{max-width:1100px;margin:0 auto}
h1{color:#ffd1c1;margin:0 0 6px}
.meta{color:#9fb0d7;margin-bottom:12px}
.toolbar{margin:10px 0}
button{background:#2f70b3;color:#fff;border:0;padding:8px 12px;border-radius:6px;margin-right:8px;cursor:pointer}
.output{background:#071021;padding:12px;border-radius:6px;min-height:220px;max-height:560px;overflow:auto;font-family:monospace;font-size:13px;line-height:1.35;border:1px solid #032;color:#cfe8ff}
.badge{display:inline-block;padding:2px 6px;border-radius:4px;background:#18314a;color:#fff;margin-left:6px;font-size:12px}
.footer{margin-top:14px;color:#95a7c8;font-size:13px}
.small{color:#9fb0d7;font-size:13px}
</style>
</head>
<body>
<div class="wrap">
    <h1>WP Scanner — Simple Paths Output</h1>
    <div class="meta">Root: <strong><?php echo htmlspecialchars($ROOT); ?></strong>
        <span class="badge">Found: <?php echo count($results); ?></span>
        <span class="badge">New: <?php echo count($new_hits); ?></span>
    </div>

    <div class="toolbar">
        <button id="copy">Copy ALL</button>
        <button id="download">Download JSON</button>
        <button onclick="location.reload()">Refresh</button>
    </div>

    <div class="output" id="out" contenteditable="false"><?php
        if (empty($results)) {
            echo "No suspicious files found.\n";
        } else {
            // print lines just as requested
            foreach ($results as $rel) {
                echo htmlspecialchars($rel) . "\n";
            }
        }
    ?></div>

    <div class="footer">
        <div class="small">Log: <code><?php echo htmlspecialchars($CONFIG['LOG_FILE']); ?></code></div>
        <div class="small">Security: change KEY & ALERT_EMAIL. Remove this script after cleanup.</div>
    </div>
</div>

<script>
(function(){
    const out = document.getElementById('out');
    document.getElementById('copy').addEventListener('click', async function(){
        try {
            // copy plain text (one path per line)
            const text = out.innerText.trim();
            await navigator.clipboard.writeText(text);
            this.textContent = 'Copied ✓';
            setTimeout(()=> this.textContent = 'Copy ALL', 1500);
        } catch(e) {
            alert('Copy failed: use Select All (Ctrl+A) then Ctrl+C');
        }
    });
    document.getElementById('download').addEventListener('click', function(){
        const data = <?php echo json_encode(array_values($results), JSON_UNESCAPED_SLASHES); ?>;
        const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url;
        a.download = 'wp-scanner-results-<?php echo date("Ymd-His"); ?>.json';
        document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    });
})();
</script>
</body>
</html>
