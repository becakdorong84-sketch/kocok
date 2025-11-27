<?php
/**
 * WP Super Scanner — Secure Final Edition
 * Save as: wp-scanner-secure.php
 *
 * FEATURES:
 * - Scan wp-content, wp-admin, wp-includes recursively for many malware/cloaking signatures
 * - Detect Googlebot cloaking and many obfuscation techniques (eval, base64, goto, preg_replace /e, rot13, chr/pack/ord, long base64/hex blobs, dynamic includes, remote fetchs)
 * - Log hashed hits and only email when new hits appear
 * - Optional backup copy (quarantine) of suspicious files (default OFF)
 * - Dark UI with Copy All and Download JSON (no Run / Delete)
 *
 * SECURITY: Change KEY & ALERT_EMAIL immediately. Consider moving file into non-public folder,
 * protect with .htaccess or restrict by ALLOWED_IPS.
 */

@set_time_limit(0);
error_reporting(0);

// =====================
// CONFIG - MUST CHANGE
// =====================
$CONFIG = [
    'KEY' => 'RAHASIASENPAI',                // <-- CHANGE THIS
    'ALERT_EMAIL' => 'becakdorong84@gmail.com',              // <-- CHANGE THIS
    'LOG_FILE' => __DIR__ . '/wp-scanner-log.json',  // stores md5 ids to avoid duplicate emails
    'ALLOWED_IPS' => [],                              // e.g. ['1.2.3.4','5.6.7.0/24'] empty = allow all
    'AUTO_BACKUP' => false,                           // copy suspicious files to quarantine folder (false by default)
    'QUARANTINE_DIR' => __DIR__ . '/scanner_quarantine', // where backups copy go (if AUTO_BACKUP true)
];

// simple key auth
if (!isset($_GET['key']) || $_GET['key'] !== $CONFIG['KEY']) {
    http_response_code(403);
    exit('ACCESS DENIED');
}

// IP whitelist check (supports plain IPs, no CIDR parsing for simplicity)
if (!empty($CONFIG['ALLOWED_IPS'])) {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $allowed = false;
    foreach ($CONFIG['ALLOWED_IPS'] as $ip) {
        if ($ip === $remote) { $allowed = true; break; }
    }
    if (!$allowed) {
        http_response_code(403);
        exit('ACCESS DENIED - IP NOT ALLOWED');
    }
}

// targets
$ROOT = rtrim(__DIR__, DIRECTORY_SEPARATOR);
$TARGETS = [
    $ROOT . DIRECTORY_SEPARATOR . 'wp-content',
    $ROOT . DIRECTORY_SEPARATOR . 'wp-admin',
    $ROOT . DIRECTORY_SEPARATOR . 'wp-includes'
];

// signature patterns (label => regex)
$PATTERNS = [
    // backdoor / execution
    'eval' => '/\beval\s*\(/i',
    'base64_decode' => '/base64_decode\s*\(/i',
    'gzinflate/gzuncompress/gzdecode' => '/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i',
    'assert' => '/\bassert\s*\(/i',
    'preg_replace_e' => '/preg_replace\s*\(.*\/e[\'"]?/i',
    'system_exec' => '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
    'file_put_php' => '/file_put_contents\s*\([^)]*\.php/i',
    'include_from_var' => '/(include|require|include_once|require_once)[^;]{0,120}\$_(GET|POST|REQUEST|COOKIE)/i',
    'php_input' => '/php:\/\/(input|filter)/i',
    'str_rot13' => '/str_rot13\s*\(/i',
    'goto' => '/\bgoto\b/i',
    'pack_chr_ord' => '/\b(pack|chr|ord)\s*\(/i',
    'long_base64' => '/[\'"][A-Za-z0-9\/+=]{160,}[\'"]/i',
    'long_hex' => '/[\'"][0-9A-Fa-f]{160,}[\'"]/i',
    'dynamic_function_call' => '/\$\{0,1}\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(/i', // loose dynamic calls
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

// Load previous log (map id => timestamp)
$log = [];
if (file_exists($CONFIG['LOG_FILE'])) {
    $json = @file_get_contents($CONFIG['LOG_FILE']);
    $log = $json ? json_decode($json, true) : [];
    if (!is_array($log)) $log = [];
}

// prepare quarantine folder (only if AUTO_BACKUP)
if ($CONFIG['AUTO_BACKUP']) {
    if (!is_dir($CONFIG['QUARANTINE_DIR'])) @mkdir($CONFIG['QUARANTINE_DIR'], 0700, true);
}

// scanning
$results = [];   // id => ['path'=>, 'labels'=>[], 'hash'=>]
$candidates = 0;

foreach ($TARGETS as $t) {
    if (!is_dir($t)) continue;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($t, RecursiveDirectoryIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if (!$file->isFile()) continue;
        $fname = $file->getFilename();
        if (!preg_match('/\.php[0-9]*$/i', $fname)) continue;

        $path = $file->getPathname();
        // skip dotfiles
        if (strpos($path, DIRECTORY_SEPARATOR . '.') !== false) continue;

        $content = @file_get_contents($path);
        if ($content === false) continue;
        $candidates++;

        $matched_labels = [];
        foreach ($PATTERNS as $label => $rx) {
            if (@preg_match($rx, $content)) {
                $matched_labels[] = $label;
            }
        }

        if (!empty($matched_labels)) {
            $id = md5($path . '|' . implode(',', $matched_labels));
            $hash = @hash_file('sha1', $path) ?: '';
            $results[$id] = [
                'path' => str_replace($ROOT, '', $path) ?: $path,
                'labels' => $matched_labels,
                'hash' => $hash
            ];

            // backup if new and AUTO_BACKUP true
            if ($CONFIG['AUTO_BACKUP'] && !isset($log[$id])) {
                $dst = rtrim($CONFIG['QUARANTINE_DIR'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . basename($path) . '.' . substr($hash,0,8) . '.bak';
                @copy($path, $dst);
            }

            // mark new hits in log later
        }
    }
}

// prepare notification for new hits
$new_hits = [];
foreach ($results as $id => $r) {
    if (!isset($log[$id])) {
        $log[$id] = time();
        $new_hits[] = $r['path'] . ' [' . implode(',', $r['labels']) . ']';
    }
}

// save updated log
@file_put_contents($CONFIG['LOG_FILE'], json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// send email if new hits
if (!empty($new_hits) && !empty($CONFIG['ALERT_EMAIL'])) {
    $subject = '⚠ WP Scanner - New suspicious files detected on ' . ($_SERVER['HTTP_HOST'] ?? 'your-site');
    $body = "New suspicious files detected:\n\n" . implode("\n", $new_hits) . "\n\nScan root: $ROOT\nTime: " . date('c') . "\n";
    @mail($CONFIG['ALERT_EMAIL'], $subject, $body);
}

// Output UI (dark) — copy-friendly and JSON download
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WP Super Scanner — Secure</title>
<style>
    body{background:#0b0f14;color:#dfe7ff;font-family:Inter, Roboto, Arial;margin:18px;}
    .wrap{max-width:1100px;margin:0 auto}
    h1{margin:0 0 6px;font-size:20px;color:#ff7b7b}
    .meta{color:#9fb0d7;margin-bottom:12px}
    .toolbar{margin:10px 0}
    button{background:#2f70b3;color:#fff;border:0;padding:8px 12px;border-radius:6px;margin-right:8px;cursor:pointer}
    .output{background:#071021;padding:14px;border-radius:8px;min-height:320px;max-height:560px;overflow:auto;font-family:monospace;font-size:13px;line-height:1.35;border:1px solid #032;}
    .line{color:#ff8b8b;margin-bottom:8px}
    .small{color:#9fb0d7;font-size:13px}
    .note{background:#07202a;border:1px solid #053;padding:10px;border-radius:6px;margin-top:12px;color:#a8e6d0}
    .footer{margin-top:14px;color:#95a7c8;font-size:13px}
</style>
</head>
<body>
<div class="wrap">
    <h1>WP Super Scanner — Secure</h1>
    <div class="meta">Root: <strong><?php echo htmlspecialchars($ROOT); ?></strong> — Candidates scanned: <strong><?php echo $candidates; ?></strong></div>

    <div class="toolbar">
        <button id="copy">Copy ALL</button>
        <button id="download">Download JSON</button>
        <button id="reload" onclick="location.reload()">Refresh</button>
    </div>

    <div class="output" id="out">
<?php
if (empty($results)) {
    echo "<div class='line' style='color:#7fe5a6'>No suspicious files found.</div>";
} else {
    foreach ($results as $r) {
        $path = htmlspecialchars($r['path']);
        $labels = htmlspecialchars(implode(',', $r['labels']));
        echo "<div class='line'>/{$path}  —  [{$labels}]</div>";
    }
}
?>
    </div>

    <div class="note">
        <div class="small">Notes: Script is read-only by default. AUTO_BACKUP is <?php echo $CONFIG['AUTO_BACKUP'] ? 'ON' : 'OFF'; ?>. 
        If you enable AUTO_BACKUP, suspicious files are copied to: <code><?php echo htmlspecialchars($CONFIG['QUARANTINE_DIR']); ?></code></div>
    </div>

    <div class="footer">
        <div class="small">Log file: <code><?php echo htmlspecialchars($CONFIG['LOG_FILE']); ?></code></div>
        <div class="small">Security: Change KEY & ALERT_EMAIL, protect this file with .htaccess or move outside webroot after use.</div>
    </div>
</div>

<script>
(function(){
    const out = document.getElementById('out');
    document.getElementById('copy').addEventListener('click', async function(){
        try {
            const text = Array.from(out.querySelectorAll('.line')).map(n=>n.innerText.trim()).join("\n");
            await navigator.clipboard.writeText(text);
            this.textContent = 'Copied ✓';
            setTimeout(()=> this.textContent = 'Copy ALL', 1500);
        } catch(e){ alert('Copy failed: use Select All'); }
    });
    document.getElementById('download').addEventListener('click', function(){
        const data = <?php echo json_encode(array_values($results), JSON_UNESCAPED_SLASHES); ?>;
        const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = 'wp-scanner-results-<?php echo date("Ymd-His"); ?>.json';
        document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    });
})();
</script>
</body>
</html>
