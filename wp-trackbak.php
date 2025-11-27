<?php
/**
 * WP Super Scanner — Improved Secure Edition
 * Save as: wp-scanner-secure.php
 *
 * Improvements:
 * - Severity levels (HIGH / MEDIUM / LOW)
 * - Built-in whitelist for common plugins/themes to reduce false positives
 * - Recent-file flag (modified within N days)
 * - Detect PHP in uploads, move_uploaded_file, remote fetchs, cloaking checks
 * - Better email formatting with severity & counts
 * - Read-only by default; optional AUTO_BACKUP (copy only)
 *
 * IMPORTANT: Change $CONFIG['KEY'] and $CONFIG['ALERT_EMAIL'] before use.
 * Consider moving file to non-public folder or adding .htaccess protection.
 */

@set_time_limit(0);
error_reporting(0);

// =====================
// CONFIG - MUST CHANGE
// =====================
$CONFIG = [
    'KEY' => 'RAHASIASENPAI',                 // <-- CHANGE THIS (strong random string)
    'ALERT_EMAIL' => 'becakdorong84@gmail.com',// <-- CHANGE THIS
    'LOG_FILE' => __DIR__ . '/wp-scanner-log.json',
    'ALLOWED_IPS' => [],                      // empty = allow all; add your IP(s) to restrict
    'AUTO_BACKUP' => false,                   // if true, copies suspicious files to quarantine dir
    'QUARANTINE_DIR' => __DIR__ . '/scanner_quarantine',
    'RECENT_DAYS' => 14,                      // flag files modified within this many days
    'SCAN_UPLOADS' => true,                   // scan wp-content/uploads for php files
];

// key auth
if (!isset($_GET['key']) || $_GET['key'] !== $CONFIG['KEY']) {
    http_response_code(403);
    exit('ACCESS DENIED');
}

// optional IP allowlist (exact match)
if (!empty($CONFIG['ALLOWED_IPS'])) {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $ok = in_array($remote, $CONFIG['ALLOWED_IPS'], true);
    if (!$ok) {
        http_response_code(403);
        exit('ACCESS DENIED - IP NOT ALLOWED');
    }
}

// ROOT and target dirs
$ROOT = rtrim(__DIR__, DIRECTORY_SEPARATOR);
$TARGETS = [
    $ROOT . '/wp-content',
    $ROOT . '/wp-admin',
    $ROOT . '/wp-includes',
];
if ($CONFIG['SCAN_UPLOADS']) {
    // ensure uploads path is considered (part of wp-content)
    // no change needed; uploads under wp-content will be scanned by default
}

// ==============
// Whitelist: common plugin/theme folders to reduce LOW-level false positives
// Edit this list to match plugins/themes you trust on your site.
// If a file path matches a whitelist entry, LOW severity detections will be suppressed.
// ==============
$WHITELIST_PATHS = [
    '/wp-content/plugins/elementor',
    '/wp-content/plugins/elementor-pro',
    '/wp-content/plugins/duplicator',
    '/wp-content/plugins/woocommerce',
    '/wp-content/themes/astra',
    '/wp-content/plugins/akismet',
    '/wp-content/plugins/contact-form-7',
    // add more as needed...
];

// ==============
// Patterns with severity: HIGH / MEDIUM / LOW
// Regex should be deliberately broad but avoid trivial catches.
// ==============
$PATTERNS = [
    // HIGH (very likely dangerous)
    ['label'=>'system_exec','re'=>'/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i','sev'=>'HIGH','desc'=>'Exec/Shell functions'],
    ['label'=>'eval','re'=>'/\beval\s*\(/i','sev'=>'HIGH','desc'=>'eval() - executes string code'],
    ['label'=>'assert','re'=>'/\bassert\s*\(/i','sev'=>'HIGH','desc'=>'assert() can execute code'],
    ['label'=>'preg_replace_e','re'=>'/preg_replace\s*\(.*\/e[\'"]?/i','sev'=>'HIGH','desc'=>'preg_replace /e (executes code)'],
    ['label'=>'include_request','re'=>'/(include|require|include_once|require_once)[^;]{0,120}\$_(GET|POST|REQUEST|COOKIE)/i','sev'=>'HIGH','desc'=>'Include/require from user input'],
    ['label'=>'move_uploaded_exec','re'=>'/move_uploaded_file\s*\(|is_uploaded_file\s*\(|\$_FILES\b/i','sev'=>'HIGH','desc'=>'File upload handling (possible webshell upload)'],

    // MEDIUM (suspicious obfuscation / remote fetch)
    ['label'=>'base64_decode','re'=>'/base64_decode\s*\(/i','sev'=>'MEDIUM','desc'=>'base64_decode usage'],
    ['label'=>'gzinflate','re'=>'/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i','sev'=>'MEDIUM','desc'=>'gzinflate/gzuncompress (compressed payload)'],
    ['label'=>'str_rot13','re'=>'/str_rot13\s*\(/i','sev'=>'MEDIUM','desc'=>'ROT13 obfuscation'],
    ['label'=>'pack_chr_ord','re'=>'/\b(pack|chr|ord)\s*\(/i','sev'=>'MEDIUM','desc'=>'pack/chr/ord obfuscation'],
    ['label'=>'dynamic_call','re'=>'/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*\$[a-zA-Z_\x7f-\xff]/i','sev'=>'MEDIUM','desc'=>'Dynamic function call (variable function)'],
    ['label'=>'file_get_http','re'=>'/file_get_contents\s*\([^\)]*http/i','sev'=>'MEDIUM','desc'=>'file_get_contents remote HTTP fetch'],
    ['label'=>'curl_exec','re'=>'/(curl_exec|curl_multi_exec)\s*\(/i','sev'=>'MEDIUM','desc'=>'curl remote fetch'],

    // LOW (common but potentially abused - many false positives)
    ['label'=>'long_base64','re'=>'/[\'"][A-Za-z0-9\/+=]{160,}[\'"]/','sev'=>'LOW','desc'=>'Long base64 blob (possible payload)'],
    ['label'=>'long_hex','re'=>'/[\'"][0-9A-Fa-f]{160,}[\'"]/','sev'=>'LOW','desc'=>'Long hex blob'],
    ['label'=>'goto','re'=>'/\bgoto\b/i','sev'=>'LOW','desc'=>'goto used for obfuscation'],
    ['label'=>'header_location','re'=>'/header\s*\(\s*[\'"]Location:/i','sev'=>'LOW','desc'=>'header Location redirect (used for cloaking/redirects)'],
    ['label'=>'ua_googlebot_check','re'=>'/HTTP_USER_AGENT[^;]{0,120}Googlebot/i','sev'=>'LOW','desc'=>'Googlebot string check (possible cloaking)'],
    ['label'=>'conditional_bot','re'=>'/if\s*\(.*(bot|Googlebot|is_bot|is_googlebot).*?\)/i','sev'=>'LOW','desc'=>'Conditional bot checks (cloaking)'],
];

// helper: check if path matches any whitelist prefix
function is_whitelisted($relpath, $whitelist) {
    $p = str_replace('\\','/',$relpath);
    foreach ($whitelist as $wp) {
        $wpn = trim($wp,'/ ');
        if ($wpn === '') continue;
        // match if path contains that segment
        if (stripos($p, '/'.$wpn) !== false || stripos($p, $wpn) === 0) return true;
    }
    return false;
}

// load log
$log = [];
if (file_exists($CONFIG['LOG_FILE'])) {
    $json = @file_get_contents($CONFIG['LOG_FILE']);
    $log = $json ? json_decode($json, true) : [];
    if (!is_array($log)) $log = [];
}

// quarantine folder if enabled
if ($CONFIG['AUTO_BACKUP']) {
    if (!is_dir($CONFIG['QUARANTINE_DIR'])) @mkdir($CONFIG['QUARANTINE_DIR'],0700,true);
}

// scan
$results = []; // each item: ['path'=>, 'labels'=>[], 'hash'=>, 'mtime'=>, 'sev_high'=>bool, 'recent'=>bool]
$candidates = 0;
$now = time();
$recent_seconds = max(0, (int)$CONFIG['RECENT_DAYS']) * 24 * 3600;

foreach ($TARGETS as $t) {
    if (!is_dir($t)) continue;
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($t, RecursiveDirectoryIterator::SKIP_DOTS));
    foreach ($it as $file) {
        if (!$file->isFile()) continue;
        $fname = $file->getFilename();
        if (!preg_match('/\.php[0-9]*$/i', $fname)) continue;

        $path = $file->getPathname();
        // skip hidden dot paths
        if (strpos($path, DIRECTORY_SEPARATOR . '.') !== false) continue;

        $content = @file_get_contents($path);
        if ($content === false) continue;
        $candidates++;

        $matched = [];
        $sev_high = false;
        foreach ($PATTERNS as $p) {
            $ok = @preg_match($p['re'],$content);
            if ($ok) {
                // severity-based whitelist suppression of LOW matches
                // if file is in whitelisted plugin/theme and match severity LOW -> skip this label
                if ($p['sev']==='LOW' && is_whitelisted($path, $WHITELIST_PATHS)) {
                    continue;
                }
                $matched[] = $p['label'];
                if ($p['sev'] === 'HIGH') $sev_high = true;
            }
        }

        if (!empty($matched)) {
            $rel = str_replace($ROOT,'',$path);
            $hash = @hash_file('sha1',$path) ?: '';
            $mtime = @filemtime($path) ?: 0;
            $recent = ($recent_seconds>0 && ($now - $mtime) <= $recent_seconds) ? true : false;

            $id = md5($path . '|' . implode(',',$matched) . '|' . $hash);
            $results[$id] = [
                'path' => $rel ?: $path,
                'labels' => $matched,
                'hash' => $hash,
                'mtime' => $mtime,
                'recent' => $recent,
                'high' => $sev_high
            ];

            // backup copy (safe copy only) if enabled and new
            if ($CONFIG['AUTO_BACKUP'] && !isset($log[$id])) {
                $dst = rtrim($CONFIG['QUARANTINE_DIR'],DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . basename($path) . '.' . substr($hash,0,8) . '.bak';
                @copy($path, $dst);
            }
        }
    }
}

// prepare email for new hits
$new_hits = [];
foreach ($results as $id => $r) {
    if (!isset($log[$id])) {
        $log[$id] = time();
        // include severity marker and recent flag
        $sev = $r['high'] ? 'HIGH' : 'MED';
        $note = $r['recent'] ? ' (recent)' : '';
        $new_hits[] = "{$r['path']} [{$sev}] {$note} - labels: " . implode(',', $r['labels']);
    }
}

// save log
@file_put_contents($CONFIG['LOG_FILE'], json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// email notification
if (!empty($new_hits) && !empty($CONFIG['ALERT_EMAIL'])) {
    $subject = '⚠ WP Scanner - New suspicious files on ' . ($_SERVER['HTTP_HOST'] ?? 'site');
    $body = "New suspicious files detected:\n\n" . implode("\n", $new_hits) . "\n\nScan root: $ROOT\nTime: " . date('c') . "\n\nNotes:\n- HIGH = likely dangerous (exec/include from input etc.)\n- MED = suspicious obfuscation or remote fetch\n- LOW = minor patterns (often false positives, may be whitelisted)\n";
    @mail($CONFIG['ALERT_EMAIL'], $subject, $body);
}

// Output HTML UI (dark) - copy-friendly & JSON download
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WP Super Scanner — Improved Secure</title>
<style>
body{background:#061018;color:#dcecff;font-family:Inter, Roboto, Arial;margin:18px;}
.wrap{max-width:1100px;margin:0 auto}
h1{margin:0 0 6px;font-size:20px;color:#ffd1c1}
.meta{color:#9fb0d7;margin-bottom:12px}
.toolbar{margin:10px 0}
button{background:#2f70b3;color:#fff;border:0;padding:8px 12px;border-radius:6px;margin-right:8px;cursor:pointer}
.output{background:#071021;padding:14px;border-radius:8px;min-height:320px;max-height:640px;overflow:auto;font-family:monospace;font-size:13px;line-height:1.35;border:1px solid #032;}
.line-high{color:#ff8b8b;margin-bottom:8px}
.line-med{color:#ffd59e;margin-bottom:8px}
.line-low{color:#9fb0d7;margin-bottom:8px}
.small{color:#9fb0d7;font-size:13px}
.note{background:#07202a;border:1px solid #053;padding:10px;border-radius:6px;margin-top:12px;color:#a8e6d0}
.footer{margin-top:14px;color:#95a7c8;font-size:13px}
.badge{display:inline-block;padding:2px 6px;border-radius:4px;background:#222;color:#fff;margin-left:6px;font-size:12px}
</style>
</head>
<body>
<div class="wrap">
    <h1>WP Super Scanner — Improved Secure</h1>
    <div class="meta">Root: <strong><?php echo htmlspecialchars($ROOT); ?></strong>
        — Candidates scanned: <strong><?php echo $candidates; ?></strong>
        <span class="badge">New hits: <?php echo count($new_hits); ?></span>
        <span class="badge">Total suspicious: <?php echo count($results); ?></span>
    </div>

    <div class="toolbar">
        <button id="copy">Copy ALL</button>
        <button id="download">Download JSON</button>
        <button id="refresh" onclick="location.reload()">Refresh</button>
    </div>

    <div class="output" id="out">
<?php
if (empty($results)) {
    echo "<div class='line-high' style='color:#7fe5a6'>No suspicious files found.</div>";
} else {
    foreach ($results as $r) {
        $path = htmlspecialchars($r['path']);
        $labels = htmlspecialchars(implode(',', $r['labels']));
        $mtime = $r['mtime'] ? date('Y-m-d H:i:s',$r['mtime']) : 'n/a';
        $recent = $r['recent'] ? ' [recent]' : '';
        if ($r['high']) {
            echo "<div class='line-high'>/{$path}  —  <strong>HIGH</strong>{$recent}  —  labels: [{$labels}]  — mtime: {$mtime}</div>";
        } else {
            echo "<div class='line-med'>/{$path}  —  <strong>MED</strong>{$recent}  —  labels: [{$labels}]  — mtime: {$mtime}</div>";
        }
    }
}
?>
    </div>

    <div class="note">
        <div class="small">Notes: This scanner is read-only by default. AUTO_BACKUP is <?php echo $CONFIG['AUTO_BACKUP'] ? 'ON' : 'OFF'; ?>.
        LOW-severity patterns are suppressed for common whitelisted plugins/themes to reduce false positives.
        Edit whitelist in the script if you trust additional plugins/themes.</div>
    </div>

    <div class="footer">
        <div class="small">Log file: <code><?php echo htmlspecialchars($CONFIG['LOG_FILE']); ?></code></div>
        <div class="small">Quarantine dir: <code><?php echo htmlspecialchars($CONFIG['QUARANTINE_DIR']); ?></code></div>
        <div class="small">Security: Change KEY & ALERT_EMAIL immediately and protect this script. Remove after use.</div>
    </div>
</div>

<script>
(function(){
    const out = document.getElementById('out');
    document.getElementById('copy').addEventListener('click', async function(){
        try {
            const text = Array.from(out.querySelectorAll('div')).map(n=>n.innerText.trim()).join("\n");
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
