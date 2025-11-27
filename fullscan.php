<?php
// wp-backdoor-fullscan-ultra.php
// Read-only, ultra-aggressive WP backdoor + HTML/TXT detector (NO .js, NO .json).
// Usage (browser): https://site/wp-backdoor-fullscan-ultra.php?key=RAHASIASENPAI
// Usage (CLI): php wp-backdoor-fullscan-ultra.php
// IMPORTANT: Read-only. Does NOT modify/delete files.

//////////// CONFIG ////////////
$BROWSER_KEY        = 'RAHASIASENPAI'; // change if needed
$EXTS               = ['php','php3','php4','php5','php7','php8','phtml','inc','txt','text','html','htm','xml','bak','old','log']; 
$MAX_FILES          = 400000;           
$MAX_TOTAL_BYTES    = 8 * 1024 * 1024 * 1024; // 8 GB
$SLEEP_EVERY        = 3000;
$SLEEP_US           = 8000;            
/////////////////////////////////

ini_set('memory_limit','3072M');
set_time_limit(0);
error_reporting(0);

// Browser access guard (CLI bypass)
if (php_sapi_name() !== 'cli') {
    $provided = $_GET['key'] ?? '';
    if (!function_exists('hash_equals') || !hash_equals($BROWSER_KEY, $provided)) {
        if (isset($_SERVER['SERVER_PROTOCOL'])) header($_SERVER['SERVER_PROTOCOL'].' 403 Forbidden'); else header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/plain; charset=utf-8');
        echo "403 Forbidden\n";
        exit;
    }
}

// Find WP root by walking up for wp-config.php; fallback to current dir
function find_wp_root($start) {
    $p = realpath($start);
    if ($p === false) return false;
    $tries = 80;
    for ($i=0;$i<$tries;$i++) {
        if (file_exists($p . DIRECTORY_SEPARATOR . 'wp-config.php')) return $p;
        $parent = dirname($p);
        if ($parent === $p) break;
        $p = $parent;
    }
    return realpath($start);
}
$WP_ROOT = find_wp_root(__DIR__);
if (!$WP_ROOT) $WP_ROOT = find_wp_root(getcwd());
if (!$WP_ROOT) $WP_ROOT = realpath(__DIR__);
if ($WP_ROOT === false || !is_dir($WP_ROOT)) {
    $msg = "ERROR: WP root not found. Place this file inside your WP folder or adjust script.\n";
    if (php_sapi_name() === 'cli') { echo $msg; } else { header('Content-Type: text/plain; charset=utf-8'); echo $msg; }
    exit(1);
}

// ---------- Ultra-aggressive patterns (match ANY) ----------
$PATTERNS = [
    '/eval\s*\(/i','/base64_decode\s*\(/i','/gzinflate\s*\(/i','/gzuncompress\s*\(/i','/gzdecode\s*\(/i',
    '/str_rot13\s*\(/i','/preg_replace\s*\(\s*[\'"].+\/e[\'"]/i',
    '/\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(/i','/\bassert\s*\(/i','/\bcreate_function\s*\(/i',
    '/\bfile_put_contents\s*\(/i','/\bfile_get_contents\s*\(/i','/\bfopen\s*\(/i','/\bcurl_exec\s*\(/i',
    '/\bfsockopen\s*\(/i','/\bstream_socket_client\s*\(/i','/\bcopy\s*\(/i',
    '/(include|require|include_once|require_once)[^\n;]*https?:\/\//i',
    '/(include|require|include_once|require_once)\s*\$\w+/i',
    '/(\\\\x[0-9A-Fa-f]{2}){6,}/','/[A-Za-z0-9+\/\s]{120,}={0,2}/','/(?:[0-9A-Fa-f]{2}\\s*){200,}/',
    '/\$\$[A-Za-z0-9_]+/','/\$\{\s*[\'"]?[A-Za-z0-9_]+[\'"]?\s*\}/',
    '/chr\s*\(\s*\d{1,3}\s*\)\s*(?:\.\s*chr\s*\(\s*\d{1,3}\s*\)\s*){6,}/i',
    '/<iframe[^>]*src=[\'"]?https?:\/\/[^\'" >]+[\'" >][^>]*>/i',
    '/<meta[^>]*http-equiv=[\'"]?refresh[\'"]?[^>]*content=/i',
    '/<form[^>]*action=[\'"]\s*https?:\/\//i',
    '/data:[^;]+;base64,[A-Za-z0-9+\/=]{50,}/i',
    '/(backdoor|webshell|phpshell|c99|r57|wso|b374k|sux|adminer|phpinfo)/i',
    '/^.{4000,}$/m',
];

// safe-read helper
function safe_read_full($file) {
    $s = @file_get_contents($file);
    if ($s !== false) return $s;
    $fp = @fopen($file, 'rb');
    if (!$fp) return false;
    $data = '';
    while (!feof($fp)) {
        $chunk = @fread($fp, 8192);
        if ($chunk === false) break;
        $data .= $chunk;
    }
    fclose($fp);
    return $data;
}

// Walk and match
$results = [];
$scanned = 0;
$totalRead = 0;
$unreadable = [];

try {
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($WP_ROOT, RecursiveDirectoryIterator::SKIP_DOTS));
} catch (Exception $e) {
    $err = "Iterator error: " . $e->getMessage();
    if (php_sapi_name() === 'cli') { echo $err . PHP_EOL; } else { header('Content-Type: text/plain; charset=utf-8'); echo $err; }
    exit(1);
}

foreach ($rii as $fileinfo) {
    if (!$fileinfo->isFile()) continue;
    $scanned++;
    if ($scanned > $MAX_FILES) break;

    $ext = strtolower(pathinfo($fileinfo->getFilename(), PATHINFO_EXTENSION));
    if (!in_array($ext, $EXTS, true)) continue;

    if ($totalRead >= $MAX_TOTAL_BYTES) break;

    $real = $fileinfo->getRealPath();
    if ($real === false) continue;

    $content = safe_read_full($real);
    if ($content === false) {
        $unreadable[] = $real;
        continue;
    }

    $totalRead += strlen($content);

    $matched = false;
    foreach ($PATTERNS as $pat) {
        if (@preg_match($pat, $content)) { $matched = true; break; }
    }

    if (!$matched && preg_match('/(^|[\/\._\-])(prv[a-z0-9]{2,}|tmp[a-z0-9]{1,}|cache_|error_|stats_|wp-admin-|wp-login-|xmlrpc|wp-cron|backdoor|webshell|hidden|adminer|phpinfo)/i', $fileinfo->getFilename())) {
        $matched = true;
    }

    if ($matched) {
        $rel = substr($real, strlen($WP_ROOT));
        if ($rel === '') $rel = '/';
        if ($rel[0] !== '/') $rel = '/'.$rel;
        $results[$real] = $rel;
    }

    if (($scanned % $SLEEP_EVERY) === 0) usleep($SLEEP_US);
}

// Prepare output (sorted naturally)
$paths = array_values($results);
sort($paths, SORT_NATURAL | SORT_FLAG_CASE);

// --------------------
// CLI MODE
// --------------------
if (php_sapi_name() === 'cli') {
    if (empty($paths)) echo "No likely backdoor/shell files detected.\n";
    else foreach ($paths as $p) echo $p . PHP_EOL;

    if (!empty($unreadable)) fwrite(STDERR, "Note: unreadable files count=" . count($unreadable) . "\n");
    exit(0);
}

// --------------------
// BROWSER MODE: BEAUTIFUL UI + COPY BUTTON
// --------------------
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
<title>WP Ultra Scanner</title>
<style>
body { background:#111; color:#eee; font-family:Consolas,monospace; margin:20px; }
.box { max-width:900px; margin:auto; background:#1b1b1b; padding:20px; border-radius:10px; box-shadow:0 0 20px rgba(255,255,255,0.1); }
h2 { color:#4be3ff; }
#results { white-space:pre-wrap; background:#000; padding:15px; border-radius:8px; border:1px solid #444; max-height:650px; overflow-y:auto; }
.btn { background:#4be3ff; color:#000; padding:10px 18px; border:none; border-radius:6px; cursor:pointer; font-weight:bold; margin-bottom:10px; }
.btn:hover { background:#00bcd4; }
</style>

<script>
function copyResults() {
    let txt = document.getElementById('results').innerText;
    navigator.clipboard.writeText(txt).then(()=>{ alert("Copied!"); });
}
</script>
</head>
<body>
<div class="box">
    <h2>WP Ultra Backdoor Scanner</h2>
    <button class="btn" onclick="copyResults()">Copy Results</button>
    <div id="results"><?php
        if (empty($paths)) echo "No likely backdoor/shell files detected.\n";
        else foreach ($paths as $p) echo htmlspecialchars($p)."\n";

        if (!empty($unreadable)) echo "\n# Note: unreadable files count=".count($unreadable)."\n";
    ?></div>
</div>
</body>
</html>
