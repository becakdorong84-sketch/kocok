<?php
/**
 * WP Core Area Malware Scanner — UI Edition (Read-only)
 * Save as: scanner-core-ui.php
 *
 * REQUIRED: Change $KEY and $ALERT_EMAIL before use.
 * USAGE: https://yourdomain.com/scanner-core-ui.php?key=YOURKEY
 *
 * This script ONLY READS files. It will NOT modify or delete anything.
 * After cleanup, remove this file from server.
 */

###############################
# CONFIG - CHANGE THESE
###############################
$KEY = "RAHASIASENPAI";          // <<---- GANTI DENGAN KEYKU
$ALERT_EMAIL = "becakdorong84@gmail.com";         // <<---- GANTI DENGAN EMAIL TUJUAN
$LOG_FILE = __DIR__ . "/scanner-core-ui-log.json"; // menyimpan hits agar email hanya utk temuan baru
###############################

if (!isset($_GET['key']) || $_GET['key'] !== $KEY) {
    http_response_code(403);
    exit("ACCESS DENIED");
}

@set_time_limit(0);
$root = rtrim(__DIR__, DIRECTORY_SEPARATOR);
$targets = [
    $root . DIRECTORY_SEPARATOR . "wp-content",
    $root . DIRECTORY_SEPARATOR . "wp-admin",
    $root . DIRECTORY_SEPARATOR . "wp-includes"
];

// patterns to detect
$patterns = [
    'eval(' => '/\beval\s*\(/i',
    'base64_decode(' => '/base64_decode\s*\(/i',
    'gzinflate/gzuncompress/gzdecode' => '/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i',
    'assert(' => '/\bassert\s*\(/i',
    'system/exec' => '/\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i',
    'include/require from _REQUEST/GET/POST/COOKIE' => '/(include|require|include_once|require_once)[^;]{0,120}\$_(REQUEST|GET|POST|COOKIE)/i',
    'file_put_contents *.php' => '/file_put_contents\s*\([^)]*\.php/i',
    'php://input or filter' => '/php:\/\/(input|filter)/i',
    'str_rot13' => '/str_rot13\s*\(/i',
    'chr/ord/pack obfusc' => '/\b(chr|ord|pack)\s*\(/i',
    'long base64 string' => '/["\'][A-Za-z0-9\/+=]{160,}["\']/i',
    'hex blob string' => '/["\'][0-9A-Fa-f]{160,}["\']/i'
];

// load previous log
$log = [];
if (file_exists($LOG_FILE)) {
    $json = @file_get_contents($LOG_FILE);
    $log = $json ? json_decode($json, true) : [];
    if (!is_array($log)) $log = [];
}

$newHits = [];
$output_lines = [];
$candidate_count = 0;

function scan_directory($dir, $patterns, &$log, &$newHits, &$output_lines, &$candidate_count) {
    if (!is_dir($dir)) return;
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));
    foreach ($rii as $file) {
        if (!$file->isFile()) continue;
        $fname = $file->getFilename();
        // only scan common php file extensions
        if (!preg_match('/\.(php|phtml|php[0-9])$/i', $fname)) continue;

        $path = $file->getPathname();
        $content = @file_get_contents($path);
        if ($content === false) continue;

        $candidate_count++;
        foreach ($patterns as $label => $regex) {
            if (preg_match_all($regex, $content, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $match) {
                    $offset = $match[1];
                    $line = substr_count($content, "\n", 0, $offset) + 1;
                    $snippet = trim(substr($content, $offset, 200));
                    // sanitize snippet for HTML output
                    $snippet_html = htmlspecialchars($snippet, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                    // unique id for this hit
                    $id = md5($path . '|' . $label . '|' . $line);
                    $record = [
                        'id' => $id,
                        'file' => $path,
                        'label' => $label,
                        'line' => $line,
                        'snippet' => $snippet_html,
                        'time' => time()
                    ];
                    // prepare output line (format: label => file (line): snippet)
                    $output_lines[] = $record;
                    if (!isset($log[$id])) {
                        $log[$id] = $record;
                        $newHits[] = $record;
                    }
                }
            }
        }
    }
}

// run scan on each target dir
foreach ($targets as $t) {
    scan_directory($t, $patterns, $log, $newHits, $output_lines, $candidate_count);
}

// save updated log
@file_put_contents($LOG_FILE, json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// send email alert if new hits
if (!empty($newHits) && !empty($ALERT_EMAIL)) {
    $subject = "⚠ New Malware Hits on Your Site";
    $message = "New suspicious files detected on site: " . $_SERVER['HTTP_HOST'] . "\n\n";
    foreach ($newHits as $h) {
        $message .= "{$h['label']} @ {$h['file']} (Line {$h['line']})\n";
    }
    $message .= "\nCount: " . count($newHits) . "\n";
    @mail($ALERT_EMAIL, $subject, $message);
}

// HTML output (UI)
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WP Fullscan Backdoor / Shell Finder — Simple List</title>
<style>
    body{font-family: Inter, Roboto, Arial; background:#f6f7fb; color:#222; padding:18px}
    .wrap{max-width:1100px;margin:0 auto}
    h1{margin:0 0 8px;font-size:20px}
    .meta{color:#666;margin-bottom:12px}
    .buttons{margin:10px 0}
    button{background:#2b6cb0;color:#fff;border:0;padding:8px 12px;border-radius:6px;margin-right:6px;cursor:pointer}
    button.secondary{background:#4a5568}
    .output{background:#0b1220;color:#cfcfff;padding:14px;border-radius:6px;min-height:320px;max-height:540px;overflow:auto;font-family:monospace;font-size:12px;line-height:1.35;border:1px solid #000;}
    .hit{color:#ff6b6b;margin-bottom:6px}
    .hit small{color:#ffd6d6}
    .summary{margin-top:8px;color:#333}
    .notice{background:#fff3cd;border:1px solid #ffeeba;padding:8px;border-radius:6px;margin-top:8px;color:#856404}
    .footer{margin-top:18px;color:#666;font-size:13px}
    .count{font-weight:700}
    .copyhint{margin-left:6px;color:#ddd;font-size:12px}
</style>
</head>
<body>
<div class="wrap">
    <h1>WP Fullscan Backdoor / Shell Finder — Simple List</h1>
    <div class="meta">WP Root: <b><?php echo htmlspecialchars($root); ?></b> — Candidates scanned: <span class="count"><?php echo $candidate_count; ?></span></div>

    <div class="buttons">
        <button id="copyAll">Copy ALL results</button>
        <button id="selectAll" class="secondary">Select All</button>
        <button id="downloadJSON" class="secondary">Download JSON</button>
    </div>

    <div class="output" id="outputArea" contenteditable="false">
<?php
if (empty($output_lines)) {
    echo "<div style='color:#98fb98'>No suspicious constructs found in the scanned folders.</div>";
} else {
    // print lines similar to screenshot: /path/to/file.php (Line N) — LABEL → snippet
    foreach ($output_lines as $rec) {
        $file_disp = htmlspecialchars(str_replace($root, '', $rec['file']), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        echo "<div class='hit'>";
        echo "/{$file_disp} <span style='color:#ffb86b'>(Line {$rec['line']})</span> — <b style='color:#ff7b7b'>{$rec['label']}</b><br>";
        echo "<small>{$rec['snippet']}</small>";
        echo "</div>";
    }
}
?>
    </div>

    <div class="summary">
        <b><?php echo count($output_lines); ?></b> total matches — <b><?php echo count($newHits); ?></b> new (email sent if >0).
    </div>

    <div class="notice">
        Read-only scanner — does NOT modify or delete files. After cleanup, <b>remove this script</b> from your server.
    </div>

    <div class="footer">
        Log file: <code><?php echo htmlspecialchars($LOG_FILE); ?></code>
        &nbsp;|&nbsp; To run again, refresh this page. Tip: protect access with .htaccess or move file outside webroot after use.
    </div>
</div>

<script>
// Select all text in output div
document.getElementById('selectAll').addEventListener('click', function(){
    let el = document.getElementById('outputArea');
    if (window.getSelection && document.createRange) {
        let range = document.createRange();
        range.selectNodeContents(el);
        let sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
    }
});
// Copy all results to clipboard
document.getElementById('copyAll').addEventListener('click', async function(){
    let el = document.getElementById('outputArea');
    // Get plain text
    let text = Array.from(el.querySelectorAll('.hit')).map(function(div){
        // collapse whitespace, replace multiple spaces/newlines
        return div.innerText.replace(/\s+\n/g, "\n").replace(/\n{2,}/g, "\n").trim();
    }).join("\n");
    try {
        await navigator.clipboard.writeText(text || el.innerText);
        this.innerText = "Copied ✓";
        setTimeout(()=> this.innerText = "Copy ALL results", 1800);
    } catch (e) {
        alert("Copy failed. Use Select All + Ctrl+C.");
    }
});
// Download JSON of results
document.getElementById('downloadJSON').addEventListener('click', function(){
    var data = <?php echo json_encode($output_lines, JSON_UNESCAPED_SLASHES); ?>;
    var blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    var url  = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'scanner-results-<?php echo date("Ymd-His"); ?>.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
});
</script>
</body>
</html>
