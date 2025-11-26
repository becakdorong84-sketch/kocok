<?php
/**
 * WP Core Area Malware Scanner — Alert Edition
 * Scan: wp-content, wp-admin, wp-includes only
 * Access: https://domain.com/scanner-core-alert.php?key=RAHASIA
 */

$key = "GANTIPASSWORD"; // GANTI PASSWORD AKSES!
$alert_email = "becakdorong84@gmail.com"; // GANTI EMAIL TUJUAN ALERT
$log_file = __DIR__ . "/scanner-core-log.json";

if (!isset($_GET['key']) || $_GET['key'] !== $key) {
    http_response_code(403);
    die("ACCESS DENIED!");
}

@set_time_limit(0);

// Direktori Penting WordPress
$targets = [
    __DIR__ . "/wp-content",
    __DIR__ . "/wp-admin",
    __DIR__ . "/wp-includes"
];

echo "<h2>🔍 WP Malware Scanner — Core & Content</h2>";
echo "Scanning target folders:<br>";
foreach ($targets as $t) echo "- <b>$t</b><br>";
echo "<br>";

$patterns = [
    'eval' => '/\beval\s*\(/i',
    'base64_decode' => '/base64_decode\s*\(/i',
    'gzinflate' => '/gzinflate\s*\(/i',
    'gzuncompress' => '/gzuncompress\s*\(/i',
    'system/exec' => '/\b(system|exec|passthru|shell_exec|proc_open|popen)\s*\(/i',
    'assert' => '/\bassert\s*\(/i',
    'include from request' => '/(include|require)[^;]*\$_(REQUEST|POST|GET|COOKIE)/i',
    'file_put to .php' => '/file_put_contents\s*\([^)]*\.php/i',
    'php://input/filter' => '/php:\/\/(input|filter)/i',
    'chr/ord/pack obfusc' => '/(chr\s*\(|ord\s*\(|pack\s*\()/i',
    'ROT13 obfusc' => '/str_rot13\s*\(/i',
    'long base64' => '/["\'][A-Za-z0-9\/+=]{180,}["\']/i',
    'hex blob' => '/["\'][0-9A-Fa-f]{180,}["\']/i',
];

$log = file_exists($log_file) ? json_decode(file_get_contents($log_file), true) : [];
$newHits = [];

function scan_dir($dir, $patterns, &$log, &$newHits) {
    if (!is_dir($dir)) return;
    
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );

    foreach ($it as $file) {
        if (!preg_match('/\.(php|phtml|php[0-9])$/i', $file->getFilename())) continue;

        $path = $file->getPathname();
        $content = @file_get_contents($path);
        if (!$content) continue;

        foreach ($patterns as $label => $regex) {
            if (preg_match_all($regex, $content, $m, PREG_OFFSET_CAPTURE)) {
                foreach ($m[0] as $match) {
                    $line = substr_count($content, "\n", 0, $match[1]) + 1;
                    $id = md5($path.$label.$line);
                    
                    if (!isset($log[$id])) {
                        $snippet = htmlspecialchars(substr($content, $match[1], 160));
                        $log[$id] = [
                            'file' => $path,
                            'rule' => $label,
                            'line' => $line,
                            'snippet' => $snippet,
                            'time' => time()
                        ];
                        $newHits[] = $log[$id];

                        echo "<div style='color:red;margin-bottom:6px'>
                                <b>NEW: {$label}</b> → {$path} (Line {$line})<br>
                                <small><code>{$snippet}...</code></small>
                              </div>";
    }}}}}
}

foreach ($targets as $dir) {
    scan_dir($dir, $patterns, $log, $newHits);
}

file_put_contents($log_file, json_encode($log, JSON_PRETTY_PRINT));

if ($newHits) {
    echo "<br><b style='color:red'>⚠ Ada malware baru terdeteksi!</b><br>";

    $msg = "⚠ Malware Baru ditemukan:\n\n";
    foreach ($newHits as $hit) {
        $msg .= "- {$hit['rule']} @ {$hit['file']} (Line {$hit['line']})\n";
    }
    $msg .= "\nSegera cek server Anda!\n";

    @mail($alert_email, "⚠ NEW Malware Detected on Website", $msg);
    echo "📧 Email Alert terkirim ke: <b>{$alert_email}</b><br>";
} else {
    echo "<b style='color:green'>Tidak ada backdoor baru 🎉</b><br>";
}

echo "<br><small>Log: {$log_file}</small>";
