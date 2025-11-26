<?php 
/**
 * WP Core Malware Scanner — SIMPLE LIST OUTPUT
 * ONLY show suspicious file paths (no code snippet)
 */

###############################
# CONFIG
###############################
$KEY = "RAHASIASENPAI"; // GANTI KEY KAMU
$ALERT_EMAIL = "becakdorong84@gmail.com"; // EMAIL NOTIFIKASI
$LOG_FILE = __DIR__ . "/scanner-simple-log.json";

if (!isset($_GET['key']) || $_GET['key'] !== $KEY) {
    http_response_code(403);
    exit("ACCESS DENIED");
}

@set_time_limit(0);
$root = rtrim(__DIR__, DIRECTORY_SEPARATOR);
$targets = [
    $root . "/wp-content",
    $root . "/wp-admin",
    $root . "/wp-includes"
];

$patterns = [
    'eval(' => '/\beval\s*\(/i',
    'base64_decode(' => '/base64_decode\s*\(/i',
    'gzdecode' => '/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i',
    'assert(' => '/\bassert\s*\(/i',
    'system|exec' => '/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i',
    'include $_REQUEST' => '/(include|require)[^;]{0,120}\$_(REQUEST|GET|POST|COOKIE)/i',
    'php://input' => '/php:\/\/(input|filter)/i'
];

// load log
$log = file_exists($LOG_FILE) ? (json_decode(file_get_contents($LOG_FILE), true) ?: []) : [];
$newHits = [];
$output = [];
$candidate_count = 0;

function scan_dir($dir, $patterns, &$log, &$newHits, &$output, &$candidate_count) {
    if (!is_dir($dir)) return;
    $rii = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    foreach ($rii as $f) {
        if (!$f->isFile()) continue;
        if (!preg_match('/\.php[0-9]*$/i', $f->getFilename())) continue;

        $path = $f->getPathname();
        $content = @file_get_contents($path);
        if (!$content) continue;
        $candidate_count++;

        foreach ($patterns as $label => $regex) {
            if (preg_match($regex, $content)) {
                $rel = str_replace($GLOBALS['root'], "", $path);
                $id = md5($path . $label);

                $output[$id] = $rel;

                if (!isset($log[$id])) {
                    $log[$id] = time();
                    $newHits[] = $rel;
                }
                break;
            }
        }
    }
}

foreach ($targets as $t) scan_dir($t, $patterns, $log, $newHits, $output, $candidate_count);
file_put_contents($LOG_FILE, json_encode($log, JSON_PRETTY_PRINT));

if ($newHits && $ALERT_EMAIL) {
    @mail($ALERT_EMAIL, "⚠ NEW MALWARE FOUND!", implode("\n", $newHits));
}

header("Content-Type: text/plain");
echo "# Suspicious Files Detected (" . count($output) . " results)\n";
foreach ($output as $path) echo $path . "\n";
