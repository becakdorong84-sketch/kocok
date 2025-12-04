<?php
error_reporting(0);

$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$remoteIp  = $_SERVER['REMOTE_ADDR'] ?? '';

function isGoogleBot($ip, $ua) {
    if (!preg_match('/googlebot|adsbot-google|mediapartners-google|google-inspectiontool/i', $ua)) {
        return false;
    }

    $hostname = @gethostbyaddr($ip);
    if (!$hostname) return false;

    if (preg_match('/\.googlebot\.com$|\.google\.com$/i', $hostname)) {
        return (gethostbyname($hostname) === $ip);
    }

    return false;
}

function isIndonesia($ip) {
    $cc = @file_get_contents("https://ipapi.co/{$ip}/country/");
    return trim($cc) === 'ID';
}

$isGoogleBot = isGoogleBot($remoteIp, $userAgent);
$isIndonesia = isIndonesia($remoteIp);

// Googlebot atau visitor Indonesia → page hitam
if ($isGoogleBot || $isIndonesia) {
    include __DIR__ . '/live-strip-girl-com.html';
    exit;
}

// Luar Indonesia → page putih
include __DIR__ . '/live-strip-girl-com-category.php';  
exit;
?>
