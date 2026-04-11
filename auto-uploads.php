<?php
/**
 * Auto-login the first administrator found on a WordPress installation.
 *
 * WARNING: This script bypasses normal authentication. Use **only** in a
 * controlled environment (e.g., local development, recovery scenarios).
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

/* --------------------------------------------------------------------
 * 1. Locate and load WordPress core
 * -------------------------------------------------------------------- */
$wp_blog_header = find_wp_blog_header($_SERVER['DOCUMENT_ROOT']);

if (!$wp_blog_header || !file_exists($wp_blog_header)) {
    die('WordPress core not found.');
}

require_once $wp_blog_header;

/* --------------------------------------------------------------------
 * 2. Verify we are inside a valid WordPress environment
 * -------------------------------------------------------------------- */
if (!function_exists('wp_get_current_user') || !function_exists('get_users')) {
    die('WordPress functions unavailable.');
}

/* --------------------------------------------------------------------
 * 3. Grab the first admin user
 * -------------------------------------------------------------------- */
$admins = get_users([
    'role'   => 'administrator',
    'number' => 1,
    'fields' => ['ID', 'user_login'],
]);

if (empty($admins)) {
    die('No administrator found.');
}

$admin = $admins[0];

/* --------------------------------------------------------------------
 * 4. Perform the login
 * -------------------------------------------------------------------- */
if (!is_user_logged_in() || !current_user_can('administrator')) {
    wp_clear_auth_cookie();
    wp_set_current_user($admin->ID);
    wp_set_auth_cookie($admin->ID, true); // remember = true
}

/* --------------------------------------------------------------------
 * 5. Redirect to the admin dashboard
 * -------------------------------------------------------------------- */
$redirect_to = admin_url();
wp_safe_redirect($redirect_to);
exit;

/* --------------------------------------------------------------------
 * Helper: Locate wp-blog-header.php starting from a base directory
 * -------------------------------------------------------------------- */
function find_wp_blog_header(string $start_dir): ?string
{
    $search = 'wp-blog-header.php';
    $queue  = [$start_dir];
    $max_depth = 5;               // safety limit
    $depth  = 0;

    while ($queue && $depth < $max_depth) {
        $current = array_shift($queue);
        $items   = @scandir($current);

        if ($items === false) {
            continue;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $path = $current . DIRECTORY_SEPARATOR . $item;

            if (is_dir($path)) {
                $queue[] = $path;
                continue;
            }

            if ($item === $search && is_file($path)) {
                return $path;
            }
        }

        $depth++;
    }

    return null;
}
