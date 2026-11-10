<?php
/**
 * Plugin Name: Security Headers
 * Plugin URI: https://github.com/Azanumer/wp-security-headers
 * Description: Sends hardened HTTP security headers — HSTS, CSP (with per-request nonces), X-Frame-Options, Referrer-Policy and Permissions-Policy — from one Settings page. No .htaccess or server config needed.
 * Version: 1.0.0
 * Author: Azan Umer
 * Author URI: https://azanumer.cv
 * License: MIT
 * License URI: https://opensource.org/licenses/mit-license.php
 * Text Domain: wsh
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WSH_VERSION', '1.0.0' );
define( 'WSH_OPTION', 'wsh_settings' );

/**
 * Default settings.
 *
 * CSP is OFF by default and report-only when first enabled: a bad policy
 * can break a site, so it should be proven in report-only mode first.
 *
 * @return array
 */
function wsh_default_settings() {
	return array(
		'hsts'               => true,
		'hsts_max_age'       => 31536000, // 1 year.
		'hsts_subdomains'    => true,
		'hsts_preload'       => false,
		'nosniff'            => true,
		'frame_options'      => 'SAMEORIGIN', // DENY | SAMEORIGIN | '' (off).
		'referrer_policy'    => 'strict-origin-when-cross-origin',
		'permissions_policy' => 'camera=(), microphone=(), geolocation=()',
		'csp_enabled'        => false,
		'csp'                => "default-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
		'csp_report_only'    => true,
		'csp_report_uri'     => '',
	);
}

/**
 * Merged settings.
 *
 * @return array
 */
function wsh_get_settings() {
	$saved = get_option( WSH_OPTION, array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}
	return array_merge( wsh_default_settings(), $saved );
}

/**
 * Per-request CSP nonce, generated once and reused for the whole request.
 *
 * Themes/plugins can output it with wsh_nonce_attr() (see below).
 *
 * @return string Base64 nonce.
 */
function wsh_csp_nonce() {
	static $nonce = null;
	if ( null === $nonce ) {
		$nonce = base64_encode( random_bytes( 16 ) );
	}
	/**
	 * Filters the CSP nonce for this request.
	 *
	 * @param string $nonce The generated nonce.
	 */
	return apply_filters( 'wsh_csp_nonce', $nonce );
}

/**
 * Ready-to-paste nonce attribute for an inline <script> or <style> tag.
 *
 * Usage in a theme: <script <?php echo wsh_nonce_attr(); ?>>…
 *
 * @return string e.g. nonce="AbCd..." or '' when CSP is disabled.
 */
function wsh_nonce_attr() {
	$settings = wsh_get_settings();
	if ( empty( $settings['csp_enabled'] ) ) {
		return '';
	}
	return 'nonce="' . esc_attr( wsh_csp_nonce() ) . '"';
}

/**
 * Send the configured headers on every front-end (and admin) response.
 */
function wsh_send_headers() {
	if ( headers_sent() ) {
		return;
	}
	$settings = wsh_get_settings();

	// HSTS only makes sense over HTTPS; sending it over HTTP is ignored
	// by browsers and would be misleading.
	if ( ! empty( $settings['hsts'] ) && is_ssl() ) {
		$value = 'max-age=' . (int) $settings['hsts_max_age'];
		if ( ! empty( $settings['hsts_subdomains'] ) ) {
			$value .= '; includeSubDomains';
		}
		if ( ! empty( $settings['hsts_preload'] ) ) {
			$value .= '; preload';
		}
		header( 'Strict-Transport-Security: ' . $value );
	}

	if ( ! empty( $settings['nosniff'] ) ) {
		header( 'X-Content-Type-Options: nosniff' );
	}

	if ( in_array( $settings['frame_options'], array( 'DENY', 'SAMEORIGIN' ), true ) ) {
		header( 'X-Frame-Options: ' . $settings['frame_options'] );
	}

	if ( '' !== trim( (string) $settings['referrer_policy'] ) ) {
		header( 'Referrer-Policy: ' . trim( (string) $settings['referrer_policy'] ) );
	}

	if ( '' !== trim( (string) $settings['permissions_policy'] ) ) {
		header( 'Permissions-Policy: ' . trim( (string) $settings['permissions_policy'] ) );
	}

	if ( ! empty( $settings['csp_enabled'] ) && '' !== trim( (string) $settings['csp'] ) ) {
		$csp = trim( (string) $settings['csp'] );
		// {nonce} in the policy is replaced with this request's nonce.
		$csp = str_replace( '{nonce}', "'nonce-" . wsh_csp_nonce() . "'", $csp );
		if ( '' !== trim( (string) $settings['csp_report_uri'] ) ) {
			$csp .= '; report-uri ' . trim( (string) $settings['csp_report_uri'] );
		}
		$header = ! empty( $settings['csp_report_only'] ) ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
		header( $header . ': ' . $csp );
	}
}
add_action( 'send_headers', 'wsh_send_headers', 1 );

/**
 * Sanitize settings on save.
 *
 * @param array $input Raw submitted values.
 * @return array Clean values.
 */
function wsh_sanitize_settings( $input ) {
	$defaults = wsh_default_settings();
	$clean    = array();

	$clean['hsts']            = ! empty( $input['hsts'] );
	$clean['hsts_max_age']    = isset( $input['hsts_max_age'] ) ? max( 0, min( 63072000, (int) $input['hsts_max_age'] ) ) : $defaults['hsts_max_age'];
	$clean['hsts_subdomains'] = ! empty( $input['hsts_subdomains'] );
	$clean['hsts_preload']    = ! empty( $input['hsts_preload'] );
	$clean['nosniff']         = ! empty( $input['nosniff'] );

	$clean['frame_options'] = isset( $input['frame_options'] ) && in_array( $input['frame_options'], array( 'DENY', 'SAMEORIGIN', '' ), true )
		? $input['frame_options'] : $defaults['frame_options'];

	$referrer_policies = array(
		'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
		'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url', '',
	);
	$clean['referrer_policy'] = isset( $input['referrer_policy'] ) && in_array( $input['referrer_policy'], $referrer_policies, true )
		? $input['referrer_policy'] : $defaults['referrer_policy'];

	// Permissions-Policy and CSP are free-form directives: strip tags and
	// newlines so a header-injection attempt cannot smuggle in a second
	// header, but otherwise pass the value through verbatim.
	$clean['permissions_policy'] = isset( $input['permissions_policy'] )
		? preg_replace( '/[\r\n]+/', ' ', wp_strip_all_tags( (string) $input['permissions_policy'] ) ) : '';
	$clean['csp'] = isset( $input['csp'] )
		? preg_replace( '/[\r\n]+/', ' ', wp_strip_all_tags( (string) $input['csp'] ) ) : '';

	$clean['csp_enabled']     = ! empty( $input['csp_enabled'] );
	$clean['csp_report_only'] = ! empty( $input['csp_report_only'] );
	$clean['csp_report_uri']  = isset( $input['csp_report_uri'] )
		? esc_url_raw( trim( (string) $input['csp_report_uri'] ) ) : '';

	return $clean;
}

/**
 * Register the settings group.
 */
function wsh_register_settings() {
	register_setting( 'wsh_settings_group', WSH_OPTION, array(
		'sanitize_callback' => 'wsh_sanitize_settings',
		'default'           => wsh_default_settings(),
	) );
}
add_action( 'admin_init', 'wsh_register_settings' );

/**
 * Register the Settings page.
 */
function wsh_register_page() {
	add_options_page(
		__( 'Security Headers', 'wsh' ),
		__( 'Security Headers', 'wsh' ),
		'manage_options',
		'wsh-security-headers',
		'wsh_render_page'
	);
}
add_action( 'admin_menu', 'wsh_register_page' );

/**
 * Render the Settings page.
 */
function wsh_render_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to view this page.', 'wsh' ) );
	}
	$settings = wsh_get_settings();
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Security Headers', 'wsh' ); ?></h1>
		<p><?php esc_html_e( 'Headers are sent on every response. HSTS is only sent over HTTPS. CSP starts in report-only mode — check your browser console for violations before enforcing it.', 'wsh' ); ?></p>

		<form method="post" action="options.php">
			<?php settings_fields( 'wsh_settings_group' ); ?>

			<h2><?php esc_html_e( 'Strict-Transport-Security (HSTS)', 'wsh' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row"><?php esc_html_e( 'Enable HSTS', 'wsh' ); ?></th>
					<td>
						<label><input type="checkbox" name="<?php echo esc_attr( WSH_OPTION ); ?>[hsts]" value="1" <?php checked( $settings['hsts'] ); ?>> <?php esc_html_e( 'Send Strict-Transport-Security (HTTPS only)', 'wsh' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wsh_max_age"><?php esc_html_e( 'Max age (seconds)', 'wsh' ); ?></label></th>
					<td><input type="number" id="wsh_max_age" name="<?php echo esc_attr( WSH_OPTION ); ?>[hsts_max_age]" min="0" max="63072000" step="86400" value="<?php echo esc_attr( $settings['hsts_max_age'] ); ?>">
					<p class="description"><?php esc_html_e( '31536000 = 1 year. Only raise this once you are sure HTTPS works everywhere.', 'wsh' ); ?></p></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'HSTS options', 'wsh' ); ?></th>
					<td>
						<label style="display:block"><input type="checkbox" name="<?php echo esc_attr( WSH_OPTION ); ?>[hsts_subdomains]" value="1" <?php checked( $settings['hsts_subdomains'] ); ?>> <?php esc_html_e( 'includeSubDomains', 'wsh' ); ?></label>
						<label style="display:block"><input type="checkbox" name="<?php echo esc_attr( WSH_OPTION ); ?>[hsts_preload]" value="1" <?php checked( $settings['hsts_preload'] ); ?>> <?php esc_html_e( 'preload (only tick this if the domain is submitted to hstspreload.org)', 'wsh' ); ?></label>
					</td>
				</tr>
			</table>

			<h2><?php esc_html_e( 'Other headers', 'wsh' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row"><?php esc_html_e( 'X-Content-Type-Options', 'wsh' ); ?></th>
					<td><label><input type="checkbox" name="<?php echo esc_attr( WSH_OPTION ); ?>[nosniff]" value="1" <?php checked( $settings['nosniff'] ); ?>> <?php esc_html_e( 'Send nosniff (stops browsers MIME-sniffing responses)', 'wsh' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="wsh_frame"><?php esc_html_e( 'X-Frame-Options', 'wsh' ); ?></label></th>
					<td>
						<select id="wsh_frame" name="<?php echo esc_attr( WSH_OPTION ); ?>[frame_options]">
							<option value="SAMEORIGIN" <?php selected( $settings['frame_options'], 'SAMEORIGIN' ); ?>><?php esc_html_e( 'SAMEORIGIN — only this site may frame pages', 'wsh' ); ?></option>
							<option value="DENY" <?php selected( $settings['frame_options'], 'DENY' ); ?>><?php esc_html_e( 'DENY — nobody may frame pages', 'wsh' ); ?></option>
							<option value="" <?php selected( $settings['frame_options'], '' ); ?>><?php esc_html_e( 'Off — use CSP frame-ancestors instead', 'wsh' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wsh_referrer"><?php esc_html_e( 'Referrer-Policy', 'wsh' ); ?></label></th>
					<td>
						<select id="wsh_referrer" name="<?php echo esc_attr( WSH_OPTION ); ?>[referrer_policy]">
							<?php foreach ( array( 'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url', '' ) as $policy ) : ?>
								<option value="<?php echo esc_attr( $policy ); ?>" <?php selected( $settings['referrer_policy'], $policy ); ?>><?php echo '' === $policy ? esc_html__( 'Off', 'wsh' ) : esc_html( $policy ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wsh_permissions"><?php esc_html_e( 'Permissions-Policy', 'wsh' ); ?></label></th>
					<td>
						<input type="text" id="wsh_permissions" name="<?php echo esc_attr( WSH_OPTION ); ?>[permissions_policy]" class="large-text" value="<?php echo esc_attr( $settings['permissions_policy'] ); ?>">
						<p class="description"><?php esc_html_e( 'Empty disables the header. Example: camera=(), microphone=(), geolocation=()', 'wsh' ); ?></p>
					</td>
				</tr>
			</table>

			<h2><?php esc_html_e( 'Content-Security-Policy', 'wsh' ); ?></h2>
			<table class="form-table">
				<tr>
					<th scope="row"><?php esc_html_e( 'Enable CSP', 'wsh' ); ?></th>
					<td>
						<label style="display:block"><input type="checkbox" name="<?php echo esc_attr( WSH_OPTION ); ?>[csp_enabled]" value="1" <?php checked( $settings['csp_enabled'] ); ?>> <?php esc_html_e( 'Send a Content-Security-Policy header', 'wsh' ); ?></label>
						<label style="display:block"><input type="checkbox" name="<?php echo esc_attr( WSH_OPTION ); ?>[csp_report_only]" value="1" <?php checked( $settings['csp_report_only'] ); ?>> <?php esc_html_e( 'Report-only (log violations, do not block) — keep this on until the policy is proven', 'wsh' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wsh_csp"><?php esc_html_e( 'Policy', 'wsh' ); ?></label></th>
					<td>
						<textarea id="wsh_csp" name="<?php echo esc_attr( WSH_OPTION ); ?>[csp]" rows="4" class="large-text code"><?php echo esc_textarea( $settings['csp'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Write {nonce} where a per-request nonce belongs, e.g. script-src \'self\' {nonce}. Output it in your theme with wsh_nonce_attr().', 'wsh' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wsh_report_uri"><?php esc_html_e( 'Report URI', 'wsh' ); ?></label></th>
					<td><input type="url" id="wsh_report_uri" name="<?php echo esc_attr( WSH_OPTION ); ?>[csp_report_uri]" class="regular-text" value="<?php echo esc_attr( $settings['csp_report_uri'] ); ?>">
					<p class="description"><?php esc_html_e( 'Optional endpoint that receives violation reports.', 'wsh' ); ?></p></td>
				</tr>
			</table>

			<?php submit_button(); ?>
		</form>
	</div>
	<?php
}
