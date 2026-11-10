<?php
/**
 * Uninstall Security Headers.
 *
 * Removes the plugin's single settings option. Headers stop being sent
 * the moment the plugin is gone — there is nothing else to clean up.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wsh_settings' );
