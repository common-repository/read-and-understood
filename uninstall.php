<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package   read-and-understood
 * @author    peter@mantos.com
 * @license   GPL-2.0+
 * @link      http://example.com
 */

// If uninstall not called from WordPress, then exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

	delete_option("rnu_db_version");
	$GLOBALS['wpdb']->query("DROP TABLE `".$GLOBALS['wpdb']->prefix."rnu_acknowledgements`");
	$GLOBALS['wpdb']->query("DROP TABLE `".$GLOBALS['wpdb']->prefix."rnu_categories`");
	$GLOBALS['wpdb']->query("OPTIMIZE TABLE `" .$GLOBALS['wpdb']->prefix."options`");
?>