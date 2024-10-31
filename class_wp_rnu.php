<?php

/**
	Plugin Name: RnU (Read and Understood)
	Plugin URI: https://bo.wordpress.org/plugins/read-and-understood/
	Description: Records acknowledgements that specific users have read specific postings (or not).
	Version: 2.4
	Author: Peter Mantos; Mantos I.T. Consulting Inc.
	Author URI: http://mantos.com
	License: GPL2
	Text Domain: read-and-understood-locale
*/

/*
 * Copyright 2014-2018 Mantos I.T. Consulting, Inc. (email : info@mantos.com)
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 * Revision History:
 * =====+=============+================+===================================================
 * REV : WHEN : WHO : WHAT
 * =====+=============+================+===================================================
 * 2.4 : 26-Mar-2018 : P.Mantos
 * : : : Functionally equivalent to version 2.3 and equally secure. Modified to
 * : : : conform to undocumented coding style preferences of Wordpress security team
 * : : : which includes sanitizing all POST variables on same line of code whether used
 * : : : to set another another variable or not. Added line at beginning of functions to
 * : : : convert global $_POST variables to $FILTERED_POST.
 * : : : TODO: remove the now redundant sanitization (filtering) of $FILTERED_POST
 * =====+=============+================+===================================================
 * 2.3 : 23-Mar-2018 : P.Mantos
 * : : : Better sanitization of arguments coming in from POST and written to DB
 * : : : Better job using nonce.
 * =====+=============+================+===================================================
 * 2.2 : 03-Feb-2018 : P.Mantos
 * : : : Addresses possibility of XSS attack reported as a security flaw by d4wner.
 * : : : Addresses possibility of CRFS security flaw by d4wner.
 * =====+=============+================+===================================================
 * 2.1 : 09-Dec-2017 : P.Mantos
 * : : : Respects [rnu_ack] shortcode even if category doesn't match. (corrects an error).
 * =====+=============+================+===================================================
 * 2.0 : 06-Dec-2017 : P.Mantos
 * : : : Corrects previous attempt to change length of id field of rnu_acknowledgment table
 * : : : reported by davidpalmer0205.
 * =====+=============+================+===================================================
 * 1.9 : 05-Dec-2017 : P.Mantos
 * : : : Retro-actively attempts to recovery any category selected before version 1.7
 * : : : by looking at the category option and using it to populate the rnu_category table
 * : : : if that table is empty.
 * =====+=============+================+===================================================
 * 1.8 : 03-Dec-2017 : P.Mantos
 * : : : Respects [rnu_ack] shortcode.
 * : : : Corrected textdomain to read-and-understood-locale.
 * =====+=============+================+===================================================
 * 1.7 : 02-Dec-2017 : P.Mantos
 * : : : Added suggested security of checking for ABSPATH
 * : : : Allows no categories or multiple categories to be selected for acknowledgements.
 * : : : (suggested as enhancement by arnold-fungai on wordpress site)
 * =====+=============+================+===================================================
 * 1.6 : 26-Oct-2014 : P.Mantos : Corrected version of 1.4
 * : : : Changed format of exported CSV file.
 * : : : Now has one column per post. Puts date/time in
 * : : : cell if the user name (row) has read the post (column).
 * : : : Reordered functions, leaning towards alphabetical..
 * =====+=============+================+===================================================
 * 1.5 : 30-Oct-2014 : P.Mantos : Wasn't really respecting ALL USERS option.
 * : : : Errors reported by users regarding headers.
 * =====+=============+================+===================================================
 * 1.4 : 26-Oct-2014 : P.Mantos : Changed format of exported CSV file.
 * : : : Now has one column per post. Puts date/time in
 * : : : cell if the user name (row) has read the post (column).
 * : : : Reordered function, leaning towards alphabetical.
 * =====+=============+================+===================================================
 * 1.3 : 08-Jun-2014 : P.Mantos : Looks for POST table using WPDB prefix, rather than
 * : : : assumed "wp_" (thanks to jwbowers for reporting this)
 * : : : Also, uninstall.php is now used.
 * =====+=============+================+===================================================
 * 1.2 : 17-Jan-2014 : P.Mantos : Corrected _(...) with __(...) Single versus double
 * =====+=============+================+===================================================
 * 1.1 : 17-Jan-2014 : P.Mantos : Used __(...) throughout javascript. Translation ready.
 * : : : Corrected confirmation button error not showing number.
 * : : : Removed WP_DEBUG (should be defined in wp_config)
 * : : : Replaced incomplete copy of jquery.js with 1.7.2
 * : : : Created css/images to house jquery-ui images
 * : : : Moved rnu_uninstall outside of class
 * : : : Exploits, but does not require javascript.
 * : : : Moved javascript to external file in /js folder
 * =====+=============+================+===================================================
 * 1.0 : 09-Jan-2014 : P.Mantos : Corrected "not" re. checkbox on option screen.
 * : : : Enclosed more string literals in __(...)
 * =====+=============+================+===================================================
 * 0.2 : 09-Jan-2014 : P.Mantos : Removed reference to 'http://ajax.googleapis.com/
 * : : : and added local copy of jquery-ui.css in /css
 * =====+=============+================+===================================================
 */
defined('ABSPATH') or die('No script kiddies please!');
if (! defined('READ_AND_UNDERSTOOD_PLUGIN_VERSION'))
    define('READ_AND_UNDERSTOOD_PLUGIN_VERSION', '2.4');
class class_wp_rnu
{

    /**
     */
    public $rnu_username; // the username of logged-user or the one entered by a non-logged-in user

    public $rnu_user_id; // the userid of logged-user or 0 if not logged-in

    public $rnu_plugin_version = READ_AND_UNDERSTOOD_PLUGIN_VERSION;

    public $rnu_db_version = "1.0";

    public $shortname = "rnu";

    public $rnu_default_username_pattern = '[A-Z]{1,10}';

    public $rnu_default_username_title = 'at least one but no more than 10 capital letters';

    public $export_warning_msg = "Danger, Will Robinson"; // used to display error messages concerning the date
    
    public function __construct()
    {
        // Use of text domains allows internationalization (I18n) of text strings; none are in place as yet
        load_plugin_textdomain('read-and-understood-locale', false, basename(dirname(__FILE__)) . '/languages/');
        add_action('wp_enqueue_style', array(
            $this,
            'register_enqueue_plugin_styles'
        ));
        add_action('wp_head', array(
            $this,
            'register_enqueue_plugin_scripts'
        ));
        add_action('init', array(
            $this,
            'register_enqueue_plugin_scripts'
        ));
        add_action('admin_menu', array(
            $this,
            'rnu_plugin_menu'
        ));
        add_action('admin_init', array(
            $this,
            'wpse9876_download_csv'
        ));
        // RnU adds one or more buttons following the post. The buttons will be added to the end of the posting content.
        add_filter('the_content', array(
            $this,
            'append_post_notification'
        ));

        add_action('wp_ajax_rnu_action', array(
            $this,
            'rnu_action_callback'
        ));
        add_action('wp_ajax_nopriv_rnu_action', array(
            $this,
            'rnu_action_callback'
        ));
        
        add_shortcode( 'rnu_ack', array($this, 'rnu_ack_shortcode' ) );

        //checkVersion checks if the verison in the database (options table) matches the hard-coded version defined above.
        //if not, it will take appropriate action
        add_action('plugins_loaded', array(
            $this,
            'checkVersion'
        ));
    }
     /**
     */
    function __destruct()
    {
        // TODO - Insert your code here
    }

    public function append_post_notification($content, $boolRegardlessOfCategory = false)
    {
        // this is the main action of the plugin that adds the RnU form, button, and messages
        // to the content of a posting before WP displays that posting.
        // it also records the acknowledgement if the submit button had been pressed
        global $post;
        global $current_user;
        $FILTERED_POST = self::filter_either($_POST); // Sanitize $_POST varibales immediately
        
        $username_validation_error_msg = "";
        if (null != (filter_var($FILTERED_POST['rnu_submit'],FILTER_SANITIZE_STRING ))) { // the user has requested a acknowledgement using the form submit, which was not intercepted by JavaScript
        }
        // load in any RNU variables posted; specifically want to preserve Username if just acknowledged
        $post_vars = '';
        $rnu_user_id = 0; // by default
        $rnu_username = ''; // by default
        foreach ($FILTERED_POST as $opt_name => $opt_val) {
            if (strpos($opt_name, $this->shortname) === 0) {
                $$opt_name = filter_var($opt_val, FILTER_SANITIZE_STRING); // double $$ means set the variable that is named ... to the value
            }
        } // end foreach
        if ($post->post_type == 'post') { // talking about the content here, not GET or POST
            // check to see if the user is logged-in, if so, use that user_id and username
            if (function_exists('is_user_logged_in')) {
                if (is_user_logged_in()) {
                    if (function_exists('get_currentuserinfo')) {
                        get_currentuserinfo();
                        $rnu_username = $current_user->user_login;
                        $rnu_user_id = $current_user->ID;
                    } // endif get_currentuserinfo function exists
                } // endif is_user_logged_in
            } // endif is_user_logged_in function exists
            $rnu_post_id = get_the_ID(); // set via WP's "The Loop"
                                         // loop through all the categories of the site to see if this post matches
                                         // the category selected on the admin's RnU settings page
            
            //see if the category matches one of the selected categories to be acknowledged
            $categories = get_the_category(); // an array of categories of this particular posting
            $category_matches = false;
            for ($i = 0; $i < count($categories); ++ $i) {
                $category_id = (int) $categories[$i]->cat_ID;
                $category_matches =  $this->boolCategoryShouldBeAcknowledged($category_id);
                if ($category_matches  == true) {
                    break; // no sense completing the for loop through the categories of this posting
                }
            }
            
            if ($category_matches == true || $boolRegardlessOfCategory == true) { // the category is appropriate
                $append = $this->rnu_add_notification($username_validation_error_msg, $rnu_user_id, $rnu_post_id, $rnu_username);
                return $content . $append;
                 
            } else {
                // the category is was not appropriate
                return $content;
            }
        } else {
            // wasn't a posting, probably a web page; leave it alone
            return $content;
        }
    }

    public function boolCategoryShouldBeAcknowledged($category)
    {
         // checks to see if the category is one that has been selected to be acknowledged
        $boolCategoryShouldBeAcknowledged = false;
        
        $rnu_categories = $this->rnudb_get_categories(); // the categories selected to be acknowledged,
        if (in_array((int) $category, $rnu_categories) ) {
               $boolCategoryShouldBeAcknowledged = true;
        } 
        
        return $boolCategoryShouldBeAcknowledged;
    }
    
    function checkVersion() {
      // Checks to see if the version hard-coded above in the define statement is the same
      // as the one saved in the database as a WordPress option.  
      // If not, the INSTALL routine is run again.
       if (READ_AND_UNDERSTOOD_PLUGIN_VERSION !== get_option('rnu_plugin_version')) {
          $this->rnudb_install();  
      }
      $this->rnudb_install();
}

    public function hasBeenAcked($userid, $blogid, $username)
    {
        /*
         * This boolean function looks for at least one record in a table that
         * records that a specific (non-zero) user has acknowledged a specific posting.
         * If so, it returns true; otherwise, false.
         *
         * Inputs: $userid - the userid of the logged-in username; or zero
         * $blogid - an integer specifying the posting in the WP database
         * $username - only used for userid = 0 and a user entered the username
         */
        global $wpdb;
        $intermediate = false; // presume that a record will not be found
        $rnu_ack_tablename = $wpdb->prefix . "rnu_acknowledgements";
        if ($userid != 0) {
            $query = "SELECT * FROM $rnu_ack_tablename where ";
            $query .= " RNU_POST_ID = ";
            $query .= $blogid;
            $query .= " and RNU_USER_ID = ";
            $query .= $userid;
            $query .= ";";
        } else {
            if (! (strcmp($username, '') === 0)) {
                $query = "SELECT * FROM $rnu_ack_tablename where ";
                $query .= " RNU_POST_ID = ";
                $query .= $blogid;
                $query .= " and RNU_USER_ID = 0";
                $query .= " and RNU_USERNAME = '";
                $query .= $username . "'";
                $query .= ";";
            }
        }
        $result = $wpdb->get_row($query);
        if ($result != null) {
            $intermediate = true; // indeed a record was found
        }
        return $intermediate;
    }

    function maybeEncodeCSVField($string)
    {
        // courtesy of http://stackoverflow.com/users/2043539/oleg-barshay
        if (strpos($string, ',') !== false || strpos($string, '"') !== false || strpos($string, "\n") !== false) {
            $string = '"' . str_replace('"', '""', $string) . '"';
        }
        return $string;
    }

    public function register_plugin_deactivate_hook()
    {
        register_deactivation_hook(__FILE__, array(
            &$this,
            'rnudb_deactivate'
        )); // note: uninstall is not the same as deactivation
    }

    public function register_plugin_activation_hook()
    {
        register_activation_hook(__FILE__, array(
            &$this,
            'rnudb_install'
        ));
    }

    public function register_enqueue_plugin_scripts()
    {
        wp_register_script('read-and-understood-scripts', plugins_url('js/rnu_javascript.js', __FILE__ ), array(
            'jquery'
        ));
        wp_enqueue_script('read-and-understood-scripts', false, array(
            'jquery'
        ));
        wp_enqueue_script('jquery-ui-datepicker', false, array(
            'jquery'
        ));
        // in javascript, object properties are accessed as ajax_object.ajax_url, ajax_object.we_value
        wp_localize_script('read-and-understood-scripts', 'ajax_object', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'Username:' => __('Username:'),
            'does not match the pattern:' => __('does not match the pattern:'),
            'Please enter a username that has:' => __('Please enter a username that has'),
            'Purge Acknowledgements' => __('Purge Acknowledgements')
        ));
    }

    public function register_plugin_scripts()
    {}

    function rnu_action_callback()
    {
        // This routine is called if javascript is on and the user presses the "Read and Understood" button.
        // It is called per the "$.post(myurl, data, function(response)" in the javascript, which calls ajax.
        // When ajax is called, rnu_action_callback is called because it was earlier bound to the
        // 'wp_ajax_rnu_action', and 'wp_ajax-nopriv_rnu_action' using add_action in the _counstruct subroutine.
        // The output (echo) of this callback is then passed back to javascript via the 'response' parameter.
        $FILTERED_POST = self::filter_either($_POST);
        $rnu_username = $FILTERED_POST['rnu_username'];
        $rnu_username = trim(filter_var($rnu_username, FILTER_SANITIZE_STRING));
        if ($rnu_username == '') {
            ob_clean(); // clear buffers in case DEBUG is on
            echo ''; // returned as the response; note that the 'please enter username' message will become visible
        } else {
            $rnu_username_validation_pattern = trim(htmlspecialchars(stripslashes(get_option($this->shortname . '_username_validation_pattern', ''))));
            // do NOT check pattern if user is logged in
            if ((is_user_logged_in() || preg_match("/^" . $rnu_username_validation_pattern . "$/", $rnu_username))) { // server side validation, in case JavaScript was off
                $this->rnu_action_record_acknowledgment(); // assumes post_id, user_id etc. where passed in via the .POST
                ob_clean(); // clear buffers in case DEBUG is on
                echo __('Your acknowledgement has been recorded.', 'read-and-understood-locale'); // returned as (non-blank) response
            } else {
                ob_clean(); // clear buffers in case DEBUG is on
                echo ''; // returned as the response;
            }
        }
        die(); // this is required to return a proper result
    }

    function rnu_ack_shortcode( $atts, $content = null )
    {
        global $wpdb; // this is how you get access to the database
        return $this->append_post_notification($content, true);
     }
    
    function rnu_action_record_acknowledgment()
    {
        global $wpdb; // this is how you get access to the database
        $FILTERED_POST = self::filter_either($_POST);
        
        $rnu_user_id = intval(filter_var($FILTERED_POST['rnu_user_id'],FILTER_SANITIZE_STRING));
        $rnu_post_id = intval(filter_var($FILTERED_POST['rnu_post_id'],FILTER_SANITIZE_STRING));
        $rnu_username = $FILTERED_POST['rnu_username'];
        $rnu_username = trim(filter_var($rnu_username, FILTER_SANITIZE_STRING));
        if (($rnu_username != '') && ($rnu_post_id > 0) && ($rnu_user_id >= 0)) {
            if (! $this->hasBeenAcked($rnu_user_id, $rnu_post_id, $rnu_username)) { // avoid re-acknowledgement
                $rnu_ack_tablename = $wpdb->prefix . "rnu_acknowledgements";
                $query = "INSERT INTO $rnu_ack_tablename ( RNU_USER_ID, RNU_POST_ID, RNU_USERNAME, RNU_ACK_DATETIME) VALUES (";
                $query .= "%d, ";
                $query .= "%d, '";
                $query .= "%s', now());";
                $query = $wpdb->prepare($query, $rnu_user_id, $rnu_post_id, $rnu_username); // uses mysql_real_escape_string
                $wpdb->query($query);
            }
        }
    }

    public function rnu_add_notification($username_validation_error_msg, $rnu_user_id, $rnu_post_id, $rnu_username)
    {
    $FILTERED_POST = self::filter_either($_POST);
     if ($this->hasBeenAcked($rnu_user_id, $rnu_post_id, $rnu_username)) {
        $rnu_form .= '<div class="hidden_acknowledgement_msg" style="visibility:visible;display:block" name="rnu_acknowledged_msg";><font color="green">You have acknowledged this posting.</font></div>';
        $java_text = '';
        $notification = '';
    } else {
        $rnu_button_label = __('READ AND UNDERSTOOD', 'read-and-understood-locale');
        if (! null != (filter_var($FILTERED_POST['rnu_submit'],FILTER_SANITIZE_STRING ))) { // the user has not requested an acknowledgement using the form submit, allow the form
            $rnu_form = '<form id="rnuform" name="rnuform" method="post">';
            if ($rnu_username == '') {
                // allow user to enter a name
                $rnu_form .= '<div  name="rnu_hide_username">';
                $rnu_require_login = htmlspecialchars(stripslashes(get_option($this->shortname . '_require_login', '')));
                $rnu_form .= '<a href="' . wp_login_url(get_permalink()) . '" title="' . __('Login', 'read-and-understood-locale') . '">' . __('Login (using this link)', 'read-and-understood-locale') . '</a>';
                if (strcmp($rnu_require_login, "YES") != 0) {
                    $rnu_username_validation_pattern = trim(htmlspecialchars(stripslashes(get_option($this->shortname . '_username_validation_pattern', ''))));
                    $rnu_username_validation_title = trim(stripslashes(stripslashes(get_option($this->shortname . '_username_validation_title', ''))));
                    $rnu_form .= __(' or enter a Username: ', 'read-and-understood-locale');
                    $rnu_form .= '<input type="text" name="rnu_username" ';
                    if (! (strcmp($rnu_username_validation_pattern, '') === 0)) {
                        $rnu_form .= ' pattern="' . htmlspecialchars($rnu_username_validation_pattern) . '" ';
                    }
                    if (! (strcmp($rnu_username_validation_title, '') === 0)) {
                        $rnu_form .= ' title="' . htmlspecialchars($rnu_username_validation_title) . '" ';
                    }
                    if (! (strcmp($rnu_username, '') === 0)) {
                        $rnu_form .= 'value="' . htmlspecialchars($rnu_username) . '"';
                    }
                    $rnu_form .= '>';
                } else {
                    // username is required, but we need a hidden username for the javascript to detect the input field
                    $rnu_form .= '<input type="text" name="rnu_username" ';
                    if (! (strcmp($rnu_username, '') === 0)) {
                        $rnu_form .= 'value="' . htmlspecialchars($rnu_username) . '"';
                    }
                    $rnu_form .= '>';
                }
                $rnu_form .= '</div>';
            } else {
                // the user is logged-in and we already have the username
                $rnu_form .= '<div  name="rnu_hide_username"><input type="hidden" name="rnu_username" value="' . htmlspecialchars($rnu_username) . '" ></div>';
            }
            $rnu_form .= '<input type="hidden" name="rnu_user_id" value="' . htmlspecialchars($rnu_user_id) . '">';
            $rnu_form .= '<input type="hidden" name="rnu_post_id" value="' . htmlspecialchars($rnu_post_id) . '">';
            $rnu_form .= '<input type="submit" name="rnu_submit" value="' . $rnu_button_label . '">';
            $rnu_form .= '<div class="hidden_need_name_msg" style="visibility:hidden;display:none" name="rnu_need_name_msg";>';
            $rnu_form .= '<font color="red">' . __('Please login to this site', 'read-and-understood-locale');
            if (strcmp($rnu_require_login, "YES") != 0) {
                $rnu_form .= __(' or enter a Username that matches the pattern', 'read-and-understood-locale');
            }
            $rnu_form .= '</font></div>';
            $rnu_form .= '</form>';
            // end of not if already submitted using form
        }
        $style = "visibility:hidden;display:none"; // default: do NOT show acknowledgement block
        if (null != (filter_var($FILTERED_POST['rnu_submit'],FILTER_SANITIZE_STRING ))) { // the user has requested a acknowledgement using the form submit
            $rnu_username_validation_pattern = trim(htmlspecialchars(stripslashes(get_option($this->shortname . '_username_validation_pattern', ''))));
            $rnu_username_validation_title = trim(htmlspecialchars(stripslashes(get_option($this->shortname . '_username_validation_title', ''))));
            if (is_user_logged_in() || preg_match("/^" . $rnu_username_validation_pattern . "$/", $rnu_username)) { // server side validation, in case JavaScript was off
                $this->rnu_action_record_acknowledgment();
                $style = "visibility:visible;display:block"; // show ack block
            } else {
                $rnu_form .= __('Username') . ': "' . $rnu_username . '"' . __('does not match the pattern') . ': ' . htmlspecialchars($rnu_username_validation_pattern) . '\r\n';
                $rnu_form .= __('Please enter a username that has') . ' ' . htmlspecialchars($rnu_username_validation_title);
            }
        }
        $rnu_form .= '<div class="hidden_acknowledgement_msg" style="' . $style . '" name="rnu_acknowledged_msg";><font color="green">';
        $rnu_form .= __('You have acknowledged this posting', 'read-and-understood-locale');
        $rnu_form .= '</font></div>';
        $rnu_form .= '<br />';
    }
    $notification = __('Acknowledgements recorded using the "Read and Understood"(RnU) Plugin.', 'read-and-understood-locale');   
    return $rnu_form . $username_validation_error_msg . $notification;
   }
   
    function rnu_check_date($postedDate)
    {// serves to validate dates
        if (preg_match('/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/', $postedDate)) {
            list ($year, $month, $day) = explode('-', $postedDate);
            return checkdate($month, $day, $year);
        } else {
            return false;
        }
    }

    function rnu_plugin_menu()
    {
        add_options_page('Read and Understood Plugin Options', 'Read and Understood', 'manage_options', 'read-and-understood-menu-slug-01', array(
            &$this,
            'rnu_plugin_options'
        ));
    }

    function rnu_plugin_options()
    {
        if (! current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'read-and-understood-locale'));
        }
        global $wpdb;
        $FILTERED_POST = self::filter_either($_POST);
        
        $rnu_ack_tablename = $wpdb->prefix . "rnu_acknowledgements";
        $date_error_msg = ''; // no errors detected , yet
        $shortname = "rnu";
        $rnu_records_purged_count = 0; // haven't deleted any yet
                                       // variables for the field and option names
        $hidden_field_name = 'submit_hidden';
        // Read in existing option value from database
        // See if the user has posted us some information
        // If they did, this hidden field will be set to 'Y'
        if (null != (filter_var($FILTERED_POST['rnu_ExportBtn'], FILTER_SANITIZE_STRING )) || null != (filter_var($FILTERED_POST['rnu_PurgeBtn'],FILTER_SANITIZE_STRING ))) {
            // load in any RnU variables posted
            foreach ($FILTERED_POST as $opt_name => $opt_val) {
                if (strpos($opt_name, $shortname) === 0) {
                    $$opt_name = filter_var($opt_val, FILTER_SANITIZE_STRING ); // double $$ means set the variable that is named ... to the value
                }
            } // end foreach
              // check the dates
            if (! isset($rnu_end_date) || $rnu_end_date == '' || ! isset($rnu_start_date) || $rnu_start_date == '') {
                $date_error_msg = __('Need to set start and end date!', 'read-and-understood-locale') . '<br />';
            } else {
                if (($this->rnu_check_date($rnu_start_date) === false) || ($this->rnu_check_date($rnu_end_date) === false)) {
                    $date_error_msg = __('Error: Dates should be in yyyy-mm-dd format.', 'read-and-understood-locale') . '<br />';
                } else {
                    if (strcmp($rnu_start_date, $rnu_end_date) > 0) { // works because of yyyy-mm-dd format
                        $date_error_msg = "Start date may not be after end date. <br />";
                    } // end of if date range is valid
                }
            } // end of if start date and end date are present
              // end of checking dates
              // export is handled using a different function since it needs to output html headers
              // purge is handled here
            if (null != (filter_var($FILTERED_POST['rnu_PurgeBtn'],FILTER_SANITIZE_STRING )) && ($date_error_msg == '')) {
                if (null != (filter_var($FILTERED_POST['rnu_records_to_be_purged_count'],FILTER_SANITIZE_STRING )) && ($rnu_records_to_be_purged_count != 0)) {
                    // if the dates have changed between the original purge and the confirmation, skip the deletion
                    $purge_start_date = htmlspecialchars(stripslashes(get_option($shortname . '_start_date', ''))); // was saved when user pressed purge 1st time
                    $purge_end_date = htmlspecialchars(stripslashes(get_option($shortname . '_end_date', ''))); // was saved when user pressed purge 1st time
                    if ((strcmp($rnu_start_date, $purge_start_date) == 0) && (strcmp($rnu_end_date, $purge_end_date) == 0)) {
                        // really delete them
                        update_option('rnu_start_date', $rnu_start_date);
                        update_option('rnu_end_date', $rnu_end_date);
                        $day_before_range = date('Y-m-d', strtotime($rnu_start_date . ' -1 day'));
                        $day_after_range = date('Y-m-d', strtotime($rnu_end_date . ' +1 day'));
                        $sql = "DELETE ";
                        $sql .= " from $rnu_ack_tablename ";
                        $sql .= " where ";
                        $sql .= "RNU_ACK_DATETIME > '" . $day_before_range . " 23:59:59' and ";
                        $sql .= "RNU_ACK_DATETIME < '" . $day_after_range . " 00:00:00';";
                        // echo $sql . " <br />";
                        $wpdb->query($sql);
                        $rnu_records_purged_count = $wpdb->rows_affected;
                        // echo "\$rnu_records_purged_count = $rnu_records_purged_count<br />";
                    }
                    $rnu_records_to_be_purged_count = 0; // will set the purge button to read "purge" instead of confirm
                } else {
                    // just count the records and get confirmation
                    update_option('rnu_start_date', $rnu_start_date);
                    update_option('rnu_end_date', $rnu_end_date);
                    $day_before_range = date('Y-m-d', strtotime($rnu_start_date . ' -1 day'));
                    $day_after_range = date('Y-m-d', strtotime($rnu_end_date . ' +1 day'));
                    $sql = "SELECT count(*) ";
                    $sql .= " from $rnu_ack_tablename ";
                    $sql .= " where ";
                    $sql .= "RNU_ACK_DATETIME > '" . $day_before_range . " 23:59:59' and ";
                    $sql .= "RNU_ACK_DATETIME < '" . $day_after_range . " 00:00:00';";
                    $rnu_records_to_be_purged_count = $wpdb->get_var($sql);
                }
            } // end of running purge
        }
        // normal processing
        echo "<h2>" . __('Read and Understood Plugin Settings', 'read-and-understood-locale') . ' ';
        echo ' (' . $this->rnu_plugin_version . ")</h2>";
        // See if the user has posted us some information
        // If they did, this hidden field will be set to 'Y'
        if (null != (filter_var($FILTERED_POST[$hidden_field_name],FILTER_SANITIZE_STRING )) && $FILTERED_POST[$hidden_field_name] == 'Y') {
            if (null != (filter_var($FILTERED_POST["Submit"],FILTER_SANITIZE_STRING )) && strcmp(filter_var($FILTERED_POST["Submit"],FILTER_SANITIZE_STRING ), esc_attr('Save Changes')) == 0) {
                foreach ($FILTERED_POST as $opt_name => $opt_val) {
                    if (strpos($opt_name, $shortname) === 0) {
                        update_option($opt_name, filter_var($opt_val,FILTER_SANITIZE_STRING ));
                    }
                } // end for
                
                // Categories:
                $this->rnudb_clearCategories();// Need to delete all rnu categories from database
                $opt_name = $shortname . "_category";
                if (is_array($FILTERED_POST[$opt_name])) {
                    if (null != (filter_var_array($FILTERED_POST[$opt_name],FILTER_SANITIZE_STRING ))) {
                        foreach ($FILTERED_POST[$opt_name] as $selectedOption) {
                             $this->rnudb_addCategory(filter_var($selectedOption, FILTER_SANITIZE_STRING ));   // 'Go ahead and add category ' . $selectedOption."\n";
                        }
                    } else {
                   }
                }
                // Check boxes:
                $opt_name = $shortname . "_require_login";
                if (null != (filter_var($FILTERED_POST[$opt_name],FILTER_SANITIZE_STRING ))) {
                    $opt_val = "YES";
                } else {
                    $opt_val = "NO"; // it's not set, so the box was not checked
                }
                update_option($opt_name, $opt_val); // it's set, so the box was checked
                                                    // Put an settings updated message on the screen
                echo '<div class="updated"><p><strong>' . __('settings saved.', 'read-and-understood-locale') . '</strong></p></div>';
            } // end of Save Changes
            if (null != (filter_var($FILTERED_POST["Submit"],FILTER_SANITIZE_STRING )) && strcmp(filter_var($FILTERED_POST["Submit"],FILTER_SANITIZE_STRING ), esc_attr('Validate Username')) == 0) {
                if (!null != (filter_var($FILTERED_POST['rnu_update_setting'],FILTER_SANITIZE_STRING ))) die("<br><br>Hmm .. looks like you didn't send any credentials.. No CSRF for you! ");
                if (!wp_verify_nonce(filter_var($FILTERED_POST['rnu_update_setting'],FILTER_SANITIZE_STRING ),'rnu-update-setting')) die("<br><br>Hmm .. looks like you didn't send any credentials.. No can do for you! ");
                $rnu_username_validation_pattern = filter_var($FILTERED_POST["rnu_username_validation_pattern"],FILTER_SANITIZE_STRING );
                $rnu_username = filter_var($FILTERED_POST["rnu_username"],FILTER_SANITIZE_STRING );
                if (preg_match("/^" . $rnu_username_validation_pattern . "$/", $rnu_username)) { // server side validation, in case JavaScript was off
                    echo '<div class="updated"><p><strong>' . __('Username') . ': "' . $rnu_username . '" ' . __('matches the pattern') . ': ' . $rnu_username_validation_pattern . '</strong></p></div>';
                } else {
                    echo '<div class="updated"><p><strong>' . __('Username') . ': "' . $rnu_username . '" ' . __('does not match the pattern') . ': ' . $rnu_username_validation_pattern . '</strong></p></div>';
                }
            } // end of Validate UserName
        } // end of if hidden field requires saving options
          // Now display the settings editing screen
        echo '<div class="wrap">';
        // settings form
  
        $wp_categories = get_categories("hide_empty=0&parent=0"); // get the categories used in WordPress proper
    
        $rnu_categories = $this->rnudb_get_categories(); // the categories selected to be acknowledged,
        
        echo '<form name="form1" method="post" action="">';
        echo '<div class="table">';
        echo '<div class="table-row">';
        echo '<div class="table-cell">' . __('Categories to be acknowledged', 'read-and-understood-locale') . ':</div>';
        echo '<div class="table-cell"><select name="' . $shortname . '_category[]" multiple="multiple">';
        for ($i = 0; $i < count($wp_categories); ++ $i) {
             if (in_array((int) $wp_categories[$i]->cat_ID, $rnu_categories) ) {
                $selected = "selected";
            } else {
                $selected = "";
            }
            echo '<option value=' . $wp_categories[$i]->cat_ID . '  ' . $selected . ' >' . htmlspecialchars($wp_categories[$i]->cat_name) . '</option>';
        }
        echo '</select></div>';
        echo '<div class="table-cell">' . __('The categories (if any) of any postings to be acknowledged by users.', 'read-and-understood-locale');
        echo '  ' . __('Use ctrl key to select / deselect any or all options.', 'read-and-understood-locale'). '</div>';
        echo '</div>';
        echo '<div class="table-row">';
        echo '<div class="table-cell">' . __('Require Login', 'read-and-understood-locale') . ':</div>';
        $opt_name = $shortname . "_require_login";
        $opt_val = htmlspecialchars(stripslashes(get_option($opt_name, '')));
        echo '<div class="table-cell"><input id="require_login" name="' . $shortname . '_require_login"';
        if (strcmp($opt_val, "YES") == 0) {
            echo " CHECKED ";
        }
        echo "type='checkbox' ";
        echo 'value="YES"/></div><div class="table-cell" >';
        echo __('If checked, users must login to the site using a WordPress login; otherwise, they may enter a courtesy username.', 'read-and-understood-locale');
        echo '</div>';
        echo '</div>';
        echo '<div class="table-row">';
        echo '<div class="table-cell"  name="' . $shortname . '_hdr_username_validation_pattern">' . __('Courtesy Username Validation Pattern') . ':</div>';
        echo '<div class="table-cell"><input type="text" name="' . $shortname . '_username_validation_pattern" class="ss_text" ';
        echo 'value="' . htmlspecialchars(stripslashes(get_option($shortname . '_username_validation_pattern', '')), ENT_QUOTES) . '" /></div>';
        echo '<div name="' . $shortname . '_ftr_username_validation_pattern">' . __('A regular expression used as the \'PATTERN\' e.g. ', 'read-and-understood-locale') . $this->rnu_default_username_pattern;
        echo '</div>';
        echo '</div>';
        echo '<div class="table-row">';
        echo '<div class="table-cell" name="' . $shortname . '_hdr_username_validation_title">' . __('Courtesy Username Validation Title', 'read-and-understood-locale') . ':</div>';
        echo '<div class="table-cell"><input type="text" name="' . $shortname . '_username_validation_title" class="ss_text" ';
        echo 'value="' . htmlspecialchars(stripslashes(get_option($shortname . '_username_validation_title'))) . '" /></div>';
        echo '<div class="table-cell" name="' . $shortname . '_hdr_username_validation_title">' . __('A description of the \'PATTERN\' e.g. ', 'read-and-understood-locale') . $this->rnu_default_username_title;
        echo '</div>';
        echo '</div>';
        echo '<div class="table-row">';
        echo '<div class="table-cell" name="' . $shortname . '_hdr_username">' . __('Courtesy Username Validation Test', 'read-and-understood-locale') . ':</div>';
        echo '<div class="table-cell"><input type="text" name="' . $shortname . '_username" class="ss_text" ';
        echo 'value="" /></div>';
        echo '<div class="table-cell" name="' . $shortname . '_ftr_username">' . __('Type a username here and it will be validated using the regular expression.', 'read-and-understood-locale') . '<br />';
        echo __('*validation requires that javascript be enabled.', 'read-and-understood-locale') . '</div>';
        echo '</div>'; // end row
        echo '<div class="table-row">';
        echo '<div class="table-cell"></div>';
        echo '<div class="table-cell">';
        echo '<p class="submit">';
        echo '<input type="submit" name="Submit" class="button-primary" value="' . esc_attr('Validate Username') . '" />';
        echo '</p>';
        echo '</div>';
        echo '<div class="table-cell"></div>';
        echo '</div>'; // end row
        echo '</div class="table">';
        echo '<p class="submit">';
        echo '<input name="rnu_update_setting" type="hidden" value="' . wp_create_nonce('rnu-update-setting'). '" />';
        echo '<input type="submit" name="Submit" class="button-primary" value="' . esc_attr('Save Changes') . '" />';
        echo '</p>';
        echo '<input type="hidden" name="' . $hidden_field_name . '" value="Y">'; // a signal that new values are to be saved
        echo '</form>';
        wp_enqueue_script('jquery-ui-datepicker');
        wp_enqueue_style('jquery-style', plugins_url('css/jquery-ui.css', __FILE__ ));
        echo '<form name="form2" method="post" action="">';
        echo 'Export or Purge records acknowledged between (YYYY-MM-DD)';
        echo '<input type="text" id="_start_date" name="' . $shortname . '_start_date" ';
        echo 'value="' . htmlspecialchars(stripslashes(get_option($shortname . '_start_date', ''))) . '" />';
        echo ' and  ';
        echo '<input type="text" id="_end_date" name="' . $shortname . '_end_date" ';
        echo 'value="' . htmlspecialchars(stripslashes(get_option($shortname . '_end_date', ''))) . '" />';
        echo '<br />';
        if ($date_error_msg) {
            echo "<font color:red>$date_error_msg</font>";
        }
        echo '*' . __('default dates are loaded from the last successful export/purge', 'read-and-understood-locale') . '<br />';
        echo '<p class="submit">';
        echo '<input type="submit" name="rnu_ExportBtn" class="button-primary" value="' . esc_attr('Export Acknowledgements') . '" />';
        echo '<div class="table-cell">' . __('All Users', 'read-and-understood-locale') . ' : </div>';
        $opt_name = $shortname . "_all_users";
        $opt_val = htmlspecialchars(stripslashes(get_option($opt_name, '')));
        echo '<div class="table-cell"><input id="all_users" name="' . $shortname . '_all_users"';
        if (strcmp($opt_val, "YES") == 0) {
            echo " CHECKED ";
        }
        echo "type='checkbox' ";
        echo 'value="YES"/></div><div class="table-cell" >';
        echo __('If checked, all users will be exported regardless of whether any acknowledgements are found. This helps if you are looking to see who has NOT acknowledged.', 'read-and-understood-locale');
        echo '</div>';
        echo '</div>';
        /*
        echo '<div class="table-cell">' . __('Old Export Format', 'read-and-understood-locale') . ' : </div>';
        $opt_name = $shortname . "_old_format";
        $opt_val = htmlspecialchars(stripslashes(get_option($opt_name, '')));
        echo '<div class="table-cell"><input id="all_users" name="' . $shortname . '_old_format"';
        if (strcmp($opt_val, "YES") == 0) {
            echo " CHECKED ";
        }
        echo "type='checkbox' ";
        echo 'value="YES"/></div><div class="table-cell" >';
        echo __('If checked, the pre V1.4 format will be used.', 'read-and-understood-locale');
        echo __('Warning: The old export format is deprecated and will be retired 11/1/2015.', 'read-and-understood-locale');
        echo '</div>';
        echo '</div>';
        */
        echo '<div  name="' . $shortname . '_export_warning_msg">';
        if ($this->export_warning_msg) {
            echo "<br /><font color:red>" . $this->export_warning_msg . "</font>";
        }
        echo '</div>';
        echo '</p>';
        echo '<p class="submit">';
        if (isset($rnu_records_to_be_purged_count) && ($rnu_records_to_be_purged_count != 0)) {
            $purge_btn_name = __('Confirm Purge of ', 'read-and-understood-locale') . $rnu_records_to_be_purged_count . __(' record(s)', 'read-and-understood-locale');
        } else {
            $purge_btn_name = esc_attr('Purge Acknowledgements');
            $rnu_records_to_be_purged_count = 0;
        }
        echo '<input type="hidden" id="_records_to_be_purged_count" name="' . $shortname . '_records_to_be_purged_count" ';
        echo "value = $rnu_records_to_be_purged_count >";
        echo '<input type="submit" name="rnu_PurgeBtn" class="button-primary" value="' . $purge_btn_name . '" />';
        echo '</p>';
        if ($rnu_records_purged_count != 0) {
            echo $rnu_records_purged_count . __(' record(s) have been purged.', 'read-and-understood-locale') . '<br />';
        }
        echo '</form>';
        echo '<a href = "http://mantos.com/experience-and-expertise/plugin-read-understood/" >';
        echo __('Read and Understood plugin page', 'read-and-understood-locale') . '</a>';
        // end of normal settings page
    } // end of function

  function rnudb_addCategory($selectedCategory)
    {
        global $wpdb;
        $rnu_cat_tablename = $wpdb->prefix . "rnu_categories";
        $sql = "Insert into $rnu_cat_tablename (WP_CATEGORY_ID) Values ($selectedCategory);";
        $results = $wpdb->query($sql);
    }
  function rnudb_clearCategories()
    {
        global $wpdb;
        $rnu_cat_tablename = $wpdb->prefix . "rnu_categories";
        $sql = "Delete from $rnu_cat_tablename;";
        $results = $wpdb->query($sql);
    }
  function rnudb_get_categories()
    {
        // Returns an array of category id's found in the run_categories table.  
        // All postings in any of these categories are to be acknowledged.
        global $wpdb;
        $rnu_cat_tablename = $wpdb->prefix . "rnu_categories";
        $date_error_msg = ''; // no errors detected , yet
        $shortname = "rnu";
        $selected_categories = array();
        $rnu_records_purged_count = 0; // haven't deleted any yet
        $sql .= " Select * from $rnu_cat_tablename;";
        
        $results = $wpdb->get_results($sql);
        $rows_total = $wpdb->num_rows;
        
        if ($rows_total > 0) {
            
                // Get The Data fields
                for ($i = 0; $i < $rows_total; $i ++) {
                    $row = $results[$i];
                    $selected_categories[] = (int) $row->WP_CATEGORY_ID;
                }
        }
        return $selected_categories;
    }
    
function rnudb_install()
        {
        global $wpdb;
        
        $rnu_ack_tablename = $wpdb->prefix . "rnu_acknowledgements";
        $sql = "CREATE TABLE IF NOT EXISTS  $rnu_ack_tablename  (
        `idRNU_ACKNOWLEDGMENT` BIGINT NOT NULL AUTO_INCREMENT ,
        `RNU_USER_ID` BIGINT NULL ,
        `RNU_POST_ID` BIGINT NULL ,
        `RNU_ACK_DATETIME` DATETIME NULL ,
        `RNU_USERNAME` VARCHAR(45) NULL ,
        PRIMARY KEY (`idRNU_ACKNOWLEDGMENT`) ,
        INDEX `USERNAME` (`RNU_USER_ID` ASC) )

        COMMENT = 'Not a standard WORDPRESS table and may be deleted.  Used to support Read and Understood plugin by storing acknowledgements.'";
        
          // The dbDelta function examines the current table structure, compares it to the desired table structure,
        // and either adds or modifies the table as necessary. It is found in upgrade.php which is not loaded by default.
        require_once (ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql); // unfortunately there are no results; errors will be 'shown' by default
        
        $sql = "ALTER TABLE  $rnu_ack_tablename  CHANGE COLUMN `idRNU_ACKNOWLEDGMENT` `idRNU_ACKNOWLEDGMENT` BIGINT(20) NOT NULL AUTO_INCREMENT;";
        $results = $wpdb->query($sql);
                              
        // add the categories table, if not there (added in version 1.7)
        $rnu_cat_tablename = $wpdb->prefix . "rnu_categories";
        $sql = "CREATE TABLE IF NOT EXISTS  $rnu_cat_tablename  (
        `idRNU_CATEGORY` BIGINT NOT NULL AUTO_INCREMENT,
        `WP_CATEGORY_ID` BIGINT NULL ,       
        PRIMARY KEY (`idRNU_CATEGORY`),
        UNIQUE INDEX `WP_CATEGORY_ID_UNIQUE` (`WP_CATEGORY_ID` ASC))
        COMMENT = 'Not a standard WORDPRESS table and may be deleted.  Used to support Read and Understood plugin to designated any categories requiring an acknowledgement.'";

        dbDelta($sql); // unfortunately there are no results; errors will be 'shown' by default
        
        // version 1.7 effectively wiped out whatever category the user had previously chosen to be acknowledged.
        // attempt to mitigate that error by looking to see if the option still exists, yet no categories have yet been selected.
        $oldSingleCategoryId = htmlspecialchars((string) get_option($this->shortname . '_category', ''));
        $rnu_cat_tablename = $wpdb->prefix . "rnu_categories";
        $sql = " Select * from $rnu_cat_tablename;";
        $results = $wpdb->get_results($sql);
        $rows_total = $wpdb->num_rows;
        
        if ($oldSingleCategoryId != false ) {
            if ($rows_total == 0) {
               //does not appear that user has set categories (but could have deselected all)
                if (!is_array($oldSingleCategoryId)) {
                    $oldSingleCategoryId = (int) $oldSingleCategoryId; // make sure it is a number
                    // echo "<br/>                      need to update categories with $oldSingleCategoryId <br/>";
                    $this->rnudb_addCategory($oldSingleCategoryId);
                 } else {
                    // echo "<br/>              looks like old single category is an array <br/>";
                }
            } else {
                // echo "<br/>                Looks like categories have already been chosen <br/>";
            }
        } else {
           // \ echo "<br/>                Looks as though category option has not been set at all <br/>";
        }
        
        update_option('rnu_plugin_version', $this->rnu_plugin_version); // update to the current version regardless of existing version whihc has already been checked.
        if (get_option('rnu_db_version') === false)
            update_option('rnu_db_version', $this->rnu_db_version); // stores the name/value pair in the wp_options table
        if (get_option('rnu_username_validation_pattern') === false)
            update_option('rnu_username_validation_pattern', $this->rnu_default_username_pattern); // stores the name/value pair in the wp_options table
        if (get_option('rnu_username_validation_title') === false)
            update_option('rnu_username_validation_title', $this->rnu_default_username_title); // stores the name/value pair in the wp_options table
        if (get_option('rnu_require_login') === false)
            update_option('rnu_require_login', "NO"); // stores the name/value pair in the wp_options table
     }

function filter_either($original_variable, $filter_type = FILTER_SANITIZE_STRING) {
    /* This recursive function serves to sanitize varibles, particuly the $_POST variables.
     * However, it can be used with any variable and can optionally include any of the
     * options and flags associated with the filter_var or filter_array functions.
     
     Some Possible options and flags:
     FILTER_FLAG_NO_ENCODE_QUOTES - Do not encode quotes
     FILTER_FLAG_STRIP_LOW - Remove characters with ASCII value < 32
     FILTER_FLAG_STRIP_HIGH - Remove characters with ASCII value > 127
     FILTER_FLAG_ENCODE_LOW - Encode characters with ASCII value < 32
     FILTER_FLAG_ENCODE_HIGH - Encode characters with ASCII value > 127
     FILTER_FLAG_ENCODE_AMP - Encode the "&" character to &amp;
     */
    if (isset($original_variable) ) {
        if (is_array($original_variable)) {
            foreach ($original_variable as $inner_child => $inner_value) {
                $original_variable[$inner_child] = self::filter_either($inner_value);
            }
        } else {
            $original_variable = (filter_var($original_variable,$filter_type ) ); // Actual sanitize done here!!!
            }
        }
        return $original_variable;
}
     
    function wpse9876_download_csv()
  
    {
        global $wpdb;
        $FILTERED_POST = self::filter_either($_POST);
        $debug_csv = false;
        if ($debug_csv)
            $file = fopen('c:\Rnu.txt', 'w');
		if ($debug_csv) echo 'Step 0' . "\r\n"; ;

        $rnu_ack_tablename = $wpdb->prefix . "rnu_acknowledgements";
        $wp_user_tablename = $wpdb->base_prefix . "users"; // only one set of users per multisite
        $this->export_warning_msg = ""; // resets the export warning
        wp_register_style('jquery-style', plugins_url('css/jquery-ui.css', __FILE__ ));
        wp_enqueue_style('jquery-style');
        wp_enqueue_script('jquery-ui-datepicker');
        wp_enqueue_style('jquery-style', plugins_url('css/jquery-ui.css', __FILE__ ));
        wp_register_style('read-and-understood-style', plugins_url('css/rnu-plugin.css', __FILE__ ));
        wp_enqueue_style('read-and-understood-style');
        wp_register_script('read-and-understood-scripts', plugins_url('js/rnu_javascript.js', __FILE__ ));
        wp_enqueue_script('read-and-understood-scripts');
        if (isset($FILTERED_POST['rnu_ExportBtn'])) {
            foreach ($FILTERED_POST as $opt_name => $opt_val) {
                if (strpos($opt_name, $this->shortname) === 0) {
                    $$opt_name = filter_var($opt_val,FILTER_SANITIZE_STRING ); // double $$ means set the variable that is named ... to the value
                }
            } // end foreach
              
            // this function is short-circuited by the "old" return if the user wants the "old" format
              // There is a lot of duplicated code in the old function, but no effort is made to refactor
              // as the "old" format will be removed completely at some point.
            if (isset($rnu_old_format) && $rnu_old_format) {
                $this->wpse9876_download_old_format();
                return;
            }
            $myLine = 'Step 0';
			if ($debug_csv)
                fwrite($file, $myLine);

            if (! isset($rnu_end_date) || $rnu_end_date == '' || ! isset($rnu_start_date) || $rnu_start_date == '') {
                // echo __('Error: Need to set start date and end date.', 'read-and-understood-locale') . '<br />';
            } else {
                if (($this->rnu_check_date($rnu_start_date) === false) || ($this->rnu_check_date($rnu_end_date) === false)) {
                    // echo __('Error: Dates should be in yyyy-mm-dd format.', 'read-and-understood-locale') . '<br />';
                } else {
                    if (strcmp($rnu_start_date, $rnu_end_date) > 0) { // works because of yyyy-mm-dd format
                       if ($debug_csv) echo 'Error: Start date may not be after end date' . "\r\n"; ;

                                                                          // echo __('Error: Start date may not be after end date.', 'read-and-understood-locale') . '<br />';
                    } else {
						            $myLine = 'Step 2';
			if ($debug_csv)
                fwrite($file, $myLine);
                        $day_before_range = date('Y-m-d', strtotime($rnu_start_date . ' -1 day'));
                        $day_after_range = date('Y-m-d', strtotime($rnu_end_date . ' +1 day'));
                        $sql = "select tbl1.RNU_USERNAME, tbl1.RNU_USER_ID, tbl3.post_title, tbl2.RNU_ACK_DATETIME, tbl2.RNU_POST_ID, tbl4.user_email from ";
                        $sql .= "(SELECT RNU_USERNAME, RNU_USER_ID from $rnu_ack_tablename ";
                        if (isset($rnu_all_users) && $rnu_all_users) {
                            $sql .= " union select user_login as RNU_USERNAME, id as RNU_USER_ID from $wp_user_tablename  "; // get usernames from both acknowledgments and users
                        }
                        $sql .= "  ) as tbl1 "; // get usernames from both acknowledgments and users
                        $sql .= "left join  $rnu_ack_tablename as tbl2 on tbl1.RNU_USERNAME =  tbl2.RNU_USERNAME and "; // get acknowledgements (if any)
                        $sql .= "tbl1.RNU_USER_ID =  tbl2.RNU_USER_ID and "; // limited to the same username and id
                        $sql .= "RNU_ACK_DATETIME > '" . $day_before_range . " 23:59:59' and "; // that meet date criteria
                        $sql .= "RNU_ACK_DATETIME < '" . $day_after_range . " 00:00:00' ";
                        $sql .= "left join " . $wpdb->prefix . "posts as tbl3 on tbl2.RNU_POST_ID = tbl3.ID "; // and get the post title
                        $sql .= "left join " . $wp_user_tablename . " as tbl4 on tbl1.RNU_USER_ID = tbl4.ID "; // and get the email address
                        $sql .= " ORDER BY tbl1.RNU_USERNAME, tbl3.post_title;";
						           $myLine = 'Step 0';
                        $myLine = '"' . str_replace('"', '""', $sql) . '"' . "\r\n"; ;
						if ($debug_csv)
							fwrite($file, $myLine);

                        if ($debug_csv) echo '"' . str_replace('"', '""', $sql) . '"' . "\r\n"; ;
                        // TODO: include posts that contain the [rnu_ack] short tag or in an acknowledgement category to which no one has yet acklowedged. Make (empty) columns for these.
                        $results = $wpdb->get_results($sql, ARRAY_A); 
                        $rows_total = $wpdb->num_rows;
                        if ($rows_total > 0) {
                            if (! isset($rnu_start_date))
                                $rnu_start_date = "";
                            update_option('rnu_start_date', $rnu_start_date);
                            if (! isset($rnu_end_date))
                                $rnu_end_date = "";
                            update_option('rnu_end_date', $rnu_end_date);
                            if (! isset($rnu_all_users))
                                $rnu_all_users = "";
                            update_option('rnu_all_users', $rnu_all_users);
                            if (! isset($rnu_old_format))
                                $rnu_old_format = "";
                            update_option('rnu_old_format', $rnu_old_format);
                            
                            // Download the file. Assumes only one administrator would be exporting at a time.
                            $filename = "RnU_" . date("Ymdhis") . ".csv"; // add date and time to export file name
                            header('Content-type: application/csv');
                            header('Content-Disposition: attachment; filename=' . $filename);
                            
                            // Get The Data fields
                            for ($i = 0; $i < $rows_total; $i ++) {
                                $row = $results[$i];
                                $lineout = '';
                                if (! empty($row['RNU_ACK_DATETIME'])) {
                                    $output_matrix[$row['RNU_USERNAME']][$row['RNU_USER_ID']][$row['post_title']] = $row['RNU_ACK_DATETIME'];
                                    $output_email[$row['RNU_USERNAME']][$row['RNU_USER_ID']] = $row['user_email'];
                                } else {
                                    $output_matrix[$row['RNU_USERNAME']][$row['RNU_USER_ID']] = ""; // a user who made no acknowledgements during time frame
                                    $output_email[$row['RNU_USERNAME']][$row['RNU_USER_ID']] = $row['user_email'];
                                }
                            }
                            // get the titles of all posts that are found in any of the acknowledgements found in the time frame
                            $post_titles = array();
                            foreach ($output_matrix as $username => $id_entities) {
                                if (is_array($id_entities)) {
                                    foreach ($id_entities as $title_entry) {
                                        if (! empty($title_entry)) {
                                            foreach ($title_entry as $post_title => $when) {
                                                // if there is a title that is not yet in the array, then put it in the array
                                                if (empty($post_titles) || ! in_array($post_title, $post_titles)) {
                                                    $post_titles[] = $post_title;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // use the post_titles that were found as column headers in alphabetical order
                            asort($post_titles);
                            
                            $myLine = "USERNAME,USERID,USEREMAIL,COUNT,";
                            $column_number = 1;
                            foreach ($post_titles as $key => $column_name_string) {
                                $myLine .= '"' . str_replace('"', '""', $column_name_string) . '",';
                                // the column headed with the title $column_name_string, will be the
                                // column numbered by $column_number, start with #1
                                $column_numbers[$column_name_string] = $column_number ++;
                            }
                            echo $myLine . "\r\n"; // header row (username, userid, title1, title2, ...)
                            if ($debug_csv)
                                fwrite($file, $myLine);
                                
                                // there will be one row for every unique username / userid combination
                            foreach ($output_matrix as $username => $user_ids) {
                                if (is_array($user_ids)) {
                                    if ($debug_csv) {
                                        print_r($user_ids); print "\r\n";
                                    }
                                    // if the user_ids is an array, then thereis at least one userid associated
                                    // username, meaning that the username is not a person who has no acknowledgments
                                    foreach ($user_ids as $userid => $acknowledgments) {
                                        // the comma separated values will be enclosed in double-quotes.
                                        // if the username has a double quote, escape it using double double-quotes
                                        $myLine = '"' . str_replace('"', '""', $username) . '",'; // the first column
                                        $myLine .= $userid; // the second column, the id
                                        $useremail = $output_email[$username][$userid];
                                        $myLine .= ',' . $useremail; // the third column, the email address
                                        $ack_dates = array(); // no acknowledgments seen as yet
                                        if (! empty($acknowledgments)) {
                                            // there are acknowledgements, loop through them
                                            foreach ($acknowledgments as $post_title => $when) {
                                                // the column depends on which post
                                                $column_number = $column_numbers[$post_title];
                                                $ack_dates[$column_number] = $when;
                                            }
                                            
                                            $myLine .= ',' . count($acknowledgments); // the fourth column, the count
                                            // loop through the remaining columns (the postings)
                                            // if there is a date associated with that column, add it to the line
                                            for ($i = 1; $i <= max(array_keys($ack_dates)); $i ++) {
                                                if (array_key_exists($i, $ack_dates)) {
                                                    $myLine .= ',"' . str_replace('"', '""', $ack_dates[$i]) . '"';
                                                } else {
                                                    $myLine .= ',""'; // no acknowledgement for this post, skip column
                                                }
                                            }
                                        } else {
                                            // There are no userid's associated with this username.
                                            // meaning that we got the username from the list of users,
                                            // NOT from the acknowledgments found in the data range.
                                            $myLine .= ',0'; // the fourth column, the count - none
                                        }
                                        // output only if there are acknowledgements, or if the user requested ALL users.
                                        if ((isset($rnu_all_users) && $rnu_all_users) || (! empty($ack_dates))) {
                                            echo $myLine . "\r\n";
                                            if ($debug_csv)
                                                fwrite($file, $myLine);
                                        }
                                    }
                                } else {
                                    // There are no userid's associated with this username.
                                    // meaning that we got the username from the list of users,
                                    // NOT from the acknowledgments found in the data range.
                                    $myLine = '"' . str_replace('"', '""', $username) . '",'; // the first column
                                    $myLine .= $userid; // the second column, the id
                                    $useremail = $output_email[$username][$userid];
                                    $myLine .= ',' . $useremail; // the third column, the email address
                                    $myLine .= ',0'; // the fourth column, the count - none
                                    echo $myLine . "\r\n"; // TODO: do NOT export unless the user is a member of this site, not just the the multisite.
                                    if ($debug_csv)
                                        fwrite($file, $myLine);
                                }
                            }
                            if ($debug_csv)
                                fclose($file);
                            exit(); // important! or you will end up including the admin page in the extract
                        } else {
                            $this->export_warning_msg .= __('Warning: No records to export within date range.', 'read-and-understood-locale');
                        }
                    } // end of if date range is valid
                } // end of if dates are valid
            } // end of if start date and end date are present
        } // end of if export button
    }

    function wpse9876_download_old_format()
    {
        global $wpdb;
        $FILTERED_POST = self::filter_either($_POST);
        
        $rnu_ack_tablename = $wpdb->prefix . "rnu_acknowledgements";
        $this->export_warning_msg = ""; // resets the export warning
        
        wp_register_style('jquery-style', plugins_url('css/jquery-ui.css', __FILE__ ));
        wp_enqueue_style('jquery-style');
        wp_enqueue_script('jquery-ui-datepicker');
        wp_enqueue_style('jquery-style', plugins_url('css/jquery-ui.css', __FILE__ ));
        
        wp_register_style('read-and-understood-style', plugins_url('css/rnu-plugin.css', __FILE__ ));
        wp_enqueue_style('read-and-understood-style');
        wp_register_script('read-and-understood-scripts', plugins_url('js/rnu_javascript.js', __FILE__ ));
        wp_enqueue_script('read-and-understood-scripts');
        
        if (null != (filter_var($FILTERED_POST['rnu_ExportBtn'],FILTER_SANITIZE_STRING ))) {
            foreach ($FILTERED_POST as $opt_name => $opt_val) {
                if (strpos($opt_name, $this->shortname) === 0) {
                    $$opt_name = filter_var($opt_val,FILTER_SANITIZE_STRING ); // double $$ means set the variable that is named ... to the value
                }
            } // end foreach
            if (! isset($rnu_end_date) || $rnu_end_date == '' || ! isset($rnu_start_date) || $rnu_start_date == '') {
                // echo __('Error: Need to set start date and end date.', 'read-and-understood-locale') . '<br />';
            } else {
                if (($this->rnu_check_date($rnu_start_date) === false) || ($this->rnu_check_date($rnu_end_date) === false)) {
                    // echo __('Error: Dates should be in yyyy-mm-dd format.', 'read-and-understood-locale') . '<br />';
                } else {
                    if (strcmp($rnu_start_date, $rnu_end_date) > 0) { // works because of yyyy-mm-dd format
                                                                          // echo __('Error: Start date may not be after end date.', 'read-and-understood-locale') . '<br />';
                    } else {
                        $day_before_range = date('Y-m-d', strtotime($rnu_start_date . ' -1 day'));
                        $day_after_range = date('Y-m-d', strtotime($rnu_end_date . ' +1 day'));
                        $sql = "SELECT RNU_USERNAME, post_title, idRNU_ACKNOWLEDGMENT, RNU_USER_ID, RNU_POST_ID, RNU_ACK_DATETIME ";
                        $sql .= " from $rnu_ack_tablename ";
                        $sql .= "left join " . $wpdb->prefix . "posts on $rnu_ack_tablename.RNU_POST_ID = " . $wpdb->prefix . "posts.ID ";
                        $sql .= " where ";
                        $sql .= "RNU_ACK_DATETIME > '" . $day_before_range . " 23:59:59' and ";
                        $sql .= "RNU_ACK_DATETIME < '" . $day_after_range . " 00:00:00';";
                        
                        $results = $wpdb->get_results($sql);
                        $rows_total = $wpdb->num_rows;
                        
                        if ($rows_total > 0) {
                            update_option('rnu_start_date', $rnu_start_date);
                            update_option('rnu_end_date', $rnu_end_date);
                            update_option('rnu_all_users', $rnu_all_users);
                            update_option('rnu_old_format', $rnu_old_format);
                            
                            // Download the file
                            $filename = "RnU_" . date("Ymdhis") . ".csv"; // add date and time to export file name
                            header('Content-type: application/csv');
                            header('Content-Disposition: attachment; filename=' . $filename);
                            
                            $col_names = $wpdb->get_col_info('name');
                            $columns_total = count($col_names);
                            
                            // TODO: sometimes in chrome, a blank line appears instead of the header row. Need to clear buffer?
                            
                            // Get The Field Name(s)
                            $lineout = '';
                            for ($i = 0; $i < $columns_total; $i ++) {
                                $heading = $col_names[$i];
                                if ($lineout) {
                                    $lineout .= ',"' . $heading . '"';
                                } else {
                                    $lineout .= '"' . $heading . '"';
                                }
                            }
                            echo $lineout . "\r\n";
                            
                            // Get The Data fields
                            for ($i = 0; $i < $rows_total; $i ++) {
                                $row = $results[$i];
                                $lineout = '';
                                foreach ($row as $col_name => $col_val) {
                                    if ($lineout) {
                                        $lineout .= ',"' . $col_val . '"';
                                    } else {
                                        $lineout .= '"' . $col_val . '"';
                                    }
                                }
                                echo $lineout . "\r\n";
                            }
                            
                            exit(); // important! or you will end up including the admin page in the extract
                        } else {
                            $this->export_warning_msg .= __('Warning: No records to export within date range.', 'read-and-understood-locale');
                        }
                    } // end of if date range is valid
                } // end of if dates are valid
            } // end of if start date and end date are present
        } // end of if export button
    }
} // end of class
$demo = new class_wp_rnu(); // calls __construct()
$demo->register_plugin_scripts();
$demo->register_plugin_activation_hook();
$demo->register_plugin_deactivate_hook();
?>