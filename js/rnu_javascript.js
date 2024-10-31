// rnu_javascript.js
//
// revised 1/16/2014
//
// Supports the "Read and Understood" WordPress Plugin
//
//
jQuery.fn.setVisibilityPlugin = function($){
    // hides or shows an element by changing css attributes
    var selectedObjects = this;
    return {
        show : function(){
            jQuery(selectedObjects).each(function(){
				jQuery(this).css('visibility', 'visible');
                jQuery(this).css('display', 'block');
            });
                              return selectedObjects; 
                            },
        hide : function(){
            jQuery(selectedObjects).each(function(){
                jQuery(this).css('visibility', 'hidden');
                jQuery(this).css('display', 'none');
            });
                  return selectedObjects;
                 }
           };
}
jQuery(document).ready(function($) {
	// by enclosing this code within the .ready, 
	//alert( "You are running jQuery version: " + jQuery.fn.jquery );

	var set_validation_visibility = function() {   		
			var is_require_login_checked;
		var does_button_exist;
		
		does_button_exists = ($("div[name$='_export_warning_msg']").filter("[name^='rnu']").length > 0 )
        if (does_button_exists) {
			$("div[name$='_export_warning_msg']").filter("[name^='rnu']");
		}
		does_button_exists = ($("input[name$='_require_login']").filter("[name^='rnu']").length > 0 )
        if (does_button_exists) {
        is_require_login_checked = $("input[name$='_require_login']").filter("[name^='rnu']").attr('checked');

        if (is_require_login_checked) {	
    		  $("[name$='_username_validation_pattern']").filter("[name^='rnu']").setVisibilityPlugin().hide();  
    		  $("[name$='_username_validation_title']").filter("[name^='rnu']").setVisibilityPlugin().hide();  
    		  $("[name$='_username']").filter("[name^='rnu']").setVisibilityPlugin().hide();  
		} else {
    		  $("[name$='_username_validation_pattern']").filter("[name^='rnu']").setVisibilityPlugin().show();  
    		  $("[name$='_username_validation_title']").filter("[name^='rnu']").setVisibilityPlugin().show();  
     		  $("[name$='_username']").filter("[name^='rnu']").setVisibilityPlugin().show();  
    	}
    	}
    };

	set_validation_visibility(); // set visibility when the document (admin settings page) is ready/loaded

    $("input[name$='_username']").filter("[name^='rnu']").change(function() {
//       if ( event.which == 13 ) {
//			event.preventDefault();  //don't submit any forms if return is entered in text box
//		}
		//check the field against its own pattern 
		if ($("input[name$='_username_validation_pattern']").filter("[name^='rnu']").length >0) {
			// we must be on the admin page
			ptrn = $("input[name$='_username_validation_pattern']").filter("[name^='rnu']").val();
			title = $("input[name$='_username_validation_title']").filter("[name^='rnu']").val();	
			valu = $("input[name$='_username']").filter("[name^='rnu']").val();
		} else {
			// we must be on some other page on the site, possible a posting page
			if ($(this).prop('pattern').length >0) {
				ptrn = $(this).prop('pattern');
				title = $(this).prop('title');	
				valu = $(this).val();
			}
		}
       	if(ptrn) {
	  		matches = valu.match(ptrn);
 	       	if(matches != valu) {
 	 			msg = 'Username: "'.concat(valu,'" does not match the pattern: ').concat(ptrn,'\r\n');  			
	        	msg = msg.concat('Please enter a username that has ', title);
	    		alert(msg);
				return false; // aborts the change
			}
		}
    });
	
    $("input[name$='_require_login']").filter("[name^='rnu']").click(function() {
        	set_validation_visibility();
    });


	$("input[name='rnu_submit']").click(function(e) {
		var myurl = ajax_object.ajax_url;
		var data = new Object();
			data.action = 'rnu_action';
			data.rnu_username = document.getElementsByName('rnu_username')[0].value; // the user might be allowed to change this
			data.rnu_user_id = document.getElementsByName('rnu_user_id')[0].value;
			data.rnu_post_id =  document.getElementsByName('rnu_post_id')[0].value;
		$.post(myurl, data, function(response) {
			if ( (document.getElementsByName('rnu_username')[0].value) ){		
				$(".hidden_need_name_msg").setVisibilityPlugin().hide();  // got a name
			} else {
				$(".hidden_need_name_msg").setVisibilityPlugin().show();  
			}

			if (response) {		
				// if all went well, the response is something like 'Your acknowledgement has been recorded.'
				$(".hidden_acknowledgement_msg").filter("[name^='rnu']").setVisibilityPlugin().show(); // show the acknowledgement message
				$(".hidden_need_name_msg").filter("[name^='rnu']").setVisibilityPlugin().hide();  
				$("input[name='rnu_submit']").filter("[name^='rnu']").setVisibilityPlugin().hide();// hide the submit button
				$("div[name='rnu_hide_username']").filter("[name^='rnu']").setVisibilityPlugin().hide(); // hide the name text box
			} else {
				// otherwise, the response	 is blank
				$(".hidden_need_name_msg").setVisibilityPlugin().show();  
			}
		});
		return false; // pre the form from being submitted, since the .post to ajax took care of that through the callback
	});
									
    $("input[name$='_date']").filter("[name^='rnu']").datepicker({
            dateFormat : 'yy-mm-dd'
    });

    $("input[name$='_date']").filter("[name^='rnu']").datepicker({
      onSelect: function() {
        $(this).change();
      }
    });

    $("input[name$='_date']").filter("[name^='rnu']").change(function(){
        $("input[name$='PurgeBtn']").filter("[name^='rnu']").val('Purge Acknowledgements');
        $("input[name$='_purged_count']").filter("[name^='rnu']").val(0);
        $("div[name$='_export_warning_msg']").filter("[name^='rnu']").setVisibilityPlugin().hide();
    });
        				

});
