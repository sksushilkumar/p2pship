<?php

require_once('inc.php');

/*

Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: 
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_uninstall: 1
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_locale: en_US
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_in_new_facebook: 1
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_time: 1282050735.8398
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_added: 0
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_user: 724012920
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_country: fi
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_api_key: bfa72b13896a5234aebd3928e9c66a29
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig_app_id: 151506128200294
[Tue Aug 17 16:11:29 2010] [error] [client 66.220.153.246] postremove: fb_sig: e21e86d898cb29f21eb8a25e888d67fb

 */

if ($a = check_facebook_sig($_REQUEST, FACEBOOK_SECRET)) {
	Log::add($a['user'], "post_remove");

	$fb = new FbUser();
	$u = $fb->by_fbid($a['user']);
	$u->active = 0;
	$u->save();
}

/*
error_log('postremove: ');
foreach ($_REQUEST as $k => $v)
	error_log("postremove: $k: $v");

if (check_facebook_sig($_REQUEST, FACEBOOK_SECRET))
	error_log("signature match!");
else
	error_log("signature did not match!");
*/

unset_facebook_cookie(FACEBOOK_APP_ID);

