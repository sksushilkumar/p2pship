<?php

require_once('inc.php');

/*
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_authorize: 1
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_locale: en_US
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_in_new_facebook: 1
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_time: 1282051006.6574
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_added: 1
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_profile_update_time: 1258621196
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_expires: 1282057200
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_user: 724012920
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_session_key: 2.U2y_MdpKoCs1OufFdQwOFw__.3600.1282057200-724012920
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_ss: pakS_ZuFLTA0CmwMwJqHHA__
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_cookie_sig: 539d3ec1762872e22146a936eb59dfb4
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_country: fi
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_api_key: bfa72b13896a5234aebd3928e9c66a29
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig_app_id: 151506128200294
[Tue Aug 17 16:16:00 2010] [error] [client 66.220.156.247] postauth: fb_sig: 8287e8cc2e94b01187a921349a0dcf11
  


 */


if ($a = check_facebook_sig($_REQUEST, FACEBOOK_SECRET)) {
	Log::add($a['user'], "post_auth");

	$fb = new FbUser();
	$u = $fb->by_fbid($a['user']);
	$u->active = 1;
	$u->save();
}

/*
error_log('postauth: ');
foreach ($_REQUEST as $k => $v)
	error_log("postauth: $k: $v");

if (check_facebook_sig($_REQUEST, FACEBOOK_SECRET))
	error_log("signature match!");
else
	error_log("signature did not match!");
*/
