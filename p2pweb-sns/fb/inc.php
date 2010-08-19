<?php

require_once('lib/lib.php');

define('FACEBOOK_APP_ID', '151506128200294');
define('FACEBOOK_SECRET', '76aa8c7e73c78680ac974ff89d746f0f');

//2.aFq6yklU9WbxjnMAlS_OSw__.3600.1282129200-724012920
//151506128200294|2.aFq6yklU9WbxjnMAlS_OSw__.3600.1282129200-724012920|EFzc_TWR9jU-QXq6jWSpT7Zr4ko.

function get_facebook_user() {
	$cookie = get_facebook_cookie(FACEBOOK_APP_ID, FACEBOOK_SECRET);
	$user = false;
	if ($cookie) {
		//$me = file_get_contents("https://graph.facebook.com/me?access_token=" . urlencode($cookie['access_token']));
		$fb = new FbUser();
		$user = $fb->by_fbid($cookie['uid']);
		if ($user->session != $cookie['session_key']) {
			print "updating .. <p>";
			$user->fb_update($cookie['access_token']);
			$user->session = $cookie['session_key'];
			$user->save();
		}
	}
	return $user;
}

function get_facebook_cookie($app_id, $application_secret) {

	/*
	if (1) {
		return array( 'access_token' => '151506128200294|2.oY89wD3bcsiAICHnt0cDcQ__.3600.1282147200-724012920|jsIfZXFntuTL3aYcvxRneiShcXk.',
			      'expires' => '1282147200',
			      'secret' => 'GtxHOXB1Axm_nnB3Ddz_qw__',
			      'session_key' => '2.oY89wD3bcsiAICHnt0cDcQ__.3600.1282147200-724012920',
			      'sig' => '010bd480752ed5d8edc877174c62d0da',
			      'uid' => '724012920' );
	}
	*/

    if (!isset($_COOKIE['fbs_' . $app_id]))
	    return null;

    $args = array();
    parse_str(trim($_COOKIE['fbs_' . $app_id], '\\"'), $args);
    ksort($args);
    $payload = '';
    foreach ($args as $key => $value) {
        if ($key != 'sig') {
            $payload .= $key . '=' . $value;
	    //echo $key . '=' . $value . "<br>";
        }
    }

    if (!isset($args['sig']))
	    return null;
    if (md5($payload . $application_secret) != $args['sig']) {
      return null;
    }
    return $args;
}

function unset_facebook_cookie($app_id) {
	setcookie('fbs_' . $app_id);
}

function check_facebook_sig($req, $application_secret) {
   
	$args = array();
	foreach ($req as $k => $v) {
		if (strpos($k, 'fb_sig_') == 0)
			$args[substr($k, 7)] = $v;
	}
	
	ksort($args);
	$payload = '';
	foreach ($args as $key => $value) {
		if ($key != 'sig')
			$payload .= $key . '=' . $value;
	}
	error_log("checking " . md5($payload . $application_secret) . " against " . $req['fb_sig']);
	if (md5($payload . $application_secret) != $req['fb_sig']) {
		return false;
	}
	return $args;
}
