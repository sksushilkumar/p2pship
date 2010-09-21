<?php

require_once('lib/lib.php');

define('FACEBOOK_APP_ID', '151506128200294');
define('FACEBOOK_SECRET', '76aa8c7e73c78680ac974ff89d746f0f');

//2.aFq6yklU9WbxjnMAlS_OSw__.3600.1282129200-724012920
//151506128200294|2.aFq6yklU9WbxjnMAlS_OSw__.3600.1282129200-724012920|EFzc_TWR9jU-QXq6jWSpT7Zr4ko.

function get_facebook_user() {
	$cookie = get_facebook_data(FACEBOOK_APP_ID, FACEBOOK_SECRET);
	$user = false;
	if ($cookie) {
		$fb = new FbUser();
		$uid = $cookie['user'];
		if (isset($cookie['uid']))
			$uid = $cookie['uid'];
		$user = $fb->by_fbid($uid);
		if ($user && $user->session != $cookie['session_key']) {
			//print "updating .. <p>";
			$user->fb_update($cookie['access_token']);
			$user->session = $cookie['session_key'];
			$user->save();
		}
	}
	return $user;
}

/* returns the facebook data as a hashmap. checks signatures etc.
 * doesn't really have to be from the cookie, can be cached / get parameters 
 *
 * obtains a access token if one is not present!
 */
function get_facebook_data($app_id, $application_secret) {

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
	
	/*
	  
	  logic: 

	  - check first GET parameters
	  - if not, check the same for cookie
	  - or, whatever ... check either one, but get the hashtable

	  - check php session: if session == session in phpsession:
	     .. and accesstoken still valid:
	       return hashmap.

	  - if not access_token, get one
	  
	  - set into phpsession: accesstoken & session & everything else ..


	 */

	$args = array();
	if (isset($_REQUEST['fb_sig'])) {
		foreach ($_REQUEST as $k => $v) {
			if (strpos($k, 'fb_sig_') == 0)
				$args[substr($k, 7)] = $v;
		}
		$args['sig'] = $_REQUEST['fb_sig'];
	} else if (isset($_COOKIE['fbs_' . $app_id])) {
		parse_str(trim($_COOKIE['fbs_' . $app_id], '\\"'), $args);
	} else
		$args = null;

	if ($args) {
		ksort($args);
		$payload = '';
		foreach ($args as $key => $value) {
			if ($key != 'sig')
				$payload .= $key . '=' . $value;
		}
		
		if (!isset($args['sig']))
			$args = null;
		else if (md5($payload . $application_secret) != $args['sig'])
			$args = null;
	}

	session_start();
	if (isset($_SESSION['data'])) {
		$args2 = $_SESSION['data'];
		if (!$args)
			$args = $args2;
		else if ($args['session_key'] == $args2['session_key'])
			$args = $args2;
	}
	
	/* check access token validity, acquire new */
	if (!isset($args['access_token'])) {
		$data = do_post_data('https://graph.facebook.com/oauth/exchange_sessions?', http_build_query(array("type" => "client_cred",
														   "client_id" => $app_id,
														   "client_secret" => $application_secret,
														   "sessions" => $args['session_key'])));
		if ($data) {
			$arr = json_decode($data, TRUE);
			if ($arr && $arr[0]['access_token'])
				$args['access_token'] = $arr[0]['access_token'];
		}
	}
	$_SESSION['data'] = $args;
	return $args;
}


/*
curl -F type=client_cred \
     -F client_id=your_app_id \
     -F client_secret=your_app_secret \
     -F sessions=session_key \
     https://graph.facebook.com/oauth/exchange_sessions
*/




function unset_facebook_cookie($app_id) {
	setcookie('fbs_' . $app_id);
}

/*
function get_facebook_sig($req, $application_secret) {
   
	if (!isset($req['fb_sig']))
		return null;
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
	if (md5($payload . $application_secret) != $req['fb_sig']) {
		return null;
	}
	return $args;
}
*/