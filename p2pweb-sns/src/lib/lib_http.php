<?php

function create_p2purl($user, $base, $params = null) {
	return create_url('http://' . str_replace("@", ".at.", $user) . $base, $params);
}

/* util - creates a http parameters string from the given array */
function create_url($base, $params = null)
{
	$ret = $base;
	if ($params != null) {
		$ret .= "?";
		foreach ($params as $k => $v)
			$ret .= urlencode($k) . "=" . urlencode($v) . "&";
	}
	return $ret;
}

/* returns an url to myself through p2p */
function p2p_url($url, $params = null) {
	global $urlpre;
	return $urlpre . create_url($url, $params);
}

/* class for handling the responses */
class http_response {

	var $code = 500;
	var $body = null;
	var $ok = false;
	var $info = null;
	var $resp = null;

	public function __construct($ch, $resp) {
		if ($resp != false) {
			$this->resp = $resp;
			$this->info = curl_getinfo($ch); 
			$this->code = $this->info['http_code'];
			if (($p = strpos($resp, "\r\n\r\n")) === FALSE)
				$this->body = $resp;
			else
				$this->body = substr($resp, $p+4);
			if (($this->code / 100) == 2)
				$this->ok = true;
		}
	}

	public function __toString() {
		if ($this->body)
			return "Connection " . ($this->ok? "OK":"FAIL") . ", response code " . $this->code . ", body: " . $this->body;
		else
			return "No connection";
	}

	public function exec($ch) {
		$resp = curl_exec($ch); 
		$ret = new http_response($ch, $resp);
		curl_close($ch);
		return $ret;
	}
}

/* registers the p2p web service */
function register()
{
	global $p2pident;
	global $urlpre;
	global $extapi_url;
	global $p2pproxy;

	//localhost:9061/http_register?aor=socialize@jookos.org&ttl=3600&url=localhost:80&dport=80
	$url = create_url($extapi_url . "/http_register", array("aor" => $p2pident,
								"ttl" => "-1",
								"url" => "localhost:80",
								"dport" => "80"));
	$ch = curl_init();
	$ops = array(CURLOPT_URL => $url,
		     //CURLOPT_HTTPPROXYTUNNEL => 1,
		     //CURLOPT_PROXYUSERPWD => $p2pident . ":",
		     //CURLOPT_PROXY => $p2pproxy, 
		     CURLOPT_RETURNTRANSFER => true, 
		     CURLOPT_CUSTOMREQUEST => 'GET', 
		     CURLOPT_HEADER => true);
	
	curl_setopt_array($ch, $ops);
	return http_response::exec($ch);
}


function fetch_p2p($user, $path)
{
	global $p2pident;
	global $p2pproxy;

	$url = 'http://' . str_replace("@", ".at.", $user) . $path;
	$ch = curl_init();
	$ops = array(CURLOPT_URL => $url,
		     CURLOPT_CONNECTTIMEOUT => 0,
		     //CURLOPT_HTTPPROXYTUNNEL => 1,
		     CURLOPT_PROXYUSERPWD => $p2pident . ":",
		     CURLOPT_PROXY => $p2pproxy, 
		     CURLOPT_RETURNTRANSFER => true, 
		     CURLOPT_CUSTOMREQUEST => 'GET', 
		     CURLOPT_HEADER => true);
	
	curl_setopt_array($ch, $ops);
	return http_response::exec($ch);
}

function fetch_data($url)
{
	global $p2pident;
	global $p2pproxy;

	$ch = curl_init();
	$ops = array(CURLOPT_URL => $url,
		     CURLOPT_CONNECTTIMEOUT => 0,
		     //CURLOPT_HTTPPROXYTUNNEL => 1,
		     CURLOPT_PROXYUSERPWD => $p2pident . ":",
		     CURLOPT_PROXY => $p2pproxy, 
		     CURLOPT_RETURNTRANSFER => true, 
		     CURLOPT_CUSTOMREQUEST => 'GET', 
		     CURLOPT_HEADER => true);
	
	curl_setopt_array($ch, $ops);
	return http_response::exec($ch);
}

function post_data($url, $data)
{
	$ch = curl_init();
	$ops = array(CURLOPT_URL => $url,
		     /*
		     CURLOPT_CONNECTTIMEOUT => 0,
		     //CURLOPT_HTTPPROXYTUNNEL => 1,
		     CURLOPT_PROXYUSERPWD => $p2pident . ":",
		     CURLOPT_PROXY => $p2pproxy, 
		     CURLOPT_RETURNTRANSFER => true, 
		     CURLOPT_CUSTOMREQUEST => 'POST',*/
		     CURLOPT_POST => 1,
		     CURLOPT_POSTFIELDS => $data);
	
	curl_setopt_array($ch, $ops);
	return http_response::exec($ch);
}

function do_post_data($url, $data)
{
	$params = array('http' => array('method' => 'POST',
					'content' => $data));
	$ctx = stream_context_create($params);
	$fp = @fopen($url, 'rb', false, $ctx);
	if (!$fp) 
		return null;
	return @stream_get_contents($fp);
}
