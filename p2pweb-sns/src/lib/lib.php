<?php

/* settings */
//$p2pident = "socialize@jookos.org";
$p2pident = "vetar2@jookos.org";
$localpath = "/jookos/p2pweb/";
$extapi_url = "localhost:9061";
$p2pproxy = 'localhost:9070';


$urlpre = "http://" . str_replace("@", ".at.", $p2pident) . $localpath;
$user = null;

$DB_HOST="localhost:3306";
$DB_USER="p2pweb";
$DB_PASSWD="p2pweb";
$DB_DBNAME="p2pweb";


require_once('lib_user.php');
require_once('lib_http.php');
require_once('lib_login.php');
require_once('display.php');
require_once('db.php');


function preamble() {
	global $user;

	// check that we are logged in
	$user = check_login();

	// put all the necessary css, js's etc ..

}
