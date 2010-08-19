<?php
require_once('../lib/lib.php');

//alert('hello');
$h = apache_request_headers();
$ident = $h['X-P2P-From'];
if (isset($_REQUEST['session'])) {
	$u = new FbUser();
	$u = $u->by_session($_REQUEST['session']);
	if ($u) {
		$u->set_p2pid($ident);
	}
}
?>

var $ident = "<?= $ident ?>";
$(document).ready(function(){
	enable_p2p($ident);
});