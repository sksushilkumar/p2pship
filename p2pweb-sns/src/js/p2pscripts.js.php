<?php
//alert('hello');
$h = apache_request_headers();
?>

var $ident = "<?= $h['X-P2P-From'] ?>";
$(document).ready(function(){
	enable_p2p($ident);
});