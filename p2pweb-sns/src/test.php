<?php
require_once('lib.php');


?><html>
  <head>
    <script type="text/javascript" src="jquery.js"></script>
    <script type="text/javascript">
function enable_p2p($enable, $ident) {
	if ($enable) {
		alert("hooray, you're p2p enabled, sir " + $ident);
	} else {

	}
}
    </script>
    <script type="text/javascript" src="<?= p2p_url('p2pscripts.js.php') ?>"></script>
  </head>
<body>

<?php
echo "<pre>";
$ret = fetch_p2p("hafnium@jookos.org:50050", "/echo");
echo "\nret is " . $ret;

echo "</pre>";
?>
<h1>testing..</h1>
  

</body>
</html>
