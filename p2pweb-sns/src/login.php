<?php
require_once('lib/lib.php');
if (login())
     return;
?><html>
  <head>
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <script type="text/javascript" src="js/jquery.js"></script>
    <script type="text/javascript" src="<?= p2p_url('js/p2pscripts.js.php') ?>"></script>
    <script type="text/javascript">

function enable_p2p($ident) {
	$('#warn').hide();
	$('#login').val($ident);
}

$(document).ready(function(){
	var $w = "<?= $login_warning ?>";
	if ($w.length > 0)
		$('#warn2').html($w);
	else
		$('#warn2').hide();
});

    </script>
  </head>
<body>

<center>

<div id=warn2 class=warn>
Please enable JavaScript!
</div>

<h1>P2P Web Socializing</h1>
<div id=logindiv>
<form method=post>
    <table><tbody>
    <tr><td>Your name:</td><td><input type=text name=login id=login></td></tr>
    <tr><td>Password:</td><td><input type=password name=passwd></td></tr>
    <tr><td colspan=2 align=right><input id=loginbtn type=submit value="Login"></td></tr>
    </tbody></table>
    Not a member? <a href=register.php>Register here!</a>
</form>
</div>

<p>

<div id=warn class=warn>
    Warning! You don't seem to be P2P enabled!
</div>
</center>


</body>
</html>
