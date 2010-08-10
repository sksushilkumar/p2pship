<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-15">
<title>Register yourself!</title>
</head>
<body>

<?php
require_once('lib/lib.php');

if (isset($_REQUEST['id'])) {
	$u = User::create_user($_REQUEST['id'],
			       $_REQUEST['name'],
			       $_REQUEST['passwd']);
	if ($u != null) {
		echo "ok. " . $u->name . ", you are registered.";
	} else {
		echo "oops. something bad happened";
	}
} else {
?>

<h1>Registering you!</h1>

<form method=post>
P2P ID: <input type=text name=id><br>
Name: <input type=text name=name><br>
Password: <input type=password name=passwd><br>
<input type=submit value=register>
</form>


</body> </html>
<?php 
	 }