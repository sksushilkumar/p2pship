<?php

/*
 *
 * login stuff
 *
 */
function login()
{
	global $login_warning;
	if (isset($_REQUEST['login'])) {
		$l = $_REQUEST['login'];
		$p = $_REQUEST['passwd'];
		$u = user::by_login($l, $p);
		if ($u != null) {
			session_start();
			$_SESSION['user'] = $u->id;
			header('Location: home.php');
		} else {
			$login_warning = "Invalid login / password";
		}
	}
	return false;
}

function check_login() {
	session_start();
	if (isset($_SESSION['user']))
		return User::by_id($_SESSION['user']);
	else {
		header('Location: login.php');
		exit(0);
	}
}

function logout() {
	session_start();
	session_destroy();
}

