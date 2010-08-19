<?php

require_once('../inc.php');

$user = get_facebook_user();
if ($user) {
	include('../app/main.php');
} else { 
	include('../app/unreg.php');
}
