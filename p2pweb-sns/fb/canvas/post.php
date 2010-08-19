<?php
require_once('../inc.php');

$user = get_facebook_user();
if ($user) {

$action = $_REQUEST['action'];
$id = $_REQUEST['id'];
$msg = $_REQUEST['data'];
$param = $_REQUEST['param'];

if ($action == "wallmsg") {
	if ($user->is_me($id) || $user->is_friend($id))
		$user->add_to_wall($id, $msg);
} else if ($action == "addcontent") {
	$name = $msg;
	$type = $param;
	$description = $_REQUEST['param2'];

	$resp = fetch_p2p($user->user->p2pid, create_url("/addcontent", array( "name" => $name,
									 "type" => $type)));
	if ($resp->ok) {
		if (preg_match("/id:([^ ]+)/i", $resp->body, $m)) {
			$cid = $m[1];
			$user->user->add_content($cid, $name, $description, $type);
			echo "Content added with id " . $cid;
		} else 
			echo "Error adding content: " . $resp->body;
	} else if ($resp->body)
		echo "Error: Could not add content!";
	else
		echo "Error: Could not connect!";

} else if ($action == "removecontent") {
	$user->user->remove_content($id);
} else if ($action == "freq") {
	display_friend($user->user->request_friend($id, $msg));
}

}