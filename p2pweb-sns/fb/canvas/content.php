<?php
require_once('../inc.php');

$user = get_facebook_user();
if (!$user)
	return;

function unspace($str) {
	return str_replace(" ", "&nbsp;", $str);
}

function dform($d) {
	return strftime("%a %e %b %Y, %H:%M", strtotime($d));
	//return "format " . $d;
}

function print_contents($contents, $name, $ismy = false) {
 ?>
<div class="some_div">
		<h3><?= htmlspecialchars($name) ?> shared content</h3>  
<?php	if (count($contents) == 0) { ?>
<p class="upd_on"></p></div>
<p>
<h3>No content shared</h3>  

<?php
        } else {
 ?>
		<p class="upd_on">Updated <?= dform($contents[0]->added) ?>, total <?= count($contents) ?></p></div>
<p>
<?php		
		foreach ($contents as $c)
			print_content($c, $ismy);
	}
}

function print_content($c, $ismy = false) {
?>
<div class="img">
<table class=img><tbody>
<tr><td colspan=2><img width=200 height=150 src='<?= $c->url ?>' alt='Sorry, not available right now'></td></tr>
<tr><td class=ctitle><?= $c->name ?></td><td align=right>
		<?php if ($ismy) { ?>
<img src=images/remove.png width=16 height=16 alt=Remove onclick='remove_content(<?= $c->id ?>);'>
		<?php } ?>
</td></tr>
<tr><td class=cdesc colspan=2><?= $c->description ?></td></tr>
	  <tr><td class=cdesc colspan=2><i>Added <?= dform($c->added) ?></i></td></tr>
</tbody></table>
</div>
<?php
}


$action = $_REQUEST['page'];
$id = $_REQUEST['id'];

/****************************/
if ($action == "latest") {

print_contents($user->get_friends_content(20), "Latest", false);

/****************************/
} else if ($action == "friends") {

	$friends = $user->get_friends(true);
	if (count($friends) == 0) {
?>
<h3>None of your friends are sharing anything!</h3>  
<?php
	} else {
?>
<table width=100%><tbody>
<tr><td valign=top height=100% class=friends>
<div class=friends>
<?php
	foreach ($friends as $f) {
		$contents = $f->get_content();
?>


<a class=friends onclick='load_subcontent("content", <?= $f->fb_id ?>);'>
<table class=friends width=100%><tbody>
<tr><td><img src='http://graph.facebook.com/<?= $f->fb_id ?>/picture'></td>
<td valign=top align=left width=100%>
<table width=100% cellspacing=0 cellpadding=0><tbody>
<tr><td align=left><b><?= unspace($f->name) ?></b>
<tr><td><?= unspace("Sharing " . count($contents) . " objects") ?>
<tr><td><?= (count($contents) > 0? unspace("Updated " . dform($contents[0]->added)) : "") ?>
</tbody></table>
</td></tr>
</tbody></table>
</a>

<?php
	}
?>
</div>
<td valign=top width=100%>
<div id=subcontent width=100%>
</div>
</td></tr></tbody></table>

<?php
	  }
/****************************/
} else if ($action == "own") {

print_contents($user->get_content(), "Your", true);

/****************************/
} else if ($action == "share") {
?>

<div class="some_div">
<h3>Share content</h3>  
<p class="upd_on">
<!-- With friends -->
</p>  
</div>

<p>

<div id=addcontent>
<table><tbody>
<tr><td>Name: <td><input type=text width=100% id=addin>
<tr><td valign=top>Description:<td><textarea id=addde></textarea><br>
<tr><td>Type: <td><select id=addch>
<option value=image>Image</option>
<option name=audio>Audio</option>
<option name=video>Video</option>
<option name=text>Text</option>
</select>
<tr><td colspan=2 align=right>
<input type=submit value=Add onclick='add_content($("#addin").val(), $("#addde").val(), $("#addch").val());'>
</tbody></table>
</div>


<?php

/****************************/
} else if ($action == "content") {

	$fbu = new FbUser();
	$fbu = $fbu->by_fbid($id);
	print_contents($fbu->get_content(), $fbu->name . "'s", false);
} else {
?>

<div class="some_div">  
<h3>Invalid id</h3>  
<p class="upd_on">
</p>  
</div>

<p>
	 Try again, bitte!
		<i>could not understand the action <?= htmlspecialchars($action) ?></i>
<?php
}



