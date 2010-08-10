<?php
require_once('lib/lib.php');
preamble();
$id=$_REQUEST['id'];
$friend = null;
$u = $user;
if (isset($_REQUEST['fid'])) {
	$friend = User::by_id($_REQUEST['fid']);
	if ($friend != null && !$user->is_me($friend))
		$u = $friend;
	else
		$friend = null;
}

$param = null;
if (isset($_REQUEST['param']))
     $param = $_REQUEST['param'];
     
?><html><body><?php


/* sorry, but.. */
if (!$user->is_me($u) && !$user->is_friend($u)) {
?>

<h2>You need to be <?= $u->name ?>s friend to see the profile!</h2>

<?php
/* MENU */
} else if ($id == "menu") {
?>

<h3>Notifications</h3>
<?php foreach ($user->get_notifs() as $note) { echo $note . "<br>"; } ?>

<?php $friends = $user->get_friends(); $i = 0;?>
<h3>Friends (<?= count($friends) ?>)</h3>
<table><tbody>
<?php foreach ($friends as $friend) { 
	if ($i % 5 == 0) echo "<tr>";
?>
          <td class=friend><img width=36 height=36 src='<?= $friend->image_url() ?>' alt='<?= $friend->name ?>' onClick='show_friend("<?= $friend->id ?>");'></td>
<?php 
	if ($i % 5 == 4) echo "</tr>";
	$i++;
} ?>
</tbody></table>


 <?php 

/* WALL */
} else if ($id == "wall") { 
	display_friendpre($friend);
?>

<h2>The Wall of <?= $u->name ?></h2>
<div class=wallmsg>
Add something:
<textarea id=postmsga></textarea>
<input type=submit id=postmsg value=Post onclick='post("wallmsg", <?= $u->id ?>, $("#postmsga").val(), null,
                                                  function(html){
                                                      load_content($("#content"), "wall", <?= $u->id ?>);
                                                  });'>
</div>

<?php foreach ($u->get_wall() as $msg) { ?>
<div class=wallmsg>
<div class=wallmsg_time><?= $msg->time ?></div>
<div class=wallmsg_auth><?= $msg->user ?></div> says:
<div class=wallmsg_msg><?= $msg->message ?></div>
</div>
<?php } 

/* Find friends! */
} else if ($id == "friends") {
 display_friendpre($friend);

 if ($user->is_me($u)) {
?>
<h2>Find new friends</h2> 
	 Search for: <input type=text id=fffin>
	 <input type=submit id=fff value=Search onclick="load_content($('#content'), 'friends', <?= $u->id ?>, $('#fffin').val());">
<hr>
<?php
				    }

if ($param != null && $param != "pending") {
	$friends = User::find($param);
?>
	<h3>Results for query <?= $param ?>: (<?= count($friends) ?>)</h3>
<?php
} else if ($param != null) {
	$friends = $u->get_friends(false, true, false);
?>
	<h3>Results for query <?= $param ?>: (<?= count($friends) ?>)</h3>
<?php
} else {
	$friends = $u->get_friends();
?>
	<h3>Friends of <?= $u->name ?> (<?= count($friends) ?>)</h3>
<?php
}

foreach ($friends as $id => $friend)
	display_friend($friend);

 if ($user->is_me($u)) {
 $friends = $u->get_friends(false, false, true);
 if (count($friends) > 0) {
?>
	<h3>Pending</h3>
<?php

foreach ($friends as $id => $friend)
	display_friend($friend);

 }
 }

/* content! */
} else if ($id == "content") {
	display_friendpre($friend);
?>
	<h2><?= $u->name ?>'s shared content</h2> 
<?php //'
        $i=0;
	echo "<table width=100%><tbody>";
	foreach ($u->get_content() as $c) {
		if ($i % 4 == 0) echo "<tr>";
		echo "<td valign=top><table width=200><tbody>";
		echo "<tr><td colspan=2><img width=200 height=150 src='".$c->url."' alt='Sorry, not available right now'></td></tr>";
		
		if ($user->is_me($u)) {
			echo "<tr><td class=ctitle>".$c->name."</td><td><img src=images/remove.png width=16 height=16 alt=Remove onclick='remove_content(".$c->id.");'></td></tr>";
		} else {
			echo "<tr><td colspan=2 class=ctitle>".$c->name."</td></tr>";
		}
		echo "<tr><td class=cdesc colspan=2>".$c->description."</td></tr>";
		echo "</tbody></table></td>";
		if ($i % 4 == 3) echo "</tr>";
		$i++;
	}
	echo "</tbody></table>";


 if ($user->is_me($u)) {
?>

<div id=addcontent>
	 Add content. <br>
Name: <input type=text width=100% id=addin><br>
Description: <textarea id=addde></textarea><br>
<select id=addch>
<option value=image>Image</option>
<option name=audio>Audio</option>
<option name=video>Video</option>
<option name=text>Text</option>
</select><br>
<input type=submit value=Add onclick='add_content($("#addin").val(), $("#addde").val(), $("#addch").val());'>
</div>

<?php
	 }

/* everything else.. */
} else { 
	display_friendpre($friend);

?>

<h2>The <?= $id ?> of <?= $u->name ?></h2> 

 <?php 
}
?></body></html>