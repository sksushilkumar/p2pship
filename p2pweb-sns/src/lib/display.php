<?php
/* friend preamble */
function display_friendpre($friend) {
	if ($friend == null)
		return;
?>	     
<div id=ftabs class=tabs>
<ul class=tabs>
    <li class=tabs id=fwall>Wall</li>
    <li class=tabs id=fcontent>Content</li>
    <li class=tabs id=ffriends>Friends</li>
    <li class=tabs id=fsettings>Settings</li>
</ul>

<script>
	$('#fwall').click(function(){ load_content($('#content'), "wall", <?= $friend->id ?>); });
	$('#fcontent').click(function(){ load_content($('#content'), "content", <?= $friend->id ?>); });
	$('#ffriends').click(function(){ load_content($('#content'), "friends", <?= $friend->id ?>); });
	$('#fsettings').click(function(){ load_content($('#content'), "settings", <?= $friend->id ?>); });
</script>

</div>
<?php
     }


     /* utility func for formatting a friend's info for the search */
     function display_friend($friend) {
	     global $user;
?>
<div class=flist id=<?= "flist" . $friend->id ?>>
<table><tbody>
<tr><td class=friend><img width=36 height=36 src='<?= $friend->image_url() ?>' alt='<?= $friend->name ?>' onClick='show_friend("<?= $friend->id ?>");'></td>
<td><div class=flist_name><?= $friend->name ?></div>
<div class=flist_id><?= $friend->p2pid ?></div>

<?php if ($user->is_me($friend)) { ?>
That is You!
<?php } else if ($user->is_friend($friend)) { ?>
Your friend <input type=submit value="De-friend" onclick='friend_req(false, <?= $friend->id ?>, "<?= "flist" . $friend->id ?>");'>
<?php } else if ($user->made_friend_request($friend)) { ?>
Requested friend, <input type=submit value="Cancel request" onclick='friend_req(false, <?= $friend->id ?>, "<?= "flist" . $friend->id ?>");'>
<?php } else if ($user->got_friend_request($friend)) { ?>
Has requested you as a friend, <input type=submit value="Accept" onclick='friend_req(true, <?= $friend->id ?>, "<?= "flist" . $friend->id ?>");'>
<?php } else { ?>
<input type=submit value="Request as friend" onclick='friend_req(true, <?= $friend->id ?>, "<?= "flist" . $friend->id ?>");'>
<?php } ?>

</td></tr>
</tbody></table>
</div>
<?php
	  }



