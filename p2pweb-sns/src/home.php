<?php
require_once('lib/lib.php');
preamble();

?><html>
  <head>
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <script type="text/javascript" src="js/jquery.js"></script>
    <script type="text/javascript" src="<?= p2p_url('js/p2pscripts.js.php') ?>"></script>
    <script type="text/javascript">

//		 beforeSend: function(){$("#loading").show("fast");},
//	 complete: function(){ $("#loading").hide("fast");},

function enable_p2p($ident) {
	
}

function post($action, $id, $data, $param, $f, $param2) {
	var $data = "action="+$action+"&data=" + $data + "&id=" + $id + "&param="+$param + "&param2="+$param2;
	$.ajax({ method: "post", url: "post.php", data: $data,
                 success: $f
	});
}

function remove_content($id) {
	post("removecontent", $id, null, null, function(html) { 
		load_content($('#content'), "content");
	});
}	
	
function add_content($name, $description, $type) {
	$('#addcontent').html("Adding, please wait..");
	post("addcontent", 0, $name, $type, function(html) { 
		load_content($('#content'), "content");
		//$('#addcontent').html(html); 
	}, $description);
}

function load_content($e, $id, $fid, $param) {
	$data = "id="+$id;
	if ($fid != null)
		$data += "&fid="+$fid;
	if ($param != null)
		$data += "&param="+$param;
	$.ajax({ method: "get", url: "content.php", data: $data,
                 success: function(html){
                      $e.show("slow");
                      $e.html(html);
		 }
	});
}

function show_friend($id) {
	load_content($('#content'), "wall", $id);
}

function friend_req($req, $id, $targetid) {
	//alert("friend req: " + $req + ", id: " + $id);
	//$('#' + $targetid).html("<i>Processing..</i>");
	post("freq", $id, ($req? "1":"0"), null, function(html){
                      $('#' + $targetid).html(html);
		      load_content($('#menu'), "menu");
	});
}

$(document).ready(function(){
	load_content($('#menu'), "menu");
	load_content($('#content'), "wall");
	$('#twall').click(function(){ load_content($('#content'), "wall"); });
	$('#tcontent').click(function(){ load_content($('#content'), "content"); });
	$('#tfriends').click(function(){ load_content($('#content'), "friends"); });
	$('#tsettings').click(function(){ load_content($('#content'), "settings"); });
	$('#tstuff').click(function(){ load_content($('#content'), "stuff"); });
});

    </script>
  </head>
<body>


<h1>Welcome <?= $user->name ?></h1>
<a href=logout.php>Logout</a>

<div id=tabs class=tabs>
<ul class=tabs>
    <li class=tabs id=twall>Wall</li>
    <li class=tabs id=tcontent>Content</li>
    <li class=tabs id=tfriends>Friends</li>
    <li class=tabs id=tsettings>Settings</li>
    <li class=tabs id=tstuff>Notifications</li>
</ul>
</div>


<table id=main><tbody>
<tr><td id=menu>
    Loading sidebar ..
</td><td id=content>

    Loading content ..
</td></tr>
</tbody></table>


</body>
</html>
