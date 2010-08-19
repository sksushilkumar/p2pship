<html>
<head>
<title>ShipSharing - Sharing stuff privately</title>
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <script src="http://connect.facebook.net/en_US/all.js"></script>
    <script type="text/javascript" src="js/jquery.js"></script>
    <script type="text/javascript" src="<?= p2p_url('js/p2pscripts.js.php', array('session' => $user->session)) ?>"></script>
    <script type="text/javascript">
	 
function enable_p2p($ident) {
	$('#warn').hide();
	$('#p2pid').html($ident);
}

function load($action, $id, $data, $param, $f, $param2) {
	var $data = "action="+$action+"&data=" + $data + "&id=" + $id + "&param="+$param + "&param2="+$param2;
	$.ajax({ method: "post", url: "post.php", data: $data,
                 success: $f
	});
}

function post($action, $id, $data, $param, $f, $param2) {
	var $data = "action="+$action+"&data=" + $data + "&id=" + $id + "&param="+$param + "&param2="+$param2;
	$.ajax({ method: "post", url: "post.php", data: $data,
                 success: $f
	});
}

function remove_content($id) {
	post("removecontent", $id, null, null, function(html) { 
		load_content(3, 'own');
	});
}	
	
function add_content($name, $description, $type) {
	$('#content').html("Adding, please wait..");
	post("addcontent", 0, $name, $type, function(html) { 
		load_content(3, 'own');
	}, $description);
}

function load_content($tab, $name) {
	$tabs = 4;
	for ($i = 1; $i <= $tabs; $i++)
		if ($i == $tab)
			$('#tab' + $i).addClass("active");
		else
			$('#tab' + $i).removeClass("active");

	$('#content').html("Loading..");
	$.get('content.php?page=' + $name, function(data) {
		$("#content").html(data);
        });
}

function load_subcontent($name, $id) {
	$('#subcontent').html("Loading..");
	$.get('content.php?page=' + $name + "&id=" + $id, function(data) {
		$("#subcontent").html(data);
        });
}

    </script>

</head>
<body onload="load_content(1, 'latest');">

<center>
<div id='warn'>You need to have the p2pship system installed to use ShipSharing!<br>
Please visit <a href='http://code.google.com/p/p2pship'>the project page</a></div>
</center>


<!-- <img src='http://graph.facebook.com/<?= $user->fb_id ?>/picture'>  -->

<h1>ShipSharing</h1>

<p>


<div class="ftabs"> 
<div id="ftabs"> 
<a id="tab1" class="active" onclick="load_content(1, 'latest');">Recently shared</a> 
<a id="tab2" onclick="load_content(2, 'friends');">Friends</a> 
<a id="tab3" onclick="load_content(3, 'own');">Your shared</a> 
<a id="tab4" class="last" onclick="load_content(4, 'share');">Share</a> 
</div> 
<img id="friends_loading" style="height: 8px; width: 28px;" alt="loading" src="static.ak.fbcdn.net/images/upload_progress.gif?1:25923"/> 
</div>


<div id="content">
</div>

  </body>
</html>
