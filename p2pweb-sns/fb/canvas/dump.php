<?php

require_once('../inc.php');

?><html>
  <body>

Welcome to ShipSharing

<hr>
      Yer HTTP request: <pre><?= print_r($_REQUEST) ?></pre>
<hr>
      Yer HTTP headers: <pre><?= print_r($_SERVER) ?></pre>
<hr>
      Yer cookie: <pre><?= print_r($_COOKIE) ?></pre>
<hr>

<?php

	//unset_facebook_cookie(FACEBOOK_APP_ID);

$cookie = get_facebook_data(FACEBOOK_APP_ID, FACEBOOK_SECRET);
if ($cookie) { ?>
      Your user ID is <?= $cookie['uid'] ?>
      Yer cookie: <pre><?= print_r($cookie) ?></pre>
      
	      <img src='https://graph.facebook.com/<?= $cookie['uid'] ?>/picture'>
<?php 

	      $friends = file_get_contents("https://graph.facebook.com/me?access_token=" . urlencode($cookie['access_token']));
      echo "friedns: <pre>$friends</pre>";

	      $friends = file_get_contents("https://graph.facebook.com/me/friends?access_token=" . urlencode($cookie['access_token']));
      echo "friedns 2: <pre>$friends</pre>";


}


?>
  </body>
</html>
