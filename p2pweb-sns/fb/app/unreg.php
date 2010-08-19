<html>
<head>
<title>ShipSharing - Sharing stuff privately</title>
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <script src="http://connect.facebook.net/en_US/all.js"></script>
    <script type="text/javascript" src="js/jquery.js"></script>
    <script type="text/javascript">
	 
	 // todo..

    </script>

</head>
<body>

<h3>ShipSharing</h3>

<p>
 ShipSharing is an experimental facebook application which allows you to share content over facebook in a
privacy-preserving manner. You images, videos or other content will never be exposed to unauthorized parties,
including even the facebook site.
<p>
Sharing is done peer-to-peer using the <a href='http://code.google.com/p/p2pship'>p2pship</a> system. Please
visit <a href='http://code.google.com/p/p2pship'>the p2pship project page</a> for the software and instructions on use.

<p>


      <fb:login-button>Install ShipSharing</fb:login-button>

    <div id="fb-root"></div>
    <script>
      FB.init({appId: '<?= FACEBOOK_APP_ID ?>', xfbml: true, cookie: true});
      FB.Event.subscribe('auth.login', function(response) {
        // Reload the application in the logged-in state
        window.top.location = 'http://apps.facebook.com/shipsharing/';
      });
    </script>
  </body>
</html>
