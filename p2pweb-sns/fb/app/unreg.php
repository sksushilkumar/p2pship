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
privacy-preserving manner. Your images, videos or other content will never be exposed to unauthorized parties,
including even the facebook site itself, without your explicit permission.
<p>
Although facebook is used as a platform for sharing content, ShipSharing is not bound to or dependent on it. This means that
	 even though your facebook account (or facebook itself) would be compromized, or the privacy policies would suddently 
change, the content shared through this application
will still be safe. Sharing is done peer-to-peer using the <a href='http://code.google.com/p/p2pship'>p2pship</a> system. Please
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
