# Introduction #

The P2P Social networking site was created to test some of the advanced HTTP features enabled by the [p2p http subsystem](P2PHTTP.md) as well as the [scripting engine](PRE.md).

It is a simple php/mysql social networking site, enabling you to create social connections (friends), share updates on your _wall_ as well as content (images, video etc). It uses the p2pship p2p http to access the site, which means that you will be identified based on your p2pship identity, not a traditional web login.

Furthermore, the content you share is always kept by yourself locally. It is never transmitted to the web site, giving you better control over whom it is shared to. When a friend of yours tries to access the content, the P2P social site provides only a link to the content which points to your p2pship identity. You are then able to control whom you actually provide the content to.

**Update:**

A facebook-app version of the site was receintly forked. It uses the same logic as the stand-alone site, except for utilizing the facebook user ids and relationships. Each p2pship identity is tied to an facebook account. Content shared is thus associated with the facebook identity as well. Please see [below](P2PSNS#Facebook.md) for more information.

## Logic ##

The SNS is built as a php site which has access the p2pship network. This site is accessed using the p2pship proxy's HTTP proxy feature, which enables the client to render pages containing both legacy (publicly available on the Internet) content and p2p shared content.

Content sharing is built using a python script which sets up an HTTP-based content server. When asking to share content, the SNS web site issues an HTTP request to the content server on the client's host, requesting for content to be shared. The python script intercepts this request and opens up a dialog for the user to choose what content to share. After selecting a file, the python script does not return the content, but instead an unique identifier which it maps to point to the selected file.

The web site uses this identifier when embedding the users' content by using an URL to the owner's python content server, with the unique content id as parameter (e.g., _http://test.at.test.com/contentserver?id=1234_). The owner's content server will view the request, checking its access control policies, and serve the content of the file. This way the content itself is newer exposed to the SNS, while still being seamlessly rendered to others when visiting the site.

# Configuring #

The use-case assumes that you have successfully installed and configured the p2pship proxy with your own p2pship identity. Please see [here](Compiling.md), [here](Configuration.md), [here](IdentityManagement.md) and [here](P2PHTTP.md) for more information.

Furthermore, the site requires a dedicated identity for the social web site.

## Installing the Social networking site ##

The social networking site requires a working apache / php / mysql installation. It needs a dedicated database and the php/mysql/curl extensions to the apache/php environment.

From the source directory, copy the /src directory to your web servers document folder. Create a new database and a user that has all access rights to the database. See the /db folder of the source directory for a script which initializes the database.

## Configuring the SNS ##

The SNS requires a dedicated p2pship identity. Once installed, the p2pship proxy should be run on a machine accessible to the apache/php server (usually the local host).

Open the lib/lib.php file of the php source. Edit the following variables according to your setup:

**$p2pident**; the name of the identity dedicated to the site.

**$localpath**; the path within the apache web server to the root of the site source.

**$extapi\_url**; the host:port address to the p2pship instance's extapi interface.

**$p2pproxy**; the host:potr address to the p2pship instance's http proxy interface.

Point your browser to `http://<host</<path-to-src>/server_register.php`. If the installation has been successful, you should see a page discplaying a 200 HTTP ok page. This means that the php application has successfully registered the web services of the sns identity to be forwraded to the local apache web server.

## Configuring clients ##

Clients should have the [Python runtime](PRE.md) enabled and the `content_server.py` script application running. The web browser in use should be configured to use the local p2pship instance as HTTP proxy.

# Use #

Using the p2pship HTTP proxy, visit the page `http://<host>/<path-to-src>/home.php`. You should see a login prompt where the name of your identity has been pre-filled in the login-input.

If not, check your configuration.

# Facebook #

Please see the facebook developer's site for information on deploying facebook applications.

Short checklist for deploying your own instance:

  * Initialize the environment (database, apache, p2pship proxy) as described above
  * Point the facebook canvas url to the `canvas/` folder of the source
  * Make sure the `lib/` symbolic link actually points to the p2psns library
  * Point the facebook post auth/remove to the `postauth.php`and `postremove.php` files.

An instance of the application is currently running at http://apps.facebook.com/shipsharing.