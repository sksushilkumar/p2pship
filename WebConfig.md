# Introduction #

The p2pship proxy provides a web-based configuration interface which is meant to provide a better overview of the possible configuration values, and a more user-friendly way of configuring the system, than the standard `settings.conf` file.


## Enabling the web interface ##

The web configuration interface is enabled by default, controlled by the switch
```
./configure --enable-webconf
```

# Setting up the web interface #

The web configuration interface is actually just a simple json-based API, with all the logic and presentation the responsibility of the web pages that use it (through json ajax requests).

That is, it serves as both a simple web server (serving static pages), and as a json API interface, providing data and accepting requests for changing the behaviour of the proxy.

## Quick set-up for the impatient ##

Unless the configuration of the web interface (the interface it is listening to or the data paths it uses) has been modified, please copy (or make a symbolic link) the files in the `webconf/` folder of the source tree into `~/.p2pship/web/` (of the user which will run p2pship), creating the folder unless it exists.

By default, it binds itself to the localhost (128.0.0.1) interface on port 9080, so entering
```
http://localhost:9080
```
in your browser should take you to the start page.

## Web configuration overview ##

As mentioned, the web configuration interface listens to port 9080 on the localhost interface by default. This can be changed with the `webconf` setting. E.g.,
```
webconf=127.0.0.1:4050
```
in `settings.conf` would change this to port 4050.

### Static files ###

By default, the web interface serves files from the folder
```
~/.p2pship/web/
```

This can be changed with the `web_dir` configuration value in `settings.conf`. Static files are served from this folder if the request path starts with `/web/`.

For instance, `http://localhost:9080/web/file.txt` would serve, with a default configuration, the file `.p2pship/web/file.txt`.

**Note:** The default index page (empty path) is routed to `/web/start.html`.

### json API ###

All json API calls start with the path `/json/`. Following is a list of the currently supported calls:

  * `/json/config`: Returns the system configuration
  * `/json/idents`: The identities info
  * `/json/cas`: Info on the certificate authorities
  * `/json/remote_idents`: Known remote peers
  * `/json/mps`: Media proxy statistics
  * `/json/info`: Debugging info
  * `/json/stats`: Call statistics (depends on build)

### Registration packages ###

(Cached) Registration packages can be got from the `/reg` url, providing either a `local` or `remote` parameter containing the AOR.

e.g.,
```
http://localhost:9080/reg?local=alice@p2psip.hiit.fi
```
would return the local user's (alice) registration package, if known.

### posting data ###

`/post/*`

### Misc ###

`/shutdown` - Shut downs the proxy
`/retarthipd` - Restarts HIPD