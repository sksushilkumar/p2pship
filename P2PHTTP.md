# Introduction #

HTTP being the versatile and popular protocol it is, was the second application protocol supported by the p2pship system.

In addition to being able to establish peer-to-peer HTTP connections between peers (where one peer is serving as a serving host), the system includes also a peer-to-peer web caching module as well as HTTP interfaces for sending 'raw' application data packets (known as the external API, `extapi`).

The P2P HTTP functionality can be used through an URL-rewriting scheme or by using the p2pship system as a normal HTTP proxy for applications.

# Configuring #

The HTTP support is enabled by compiling the system with the `extapi` option enabled,
```
./configure --enable-extapi
```

This enables not only the basic peer-to-peer HTTP, but also the external HTTP-based API for sending raw application packages.

To enable the HTTP proxy access interface as well as a convenience ext api interface, the following option must be set as well:
```
--enable-httpproxy
```

The P2P webcaching is enabled using the option
```
--enable-webcache
```

This is currently the only one of the three that is **not** enabled by default. Using P2P web caching results in a fair amount of traffic (updating indexes, fetching pointers) and has a number of privacy implications (namely that it is quite easy to follow which pages you visit by tracking what you announce to have cached) which has led to it being disabled by default.

## Settings ##

Please see the [extapi](http://code.google.com/p/p2pship/wiki/Configuration#ExtAPI) and [P2PHTTP](http://code.google.com/p/p2pship/wiki/Configuration#P2PHTTP) sections of the configurations. The settings relate largely only to which local address / port is used for incoming traffic.

The [WebCache](http://code.google.com/p/p2pship/wiki/Configuration#Webcache) part contains the settings of the p2p web caching.

# Use #

The HTTP functionality is used either through the ext api interface or the http proxy interface. The ext api interface provides a REST-like API for not only making P2P HTTP requests, but also sending raw data packets as well as for registering HTTP services provided by applications outside the p2pship system.

A P2P HTTP service is provided by registering it at a specific port for an _identity_. This is similar to normal HTTP schematics, except that the service (e.g. an Apache server) is not served at a specific `host:port` combination, but a _identity:port_ combination instead.

Accessing these P2P services can be done either using the HTTP proxy or the ext api interface. In the following, `<proxy>` refers to the `host:port` combination for which the HTTP proxy interface configured. `<extapi`refers to the `host:port` combination of the external API.

## Registering a service ##

Services are registered by calling
```
http://<extapi>/http_register
```

The following parameters are accepted:
```
dport   - The port of the identity on which the service
aor     - The AOR of the identity to use. If missing, use the default identity
ttl     - The duration of the registration (in seconds)
url     - The distination URL of the service (where the service is running)
```

E.g.
```
http://<extapi>/http_register?aor=test%40domain.com&dport=9000&ttl=3600&url=localhost%3A80
```

Would register the HTTP service running at `localhost:80` at _test@domain.com:9000_.

## Accessing services ##

P2P services are accessed using the following extapi call
```
http://<extapi>/http/<target aor>/<path>
```
where the aor's at-sign (@) is replaced with `.at.`.

E.g. a call to
```
http://<extapi>/http/test.at.domain.com/index.html
```

would access the `/index.html` document from the service registered for _test@domain.com:80_.

The following call offers the possibility to change the identity used to access the remote service as well as the target port of the service:
```
http://<extapi>/http_forward/<source aor>/<target aor>/<port>/<path>
```

E.g.
```
http://<extapi>/http_forward/me%40domain.com/test%40domain.com/9000/index.html
```

would access the `/index.html` document of the service registered in the registration example using the identity _me@domain.com_.

A third alternative exists which does not include the source aor, but uses HTTP authentication mechanisms to obtain it from the user (browsers normally display a popup requesting user name and password). The source aor is provided as the user name of this exchange. The syntax is
```
http://<extapi>/http_auth_forward/<target aor>/<port>/<path>
```


## HTTP proxy ##

The HTTP proxy interface is used by configuring the client software (e.g. web browser) to use the p2pship as a web proxy at the address configured in the settings.

P2P services are accessed in a similar fashion as normal HTTP services, by replacing the host part of an URL with the serving peer's aor. The at-sign (@) of the aor is replaced with '.at.'. For instance, navigating to
```
http://test.at.domain.com:80/index.html
```
would access the document `/index.html` of the service in the registration example.

The HTTP proxy interface uses the HTTP proxy authentication mechanism for selecting the identity used to access the P2P services. Providing an empty username results in the default identity of the system to be used.

## Revealing identities in the HTTP headers ##

The p2pship system adds the following HTTP headers to all calls it forwards
```
X-P2P-From       - The source identity's aor
X-P2P-To         - The target identity's aor
```

## Additional external API calls ##

In addition to the features provided for the p2p http connectivity, the ext api interface provides the following functionalities (all urls are relative to `http://<extapi>`:

### Overlay storage ###

Getting a value:
```
/get
```
Parameters:
```
key    - The value key
```

Setting a value:
```
/set
```
Parameters:
```
key     - The value key
data    - The data value
ttl     - The TTL in seconds
secret  - The storage secret for mutable puts
```

Removing a value:
```
/rm
```
Parameters:
```
key     - The value key
secret  - The storage secret
```

### Raw service packets ###

Registering a receiver for packets:
```
/register
```
Parameters:
```
aor      - The identity
ttl      - The validity of the registration in seconds
url      - The target URL where the data packets are to be delivered
service  - The service number
```

Sending a service packet
```
/send
```
Parameters:
```
to       - The target identity's aor
from     - The source identity
service  - The service number
data     - The data packet
```


# Notes #

The HTTP proxy interface will act as a normal (non P2P) HTTP proxy unless the '.at.' string is found in the hostname. This enables applications to use it for hybrid P2P/CS sessions.

A TTL of -1 means forever.

Using an empty aor as the source identity results in the default identity to be used.