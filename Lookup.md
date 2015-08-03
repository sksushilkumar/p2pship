# Introduction #



# Modules #

The following lookup modules are supported:

## Broadcast ##

Based on UDP/IP multicast. A simple query-response mechanism initially developed only for testing purposes.

Is enabled by default, can be disabled by
```
./configure --disable-broadcast
```

Requests are sent in UDP packets containing the string
```
req:<key_sha1_base64>\n
```

Where the key is SHA1 hashed and base64 encoded (and '\n' denotes a linefeed). Responses are sent in packages containing:
```
resp:<key>\n
<data>
```

See [the settings](Configuration#Broadcast.md) for configuring.

## OpenDHT ##

Uses the [OpenDHT](http://www.opendht.org) interface for fetching data.

Currently disabled by default due to possible instability / deadlock issues that haven't been properly debugged yet (and the fact that OpenDHT isn't available).

Enabled using
```
./configure --enable-opendht
```

See [the settings](Configuration#OpenDHT.md) for configuring.

## P2PEXT ##

A really simple web-based key-value store interface. This was created as a response to the frustration caused by the instability and slowness of OpenDHT as an alternative 'global' lookup scheme.

See http://p2pext.appspot.com for a reference deployment.

Enabled by default. Can be disabled with
```
./configure --disable-p2pext
```

See [the settings](Configuration#P2PEXT.md) for configuring.