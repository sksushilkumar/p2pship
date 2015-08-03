# Introduction #

Due to the system's history as a HIP-oriented application, the connectivity subsystem was designed to use HIP-protected sockets for exchanging data. Along the way plain TCP sockets were added for testing purposes, but the basic model remained the same; a stream-based socket which is authenticated on connect through which packets are exchanged.

The purpose of the updated connectivity framework is to make this modular and more flexible. The connection types (currently HIP and plain-TCP) will be put into _transport handler_ modules which abstract the actual work to a nice, clean interface.

Packets related to the channel authentication will be left to the inner workings of the specific transport handlers that need it. Instead, the connectivity subsystem will only see an interface for querying:

  * Whether we have a working connection to a specific peer
  * A call to establish a connection to a specific peer
  * A call to transmit a service packet (application data) to a peer
  * The general type of the connection

The _type_ of connection will be (atleast) slow and fast. Fast being directly connected, such as HIP or SSL sockets, where slow can be DTN, overlay routed. Other, security-related types (secure, authenticated but unencrypted etc) might be added in the future. When sending data to a peer, the caller will specify how the packet is preferred to be delivered. For instance, sending a call invitation could go through a slow connection unless we already have a fast connection from before.

Whether we _have_ a connection to a specific peer, and establishing a connection, might mean different things depending on the transport. For TCP-based sockets, it is easily understood. For overlay-based transports, _having_ a connection might simply mean that the overlay module has been initialized and is connected to _an_ overlay network; nothing additional is required to "establish" connections to different peers.

For these _slow_ transports, knowing when a packet has actually been sent is not as straightforward. Instaad of the old model (based on TCP sockets), where it was known immediately whether the packet had been delivered, the new connectivity framework will allow the handlers to return a _pending_ result. Depding on the urgency and type of application data, the transport subsystem can then choose to use another transport as well, in case the packet is not delivered at all (e.g., the target peer is not in the overlay at all).

As data packets can be delivered through multiple channels, we need a way of identifying duplicate packets as well as way of acknowledging received packets when they are finally delivered.

Steps needed:

  * ~~Unique message ids for packets, ACK/NACK response~~ (complete)
  * ~~Modularize the connection parameters in the registration packets~~ (complete)
  * Create common wrapper-functions for stream transports based on the current logic
  * Move HIP & TCP connection into their own handlers
  * ~~Cleanup conn.c from obsolete code & features~~
  * Create common wrapper functions for packet-based transports; encrypting data packets, decrypting
  * Create more, packet-based, transport handlers. Overylays and such.

Examples of different possible transport handlers:

  * Different overlay routing
  * Cloud-storage and routing
  * DTN (the official IETF version)
  * 'Homebrewed'-DTN; through memorysticks, email or similar
  * XMPP or other global message exchange systems
  * TLS/SSL/DTLS
  * Native PubSub systems