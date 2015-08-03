# Introduction #

As much as we would like it, it seems like the whole world's communication will not be done through p2pship for a while yet. To accommodate this (short) transition period, the p2pship proxy supports Gateway relays, enabling calls to be made between the peer-to-peer network and other telephony systems which offer a SIP interface. This allows calls to be made from your client to both p2p users as well as, for instance, normal PSTN phones.

This feature is based on (trusted) gateway nodes that receive the calls (or signalling) meant for the external system, and forwards those to the actual Gateway provided by that network. Mediaproxying (if necessary) is done on the p2pship proxy. The architecture looks something like the following:

```
  PCn = P2P clients, configured as gateway clients (using p2pship)
  PG = A P2P client configured as gateway (using p2pship)
  GAD = A gateway adaptor (part of the p2pship project)
  GW = The Gateway to the external network, run by PSTN operators


 alice
  PC1 -- call:123456@pots --> PG -- call:123456@pots:from:alice --> GAD -- call:123456:from:accountX --> GW -->
```

The local p2pship proxy configured as a gateway client checks the SIP AORs to which calls are placed. By configuring specific regexp-like patterns (e.g., "`.*@pots`"), it knows which ones are 'normal' p2psip calls, and which ones are meant for an external network.

Those meant for an external network are forwarded to the gateway p2pship client configured for those. This p2pship instance is located so that it has direct access to a gateway adapter (preferably on the same host). When receiving connections, it checks the SIP AORs and matches them through, again, regexp-like strings to know whether to accept them and where to forward them (to which gateway adapter).

The gateway adapter is a separate application that keeps track of the user accounts used in the external network, and the mapping of those to p2pship accounts. For instance, a gateway to Skype might map the p2pship identity 'alice@p2psip.info' to 'alice\_on\_skype'. This one-to-one mapping is not strictly necessary (all p2pship identities can be configured to use the same), but then again when calling someone on the external network, the receiver will not know which one of the p2pship users is actually calling. And, receiving calls is not possible.

The GAD is also responsible for keeping the registrations to the external network alive. This might cause some confusion as if someone on the external network is trying to call a user mapped to the p2pship network, that user might seem online, but when the gateway adapter actually tries to connect the call, it might get a 404 Not found response.

The GAD would ideally be part of the p2pship proxy, but in this manner, it can be moved to another location for better security. After all, it would contain all the usernames and passwords used in the external network.

# Details #

Sample configurations for the gateway clients will be provided hopefully soon. Also, the source code of our implementation of the GAD will be released.