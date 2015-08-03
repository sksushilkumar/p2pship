# SIP Gateway #

The [SIP](SIP.md) integration allows users to communicate using their existing
SIP applications with other users within the P2P network.  However,
this can be restrictive as they would have to use another application
for communicating with friends that have not adopted the system (yet ;).

The support for external SIP systems (or others, with a suitable adapter in place) is built using _gateway_ peers and redirection. Clients (normal users) configure their proxy with simple redirection rules that guide the proxy to send data (SIP signalling) with specific addressing to these gateway peers (instead of the peers it would otherwise, as indicated by the to-field). The gateway peers are configured to accept signalling not addressed to their own identities, and have network addresses where these should go. On these addresses there should be a gateway adapter positioned which accepts the signalling and translates into the external system's domain.

For instance. `alice@example.com` calls `12345@pots.com`. Her proxy is configured to route all signalling matching the pattern `[0-9]+@pots.com` to `pots-gw@example.com`.

When `pots-gw@example.com` received this signalling, it is configured to allow such signalling from `.*@example.com` (anyone on the example.com domain) matching the pattern `[0-9]+@pots.com`, and send it further to `localhost:1234`. At this address is a gateway adapter listening, which accepts the signalling and looks up in its internal registry that `alice@example.com` signalling should be mapped to the account `67890` in the external system (which you've probably figured out by now is a POTS system). The adaptor also has a rule for translating the target AOR to the external system's accounts, which in this case is done simply by stripping the domain.

The adaptor thus places a call from `67890` (alice) to `12345` via the telephone system, and routes all data traffic through the addresses found in the SIP messages (which get routed through whatever route alice/pots-gw have decided on).

The adaptor is not something that people need to implement themselves. The p2pship proxy only contain the redirection / routing needed. We have a reference implementation of a adaptor to external SIP systems, which we may release at some point.


# Configuration #

The system configuration contains an entry pointing to the configuration file. This file would contain something alike (as configured for the example described above):

**Clients** have normally only `route` entries:
```
<?xml version="1.0" ?>
<sip-routing>
  <route>
    <source>.*</source> <!-- local aor, any here. -->
    <target>^[0-9]+@pots.com$</target> <!-- dest aors -->
    <via>pots-gw@example.com</via> <!-- the gateway peer -->
  </route>
</sip-routing>
```

**Gateway** peers use the `relay` elements:
```
<?xml version="1.0" ?>
<sip-routing>
  <relay>
    <ident>pots-gw@example.com</ident> <!-- the local identity -->
    <subject>^[0-9]+@pots.com$</subject> <!-- foreign aors we accept -->
    <allow>^.*@example.com$</allow> <!-- from these.. -->
    <address>localhost:1234</address> <!-- .. that we send here! -->
  </relay>
</sip-routing>
```

Note that clients can act as gateways simultaneously. And there can be multiple routes and relay rules configured. And the rules use normal regex syntax.