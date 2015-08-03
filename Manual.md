# Introduction #

The p2pship system is an experimental application that provides peer-to-peer communication capaiblities for different applications.  It is designed to be used as a proxy for existing applications or (recently) as a run-time environment for new applications.

The system was originally designed for SIP-based communication applications (a SIP proxy), allowing users to make peer-to-peer voice / video calls, without the help of a centralized SIP infrastructure. The Host Identity Protocol (HIP) was used as data transport, making the connections secure and enabling features such as mobility and multihoming.

## Overview ##

In a nutshell, the p2pship system provides applications identity-based communication. Instead of network addresses, applications use _identities_ as end points. The p2pship system resolves these identties into actual nodes where the data is delivered. Identities in the p2pship system are (due to its roots as a SIP proxy) email-like SIP address of records (AORs), for instance _jookos@example.com_.

Compared to other identity protocols (such as HIP), the p2pship system differs as it:

  * A global human-readable identity scheme (name lookup)
  * Different application interfaces
  * Support for multiple lookup / rendezvous systems
  * Support for multiple data bearers

In short, the system is not designed primarly to provide generic identity-based connectivity (as HIP), but as an application-specific abstraction for peer-to-peer communication. Although possible, it is not designed to be used to create, for instance, duplex data channels. Instead, it interprets application data and delivers it in the most suitable manner.

## Features ##

Currently the p2pship proxy supports the following applications

  * SIP with media proxying (see [SIP](SIP.md))
    * With [Gateway](PSTN.md) support
  * Peer-to-peer HTTP (see [P2PHTTP](P2PHTTP.md))
  * Peer-to-peer web caching (see [the webcache part](P2PHTTP.md) of the P2PHTTP documentation)

For lookup:

  * LAN broadcast (see [the lookup documentation](Lookup#Broadcast.md))
  * [OpenDHT](http://www.opendht.org) / [OpenLookup (version 1)](http://code.google.com/p/openlookup/) (see [the lookup documentation](Lookup#OpenDHT.md))
  * P2PExt, a simple key-based web lookup (see [the lookup documentation](Lookup#P2PEXT.md))

Transports:

  * HIP (TCP/UDP)
  * Unencrypted TCP/UDP

## P2P SIP feature support ##

  * Voice / Video calls
  * Instant messaging
  * Presence
  * Transparent multi-party conferencing
  * Transparent voicemail

# Sections #

  * [Building and installing form source](Compiling.md)
  * [Configuring the system](Configuration.md)
  * [Identity Management](IdentityManagement.md)
  * [Setting up and using the web configuration interface](WebConfig.md)
  * [Using SIP applications with the proxy](SIP.md)
  * [Using the peer-to-peer HTTP interface](P2PHTTP.md)
  * [Configuring and using the Python run-time environment](PRE.md)

## Applications, use-cases, related projects ##

  * [Setting up and testing the peer-to-peer hybrid social network site](P2PSNS.md)

## Development directions ##

_See the page for [planned features](UpcomingFeatures.md)_