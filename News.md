**9 January 2012 / jookos**

We'd like to announce that p2pship has now officially been used in withing the realms of Internet-based Virtual Worlds as a backend for the [realXtend](http://www.realxtend.org) framework. Check out the [youtube video](http://www.youtube.com/watch?v=g3EJ71dd8sY) as it's being used for communicating with fellow virtual characters!

The integration was implemented as a SIP mobule by the realXtend people. Please visit their web site or the [SPEAR project site](http://p2psip.info/virtual.html) for more info. Excellent work!

**30 September 2011 / jookos**

After a good amount of testing, we are confident enough to release version 3.0 of the p2pship package.  This includes the system updates made since 2.0, complete with the extensions (voicemail, multiparty and presence), which forms together a nice, complete, package for peer-to-peer communication.

The final update pre-3.0 was a re-examination of the way HIPD is executed and how sockets are created (to prevent child processes from hogging them in case of a restart).  This version will be the base for future features, including a better IPC interface and communication channel handling.

**30 June 2011 / jookos**

The [Voicemail](Voicemail.md) plugin / support has now officially been released! Pre-compiled packages are available in the HIIT repository, and the source can be found right here on Google Code.  The feature allows you to both leave messages for friends that are currently offline or unavailable, as well as have friends leave messages for you locally when away.

The plugin notifies you of these voicemails through the presence status of a special contact, `voicemail@domain`, which becomes 'online' whenever there is a pending voicemail. Also, an instant message notification is sent providing the details, and allowing the user to control (list, delete) stored messages. Listening to the messages is as easy as to place a VoIP call to the special voicemail contact.

Greetings can also be customized and recorded by calling an extension number of the voicemail contact. The audio is recorded as mp3 files (if a suitable gstreamer plug-in is present) or wav. The HIIT repository contains pre-compiled packages of lame for gstreamer which enable mp3 encoding.

**Bloomsday (16 June) 2011 / jookos**

We're happy to announce that an initial (preview?) version of the [Voicemail](Voicemail.md) feature has now been commited to the Google Code repository.  Implemented as a Python Plug-In, it has caused a number of reforms and additions in the [PRE](PRE.md), as well as a much awaited redesign of the SIP message flow.  Both local (you leaving messages for an unavailable friend) and remote (a friend leaving a message on your device while you're away/busy) messages are supported with the possibility to use custom greeting messsages.  Please see the [Voicemail](Voicemail.md) page for details!

**12 May 2011 / jookos**

In anticipation of the upcoming _offline_ message exchange support (namely distributed voice mail), we finally got around to plan the re-work the packaging system for the maemo tablets. We now have two core versions: `p2pship` and `p2pship-pre`. The `-pre` version includes the Python run-time, and is needed for some of the newer features.

We also created add-on packages for the presence support and multiparty conferencing (`p2pship-presence` and `p2pship-multiparty`). These require the `-pre` version of the p2pship suite. Furthermore, the multiparty conferencing add-on requires a specific mixer plugin for gstreamer (liveadder). As this is not available in the normal Maemo distributions, we took the liberty of creating our own version of it in our repository (package `gstreamer0.10-plugin-liveadder`). All of these dependencies are, naturally, resolved automatically.

**31 Mar 2011 / jookos**

We have finally got through the features we wanted for the next release and are glad to announce version 2.0.  New features include publish-subscribe support and presence for SIP, as well as a ton of improvements.  Available from the repository, pre-compiled packages coming soon!

**30 Dec 2010 / jookos**

Seasons greetings! Have during this month commited the first version of the [multiparty](Multiparty.md) conferencing system (based on PRE) as well as more extensive [spit/spam](SPAM.md) mechanisms.

**9 Dec 2010 / jookos**

Added an experimental package for the Nokia N900 mobile phone. Please check the [download](http://code.google.com/p/p2pship/downloads/list) section as well as [the release notes](N900Notes.md).

**8 Oct 2010 / jookos**

The DTN branch has been merged into trunk. The experimental [new connectivity](DTN.md) framework be developed in the `new_conns` branch.

**21 Sep 2010 / jookos**

A [testbed](Testbed.md) has been set up in HIIT. Currently hosting (in addition to person-to-person calling) also the [CoffeeSipper](CoffeeSipper.md) service. More to come!

**19 Aug 2010 / jookos**

A [facebook](http://www.facebook.com) version of the p2pweb sharing was forked off the stand-alone site. Please see [the manual](P2PSNS.md) for more info. An instance can (for now..) be found as [facebook's ShipSharing](http://apps.facebook.com/shipsharing).

**10 Aug 2010 / jookos**

Added the [DTN](DTN.md) branch to the repository. This is currently the most actively developed branch which is getting the newest features integrated. Although it is bad practice, the service packet ACK/NACKs enabled by the DTN branch has been so useful that it hasn't made sense to use trunk anymore in development. These changes will be marged into trunk pretty soon, dedicating the DTN branch once again to what it was originally created for.