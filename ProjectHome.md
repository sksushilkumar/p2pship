# P2PSHIP / SPEAR #

Previously known as P2P SIP-over-HIP, an experimental system for enabling peer-to-peer communication for normally centralized applications. The roots of the system was in supporting SIP-based applications, but it has since grown to support other client protocols as well. Hence SPEAR - A Secure Peer-To-Peer Services Overlay Architecture.

Please see the [manual](Manual.md) for instructions on setup and use.

## News ##
**9 January 2012 / jookos**

We'd like to announce that p2pship has now officially been used in withing the realms of Internet-based Virtual Worlds as a backend for the [realXtend](http://www.realxtend.org) framework. Check out the [youtube video](http://www.youtube.com/watch?v=g3EJ71dd8sY) as it's being used for communicating with fellow virtual characters!
(More in the [news](News.md) section).

**30 September 2011 / jookos**

After a good amount of testing, we are confident enough to release version 3.0 of the p2pship package.  This includes the system updates made since 2.0, complete with the extensions (voicemail, multiparty and presence), which forms together a nice, complete, package for peer-to-peer communication.
(More in the [news](News.md) section).

**30 June 2011 / jookos**

The [Voicemail](Voicemail.md) plugin / support has now officially been released! Pre-compiled packages are available in the HIIT repository, and the source can be found right here on Google Code.  The feature allows you to both leave messages for friends that are currently offline or unavailable, as well as have friends leave messages for you locally when away. (More in the [news](News.md) section).

**Bloomsday (16 June) 2011 / jookos**

We're happy to announce that an initial (preview?) version of the [Voicemail](Voicemail.md) feature has now been commited to the Google Code repository.  Implemented as a Python Plug-In, it has caused a number of reforms and additions in the [PRE](PRE.md), as well as a much awaited redesign of the SIP message flow.  Both local (you leaving messages for an unavailable friend) and remote (a friend leaving a message on your device while you're away/busy) messages are supported with the possibility to use custom greeting messsages.  Please see the [Voicemail](Voicemail.md) page for details!

**12 May 2011 / jookos**

In anticipation of the upcoming _offline_ message exchange support (namely distributed voice mail), we finally got around to plan the re-work the packaging system for the maemo tablets. We now have two core versions: `p2pship` and `p2pship-pre`. The `-pre` version includes the Python run-time, and is needed for some of the newer features. (More in the [news](News.md) section).

**31 Mar 2011 / jookos**

We have finally got through the features we wanted for the next release and are glad to announce version 2.0.  New features include publish-subscribe support and presence for SIP, as well as a ton of improvements.  Available from the repository, pre-compiled packages coming soon!

**30 Dec 2010 / jookos**

Seasons greetings! Have during this month commited the first version of the [multiparty](Multiparty.md) conferencing system (based on PRE) as well as more extensive [spit/spam](SPAM.md) mechanisms.

**9 Dec 2010 / jookos**

Added an experimental package for the Nokia N900 mobile phone. Please check the [download](http://code.google.com/p/p2pship/downloads/list) section as well as [the release notes](N900Notes.md).

[More news >>](News.md)