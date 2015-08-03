# Introduction #

Voicemail, or more generally _off-line messaging_, is a useful feature for any sort of communication system. By being able to record messages for people currently not reachable, and have them delivered later, we're able to free ourselves from constantly monitoring the status of people. This naturally becomes difficult in a distributed settings where there is no reliable, constantly available, 3rd party to store these messages while the recipient is away.  Instead, we need to leverage, as always in P2P networks, the resources of possibly untrusted peers to deliver the data.  This introduces a number of issues to consider, including

**Reliability**

_How can we ensure that a recipient actually receives (in a timely fashion) a message we've left them?_

**Integrity**

_How can we ensure the message is not tampered with? How can we ensure the messages aren't being left in our name?_

**Privacy**

_How can we limit who is able to interpret (listen to) the message? How can we prevent others from konwing altogether that we've left the messsage or for whom it is intended?_

**Compatibility**

_How can we ensure the recipient is able to interpret the message?_


Some of these can be solved in a pretty straight-forward manner. With the pre-existing featues of the p2pship system, we can quite safely address at least the integrity concerns. By attaching electronic signatures to the messages, and using the identity authorities or other means of binding keys to users, we're able to detect tampering (or false entries).  The privacy issues can be mitigated by using the privacy extensions of the system, encrypting and obfuscating the overlay storage keys.

Reliability and compatibility, both addressing the delivery of the messages, are harder to perfect. But then again, these are issues which people have learned to accept a reasonable amount of risk. After all, voicemails in traditional centralized systems can always be ignored or accidentally deleted.

The goal with the voicemail extensions of the p2pship system is to provide a reasonably secure platform on which different types of delivery models can be used. We provide the basic tools for creating voicemails, exchanging the necessary parameters and communicating the existence of these in a secure and privacy conscience manner. This will be used to further develop different types of models for storing the messages _offline_, using trust models and similar constructs.


# Design overview #

The basic design of the voicemail feature utilizes an _invite-announce-acknowledge_- model. Potential recipients of voicemails (to whom voicemail can be _left_) publish _invites_ for those that they wish to receive voicemails from. These invites can be delivered through the overlay or directly during peer-to-peer sessions. And they can be public, meaning that anyone is able to leave a message (although the risk of spam in public networks does become an issue then).

When leaving a voicemail, for instance if the recipient is busy handling another call or unavailable, the caller fetches the voicemail _invite_ for the recipient. This includes media parameters, greetings and information concerning how the voicemail should be stored. The p2pship proxy (of either the recipient or caller) answers the call as if the user would have, plays the greeting and records a message.

The recorded message is stored and published using _announcements_. These are simple data packets which noteify and describe the message to the intended recipient - types, date, size and how to retrieve it. The voicemail subsystem of the recipient's proxy uses this information to fetch the message and notifies the user.  The recipient can then call a specific "number", intercepted by the local voicemail subsystem, which plays the message. Upon successfully delivering the message to the user, the proxy publishes an _acknoledgement_, which signals that the message has been delivered, and that it can be removed from any resource used for storing it.

Note that the voicemail can be recorded both the recipient or initiator of a call. The typical case for using the initiator for reocrding a voicemail is when the recipient is offline.  This requires the exchange of _invites_, _announcements_ and _acknowledgements_ as described above. Recipient-based voicemail is much simpler in that sense, as it can be transparent for the caller. The proxy of the recipient will answer the call on behalf of the recipient, play a pre-recorded greeting and record the message to the recipient's local device. From a technical point of view of the initiator, this is identical to if the user would have answered the call. No exchange of invites or announcements is needed. This is however only a special case of the voicemail mechanism. In the following we will concentrate on the initiator-based mechanism, as it presents more challanges.

## Invites ##

The invites contain everything needed to create a voicemail for a recipients. These serve also to signal the support for voicemailing in general, and that the caller has been authorized to leave those (or actually that the recipient is not likely to ignore those).  These include (or could include)

**Greetings**

These are meant to be short introductions played before the message is recorded, indicating clearly that the user could not be reached, and it is possible to record a voicemail after the greeting.  Currently pre-recorded audio greetings are supported which can be fetched using the p2pship's _resourcefetch_ interface (basically retrieving a file from a remote user), or stored on a network drive accessible through HTTP.

In the future, we could consider text-based greeting which are played using voice synthesizers or something else. Also, we could have different greetings for different situations. We could have specific greetings for when the user is offline, and others when the user just is not answering the call. These could also vary depending on who is calling, or the time of day ("..I'm probably sleeping, please leave a message!").

**Supported audio formats**

The formats in which messages are accepted. This could include codecs (mp3, wav etc), quality (16bit, 44.1 KHz) and restrictions on size and length (< 1 MB, < 240 seconds).

**Policy hints**

We could imagine different types of policies on when messages are accepted and how they should be handled. We could require the privacy enhancements to be used, or not accept voicemails during vacation periods.

**Storage parameters**

The receiver may wish to indicate trusted peers or network resources that is recommended to be used for storage of the annoucements and message data. Also, if overlay networks are used, randomized storage keys could be indicated to improve privacy.

_Note:_ Currently only the greetings are used. The messages are recorded using a pre-defined format, and the messages are only stored on the initiator's device (accessible for the recipient using the resourcefetch mechanism).

## Announcements ##

The announcements are data packets describing a voicemail that has been recorded for a user. It contains (or could contain) values such as

**Storage**

Where the actually recording can be found. This might include overlay storages, network drives and different peers which have agreed to store the message.

**Message details**

When the message was left, the size and length of it. Audio encoding parameters. And by whom it was left.

Currently only the storage parameters are used, and incdicate a resourcefetch key that can be used by the recipient to access the data.

## Acknowledgements ##

Acknoledgements are not currently used, as we do not yet support external (of the initiator/recipient) storage mechanisms. But these would be used to signal the initiator that the message has been delivered. Furthermore, these would be used also to signal 3rd party storage providers (such as trusted peers) that the message data can now be discarded. Basically this has been thought to work by the initiator creating a random _ack-storage key_, which is included in the announcement. After the message has been delivered, the recipient is expected to publish a signed package confirming the delivery using this key. Peers trusted with storing the message are also given this key, and monitor it for the acknowledgements.

# Implementation #

The voicemail system is implemented as a PRE plugin. When making a call, the voicemail manager immediately starts a search for the voicemail invite for the remote peer. If the peer is not found, or rejects the call (either through a timeout or just by rejecting), the voicemail manager 'captures' the call. It simulates the remote peer answering the call, playing the greeting of the remote peer and recording whatever the local user says.

This recording is stored and advertised as a new voice mail in the overlay. Note that this is done (by default; configurable) only for remote peers for whom a voicemail invite is found (or cached). Both the local and remote peer has to support voicemail in this sense.

The description above is called _local_ voice mail, as the voice mail is recorded on the caller's local device. Voicemail can also be _remote_, recorded on the receiver's device.

The remote voice mails can be used, for instance, when the remote peer is in the middle of another call, and cannot answer. The voicemail manager of the remote peer will capture the call after the SIP UA signals busy (or rejected), playing the greeting and recording the respose. Remote voicemail requires thus voicemail support only from the remote peer, as it will seem (to the caller) is if the remote user actually answered the call.

Note that remote voicemail is not enabled by default (configurable).


## Configuration ##

Please see the voicemail-prefixed configuration values. These are created dynamically by the plug-in.  Following is an overview of the most important ones:

_Voicemail identityprefix_ - The prefix of the special voicemail contact that is used to control the voicemail.  This should be something specific, as all AORs beginning with it will be captured by the voicemail controller. The default is _voicemail_, meaning that, for instance, _voicemail@domain.com_, _voicemail+something@localhost_, _voicemailing.dude@here.com_ will all be captured by it.

_Type of voicemail: for local caller only, remote caller only or both_ - Whether the local user should be able to leave voicemails for remote peers (local), or viceversa (local) or both.

_Codec to use_ - How the voicemails will be encoded. If the option is available, we recommend MP3 (if available).

_Default greeting file for both local and remote_: The location of the default greeting, see below for details.

_Enable xxx voicemail_: Enable voicemail for different types of 'unavailable' codes: busy (user is in another call), offline (user not found), rejected (user rejects the call).

_Leave voicemail even though no voicemail invite is found_: Whether the voicemail manager should leave "blind" voice mails; voice mails for users that may not support the whole scheme. This is not recommended (and disabled by default).

## User interface ##

Currently the voicemail system uses only standard SIP signalling to provide an interface for standard, legacy, apps. Messages are announced to the user using SIP IM, and the user is able to listen to them by calling specially prefixed SIP AORs, which are intercepted by the voicemail system.  This special SIP AOR, or AOR prefix actually, can be set in the configuration.

### Managing voice mail ###

When a voicemail has been received, the presence status of this voicemail contact will turn into 'online'. By calling this contact, the oldest un-heard voicemail will always play.

Each voicemail will be assigned a non-overlapping number, starting from 1.  When a voicemail is received, the IM notification will contain this number for the message.  Calling the voicemail contact and appending this number to its name will result in that specific message to be played, even though it has been heard before.  This can be used to listen to old voicemails.

The IM interface accepts commands to query and modify the voicemail database.  The commands accepted are:
```
/list     - lists all unheard voicemails
/all      - lists all stored voicemails (also old, heard, ones)
/remove # - deletes voicemail number #
```

For instance, when the voicemail manager discovers a new voicemail, its presence status will change into 'online', and an instant message such as the following will be sent to the user:

```
New voicemail [8] from alice@p2psip.hiit.fi!
```

The number assigned to the voicemail is here 8.  By calling the voicemail controller (which is, by default `voicemail@localhost`, where the domain `localhost` may actually be anything as only the user name of the AOR is checked for), this message will be played.  As there are no other unheard voicemails, a call to the number again will be terminated.

By adding the voicemail number to the voicemail controller's AOR, the voicemail can be heard again.  In this example that would be done by calling the AOR `voicemail8@localhost`.

By sending the instant message
```
/remove 8
```

to the voicemail controller, the message will be deleted.

### Managing greetings ###

The default greeting for all users is a pretty dull, computer-synthetized, "hello" message. The same greeting is provided to remote peers (as your greeting), as well as used as the greeting _for_ remote peers when their greetings are not available.

The greeting used for yourself (heard by remote peers when leaving a voice mail)  can be changed by calling the AOR `voicemail+record@localhost` (assuming `voicemail` is the configured voicemail management prefix).

The current greeting can be heard by calling `voicemail+greeting@localhost`.


## Notes and caveats ##

We have noticed that some systems (or versions of GStreamer) has difficulties streaming WAV data over RTP.  For this reason (as well as obvious other ones) we therefore recommend that you use mp3 encoding for all audio.  The gstreamer plug-in needed for this is the lame gstreamer encoder. This can be found in many distributions within the gstreamer-plugins-ugly package. For Maemo 4.0/4.1, the HIIT repository maintains pre-compiled packages of both lame itself as well as the lame gstreamer plugin.

In addition to the mp3 encoder, the Maemo 4.0 platform need a mp3 