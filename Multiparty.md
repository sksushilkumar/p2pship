# Introduction #

Multiparty communication is an important feature of any communication system. By supporting standard SIP signalling, the p2pship system is implicitly supporting already multiparty conferencing, although only client-based (i.e. only when the SIP client used implements the feature, using multiple concurrent calls and client-side audio mixing).

The goal of the multiparty conferencing effort for p2pship is to create a transparent subsystem which allows also legacy (one-to-one) clients to establish conference calls. Preferably the system will be rather independent from the SIP subsystem, allowing possible future communication protocols (XMPP etc) to join cross-protocol conferences (SIP and XMPP users talking to each other). This will however depend much on the semantics of the protocols.

But the goal is to allow the p2pship provide a similar conferencing service as commercial service providers do, but in a server-less peer-to-peer manner. After all, the goal of the whole project is to gradually replace the need for centralized servers with peer control.

## Conferencing overview ##

_todo: General overview of conferencing alternatives in P2P: Use of centralized peer-server for maintaining the conference. Full-mesh architecture. Opportunistic multi-proxy architecture_

## Current SIP/P2PSIP efforts ##

_todo: description of the current state of MMUSIC conferencing / other SIP-based solutions_

## Design alternatives ##

_todo: different types of topologies. We are heading for a hybrid / opportunistic one_

### Naming sessions ###

_todo: how sessions are identified. Protocol specific, SIP for now_

### Access & conference control ###

_todo: how to limit participants. In general, and how to translate that into SIP syntax_

## Conferencing API ##

The plan is to build an easy-to-use interface to the conference manager which would allow it to be extended with new functionality dynamically. This system would be based on the [PRE](PRE.md) and would only affect (naturally) the local conference manager in hybrid conferencing topologies.

Thinking in a more generic manner, the "Conferencing API" is actually a "Communications management API", as it would affect communications (calls, chats) whether or not there are more than two (or even one) persons present.  The multiparty conferencing should actually be just one of its features, and other (such as call recording, desktop sharing) should be available for all calls.

The system would be based on the IPC calls of the PRE which would allow external (to the conference manager) scripts to create hooks into the conferencing system. These would run in their own Python shell, creating a bit of protection / isolation.

The API would allow extensions to:

  * Receiving notifications on events (new conference, participants joining / leaving, changes in the media handling)
  * Capture messages in the group chat
  * Insert messages to the group chat
  * Capture media streams
  * Insert media stream
  * Add / remove participants

_note:_ These could actually work on a higher level, above the multiparty conferencing feature also, as it could be interesting to be able to record all phone calls, or insert messages in any chat. Actually, as the multiparty thing is on the way of becoming part of standard calls (any call we make would actually be a conference with 2 participants), the extensions could be multiparty-specific, but the nature of the multiparty plugin would be more of a 'tap into calls'- plugin. Which, out-of-the-box, happens to support multiparty conferencing.

### Plug-ins / extensions ###

The following are implemented in the current multiparty extension:

**audioplay**: The ability to insert audio files into the conference. For instance, typing '/play song1.mp3' into the group chat would cause the p2pship conference manager to insert (play) that audio file just as if it was an additional participant.

**videoplay**: Audioplay, but with videos (as if someone made a video call). Sources could be local files, on-line streaming, youtube etc.

**deskshare**: Desktop sharing. The recipients would see this also as if you would have made a video call to them. Excellent for collaboration.

**audiorecord**: Call recording.

**videoout / audioout**: Simple 'taps' on the streams from the mixer. Can be used by the conference mixer to check what is happening in the cenference.

### Planning ###

The following contains other examples of what could be implemented:

**taskmanager**: Bot that reacts on certain strings entered in the group chat to automatically form task lists, bug reports, or anything else. Use case: A work-related remote meeting. While discussing matters, todos and tasks are identified. The chair of the meeting enters into the group chat strings like '/task John Check the current sale figures' or '/task Mona Design a new logo for the project by friday'. These would end up in a task manager (which ever you're using) or somewhere else as a task for John, and another for Mona (with a deadline on Friday).

**mediaforward**: Forward media streams from the conference to other sinks. UPNP projectors, external screens, sound systems etc.

**misc bots**: As seen on _IRC_; '/magic8ball should i do this-or-that?`

### Social / web integration ###

_Investigate if there's any synergy in tapping into social networks. This might be also something that affects the system more profoundly, not only the multiparty functionality_

**Google+**: Somehow use the google+ groups for creating automatic conferences / content sharing environments.

**Cross-platform chats**: Support for inviting facebook etc friends into the group IM sessions. This might be more useful as a system-wide feature (possibility to translate SIP IM to XMMP, with AOR/account mapping rules).

**Cross-platform content sharing**: Possibility to share stuff from your facebook wall or something like that. Picasa photos. UI a problem. Perhaps a browser plugin would be necessary here (not too bad of an idea; [BrowserPlugin](BrowserPlugin.md))


# Milestones overview #

The first goal is to enable legacy SIP clients to establish conference calls.

The initial plan is to use a centralized peer-proxy architecture, but hopefully extend it into an opportunistic multi-proxy- like architecture. That is, the first step is to have one peer _host_ the conference. This peer will do the audio mixing for all other participants.

The second step is to extend this model so that all participating peers will actually create small 'mini' mixers for the conference call. This can be used as before, having actually just one peer acting as a center and creating the different audiostreams for each user. The mixer within the other participants would be a dummy one; having only one input and one output stream.

But, it would enable also that new peers could join the conference by calling into any one of the participating peers, which would result in that (second host) having two inputs and two outputs (of which the input from the first host would actually contain multiple audiostreams mixed together, which would be mixed with the local source and sent to the new participant). This would be quite useful, as two remote locations only need to be connected through one 'link'. All the other participants would be connected to these link end-points within their organization (through, hopefully, fast LANs).

## Milestone 1 ##

SIP support for basic centralized conferencing on a P2P network:

  * ~~Support for identity aliases (use of **+conference\_id**)~~
    * _e.g., jookos@example.com could host the conference jookos+conference@example.com_
  * ~~Subsystem for handling these (essentially a small communication client within the proxy)~~
  * ~~Support for IM conferencing~~

**Milestone 1 is complete**

## Milestone 2 ##

  * ~~Support for audio conferencing~~

**Milestone 2 is complete**

## Milestone 3 ##

  * ~~Video conferencing support~~(1)
  * ~~Advanced access control and session management~~(2)
    * ~~Basically being able to expel users, invite others, find out who's participating~~
  * Default conferences (creating one ad-hoc from an ongoing call)

(1) Video support requires various video codecs.  Works fine on normal debian distributions, but has still issues on the N810 tablet.
(2) Controls are available for the host.  Invite still pending.

## Milestone 4 ##

  * Support for multi-proxy topology
    * Session keys (possibly)
    * Multi-topology presence

## Milestone X ##

  * A clear plugin / extensions API, dynamic loading of these

# Current status #

**Milestone 1 complete.** Notes:

  * Support for '+' in identities actually only affect which identities are used when establishing the P2P connection.
  * Added a SIP _client handler_ interface which basically acts as a message processor / mangler for messages headed for a SIP UA. These are able to stop the message from being sent at all, which can be used to create small mini-clients.
  * Added a PRE interface for registering SIP client handlers. Used the SIP parsers from the [CoffeeSipper](CoffeeSipper.md) to create a simple multicast-IM center.

**Milestone 2 complete.** Notes:

  * The actual audioprocessing is done with gstreamer's livemixer
  * Python-based currently
  * Designed can still be improved. One pipeline per conference, but that pipeline is completely remade each time someone joins or leaves. This results in a small silence in between.