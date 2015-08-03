# Introduction #

As we all know, unsolicited email (SPAM), is a considerable problem. Although advanced filtering techniques have been developed, it continues to annoy leading to decreased productivity and even causing serious harm through embedded viruses, hoaxes and identity theft. SPAM is possible due to the open and free nature of email. As we're now developing also an open and free communication system, we should think about ways to prevent it from becoming as SPAM-infected as email has turned into.

Luckily, SPAM on internet telephony (SPIT) or instant messaging hasn't really been a big problem. Pert of might be due to it not being as popular and widespread as email just yet, but a large part has to do with it being seen as more close and personal, leading people to explicitly set up whitelists of contacts that are allowed. This combined with atleast rudimentary authorization or source-control (which is almost non-existent in email) has made it hard for spammers to succeed.

But as we're looking into a p2p framework for different types of applications, running in different environments with possible different types of authorization (if at all), we should keep an eye out for SPAM, as the traditional whitelist approach might not always be feasible.

# Overview #

There are a number of proposals for preventing SPAM, or more generally _unwanted traffic_, in different types of communication systems. Here are our thoughts on a number of those, together with implementation status (if relevant):

## White / black lists ##

The most basic for of prevention. Whitelists requires strong authentication (not being able to impersonate), while blacklists need an identity system where it is considered hard to gain or change your identity.

Both are currently implemented as access control modules for the SIP system. Controllable through the maemo statusbar plugin.

## Relationship-based filtering ##

One of the methods we've experimented quite a bit with is filtering based on how (if at all) you are 'related' to the caller. That is, is there a link of friends connecting you in your social network. For instance, a friend of a friend might well be allowed to call, even a friend of a friend of a friend. But beyond that, it starts getting too distant to be really able to say anything about the caller, or assume. And to find someone (a friend) to keep in some respects responsible for befriending strange people.

Relationship-based filtering is implemented through the use of the Pathfinder and the Bloombuddies. The pathfinder is essentially a trusted 3rd party that you submit your contact list to in an anonymized format. When calling someone, you request it to go through its database and try to find a path between you and the recipient. This path is signed by the pathfinder, and presented by you to the recipient when making the call.

The pathfinder is implemented also as an access control module for the SIP system. You're able to configure the location of a Pathfinder to use, as well as the maximum path distance to allow for unknown callers.

Bloombuddies does essentially what the pathfinder does, but in a distributed manner. Instead of submitting the contact list to a 3rd party, we spread them virally through our friends. But as no one is keen on publishing their contact list for the whole world to see (even in these times of facyspaces, it is a very personal thing), the contact list is presented as a bloom filter where all the contacts (AORs and certificates) are mashed together. Although it is possible to (with a certain degree of uncertainty) say whether a specific person is a friend of yours, it is not possible to extract all your contacts from it. And, basically you can add dummy data into the filter as you wish.

These filters are spread virally, and combined for friends at different degrees (the filters of friends-of-friends are combined into one and distributed as well). Although the propagation of these do take a while, in the end we have a fully distributed way of determining (with a certain confidence) whether an unknown caller is linked to you in any way.

Bloombuddies are implemented both as an access control module for SIP as well as for accepting untrusted certificates when connecting. In the access control module, it follows the same logic as the pathfinder - obeying the same max-hop-count setting. For the certificate checking, it applies to ALL applications (not only SIP). In case a certificate of a peer is found invalid (not signed by a trusted CA or expired etc), we check the bloomfilters whether the public key of that peer is found. If so (and the setting 'Allow untrusted peers trusted by friends' is set), it is accepted.

## CAPTCHAS ##

More on this later. Basically sending back some sort of challenge which requires human intellect to solve. Trying to prevent automatic calling bots. Can be based on voice (e.g., an automatic call answerer playing a recorded message of a sequence of dial tone buttons to press) or IM-based (sending an IM in response to a call, asking the caller to solve a puzzle).

## Honesty of intent ##

Related to CAPTCHAS, but trying also to weed out human callers by drawing to their sense of honesty, fairness. This is to prevent marketeers that may be selling a perfectly good and valid product, but that you right now just don't want to hear about.

This could simply be by sending back a question whether the call is concerning some commercial opportunity. In case they lie, it's pretty easy to hang up and blacklist, possible spread a bad word about them.

## Payment / Payment-on-risk ##

Require the caller to deposit some amount (either cash, computer resources or something else that is considered valuable) which will be lost in case the call is found to be unwanted. With mobile- and personal cloud computing emerging, this could be interesting to look into. Basically an unknown caller would have to participate in a cloud for a certain amount of time to be able to call.

## Reputation ##

Relation-ship based filtering is actually a subset of this. Basically having a WOT-type of thing, or database of reputation about callers which could be used to determine what to do. Hard thing though - game theory calculations and such needed.

## Lots-o-info ##

Something we've been playing around with lately on the UI-side; having the client application just show a bunch of information about the caller (from any source available) to help the user decide whether to take the call. Or just as a reminder of who the caller is.

We've done some UI testing where sources such as google, twitter, facebook, GoeIP are queried based on the name of the caller. This (we imagine) could reveal associations ("working for plentyoproducts telemarketing") or other information which can help us to accept or reject the call, depending on the situation we are in (not answering a call from someone apparently the CEO of a partner company while in a less-than-appropriate surroundings).