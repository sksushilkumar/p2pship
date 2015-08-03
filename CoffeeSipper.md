# Introduction #

The CoffeeSipper application is our version of the  [Trojan room coffee cam](http://en.wikipedia.org/wiki/Trojan_Room_coffee_pot). The main idea is to be able to remotely check whether there's coffee available in the pot. This is done by retrieving a live video feed from the internal camera of a Nokia N810 tablet placed near
the coffee maker.

The application is based on SIP - the video feed is actually just a normal SIP video call that can be viewed on any compatible device. The application itself can even be used together with a standard SIP server, although this has not been tested (the SIP and media library used is really minimal and could react badly to unexpected messages).

In addition to the video feed, the application uses SIP instant messaging (IM) to communicate with users (notifications on when coffee is being brewed etc). If features a full-screen UI which displays greetings sent by users, the freshness of the coffee (when it was made) as well as a button which is meant to be pressed each time someone decides to brew a pot.

Recently a HTTP interface was added as well. The application takes snapshots at a specific interval (60s. by default) and deposits the picture in a folder served over P2PHTTP (port 5000 by default).

# Operation details #

A couple of shortcuts have been made to keep the project from growing out of control. Firstly, the SIP "stack" used is a very simple homegrown SIP message processor. Although it does try to adhere to the SIP standard, only the features needed by us has been implemented: basic call (INVITE/BYE/CANCEL/ACK) tracking, registration and MESSAGE support. You can try to use it with a standard SIP server, but it may act up (due to things like OPTIONS, 3xx responses, PUBLISH/SUBSCRIBEs etc).

Secondly, the video streaming is very specific. It uses the same format as the N810 native video calls, ignoring any requests for other formats. To improve the stability of the application, the streaming is actually done using a command-line utility in a separate process (easier to kill, crash does not affect the main application).

It is able to stream to multiple sources at once (more than one is able to view the video stream at once). This is done by streaming the video data to a multiplexing proxy in the application. Furthermore, it only sends a video feed for a maximum of 10 seconds to a single client at a time.

# Installation and use #

The application assumes that the table it installed with the p2pship system with a valid identity. Please see the [manual](Manual.md) for details. Secondly, the tablet should be physically located at a suitable position in front of the coffee machine (duh).

## Prerequisites ##

The application has been created in Python. It uses the gstreamer framework for capturing the video feed. From the maemo garage-extras repository, the following packages should be installed on the tablet:
```
apt-get install python2.5-sdk gstreamer-tools gstreamer0.10-plugins-extra
```

Depending on the tablet OS version, these can be got from different locations. For chinook (4.0), the following repository install file will do:
```
[catalogues]
catalogues = Maemo Chinook

[Maemo Chinook]
name = Maemo Chinook
uri = http://repository.maemo.org/
dist = chinook
components = free non-free
```

(rename it to something.install, beam it to the tablet and double click!)

## Setup ##

Copy all the source files to the tablet. The source can be found in the repository in the `testbed_apps/coffeesipper/` directory.  This is relative to the _root_ of the repository, i.e. `svn checkout http://p2pship.googlecode.com/svn/`.

Add also the `http/` directory. This is the root folder for the P2P HTTP served content, and is where the `snapshot.jpg` snapshots are placed.

Run it as
```
python2.5 ./coffee-sipper.py
```

## IM command reference ##

The application uses SIP messaging for accepting commands.

**/msg _message_** - send a message to display on the front

**/motd _message_** - changes the message of the day (top-most message displayed for the rest of the day)

**/req** - Issues an request for someone to make coffee. The UI button will change its appearance and a notification will be sent to the requester immediately someone makes a new pot.

**/subscribe** - Adds the user to the notification list. A notification ('coffee available') is sent out to each subscriber roughly 5 min after someone presses the brew-button.

**/unsubscribe** - Removes the user from the list

**/help** - Returns a help page

**/color _color_** - Changes the color of the user's messages. In HTML format, e.g. '/color #ff00ff'

# Screen shots #

All our ADs/usability experts just happened to be on vacation at the same time ..

![http://trustinet.hiit.fi/p2pship/cs1.png](http://trustinet.hiit.fi/p2pship/cs1.png)

The screen shown on the tablet. MOTD on top, button on bottom.

![http://trustinet.hiit.fi/p2pship/cs2.png](http://trustinet.hiit.fi/p2pship/cs2.png)

An example frame from the video feed of our current setup.