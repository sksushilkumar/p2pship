import socket
import threading
import select
import time
import gst




class Mixer:
    """Handles the audiomixing"""

    def __init__(self):
        self.aors = {}
        self.pl = None
        
    def stop(self):
        if self.pl is not None:
            self.pl.set_state(gst.STATE_NULL)
            self.pl = None
        for aor in self.aors.keys():
            (sock, saddr, addr) = self.aors[aor]
            if sock is not None:
                sock.close()
                self.aors[aor] = (None, saddr, addr)

    def create_sock(self, addr = '127.0.0.1', port = 0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, port))
        return (sock, sock.getsockname())
    
    def add(self, aor, addr, sport = 0):

        # re-use old if one exists
        if self.aors.has_key(aor):
            (sock, saddr, oldaddr) = self.aors[aor]
        elif sport != 0:
            (sock, saddr) = (None, ('127.0.0.1', sport))
        else:
            (sock, saddr) = self.create_sock()

        info("Should add an audio-mixing channel for %s receiving at %s, sending to %s" % (aor, str(saddr), str(addr)))

        self.aors[aor] = (sock, saddr, addr)
        self.reinit_player()
        return saddr
        
    def reinit_player(self):
        self.stop()
        if len(self.aors) < 2:
            info("not enough participants to create a player!!")
            return False

        caps="application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"
        decbin = "gstrtpbin ! rtppcmadepay ! alawdec ! audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000"
        encbin = "audioconvert  ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! alawenc ! rtppcmapay"

        line = ''

        for aor in self.aors.keys():
            (sock, saddr, addr) = self.aors[aor]
            if sock is None:
                (sock, saddr) = self.create_sock(saddr[0], saddr[1])
                self.aors[aor] = (sock, saddr, addr)

            name = str(saddr[1])
            # mixer & source
            line += 'liveadder name=mixer%s ! %s ! udpsink host=%s port=%d sockfd=%d ' % (name, encbin, addr[0], addr[1], sock.fileno())
            line += 'udpsrc sockfd=%d caps="%s" ! %s ! tee name=src%s ' % (sock.fileno(), caps, decbin, name)
            for aor2 in self.aors.keys():
                if aor2 == aor:
                    continue
                name2 = str(self.aors[aor2][1][1])
                line += 'src%s. ! queue ! mixer%s. ' % (name, name2)

        self.pl = gst.parse_launch(line)
        bus = self.pl.get_bus()
        bus.add_signal_watch()
        #bus.connect("message", on_message)
        self.pl.set_state(gst.STATE_PLAYING)
        return True

    def remove(self, aor):
        info("removing mixers for %s" % aor)
        if self.aors.has_key(aor):
            (sock, saddr, addr) = self.aors[aor]

            # todo: remove the mixer for this
            # remove all sources for this.
            # if only one left, stop the player!
            
            if sock is not None:
                sock.close()
            del self.aors[aor]
            self.reinit_player()



class MultipartyHandler(SipHandler):
    """Handler for one multiparty session / room"""

    def __init__(self):
        self.verbose = False
        self.members = []
        self.title = "anon session"
        self.mixer = Mixer()
        #self.port = 6700
        
    def send_msg(self, msg, user = None, omit = None):
        if user is not None:
            self.context.create_message(user, msg).send()
        else:
            for u in self.members:
                if u != omit:
                    self.send_msg(msg, u)

    def send_msgs(self, msg1, user, msg2):
        self.send_msg(msg1, user)
        self.send_msg(msg2, omit = user)

    def message_got(self, message):
        debug("got message: %s" % str(message.body))
        message.respond(200)

        user = message.remote_aor
        cmd, s, param = message.body.partition(" ")
        cmd = cmd.lower()
        if cmd == "/join":
            if user not in self.members:
                self.send_msgs("Welcome to %s!" % self.title, user, "%s joined the conversation" % user)
                self.members.append(user)
        elif cmd == "/leave":
            if user in self.members:
                self.members.remove(user)
                self.send_msgs("Goodbye!", user, "%s has left" % user)
        elif cmd == "/title":
            self.title = param
            self.send_msg("Title of chat changed to %s" % self.title) 
        elif cmd == "/invite":
            self.send_msgs("Your invited to %s by %s. Please type /join to join!" % (self.title, param),
                           param, "%s was invited" % param)
        elif user in self.members:
            self.send_msg(user + ": " + message.body, omit = user)
        else:
            self.send_msg("Please /join first!", user)

    def ack_got(self, message):
        debug("**** ack got")

    def add_audio_mixer(self, aor, addr):
        return self.mixer.add(aor, addr)
        #self.port += 1
        #print "should add mixer for %s, streaming to %s" % (str(aor), str(addr))
        #print "\n\n** sport: %d, destport: %d **\n" % (self.port, addr[1])
        #return ("127.0.0.1", self.port)

    def remove_mixers(self, aor):
        self.mixer.remove(aor)
        #print "should remove mixer for %s" % str(aor)

    def cancel_got(self, message):
        info("got cancel...")
        self.remove_mixers(message.call.remote_aor)
        message.respond(200)

    def invite_got(self, message):
        if message.call.my_medias is None:
            if message.call.remote_medias is not None and message.call.remote_medias.has_key('audio'):
                remote_addr = (str(message.call.remote_medias['audio'][0]), int(message.call.remote_medias['audio'][1]))
                debug("** audio streaming to " + str(remote_addr))

            # check whether the caller supports what we want (8-pcma/8000)
            if message.call.remote_medias['audio'][2].get("8") is None:
                m = message.create_response(415) # unsupported media type
                m.send()
                return

            local_addr = self.add_audio_mixer(message.call.remote_aor, remote_addr)
            formats = {}
            #formats["96"] = { "rtpmap":"iLBC/8000", "fmtp":"mode=30" }
            #formats["18"] = { "rtpmap":"G729/8000" }
            formats["8"] = { "rtpmap":"PCMA/8000" }
            #formats["0"] = { "rtpmap":"PCMU/8000" }
            #formats["13"] = { "rtpmap":"CN/8000" }
            #formats["97"] = { "rtpmap":"telephone-event/8000" }
            message.call.my_medias = { "audio":[ local_addr[0], local_addr[1], formats ] }

        #message.respond(200, message.call.get_my_sdp(), "application/sdp")
        m = message.create_response(200)
        m.set_body(message.call.get_my_sdp(), "application/sdp")
        m.set_param('Contact', "<sip:whatever@127.0.0.1:5060;transport=udp>")
        m.send()

    def response_got(self, req, resp):
        debug("response " + str(resp.resp_code) + " got to my " + req.msg_type + " request")
        if int(resp.resp_code) >= 200 and req.msg_type == "INVITE":
            m = resp.create_follow_up("ACK")
            m.cseq = str(resp.cseq) + " " + m.msg_type
            m.send()

            # check if we got the video tags. if so, start streaming!
            if resp.call.remote_medias is not None:
                if resp.call.remote_medias.has_key('audio') and resp.call.remote_medias.has_key('video'):
                    debug("** audio streaming to " + str(resp.call.remote_medias['audio'][0]) + " port " + str(resp.call.remote_medias['audio'][1]))
                    debug("** video streaming to " + str(resp.call.remote_medias['video'][0]) + " port " + str(resp.call.remote_medias['video'][1]))
                    self.streamer.stream(resp.call.remote_medias['video'][0], resp.call.remote_medias['audio'][1], resp.call.remote_medias['video'][1], 15, self.streaming_done, resp)
                else:
                    debug("Heck, either audio or video was missing1!")


        
if install_sip_handler(".*", "[^+]+[+][a-z0-9]*@.+", MultipartyHandler):
    info("Multiparty handler is installed!")
else:
    warn("Error installing multiparty handler!")
