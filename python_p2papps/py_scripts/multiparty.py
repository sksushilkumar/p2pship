
import socket
import threading
import select
import time
import gst

# start of the sip-client apps:
class Multiplexer:
    """Simple udp-multiplexer. For now, until we get a real mixing
    system in place"""

    def __init__(self):
        self.running = True
        self.update = True
        self.ports = {}
        self.socks = {}
        self.sockpair = socket.socketpair()

    def do_update(self):
        self.sockpair[1].send("ping")
        self.update = True

    def add_recv(self, sport, dport):
        self.ports[sport].append(("127.0.0.1", dport))
        info("added recever %d for source %d" % (dport, sport))
        self.do_update()

    def set_recvs(self, sport, dports):
        self.ports[sport] = []
        for p in dports:
            self.ports[sport].append(("127.0.0.1", p))
        info("added recevers: %s for source %d" % (str(self.ports[sport]), sport))
        self.do_update()

    def reset_recvs(self):
        for p in self.ports.keys():
            self.ports[p] = []
        info("reset receivers")
        self.do_update()

    def remove_src(self, port):
        sock = None
        for s in self.socks.keys():
            if self.socks.get(s) == port:
                sock = s
                break
        if sock is not None:
            del self.socks[sock]
            del self.ports[port]
            self.do_update()
            sock.close()
        
    def add_src(self, sport = 0):
        return self.add_sock(self.create_sock(sport))
        
    def add_sock(self, sock):
        (addr, sport) = sock.getsockname()
        self.socks[sock] = sport
        self.ports[sport] = []
        info("added source %s" % str(sock.getsockname()))
        self.do_update()
        return sport
    
    def create_sock(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))
        return sock

    def start(self):
        server_thread = threading.Thread(target=self.run)
        server_thread.setDaemon(True)
        server_thread.start()

    def run(self):
        inputs = self.socks.keys()
        inputs.append(self.sockpair[0])
        while self.running:
            try:
                inp,outp,ex = select.select(inputs,[],[])
                if self.update:
                    inputs = self.socks.keys()
                    inputs.append(self.sockpair[0])
                    self.update = False
                    debug("we now have %d mixers .. " % (len(inputs)-1))
                for s in inp:
                    data = s.recv(65536)
                    port = self.socks.get(s)
                    if port is not None:
                        recvs = self.ports.get(port)
                        for recv in recvs:
                            s.sendto(data, recv)
            except Exception, ex:
                warn("got an nio exception %s" % str(ex))

class Mixer:
    """Handles the audiomixing"""

    def __init__(self):
        self.plexer = Multiplexer()
        self.plexer.start()
        self.aors = {}
        
    def add(self, aor, addr):

        # re-use old if one exists
        if self.aors.has_key(aor):
            (port, oldaddr, pl) = self.aors[aor]
        else:
            port = self.plexer.add_src()
            pl = None

        # this should be reserved - where the data is to be received
        local_addr = ("127.0.0.1", port)
        info("Should add an audio-mixing channel for %s receiving at %s, sending to %s" % (aor, str(local_addr), str(addr)))

        self.aors[aor] = (port, addr, pl)
        self.reinit_players()
        return local_addr
        
    def reinit_players(self):
        self.plexer.reset_recvs()
        for aor in self.aors.keys():
            (port, addr, pl) = self.aors[aor]
            if pl is not None:
                pl[0].set_state(gst.STATE_NULL)
                pl[1].close()
            debug("reiniting player for %s .. " % aor)
            self.aors[aor] = (port, addr, self.create_player(aor, port, addr))

    def create_player(self, aor, sport, addr):

        if len(self.aors) < 2:
            info("not enough participants to create a player!!")
            return None
        
        caps="application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"
    
        line = ''
        ports = []
        for a in self.aors.keys():
            if a == aor:
                continue
            (port, altaddr, pl) = self.aors[a]
            if len(line) == 0:
                line += 'udpsrc port=0 caps="%s" name=src%d ! gstrtpbin ! rtppcmadepay ! alawdec ! audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! liveadder name=mixer latency=0 ' % (caps, len(ports))
            else:
                line += 'udpsrc port=0 caps="%s" name=src%d ! gstrtpbin ! rtppcmadepay ! alawdec ! audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! mixer. ' % (caps, len(ports))
            ports.append([ port, len(ports) ])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        line += 'mixer. ! audioconvert  ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! alawenc ! rtppcmapay ! udpsink host=%s port=%d sockfd=%d ' % (addr[0], addr[1], sock.fileno())

        pl = gst.parse_launch(line)
        pl.set_state(gst.STATE_PLAYING)
        debug("launched player '%s' for %s" % (line, aor))

        for s in ports:
            self.plexer.add_recv(s[0], pl.get_by_name("src%d" % s[1]).get_property("port"))

        #ports.append(pl.get_by_name("src%d" % s).get_property("port"))
        #self.plexer.set_recvs(sport, ports)
        return (pl, sock)

    def remove(self, aor):
        info("removing mixers for %s" % aor)

        if self.aors.has_key(aor):
            (port, addr, pl) = self.aors[aor]
            self.plexer.remove_src(port)
            if pl is not None:
                pl[0].set_state(gst.STATE_NULL)
                pl[1].close()
            del self.aors[aor]
            self.reinit_players()


class MultipartyHandler(SipHandler):
    """Handler for one multiparty session / room"""

    def __init__(self):
        self.verbose = False
        self.members = []
        self.title = "anon session"
        self.mixer = Mixer()
        
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

    def remove_mixers(self, aor):
        self.mixer.remove(aor)

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
