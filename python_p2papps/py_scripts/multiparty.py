

# start of the sip-client apps:

class MultipartyHandler(SipHandler):

    def __init__(self):
        self.verbose = False
        self.members = []
        self.title = "anon session"
        self.port = 6700
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
        print "got message: %s" % str(message.body)
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
        print "**** ack got"

    def add_audio_mixer(self, aor, addr):
        # this should be reserved - where the data is to be received
        local_addr = ("127.0.0.1", self.port)
        self.port += 1
        print "Should add an audio-mixing channel for %s receiving at %s, sending to %s" % (aor, str(local_addr), str(addr))
        return local_addr

    def remove_mixers(self, aor):
        print "removing mixers for %s" % aor

    def cancel_got(self, message):
        print "got cancel..."
        self.remove_mixers(message.call.remote_aor)
        message.respond(200)

    def invite_got(self, message):
        if message.call.my_medias is None:
            if message.call.remote_medias is not None and message.call.remote_medias.has_key('audio'):
                remote_addr = (str(message.call.remote_medias['audio'][0]), int(message.call.remote_medias['audio'][1]))
                print "** audio streaming to " + str(remote_addr)

            local_addr = self.add_audio_mixer(message.call.remote_aor, remote_addr)
            formats = {}
            #formats["96"] = { "rtpmap":"iLBC/8000", "fmtp":"mode=30" }
            #formats["18"] = { "rtpmap":"G729/8000" }
            #formats["8"] = { "rtpmap":"PCMA/8000" }
            formats["0"] = { "rtpmap":"PCMA/8000" }
            #formats["13"] = { "rtpmap":"CN/8000" }
            #formats["97"] = { "rtpmap":"telephone-event/8000" }
            message.call.my_medias = { "audio":[ local_addr[0], local_addr[1], formats ] }

        #message.respond(200, message.call.get_my_sdp(), "application/sdp")
        m = message.create_response(200)
        m.set_body(message.call.get_my_sdp(), "application/sdp")
        m.set_param('Contact', "<sip:whatever@127.0.0.1:5060;transport=udp>")
        m.send()

    def response_got(self, req, resp):
        print "response " + str(resp.resp_code) + " got to my " + req.msg_type + " request"
        if int(resp.resp_code) >= 200 and req.msg_type == "INVITE":
            m = resp.create_follow_up("ACK")
            m.cseq = str(resp.cseq) + " " + m.msg_type
            m.send()

            # check if we got the video tags. if so, start streaming!
            if resp.call.remote_medias is not None:
                if resp.call.remote_medias.has_key('audio') and resp.call.remote_medias.has_key('video'):
                    print "** audio streaming to " + str(resp.call.remote_medias['audio'][0]) + " port " + str(resp.call.remote_medias['audio'][1])
                    print "** video streaming to " + str(resp.call.remote_medias['video'][0]) + " port " + str(resp.call.remote_medias['video'][1])
                    self.streamer.stream(resp.call.remote_medias['video'][0], resp.call.remote_medias['audio'][1], resp.call.remote_medias['video'][1], 15, self.streaming_done, resp)
                else:
                    print "Heck, either audio or video was missing1!"


        
if install_sip_handler(".*", "[^+]+[+][a-z0-9]*@.+", MultipartyHandler):
    print "Multiparty handler is installed!"
else:
    print "Error installing multiparty handler!"
