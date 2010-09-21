#! /usr/bin/python

from sip_handler import SipHandler, SipContext
import time

#
# sip handler
#
class BabymonSipHandler(SipHandler):

    def __init__(self, streamer):
        #SipHandler.__init__(self)
        self.streamer = streamer

    def streaming_done(self, msg):
        print "streaming done. sending bye"
        m = msg.create_follow_up("BYE")
        m.send()
        
    def response_got(self, req, resp):
        print "response " + str(resp.resp_code) + " got to my " + req.msg_type + " request"

        if int(resp.resp_code) >= 200 and req.msg_type == "INVITE":
            m = resp.create_follow_up("ACK")
            cs, s, ty = resp.cseq.partition(" ")
            m.cseq = cs + " " + m.msg_type
            m.send()

            # check if we got the video tags. if so, start streaming!
            if resp.call.remote_medias is not None:
                print "We have remote media on response!"
                for k in resp.call.remote_medias:
                    print "  media type " + k
                print resp.call.serialize_sdp(resp.call.remote_medias)
                if resp.call.remote_medias.has_key('audio') and resp.call.remote_medias.has_key('video'):
                    print "** audio streaming to " + str(resp.call.remote_medias['audio'][0]) + " port " + str(resp.call.remote_medias['audio'][1])
                    print "** video streaming to " + str(resp.call.remote_medias['video'][0]) + " port " + str(resp.call.remote_medias['video'][1])
                    self.streamer.stream(resp.call.remote_medias['video'][0], resp.call.remote_medias['audio'][1], resp.call.remote_medias['video'][1], 15, self.streaming_done, resp)
                else:
                    print "Heck, either audio or video was missing1!"
                
    def message_got(self, message):
        print "message got: " + str(message.body)
        message.respond(200)

    def ack_got(self, message):
        print "ack got:"
        if message.call.remote_medias is not None:
            for k in message.call.remote_medias:
                print "  media type " + k

        print "checking .. "
        if message.call.my_medias is not None:
            for k in message.call.my_medias:
                print "  my media type " + k
        if not message.call.my_medias.has_key("video"):
            print "adding stuff .. "
            host, aport, vport = "127.0.0.1", 8000, 8002
            formats = {}
            #formats["34"] = { "rtpmap":"H263/90000", "fmtp":"QCIF=2" }
            formats["96"] = { "rtpmap":"H263-1998/90000", "fmtp":"QCIF=2" }
            #formats["97"] = { "rtpmap":"H263-N800/90000" }
            message.call.my_medias["video"] = [ host, vport, formats ]
            #message.call.my_medias["attributes"] = [ "recvonly" ]
            m = message.create_follow_up("INVITE", message.call.get_my_sdp(), "application/sdp")
            m.set_param("Min-se", 120)
            m.set_param("Content-disposition", "session")

            #time.sleep(3)
            m.send()

    def invite_got(self, message):
        if message.call.my_medias is None:
            # where do we get these from.. ?
            #host, aport, vport = "10.0.0.10", 8000, 8002
            host, aport, vport = "127.0.0.1", 8000, 8002

            formats = {}
            formats["96"] = { "rtpmap":"iLBC/8000", "fmtp":"mode=30" }
            formats["18"] = { "rtpmap":"G729/8000" }
            formats["8"] = { "rtpmap":"PCMA/8000" }
            formats["0"] = { "rtpmap":"PCMA/8000" }
            formats["13"] = { "rtpmap":"CN/8000" }
            formats["97"] = { "rtpmap":"telephone-event/8000" }
            message.call.my_medias = { "audio":[ host, aport, formats ] }

        message.respond(200, message.call.get_my_sdp(), "application/sdp")

        # send a new message 

#
#
#

import p2pship
from streamer import StreamHandler, ServerHandler

def test():
    sport, aport, vport = 4000, 4002, 4004
    stream_handler = StreamHandler(sport, aport, vport)
    serv = ServerHandler()
    serv.add_streamer(stream_handler)
    serv.start()

    sh = BabymonSipHandler(stream_handler)
    c = SipContext(p2pship.get_default_ident(), ("localhost", 1234), sh, serv, 5000)
    c.start()

    c.register()

    while True:
        inp = raw_input("cmd> ")
        cmd, s, inp = inp.partition(" ")
        if cmd == "message" or cmd == "m":
            to, s, msg = inp.partition(" ")
            m = c.create_message(to, msg)
            c.send_msg(m)
        else:
            print "what the heck is " + cmd + "!?"
        
if __name__ == "__main__":
    test()
