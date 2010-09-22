#! /usr/bin/python

import time
import os
import osso
import p2pship
from sip_handler import SipHandler, SipContext
from streamer import StreamHandler, ServerHandler
from utils import *
from ui import CoffeeSipper
from http import *

snapshot_rate = 60

#
# sip handler
#

class CoffeeSipHandler(SipHandler, CoffeeSipper):

    def message_got(self, message):
        message.body = message.body.strip()
        if message.body.startswith("<?xml"):
            message.respond(200)
            return
        
        ret = self.message_received(message.call.remote_aor, message.body)
        message.respond(200)

        m = self.context.create_message(message.call.remote_aor, ret)
        m.send()

    def sendto(self, user, msg):
        m = self.context.create_message(user, msg)
        m.send()
        
    def __init__(self, streamer):
        CoffeeSipper.__init__(self)
        self.streamer = streamer
        # for the snapshots:
        self.last_snapshot = 0

    def periodic_update(self):
        global http_root
        if snapshot_rate > 0 and time.time() > (self.last_snapshot + snapshot_rate):
            print "taking snapshot.."
            if self.streamer.snapshot(http_root + "snapshot.jpg"):
                self.last_snapshot = time.time()

    def streaming_done(self, msg):
        print "streaming done. sending bye"
        m = msg.create_follow_up("BYE")
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
                
    def ack_got(self, message):
        print "ack got"
        if not message.call.my_medias.has_key("video"):
            host, aport, vport = "127.0.0.1", 8000, 8002
            formats = {}
            formats["96"] = { "rtpmap":"H263-1998/90000", "fmtp":"QCIF=2" }
            message.call.my_medias["video"] = [ host, vport, formats ]
            m = message.create_follow_up("INVITE", message.call.get_my_sdp(), "application/sdp")
            m.set_param("Min-se", 120)
            m.set_param("Content-disposition", "session")
            m.send()

    def invite_got(self, message):
        if message.call.my_medias is None:
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


def test2():
    print "testing handler.."

    serv = ServerHandler()
    serv.start()

    sh = CoffeeSipHandler()
    c = SipContext("alice@p2psip.hiit.fi", ("localhost", 1234), sh, serv, 5000)
    c.start()
    c.register()



def runapp():
    sport, aport, vport = 4000, 4002, 4004
    http_port = 9000
    stream_handler = StreamHandler(sport, aport, vport)

    serv = ServerHandler()
    serv.add_streamer(stream_handler)
    serv.add_http(CoffeeHTTPHandler, http_port)
    serv.start()

    p2pship.register_http(('localhost', http_port), ('', 5000))

    sh = CoffeeSipHandler(stream_handler)
    c = SipContext(p2pship.get_default_ident(), ("localhost", 1234), sh, serv, 5000)
    c.start()
    c.register()

    sh.run()


if __name__ == "__main__":
    #test1()
    runapp()
