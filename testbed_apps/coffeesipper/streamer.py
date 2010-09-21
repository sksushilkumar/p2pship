#! /usr/bin/python

#
#

import os, sys, signal, time
import select, socket, SocketServer, urlparse, re, asyncore, sys
import threading


class StreamHandler:

    def __init__(self, controlport, myaport, myvport):
        self.streams = []
        self.pid = None
        self.aport = myaport
        self.vport = myvport
        self.cport = controlport
        
    def check_dead(self):
        now = time.time()
        newstreams = []
        for s in self.streams:
            if s[1] < now:
                print "killing off one stream"
                self.serv.update = True
                if s[5] is not None:
                    s[5](s[6])
            else:
                newstreams.append(s)
        self.streams = newstreams
        if self.pid is not None and len(self.streams) == 0:
            print "killing streaming"
            os.kill(self.pid, signal.SIGTERM)
            self.pid = None

    def stream(self, host, aport, vport, duration, callback = None, obj = None):
        self.streams.append((None, time.time() + duration, host, aport, vport, callback, obj))
        self.serv.update = True
        if self.pid is None:
            self.pid = self.start_stream('localhost', self.aport, self.vport)
        
    def start_stream(self, host, aport, vport):
        print "starting stream to " + host + ":" + str(aport) + ":" + str(vport)
        #return os.spawnvp(os.P_NOWAIT, 'gst-launch', ('gst-launch v4l2src ! video/x-raw-yuv,width=176,height=144,framerate=(fraction)15/1 ! hantro4200enc stream-type=1 profile-and-level=1001 ! video/x-h263,framerate=(fraction)15/1 ! rtph263ppay mtu=1438 ! udpsink host='+host+' port='+str(vport)+' dsppcmsrc ! queue ! audio/x-raw-int,channels=1,rate=8000 ! mulawenc ! rtppcmupay mtu=1438 ! udpsink host='+host+' port='+str(aport)).split(" "))

        # note: the reason why this wasn't working:
        #  - seems that the audio was the one causing trouble. by disabling it (currently just streaming it off to dev/null)
        #    the video started working ok. great! (remove the aport+10 to have it stream to the right port!)

        # note: 176x144 and 352x288 seem both to work ok. The bigger consuming around 50-70% of cpu though..

        fr="15/1"
        #cmd = 'gst-launch v4l2src ! video/x-raw-yuv,width=176,height=144,framerate=(fraction)%s ! hantro4200enc ! rtph263ppay ! udpsink host=%s port=%s dsppcmsrc ! queue ! audio/x-raw-int,channels=1,rate=8000 ! mulawenc ! rtppcmupay ! udpsink host=%s port=%s' % (fr, host, str(vport), host, str(aport+10))
        cmd = 'gst-launch v4l2src ! video/x-raw-yuv,width=352,height=288,framerate=(fraction)%s ! hantro4200enc ! rtph263ppay ! udpsink host=%s port=%s dsppcmsrc ! queue ! audio/x-raw-int,channels=1,rate=8000 ! mulawenc ! rtppcmupay ! udpsink host=%s port=%s' % (fr, host, str(vport), host, str(aport+10))
        print "command:\n" + cmd
        return os.spawnvp(os.P_NOWAIT, 'gst-launch', cmd.split(" "))
                                                      

    def get_hosts(self):
        print "returning new hosts list!"
        ret = []
        for s in self.streams:
            ret.append(((s[2], s[3]), (s[2], s[4])))
        return ret

    def handle(self, data, socket, client_address):
        # protocol: 'targetip;aport;vport;duration'
        # if target is omitted, sending ip is used
        # if duration is omitted, 10sec is used
        
        data = data.strip()
        m = re.match('([0-9.]*);([0-9]+);([0-9]+);([0-9]*)', data)
        if m:
            (addr, aport, vport, dur) = (m.group(1), m.group(2), m.group(3), m.group(4))
            if len(addr) == 0:
                addr = client_address[0]
            if len(dur) == 0:
                dur = 10
            self.stream(addr, int(aport), int(vport), int(dur))
            socket.sendto("ok", client_address)
        else:
            print "invalid message from %s:" % client_address[0]
            print data
            socket.sendto("error: " + data, client_address)



class ServerHandler:
    """
    Server, connection manager.

    
    todo: dynamically add the stream handlers!
    -> no global a_sock, v_sock, but that is contained in the streamhandler object.
    Also, the control channel (for requesting a stream) is contained & logic in
    the stream handler object.

    """
    def __init__(self):
        self.running = True
        #self.handler = handler
        self.stream_handlers = []
        self.update = True
        self.sip_handlers = {}
        self.sip_sockets = {}
        self.sockpair = socket.socketpair()

        # for the streamers
        self.c_socks = {}
        
    def create_sock(self, port, addr=''):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, port))
        return sock

    def start(self):
        server_thread = threading.Thread(target=self.run)
        server_thread.setDaemon(True)
        server_thread.start()

        server_thread = threading.Thread(target=self.run_check)
        server_thread.setDaemon(True)
        server_thread.start()

    def do_update(self):
        self.update = True
        self.sockpair[1].send("ping")

    def add_streamer(self, streamer):
        self.c_socks[self.create_sock(streamer.cport)] = streamer
        streamer.vsock = self.create_sock(streamer.vport)
        streamer.asock = self.create_sock(streamer.aport)
        streamer.serv = self
        
        self.stream_handlers.append(streamer)
        self.do_update()

    def add_sip(self, sip_handler, port):
        sock = self.create_sock(port, "127.0.0.1")
        self.sip_handlers[sip_handler] = sock
        self.sip_sockets[sock] = sip_handler
        self.do_update()

    def get_addr(self, handler):
        s = self.sip_handlers[handler]
        return s.getsockname()

    def send(self, handler, data, remote):
        s = self.sip_handlers[handler]
        s.sendto(data, remote)

    def run(self):
        print "starting server.."
        ins = [self.sockpair[0]]
        ff_socks = {}
        while self.running:

            inp,outp,ex = select.select(ins,[],[])

            if self.update:
                ins = [self.sockpair[0]] 

                ff_socks = {}
                for handler in self.stream_handlers:
                    hosts = handler.get_hosts()
                    ff_socks[handler.vsock] = []
                    ff_socks[handler.asock] = []
                    for h in hosts:
                        ff_socks[handler.vsock].append(h[1])
                        ff_socks[handler.asock].append(h[0])
                    ins.append(handler.vsock)
                    ins.append(handler.asock)

                for s in self.sip_sockets.keys():
                    ins.append(s)
                for s in self.c_socks.keys():
                    ins.append(s)
                self.update = False

            for s in inp:
                if self.c_socks.has_key(s):
                    data, addr = s.recvfrom(65536)
                    self.c_socks[s].handle(data, s, addr)
                elif ff_socks.has_key(s):
                    data = s.recv(65536)
                    for h in ff_socks[s]:
                        s.sendto(data, h)
                elif self.sip_sockets.has_key(s):
                    data, addr = s.recvfrom(65536)
                    h = self.sip_sockets[s]
                    h.data_got(data, addr)
                else:
                    s.recv(65536)

    def run_check(self):
        while True:
            for sh in self.stream_handlers:
                sh.check_dead()
            time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "please specify port to listen to"
    else:
        sport, aport, vport = int(sys.argv[1]), int(sys.argv[1])+2, int(sys.argv[1])+4
        stream_handler = StreamHandler(sport, aport, vport)
        serv = ServerHandler()
        serv.add_streamer(stream_handler)
        serv.start()
        while True:
            #stream_handler.check_dead()
            time.sleep(1)

