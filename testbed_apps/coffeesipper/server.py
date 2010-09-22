#! /usr/bin/python

#
#

import os, sys, signal, time
import select, socket, SocketServer, urlparse, re, asyncore, sys
import threading

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

        self.http_handlers = {}
        self.http_sockets = {}

        # for the streamers
        self.c_socks = {}
        
    def create_sock(self, port, addr=''):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, port))
        return sock

    def create_tcpsock(self, port, addr=''):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
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

    def add_http(self, http_handler, port):
        #sock = self.create_tcpsock(port, "127.0.0.1")
        sock = self.create_tcpsock(port, "")
        sock.listen(10)
        self.http_handlers[http_handler] = sock
        self.http_sockets[sock] = http_handler
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
                for s in self.http_sockets.keys():
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
                elif self.http_sockets.has_key(s):
                    h = self.http_sockets[s]
                    csock, caddr = s.accept()
                    h(csock, caddr, self)
                    csock.close()
                else:
                    s.recv(65536)

    def run_check(self):
        while True:
            for sh in self.stream_handlers:
                sh.check_dead()
            time.sleep(1)


