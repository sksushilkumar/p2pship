#! /usr/bin/python

import p2pship
import urllib
import string,cgi,time
from os import curdir, sep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from streamer import ServerHandler


global http_root
http_root = "http/"

class CoffeeHTTPHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        print "we got a get for " + self.path
        if self.path == "/":
            self.path = "/index.html"
        try:
            f = open(curdir + sep + http_root + self.path)
            self.send_response(200)
            #self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f.read())
            f.close()
        except IOError:
            self.send_error(404,'File Not Found: %s' % self.path)
     
    def do_POST(self):
        pass
    
def testhttp():

    http_port = 9000

    serv = ServerHandler()
    serv.add_http(CoffeeHTTPHandler, http_port)
    serv.start()
    p2pship.register_http(('localhost', http_port), ('', 5000))

    while True:
        time.sleep(1);

def main2():
    try:
        server = HTTPServer(('', 80), MyHandler)
        print 'started httpserver...'
        server.serve_forever()
    except KeyboardInterrupt:
        print '^C received, shutting down server'
        server.socket.close()

if __name__ == '__main__':
    testhttp()

