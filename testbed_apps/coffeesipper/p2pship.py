#! /usr/bin/python

import urllib
import json

p2pship_web="localhost:9080"
p2pship_api="localhost:9081"


def get_default_ident(webapi = p2pship_web):
    f = urllib.urlopen("http://"+webapi+"/json/idents")
    #f = urllib.urlopen("http://localhost:9080/web/start.html")
    s = f.read()
    f.close()

    token = "var p2pship_idents = "
    i = s.find(token)
    if i > -1:
        js = json.read(s[len(token):])
        for ident in js:
            if js[ident][7] == "default":
                return ident
    return ""

def register_http(service_addr, p2p_addr, api = p2pship_api):
    url = "http://%s/http_register?dport=%d&aor=%s&ttl=-1&url=%s:%d" % (api, p2p_addr[1], p2p_addr[0], service_addr[0], service_addr[1])
    print "opening up '%s'" % url
    f = urllib.urlopen(url)
    s = f.read()
    f.close()
    print "Response to register: %s" % s

if __name__ == "__main__":
    print "default identity is " + get_default_ident()

