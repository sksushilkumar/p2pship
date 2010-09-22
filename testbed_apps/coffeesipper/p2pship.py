#! /usr/bin/python

import urllib
import json

p2pship_web="localhost:9080"
p2pship_api="localhost:9081"


def get_default_ident():
    f = urllib.urlopen("http://"+p2pship_web+"/json/idents")
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

def register_http(service_addr, p2p_addr):
    f = urllib.urlopen("http://%s/http_register?dport=%d&aor=%s&ttl=-1&url=%s:%d" % (p2pship_api, p2p_addr[1], p2p_addr[0], service_addr[0], service_addr[1]))
    s = f.read()
    f.close()


if __name__ == "__main__":
    print "default identity is " + get_default_ident()

