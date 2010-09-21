#! /usr/bin/python

import urllib
import json

p2pship_web="localhost:9080"


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


if __name__ == "__main__":
    print "default identity is " + get_default_ident()

