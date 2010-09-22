import time
import os

#
# a bunch of pretty ugly utils
#

def is_tablet():
    return os.uname()[4] == "armv6l"

def tf_diff(d):
    if d > (3600*24*30*24):
        return str(int(d / (3600*24*30*12))) + " years"
    elif d > (3600*24*30*2):
        return str(int(d / (3600*24*30))) + " months"
    elif d > (3600*24*2):
        return str(int(d / (3600*24))) + " days"
    elif d > (3600*2):
        return str(int(d / (3600))) + " hours"
    elif d > (60*1):
        return str(int(d / (60))) + " minutes"
    else:
        return "seconds" #str(int(d)) + " seconds"

def tf_diffday(now, t):
    ds = int(now/(3600*24)) - int(t/(3600*24))
    #dt = time.localtime(t)
    ret = "today"
    if ds == 1: ret = "yesterday"
    elif ds > 1: ret = str(ds) + " days ago"
    return ret + time.strftime(" %H:%M", time.localtime(t)) #"%s %02d:%02d" % (ret, dt[3], dt[4])

def tf_day(t):
    return time.strftime("%a %H:%M", time.localtime(t))

def tf_shdate(t):
    return time.strftime("%d %b", time.localtime(t))

def tf_date(t):
    return time.strftime("%d.%m %Y", time.localtime(t))

def tf(t):
    now = time.time()
    d = now-t

    if d < (60*90):
        return tf_diff(d) + " ago"
    elif int(now/(3600*24)) - int(t/(3600*24)) < 2:
        return tf_diffday(now, t)
    elif int(now/(3600*24)) - int(t/(3600*24)) < 6:
        return tf_day(t)
    elif d < (3600*24*30*12):
        return tf_shdate(t)
    else:
        return tf_date(t)

def fadecol(orig, t):
    d = time.time()-t
    p = 100
    if d < (60*10):
        p = 100
    elif d < (3600):
        p = 90 + (10*((3600-d)/3600))
    elif d < (3600*6):
        p = 70 + (20*(((3600*6)-d)/(3600*6)))
    elif d < (3600*24*7):
        p = 50 + (20*(((3600*24*7)-d)/(3600*24*7)))
    else:
        p = 50
        
    orig = orig.replace('#','')
    r, g, b = int(orig[0:2], 16), int(orig[2:4], 16), int(orig[4:6], 16)
    # ret = "#%02x%02x%02x" % (int(r*p/100), int(g*p/100), int(b*p/100)) # darken

    p = 100-p
    ret = "#%02x%02x%02x" % (r+int((255-r)*p/100), g+int((255-g)*p/100), b+int((255-b)*p/100)) # fade
    return ret

