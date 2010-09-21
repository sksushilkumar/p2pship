#! /usr/bin/python

import gtk
import hildon
import time
import threading
import random
import os
import osso
import p2pship
import cPickle

def is_tablet():
    return os.uname()[4] == "armv6l"


state_file = "state.bin"

#
# a bunch of pretty ugly utils
#
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

cols = [ "#ff8080", "#ffff80", "#ff80ff", "#80ff80", "#8080ff", "#80ffff", "#a0a0ff", "#ffa0a0", "#ffa080", "#ffa0ff" ]


#
#
#

class CoffeeSipper(hildon.Program):

    def colfor(self, user, t):
        if user[0] == "#":
            return fadecol(user, t)
        if not self.coltable.has_key(user):
            self.coltable[user] = cols[len(self.coltable.keys()) % len(cols)]
        return fadecol(self.coltable[user], t)

    def msg_markup(self, strings):
        mark = ""
        i = 0
        sizes = [ [ 1, "x-large" ], [ 3, "large" ], [ 7, "medium" ], [ len(strings), "small" ] ]
        for l in strings:
            if l[0] is None:
                mark += "<span font_family='monospace' color='"+self.colfor("#808080", l[2])+"' size='small'>[ system: "+l[1]+" ] ("+tf(l[2])+")</span>\n"
            else:
                for si in sizes:
                    if i < si[0]:
                        f = si[1]
                        break
                mark += "<span size='"+f+"'><span color='"+self.colfor(l[0], l[2])+"'>"+l[0]+":</span><span color='"+self.colfor("#000000", l[2])+"'> "+l[1]+"</span><span color='"+self.colfor("#808080", l[2])+"' font_family='monospace' size='x-small'> ("+tf(l[2])+")</span>"+"</span>\n"
                i+=1
        return mark

    def update_run(self):
        osso_c = osso.Context("osso_test_device_on", "0.0.1", False)
        device = osso.DeviceState(osso_c)  
        while True:
            time.sleep(1)
            gtk.gdk.threads_enter()
            self.update_label()
            self.update_motd()
            self.update_makebtn()

            # .. testing
            #if random.randint(0, 10) < 2:
            #    self.coffee_requests.append("jee")

            # send the notifs, if so ..
            while len(self.coffee_notifs) > 0 and self.coffee_notifs[0] < time.time():
                for user in self.subscribes:
                    self.sendto(user, "A fresh pot of coffee ought to be ready now!")
                self.coffee_notifs = self.coffee_notifs[1:]
            
            gtk.gdk.threads_leave()
            device.display_state_on()

    def update_label(self):
        self.msgfield.set_markup(self.msg_markup(self.msgs)) #[:20]))
        #self.msgfield.set_markup(self.msg_markup(self.msgs[:10]))
        self.msgfield.queue_draw()

    def update_motd(self):
        msg, timeout = self.motd_msg
        if time.time() < timeout:
            self.motd_box.show_all()
            self.motd.set_markup("<span size='x-large'>" + msg + "</span>")
            self.motd.queue_draw()
        else:
            self.motd_box.hide_all()
            
    def set_motd(self, msg, time):
        self.motd_msg = (msg, time)
        self.update_motd()

    def set_makebtn(self, msg):
        self.coffee_msg = msg
        self.update_makebtn()
        
    def update_makebtn(self):
        max, fade = 200, 10
        cr, cg, cb = max, fade, fade
        lcol = "#000000"
        if self.coffee_made == 0:
            msg = "No coffee has been made!"
            lcol = "#ff2020"
        else:
            msg = "Last made "+time.strftime("%H:%M", time.localtime(self.coffee_made))+" ("+tf(self.coffee_made)+")"
            diff = (time.time() - self.coffee_made) / 60
            if diff < 15:
                cr, cg, cb = fade, max, fade
            elif diff < 60:
                cr, cg, cb = (fade + ((max-fade) * ((diff-15) / (60-15)))), max, fade
            elif diff < 120:
                cr, cg, cb = max, (max - ((max-fade) * ((diff-60) / (120-60)))), fade
        col = "#%02x%02x%02x" % ( cr, cg, cb )

        cm = self.coffee_msg
        if len(self.coffee_requests) > 0:
            lcol = "#ff2020"
            cm = "Please make coffee!"
            if len(self.coffee_requests) > 1:
                cm += " (" + str(len(self.coffee_requests)) + " requests)"
        msg = "<span size='x-large' color='"+lcol+"'>"+cm+"</span>\n<span color='"+col+"'>"+msg+"</span>"
                
        self.makebtn.child.set_markup(msg)
        self.makebtn.queue_draw()
        
    def makebtn_clicked(self, btn):
        self.coffee_made = time.time()
        for user in self.coffee_requests:
            self.sendto(user, "Finally, someone started making coffee!")
        self.coffee_notifs.append(time.time() + (60 * 5))
        self.coffee_requests = []
        self.update_label()
        self.update_motd()
        self.update_makebtn()
        self.save_state(state_file)

    def save_state(self, filename):
        try:
            f = open(filename, "wb")
            cPickle.dump((self.coltable, self.coffee_made, self.coffee_msg, self.msgs, self.subscribes, self.coffee_notifs, self.motd_msg), f)
            f.close()
        except Exception, ex:
            print "Error saving state to " + filename + ": " + str(ex)

    def load_state(self, filename):
        try:
            f = open(filename, "rb")
            (coltable, coffee_made, coffee_msg, msgs, subscribes, coffee_notifs, motd_msg) = cPickle.load(f)
            (self.coltable, self.coffee_made, self.coffee_msg, self.msgs, self.subscribes, self.coffee_notifs, self.motd_msg) = (coltable, coffee_made, coffee_msg, msgs, subscribes, coffee_notifs, motd_msg)
            f.close()
        except Exception, ex:
            print "Error loadingstate from " + filename + ": " + str(ex)
        
    def __init__(self):

        # the state data
        self.coltable = {}
        self.coffee_made = 0
        self.coffee_msg = ""
        self.coffee_requests = []
        self.msgs = []
        self.subscribes = []
        self.coffee_notifs = []
        self.motd_msg = ("", 0)
        #self.msgs = testdata.test_msgs()

        self.load_state(state_file)
        
        # ui
        hildon.Program.__init__(self)
        self.window = hildon.Window()
        self.window.connect("delete_event", quit)
        self.add_window(self.window)    
        self.window.set_decorated(False)
        self.window.fullscreen()
        self.window.set_size_request(800, 480)

        motd = gtk.Label("motd")
        motd.set_use_markup(True)
        motd.set_line_wrap(True)
        motd.set_justify(gtk.JUSTIFY_LEFT)
        
        img = gtk.image_new_from_stock(gtk.STOCK_INFO, gtk.ICON_SIZE_MENU)

        hbox = gtk.HBox(False, 2)
        hbox.pack_start(motd, True, False)

        f = gtk.Frame("Message of the day")
        f.add(hbox)
        f.set_label_widget(img)
        
        self.motd_box = f
        self.motd = motd
        #self.set_motd("a great day for coffee!", time.time() + 5)
        
        label = gtk.Label("Hello World!")
        label.set_use_markup(True)
        label.set_line_wrap(True)
        label.set_padding(10, 0)
        label.set_alignment(0, 0)

        self.msgfield = label
        self.msgfield.set_size_request(self.window.get_size()[0], self.window.get_size()[1]) #-1)

        #
        # the button
        button = gtk.Button("")
        button.child.set_use_markup(True)
        button.child.set_justify(gtk.JUSTIFY_CENTER)
        button.connect("clicked", self.makebtn_clicked)

        self.makebtn = button
        self.set_makebtn("Press me when making coffee!")

        #
        f = gtk.Frame("Greetings")
        f.add(self.msgfield)

        a = gtk.Alignment()
        a.set_padding(0, 5, 5, 5)

        vbox = gtk.VBox(False, 2)
        vbox.pack_start(self.motd_box, False)
        vbox.pack_start(f)
        vbox.pack_end(self.makebtn, False)

        a.add(vbox)

        self.update_label()
        self.window.add(a)
        
    def quit(self, *args): 
        gtk.gdk.threads_enter()
        gtk.main_quit()

    def run(self):     
        self.window.show_all()

        gtk.gdk.threads_init()
        t = threading.Thread(target=self.update_run)
        t.setDaemon(True)
        if is_tablet():
            t.start()

        gtk.gdk.threads_enter()
        gtk.main()
        gtk.gdk.threads_leave()

    def sendto(self, user, msg):
        print "sending to %s message '%s'" % (user, msg)

    def message_received(self, user, msg):
        # parse message ..
        print "adding message"

        ret = "Invalid command '%s'. '/help' for a list of commands." % msg
        cmd, s, param = msg.partition(" ")
        cmd = cmd.lower()
        if cmd == "/subscribe":
            if user in self.subscribes:
                ret = "you're already subscribed to updates!"
            else:
                self.subscribes.append(user)
                ret = "ok, we'll keep you posted!"
                self.save_state(state_file)
        elif cmd == "/unsubscribe":
            if user in self.subscribes:
                self.subscribes.remove(user)
                ret = "ok, no more updates for you!"
                self.save_state(state_file)
            else:
                ret = "you aren't receiving updates right now!"
        elif cmd == "/last":
            if self.coffee_made == 0:
                ret = "No coffee has been made!"
            else:
                ret = "Last pot made "+time.strftime("%H:%M", time.localtime(self.coffee_made))+" ("+tf(self.coffee_made)+")"
        elif cmd == "/color":
            self.coltable[user] = param
            ret = "ok, your color is changed to " + param
            self.save_state(state_file)
        elif cmd == "/msg":
            self.msgs.insert(0, [user, param, time.time()])
            self.update_label()
            ret = "Ok, message displayed!"
            self.save_state(state_file)
        elif cmd == "/bt":
            pass
        elif cmd == "/help":
            ret = "/msg <message> - post a message\n/last - the last time coffee was made\n/req - request more coffee\n/subscribe - subscribe to coffee updates\n/unsubscribe - unsubscribe\n";
        elif cmd == "/req":
            self.coffee_requests.append(user)
            ret = "ok, more coffee requested. we'll keep you posted!"
        elif cmd == "/motd":
            if len(param) == 0:
                self.set_motd(param, 0)
                ret = "motd cleared"
            else:
                # round to next day
                t = time.time() + ((60*60*24) - (time.time() % (60*60*24)))
                self.set_motd(param, t)
                ret = "ok, motd changed, displaying until " + time.strftime("%d.%m %Y %H:%M", time.localtime(t))
            self.save_state(state_file)
        return ret
    
    def shell_loop(self):
        while True:
            inp = raw_input("cmd> ")
            user, s, inp = inp.partition(" ")
            ret = self.message_received(user, inp)
            print "## " + ret

def test1():
    sipper = CoffeeSipper()

    t = threading.Thread(target=sipper.shell_loop)
    t.setDaemon(True)
    t.start()

    try:
        sipper.run()
    except Exception, ex:
        pass



#
# sip handler
#

from sip_handler import SipHandler, SipContext
from streamer import StreamHandler, ServerHandler

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



def test3():
    sport, aport, vport = 4000, 4002, 4004
    stream_handler = StreamHandler(sport, aport, vport)

    serv = ServerHandler()
    serv.add_streamer(stream_handler)
    serv.start()

    sh = CoffeeSipHandler(stream_handler)
    c = SipContext(p2pship.get_default_ident(), ("localhost", 1234), sh, serv, 5000)
    c.start()
    c.register()

    sh.run()


if __name__ == "__main__":
    #test1()
    test3()
