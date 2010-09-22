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
from sip_handler import SipHandler, SipContext
from streamer import StreamHandler, ServerHandler
import urllib
from os import curdir, sep
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from utils import *

state_file = "state.bin"
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
            self.periodic_update()

    def periodic_update(self):
        pass

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


