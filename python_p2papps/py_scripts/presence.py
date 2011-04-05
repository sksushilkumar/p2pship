import random
import time
import threading

def get_local_sip_contact(aor):
    #"<sip:127.0.0.1:1234;transport=udp>"
    # todo: verify that it is in the intended format. might contain ;hostname= etc..
    return "<sip:%s>" % p2pship.sip_get_local_contact(aor)


class SubscriptionHandler:
    """Class for managing one subscription of a presence"""

    def __init__(self, target, local_aor):
        self.target = target
        self.last_resp = None
        self.remote_contact = None
        self.pdif_id = "uhpbb"
        self.local_aor = local_aor
        self.last = None
        info("New subscription handler for %s of %s" % (local_aor, target))
        
    def subscribe(self, key, callback):
        try:
            p2pship.ol_ident_subscribe(self.local_aor, key, key, self.publish_got, key)
        except Exception, ex:
            warn("subscribe of %s (for %s) failed" % (key, self.local_aor))

    def cancel_subscribe(self, key, callback):
        pass
        
    def create_pdif_simple(self, basic_status):
        return """<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:%s">
  <tuple id="%s">
     <status>
        <basic>%s</basic>
     </status>
  </tuple>
</presence>""" % (self.target, self.pdif_id, basic_status)

    def publish_got(self, key, data, real_key):
        """Callback for subscribes"""
        
        ret = p2pship.import_reg(data)
        self.update_presence(ret)

    def update_presence(self, ret = None):
        """Sends the current presence state (afaik) to the client"""
        
        if self.get_expire() < 1:
            return
        
        if ret is None:
            ret = p2pship.get_reg(self.target)

        if ret is not None:
            if ret["created"] > time.time():
                debug("The reg packet for %s has future created time!" % ret["aor"])

            if ret["valid"] < time.time():
                debug("The reg packet for %s is expired!" % ret["aor"])
                ret = False
            else:
                ret = True
        else:
            ret = False

        # send updates only when the state has changed
        if ret == self.last:
            return
        self.last = ret
            
        if ret:
            self.notify(self.create_pdif_simple("open"))
        else:
            self.notify(self.create_pdif_simple("closed"))

    def subscribe_got(self, msg):
        self.last_resp = msg.respond(202, as_remote = True)
        self.last = None # force to re-report
        self.remote_contact = msg.param("Contact")
        self.remote_contact = self.target
        self.expire = int(msg.param('Expires', 0))
        self.time = time.time()

        if self.get_expire() > 0:
            self.subscribe(self.target, self.publish_got)
        else:
            self.cancel_subscribe(self.target, self.publish_got)
        return 0

    def get_expire(self):
        """Returns the time left of the subscription"""
        
        return int(self.time + self.expire - time.time())
        
    def notify(self, presence):
        
        if self.last_resp is None:
            warn('Trying to NOTIFY without any SUBSCRIBE');
            return        

        expire = self.get_expire()
        if expire < 1:
            warn('Trying to NOTIFY even though expire is %d' % expire)
            return

        debug("notifying presence, expire on subscribe of %s for %s is %d" % (self.target, self.last_resp.sfrom, expire))
        notify = self.last_resp.create_as_remote_follow_up("NOTIFY", presence, "application/pidf+xml")
        notify.set_param("Event", "presence")
        notify.set_param("Subscription-State", "active;expires=%d" % expire)
        notify.set_param("Contact", get_local_sip_contact(self.local_aor))
        notify.target = self.remote_contact
        notify.send()
        return 0

    def response_got(self, req, resp):
        debug("Got a response!")
        return 0

class PresenceHandler(SipHandler):
    """Handler for presence subscriptions"""

    def __init__(self):
        self.handlers = {}
        # we need a periodic poller to check the validity of the reg packets!
        p2pship.call_periodically(self.check_handlers, None, 60000)

    def get_subscribe_handler(self, aor):
        """Each PresenceHandler is tied to one source aor"""

        h = self.handlers.get(aor)
        if h is None:
            h = SubscriptionHandler(aor, self.local_aor)
            self.handlers[aor] = h
        return h

    def request_got(self, msg):
        """Called by the post processor"""
        
        self.local_aor = parse_aor(msg.sfrom)
        if msg.msg_type == "SUBSCRIBE":
            handler = self.get_subscribe_handler(parse_aor(msg.sto))
            return handler.subscribe_got(msg)
        
        if msg.msg_type == "PUBLISH":
            #print "publish got " + str(msg)
            return None

    def response_got(self, req, resp):
        """Called by the post processor. If a response has an
        associated request, then it has been sent by us (and we should
        capture it!)"""

        if req.msg_type == "NOTIFY" and req is not None:
            handler = self.get_subscribe_handler(parse_aor(req.sfrom))
            return handler.response_got(req, resp)

    def check_handlers(self, data):
        """Called periodically to report on the presence state"""

        debug("checking handlers for %s" % self.local_aor)
        for sh in self.handlers.values():
            sh.update_presence()

if install_sip_request_handler(".*", ".*", PresenceHandler):
    info("Presence handler is installed!")
else:
    warn("Error installing presence handler!")
