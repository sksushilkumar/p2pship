import random
import time
import threading


class SubscriptionHandler:
    """Class for managing one subscription of a presence"""

    def __init__(self, target, local_aor):
        self.target = target
        self.last_resp = None
        self.remote_contact = None
        self.pdif_id = "uhpbb"
        self.local_aor = local_aor
        self.last = None

        self.subscribe_key = None
        info("New subscription handler for %s of %s" % (local_aor, target))
        
    def subscribe(self):

        if self.subscribe_key is not None:
            return
        
        try:
            key = sip_real_aor(self.target)
            self.subscribe_key = p2pship.ol_ident_subscribe(self.local_aor, key, key, self.publish_got, key)
        except Exception, ex:
            warn("subscribe of %s (for %s) failed" % (key, self.local_aor))

    def cancel_subscribe(self):
        if self.subscribe_key is not None:
            p2pship.ol_cancel(self.subscribe_key)
            self.subscribe_key = None
        
    def create_pdif_simple(self, basic_status):
        return create_pdif(self.target, self.pdif_id, basic_status)

    def publish_got(self, key, data, from_aor, real_key):
        """Callback for subscribes"""

        ret = None
        try:
            ret = p2pship.import_reg(data)
        except Exception, ex:
            debug("could not import reg: %s" % str(ex))
        self.update_presence(ret)

    def update_presence(self, ret = None):
        """Sends the current presence state (afaik) to the client"""
        
        if self.get_expire() < 1:
            return
        
        if ret is None:
            ret = p2pship.get_reg(sip_real_aor(self.target))

        pdif = None
        if ret is not None:
            
            if ret["created"] > time.time():
                debug("The reg packet for %s has future created time!" % ret["aor"])

            if ret["is_valid"] == 0:
                debug("The reg packet for %s is expired!" % ret["aor"])
                ret = False
            else:
                apps = ret.get('applications')
                if apps is not None:
                    pdif = apps.get('s1_presence')
                ret = True
        else:
            ret = False

        # send updates only when the state has changed
        if ret == self.last and pdif is None:
            return
        self.last = ret
            
        if ret:
            if pdif is not None:
                self.notify(pdif)
            else:
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

        self.check_subscribe()

    def check_subscribe(self):
        
        if self.get_expire() > 0:
            self.subscribe()
        else:
            self.cancel_subscribe()
        self.update_presence()


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
        notify.send(filter = False)
        return 0

    def response_got(self, req, resp):

        debug("Got a response!")

#
#
#

class PresenceManager:
    """Manager for one local user's all presence subscriptions. Uses
    the PresenceHandlers to actually do the maintanaince."""

    def __init__(self, aor, load = False):

        self.handlers = {}
        self.local_aor = aor
        if load:
            self.load()
            for sh in self.handlers.values():
                sh.subscribe_key = None
                sh.check_subscribe()

        # we need a periodic poller to check the validity of the reg packets!
        p2pship.call_periodically(self.check_handlers, None, 60000)
        
    def get_subscribe_handler(self, aor, callid):
        """Each PresenceHandler is tied to one source aor"""

        h = self.handlers.get(callid + ":" + aor)
        if h is None:
            h = SubscriptionHandler(aor, self.local_aor)
            self.handlers[callid + ":" + aor] = h
        return h

    def request_got(self, msg):
        """Called by the post processor"""
        
        self.local_aor = parse_aor(msg.sfrom)
        if msg.msg_type == "SUBSCRIBE":
            handler = self.get_subscribe_handler(parse_aor(msg.sto), msg.callid)
            handler.subscribe_got(msg)
            self.save()
            return 0
        
        if msg.msg_type == "PUBLISH":
            debug("publish got " + str(msg))
            p2pship.set_service_param(self.local_aor, SIP_SERVICE, "presence", msg.body)
            return None

        if msg.msg_type == "OPTIONS":
            m = msg.create_response(200)
            m.as_remote = True
            m.add_param("Allow", "INVITE, ACK, CANCEL, MESSAGE. OPTIONS, BYE, PUBLISH, SUBSCRIBE")

            m.send(filter = False)
            return 0
        
    def response_got(self, req, resp):
        """Called by the post processor. If a response has an
        associated request, then it has been sent by us (and we should
        capture it!)"""

        if req is None:
            return None

        if req.msg_type == "NOTIFY" and req is not None:
            # todo: why is req.callid == None??
            handler = self.get_subscribe_handler(parse_aor(req.sfrom), resp.callid)
            handler.response_got(req, resp)
            return 0

    def check_handlers(self, data):
        """Called periodically to report on the presence state"""

        debug("checking handlers for %s" % self.local_aor)
        for sh in self.handlers.values():
            sh.update_presence()
        self.save()

    def save(self):
        try:
            filename = get_datadir() + "/manager_" + self.local_aor
            f = open(filename, "w")
            pickle.dump(self.handlers, f)
            f.close()
        except Exception, ex:
            warn("Couldn't write presence manager state! %s" % str(ex))

    def load(self):
        try:
            filename = get_datadir() + "/manager_" + self.local_aor
            f = open(filename, "r")
            self.handlers = pickle.load(f)
            f.close()
        except Exception, ex:
            warn("Couldn't read presence manager state! %s" % str(ex))

presence_managers = {}
def presence_get_manager(aor):

    ret = None
    ret = presence_managers.get(aor, None)
    if ret is None:
        ret = PresenceManager(aor, False)
        presence_managers[aor] = ret
        presence_save_managers()
    return ret

def presence_load_managers():

    try:
        filename = get_datadir() + "/managers"
        f = open(filename, "r")
        keys = pickle.load(f)
        f.close()

        for aor in keys:
            man = PresenceManager(aor, True)
            man.check_handlers(None)
            presence_managers[aor] = man
            
    except Exception, ex:
        warn("Couldn't read presence managers' state! %s" % str(ex))

def presence_save_managers():

    try:
        filename = get_datadir() + "/managers"
        f = open(filename, "w")
        pickle.dump(presence_managers.keys(), f)
        f.close()
    except Exception, ex:
        warn("Couldn't write presence managers' state! %s" % str(ex))


class PresenceHandler(SipHandler):
    """Handler for presence subscriptions. One instance for each
    *local* aor is created (handling multiple remote aors). As these
    are instatiated and managed by the sip library, we use them just
    to forward the messages to our own-managed ones, which are
    persistent!"""

    def __init__(self):
        pass
        
    def request_got(self, msg):
        """Called by the post processor"""
        
        if not msg.is_internal and msg.msg_type in [ "SUBSCRIBE", "PUBLISH", "OPTIONS" ]:
            man = presence_get_manager(parse_aor(msg.sfrom))
            return man.request_got(msg)
        
    def response_got(self, req, resp):
        """Called by the post processor. If a response has an
        associated request, then it has been sent by us (and we should
        capture it!)"""

        if req is None:
            return None

        man = presence_get_manager(parse_aor(req.sto))
        return man.response_got(req, resp)


presence_load_managers()
if install_sip_request_handler(".*", ".*", PresenceHandler):
    info("Presence handler is installed!")
else:
    warn("Error installing presence handler!")
