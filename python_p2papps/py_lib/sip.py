#
# wrapper / util for doing SIP message processing
#
#

import p2pship
import time
import sys
import os
import random
import re

#
#
def get_uuid():
    #import uuid
    #return str(uuid.uuid4())
    return rand_hex(8) + "-" + rand_hex(4) + "-" + rand_hex(4) + "-" + rand_hex(4) + "-" + rand_hex(12)

def resp_str(code):
    if code < 200:
        return "Continue"
    elif code < 300:
        return "OK"
    elif code < 400:
        return "Redirect"
    elif code < 500:
        return "Error"
    else:
        return "System error"

def rand_string(length):
    return ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') for x in xrange(length)])

def rand_ints(length):
    return ''.join([random.choice('0123456789') for x in xrange(length)])

def rand_hex(length):
    return ''.join([random.choice('0123456789abcdef') for x in xrange(length)])

def parse_aor(pa):
    p = pa.find("<")
    if p > -1:
        pa = pa[p+1:]
    p = pa.find("sip:")
    if p > -1:
        pa = pa[p+4:]
    p = pa.find(">")
    if p > -1:
        pa = pa[0:p]
    return pa

def parse_name(pa):
    p = pa.find("<")
    if p > -1:
        pa = pa[0:p]
    p = pa.find("sip:")
    if p > -1:
        pa = pa[p+4:]
    
    return pa.strip('"\' ')

# const
sip_lf = "\r\n"

def do_line(*components):
    ret = ""
    for c in components:
        ret += str(c) + " "
    return ret[0:-1] + sip_lf



#
# very simple sip message parser/constructor
#
class SipMessage:

    #

    def __init__(self, context, msg_type=None, target=None, parent=None, rcode=None, rmsg=None, call=None, fill=True):
        self.context = context
        self.resp_code = rcode
        self.resp_msg = rmsg
        self.parent = parent
        self.msg_type = msg_type
        self.target = target
        self._ser = None
        self.body = None
        self.body_type = None
        self.params = {}
        self.via = []
        self.callid = None
        self.local_aor = None
        self.remote_aor = None

        if context is not None:
            self.local_aor = context.local_aor
            self.remote_aor = target

        if parent: # responses
            for k in parent.params.keys():
                if k != "Contact" and \
                       k != "Max-forwards" and \
                       k != "Content-Length" and \
                       k != "User-agent" and \
                       k != "Content-Type":
                    self.params[k] = parent.params[k]
            self.branch = parent.branch
            self.call = parent.call
            self.callid = parent.callid
            self.cseq = parent.cseq
            self.msg_type = parent.msg_type
            self.sfrom = parent.sfrom
            if parent.sto.find(";tag=") != -1:
                self.sto = parent.sto
            else:
                self.sto = parent.sto+";tag="+context.create_tag(self)
            self.via = parent.via
            self.local_aor = parent.local_aor
            self.remote_aor = parent.remote_aor
        elif self.resp_code is None and fill and context is not None: # definitely not a response!
            if call is not None:
                self.call = call
            else:
                self.call = context.get_call()
                self.call.remote_aor = target

            self.branch = context.create_branch(self)
            self.cseq = str(context.create_cseq(self)) # + " " + self.msg_type
            self.sfrom = "<sip:" + context.get_aor()+">;tag="+context.create_tag(self)
            self.sto = "<sip:"+self.target+">"
            self.via.append("SIP/2.0/UDP " + context.via_address() + ";rport;branch=" + self.branch)

        if fill:
            self.set_param("User-agent", "AmazingAgent/0.1")

    def set_context(self, context):
        self.context = context
        if self.callid is not None and context is not None:
            self.call = context.get_call(self.callid)
            if self.call.remote_aor is None:
                if self.is_response(): self.call.remote_aor = parse_aor(self.sto)
                else: self.call.remote_aor = parse_aor(self.sfrom)

    def get_local_remote(self):
        l = parse_aor(self.sto)
        r = parse_aor(self.sfrom)
        if self.is_response():
            return (r, l)
        else:
            return (l, r)
                    
    def set_param(self, key, value):
        self.params[key] = [ value ]
                       
    def add_param(self, key, value):
        if self.params.has_key(key):
            self.params[key].append(value)
        else:
            self.params[key] = [ value ]

    def param(self, key, default=None):
        if self.params.has_key(key):
            return self.params[key][0]
        return default
            
    def create_response(self, code):
        return SipMessage(self.context, parent=self, rcode=code)

    def create_ack(self):
        # same branch!
        pass

    def __str__(self):
        context = self.context
        ret = ""
        if self.is_response():
            ret = do_line("SIP/2.0", self.resp_code, resp_str(self.resp_code))
        else:
            if self.msg_type == "REGISTER":
                ret = do_line(self.msg_type, "sip:"+context.get_domain(), "SIP/2.0")
            else:
                ret = do_line(self.msg_type, "sip:"+self.target, "SIP/2.0")

        for v in self.via:
            ret += do_line("Via:", v)

        ret += do_line("From:", self.sfrom)
        ret += do_line("To:", self.sto)
        ret += do_line("Call-ID:", self.call.id)

        ret += do_line("CSeq:", str(self.cseq) + " " + self.msg_type)

        for k in self.params.keys():
            for v in self.params[k]:
                ret += do_line(k + ":", v)
                
        if self.body is None or len(self.body) == 0:
            ret += do_line("Content-Length:", 0, sip_lf)
        else:
            if self.body_type is not None:
                ret += do_line("Content-Type:", self.body_type)
            ret += do_line("Content-Length:", len(self.body), sip_lf) + self.body
                
        return ret

    def set_body(self, body, ctype="text/plain"):
        self.body = body
        self.body_type = ctype

    def is_response(self):
        return self.resp_code is not None

    def respond(self, code, body=None, body_type=None):
        m = self.create_response(code)
        m.set_body(body, body_type)
        m.send()

    def send(self):
        self.context.send_msg(self)

    def create_follow_up(self, msg_type, body=None, body_type=None):
        m = SipMessage(self.context, msg_type=msg_type, target=self.call.remote_aor, call=self.call)
        m.local_aor = self.local_aor
        m.remote_aor = self.remote_aor
        m.set_body(body, body_type)
        if self.is_response():
            m.sfrom = self.sfrom
            m.sto = self.sto
        else:
            m.sfrom = self.sto
            m.sto = self.sfrom
        return m

    #
    def parse(self, data, context = None):
        if context is None:
            context = self.context
        (line, par, rest) = data.partition(sip_lf)
        m = re.match('(SIP/2.0) ([0-9]+) (.*)', line)
        if m:
            self.__init__(context, rcode=int(m.group(2)), rmsg=m.group(3))
        else:
            m = re.match('([A-Z]+) ([^ ]+) (SIP/2.0)', line)
            if m:
                self.__init__(context, msg_type=str(m.group(1)), target=m.group(2), fill=False)
                
        self.raw_msg = data
        while len(rest) > 2:
            (line, par, rest) = rest.partition(sip_lf)
            if len(line) == 0:
                break

            k, s, v = line.partition(": ")
            if len(v) > 0:
                if k == "Via":
                    self.via.append(v)
                    for c in v.split(";"):
                        k, m, v = c.partition("=")
                        if k == "branch":
                            self.branch = v
                elif k == "Call-ID":
                    self.callid = v
                elif k == "Content-Type":
                    self.body_type = v
                elif k == "Content-Length":
                    pass
                elif k == "CSeq":
                    self.cseq, s, self.msg_type = v.partition(" ")
                    self.cseq = int(self.cseq)
                elif k == "From":
                    self.sfrom = v
                elif k == "To":
                    self.sto = v
                else:
                    self.add_param(k, v)

        if len(rest) > 0:
            self.body = rest
        self.set_context(context)
        
#
# a sip context
#
class SipContext:

    def __init__(self, aor, handler):
        self.aor = aor
        self.handler = handler
        handler.context = self
        self.cseq = random.randint(10, 10000)
        self.msgs = {}
        self.calls = {}
        self.seen_msgs = []
        self.registered = -1
        self.regthread = None
        
    def start(self):
        pass

    # sip
    def get_domain(self):
        return self.aor[self.aor.find("@")+1:]

    def get_aor(self):
        return self.aor

    def create_branch(self, msg):
        return "z9hG4bK" + rand_string(32)

    def create_tag(self, msg):
        return rand_string(10)

    def create_cseq(self, msg):
        self.cseq += 12
        return self.cseq

    def get_call(self, v=None):
        if v is not None and self.calls.has_key(v):
            ret = self.calls[v]
        else:
            ret = SipCall(v)
            self.calls[ret.id] = ret
        return ret

    def get_addr(self):
        return ('127.0.0.1', 5060) # self.server.get_addr(self)
    
    def get_contact(self):
        (host, port) = self.get_addr()
        return "sip:" + self.aor[0:self.aor.find("@")+1]+str(host)+":"+str(port)+";transport=udp"

    def via_address(self):
        (host, port) = self.get_addr()
        return str(host)+":"+str(port)

    # more sip, from message
    def create(self, type, dst):
        if dst.find("@") < 0:
            dst = dst + "@" + self.get_domain()
        ret = SipMessage(self, msg_type = type, target = dst)
        ret.add_param("Allow", "INVITE, ACK, BYE, CANCEL, OPTIONS, PRACK, MESSAGE, UPDATE")
        return ret
    
    def create_register(self, timeout):
        ret = self.create("REGISTER", self.get_aor())
        ret.add_param("Max-Forwards", 70)
        ret.add_param("Contact", "<" + self.get_contact()+">")
        ret.add_param("Expires", timeout)
        return ret

    def create_message(self, to, message):
        ret = self.create("MESSAGE", to)
        ret.add_param("Max-Forwards", 70)
        ret.set_body(message)
        return ret

    def create_invite(self, to):
        ret = self.create("INVITE", to)
        ret.add_param("Max-Forwards", 70)
        ret.add_param("Contact", "<" + self.get_contact()+">")

        host, aport, vport = "127.0.0.1", 8000, 8002
        formats = {}
        formats["96"] = { "rtpmap":"iLBC/8000", "fmtp":"mode=30" }
        formats["18"] = { "rtpmap":"G729/8000" }
        formats["8"] = { "rtpmap":"PCMA/8000" }
        formats["0"] = { "rtpmap":"PCMA/8000" }
        formats["13"] = { "rtpmap":"CN/8000" }
        formats["97"] = { "rtpmap":"telephone-event/8000" }
        ret.call.my_medias = { "audio":[ host, aport, formats ] }
        ret.set_body(ret.call.get_my_sdp(), "application/sdp")
        return ret

    #
    def data_got(self, data):
        m = SipMessage(None)
        m.parse(data)
        self.msg_got(m)

    def msg_got(self, msg):
        if msg is None:
            if self.handler.verbose:
                print "Got invalid data:'"+data+"'"
        else:
            msg.set_context(self)
            if self.handler.filter_duplicates and self.handler.is_seen(msg):
                if self.handler.verbose:
                    print "skipping already seen message.."
                return
            
            if msg.body_type == "application/sdp":
                msg.call.remote_medias = msg.call.parse_sdp(msg.body)
            if msg.is_response():
                if self.msgs.has_key(msg.branch):
                    parent = self.msgs[msg.branch]
                    if msg.resp_code >= 200:
                        self.msgs.pop(msg.branch)
                    self.handler.response_got(parent, msg)
                elif self.handler.verbose:
                    print "response to something already processed.."
            else:
                self.handler.request_got(msg)

    def send_msg(self, msg):
        if self.handler.verbose:
            print "sending mesage: '"+str(msg)+"'"
        if not msg.is_response():
            self.msgs[msg.branch] = msg

        #print "todo: insert into stream %s -> %s, %s" % (msg.remote_aor, msg.local_aor, str(msg))
        #p2pship.service_send(msg.remote_aor, msg.local_aor, 1, str(msg))
        p2pship.sip_route(str(msg))

    def register(self):
        self.registered = time.time()
        m = self.create_register(3600)
        self.send_msg(m)
        if self.regthread is None:
            self.regthread = threading.Thread(target=self.register_run)
            self.regthread.setDaemon(True)
            self.regthread.start()

    def unregister(self):
        self.registered = -1
        m = self.create_register(0)
        self.send_msg(m)

    def register_run(self):
        while True:
            if self.registered > -1 and (time.time() - self.registered) > (3600/2):
                m = self.create_register(3600)
                self.send_msg(m)
                self.registered = time.time()
            else:
                time.sleep(10)
            

#
# a sip call
#
class SipCall:
    def __init__(self, id=None):
        if id is None:
            self.id = get_uuid()
        else:
            self.id = id
        self.my_medias = None
        self.remote_medias = None
        self.o_session = rand_ints(10)
        self.o_version = 1
        self.time = "0 0"
        self.session_name = "-"
        self.remote_aor = None
        
    def parse_sdp(self, data):
        ret = {}
        ret["attributes"] = []
        current_media = None
        current_formats = None
        current_ca = None
        while len(data) > 2:
            (line, par, data) = data.partition(sip_lf)
            try:
                k, v = line.split("=", 1)
                if k == "v":
                    pass # version. boring.
                elif k == "o":
                    pass # owner. boring.
                elif k == "s":
                    self.session_name = v
                elif k == "t":
                    self.time = v
                elif k == "m":
                    mf = v.split(" ")
                    current_formats = {}
                    for f in mf[3:]:
                        current_formats[f] = {}
                    current_media = [ current_ca, int(mf[1]), current_formats ]
                    ret[mf[0]] = current_media
                elif k == "c":
                    cf, ci, current_ca = v.split(" ")
                elif k == "a":
                    aa = v.split(" ")
                    if len(aa) == 2:
                        pn, pv = aa[0].split(":")
                        current_formats[pv][pn] = aa[1]
                    else:
                        ret["attributes"].append(v)
                elif self.handler.verbose:
                    print "unrecognized line: " + line
                
                if current_media is not None and current_ca is not None:
                    current_media[0] = current_ca
            except Exception, ex:
                print "invalid line: '" + line + "'"
                print str(ex)
        return ret

    def get_my_sdp(self):
        return self.serialize_sdp(self.my_medias)
    
    def serialize_sdp(self, sdps):

        #host = "10.0.0.10" #"127.0.0.1"
        host = "127.0.0.1"
        sdp = do_line("v=0")
        sdp += do_line("o=-", self.o_session,
                       self.o_version, "IN IP4",
                       host)
        sdp += do_line("s="+self.session_name)
        sdp += do_line("t="+self.time)
        for k in sdps.keys():
            if k == "attributes":
                continue
            ma = sdps[k]
            sdp += do_line("m="+k, ma[1], "RTP/AVP", ' '.join(ma[2].keys()))
            sdp += do_line("c=IN IP4", ma[0])
            for f in ma[2].keys():
                for p in ma[2][f].keys():
                    sdp += do_line("a="+p+":"+f, ma[2][f][p])
        if sdps.has_key("attributes"):
            for i in sdps["attributes"]:
                sdp += do_line("a="+str(i))

        sdp += do_line()
        return sdp

#
# sip handler
#
class SipHandler:

    verbose = True
    filter_duplicates = True
    duplicates = []

    def is_seen(self, msg):
        # 100 latest
        self.duplicates = self.duplicates[-100:]

        # msg id: branch + seq + type + resp/req
        mid = "rq:" + msg.sfrom
        if msg.is_response():
            #mid = "re:" + msg.sto
            return False
        mid += ";" + str(msg.branch) + ";" + str(msg.msg_type) + ";" + str(msg.cseq)
        try:
            i = self.duplicates.index(mid)
            return True
        except Exception, ex:
            self.duplicates.append(mid)
            return False
    
    def request_got(self, msg):
        if self.verbose:
            print "request " + msg.msg_type + " got from " + msg.sfrom
        
        if msg.msg_type == "MESSAGE":
            self.message_got(msg)
        elif msg.msg_type == "INVITE":
            self.invite_got(msg)
        elif msg.msg_type == "BYE" or msg.msg_type == "CANCEL":
            self.cancel_got(msg)
        elif msg.msg_type == "ACK":
            self.ack_got(msg)
        else:
            msg.respond(400)
        
    def response_got(self, req, resp):
        pass

    def message_got(self, message):
        message.respond(405)

    def ack_got(self, message):
        message.respond(405)

    def invite_got(self, message):
        message.respond(405)

    def cancel_got(self, message):
        message.respond(200)


sip_clients = []
sip_client_instances = []

def sip_client_callback(local_aor, remote_aor,
                        dest_addr, data):
    #print "Got sip callback %s, %s, %s\n--\n%s\n--" % (local_aor, remote_aor,
    #                                                   dest_addr, data)
    m = SipMessage(None)
    m.parse(data)
    m.local_aor = local_aor
    m.remote_aor = remote_aor
    (loc, rem) = m.get_local_remote()
    #print "got local %s, remote %s" % (loc, rem)
    for h in sip_client_instances:
        if h[0].match(rem) and h[1] == loc:
            h[2].msg_got(m)
            m = None
            break

    if m:
        for h in sip_clients:
            if h[0].match(rem) and h[1].match(loc):
                ctx = SipContext(loc, h[2]())
                ctx.local_aor = local_aor
                sip_client_instances.append((h[0], loc, ctx))
                ctx.msg_got(m)
                m = None
                break

    if m is None:
        return None
    else:
        return data

def sip_client_install(event, instance, obj):
    if event == "sip/install":
        (from_aor, to_aor, handler) = obj
        print "installing %s -> %s" % (str(from_aor), str(to_aor))
        sip_clients.append((re.compile(from_aor), re.compile(to_aor), handler))
        return True
    return False

def install_sip_handler(from_aor, to_aor, handler):
    ret = None
    try:
        ret = p2pship.call_ipc_handler("sip/install", (from_aor, to_aor, handler))
    except Exception, ex:
        print "Error executing ipc: " + str(ex)
    return ret

try:
    p2pship.register_sip_client_handler("sipstuff", sip_client_callback)
    p2pship.register_ipc_handler("sip/install", sip_client_install)
except Exception, ex:
    pass

