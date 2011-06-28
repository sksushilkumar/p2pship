import socket
import pickle
import uuid


busy_codes = [ 486, 600, 480 ]
decline_codes = [ 603 ]
notfound_codes = [ 404, 400 ]

calls = {}

# The local voicemail invite managers
invite_managers = {}

def get_voicemail_manager(aor):

    man = invite_managers.get(aor)
    if man is None:
        man = VoicemailManager(aor)
        invite_managers[aor] = man

        try:
            filename = get_datadir() + "/managers"
            f = open(filename, "w")
            pickle.dump(invite_managers.keys(), f)
            f.close()
        except Exception, ex:
            warn("Couldn't write voicemail managers' state! %s" % str(ex))
        
    return man

def load_voicemail_managers():
    try:
        filename = get_datadir() + "/managers"
        f = open(filename, "r")
        keys = pickle.load(f)
        f.close()

        for aor in keys:
            man = VoicemailManager(aor, True)
            man.update()
            invite_managers[aor] = man
            
    except Exception, ex:
        warn("Couldn't read voicemail managers' state! %s" % str(ex))

class Voicemail:
    
    def __init__(self):
        self.id = uuid.uuid4().hex
        self.from_aor = None
        self.to_aor = None
        self.created = time.time()
        self.announced = 0
        self.storage = []

        self.local = None
        self.received = 0
        self.heard = False
        self.local_id = -1

    def dump(self):
        return pickle.dumps((self.id, self.from_aor, self.to_aor, self.created, self.storage))

    def load(self, data):
        (self.id, self.from_aor, self.to_aor, self.created, self.storage) = pickle.loads(data)
        self.received = time.time()        

    def remove(self):
        if self.local is not None:
            os.remove(self.local)


class CallHandler:
    """Class for monitoring and handling of calls"""

    def __init__(self, invite):

        self.id = invite.callid
        self.invite = invite
        self.active = False

        self.recording = False
        self.msg_player = None
        self.msg_recorder = None
        self.sock = None
        self.response = None
        self.invitation_data = None

        (self.target, self.initiator) = invite.get_real_to_from()

        self.local_aor = parse_aor(invite.sfrom)
        self.remote_aor = parse_aor(invite.sto)
        if self.invite.is_remote:
            (self.local_aor, self.remote_aor) = (self.remote_aor, self.local_aor)

        self.man = get_voicemail_manager(self.local_aor)

    def __del__(self):

        debug("******** deleting voice mail handler *******")
        if self.msg_player is not None:
            p2pship.media_pipeline_destroy(self.msg_player)
        if self.msg_recorder is not None:
            p2pship.media_pipeline_destroy(self.msg_recorder)
        if self.sock is not None:
            self.sock.close()

    def send_response(self, code, with_media = True):

        req = self.invite
        m = req.create_response(200)

        if with_media:
            # create local recording socket address
            (sock, saddr) = self.get_sock()
            
            formats = {}
            formats["8"] = { "rtpmap":"PCMA/8000" }
            req.call.my_medias = { "audio":[ saddr[0], saddr[1], formats ] }
            
            m.set_body(req.call.get_my_sdp(), "application/sdp")
            m.set_param('Contact', "<sip:whatever@127.0.0.1:5060;transport=udp>")

        m.send(as_remote = not self.invite.is_remote) #as_remote = True)
        self.response = m

    def terminate_call(self, code = 503):
        warn("Forced to terminate call!");
        if self.response is not None:
            m = self.response.create_as_remote_follow_up("BYE")
            m.send(as_remote = not self.invite.is_remote)
        else:
            self.send_response(code, False)
        try:
            del calls[self.id]
        except Exception, ex:
            pass

    def player_callback(self, handler, msgtype, data):
        pass
                
    def create_recorder(self, filename):

        (sock, saddr) = self.get_sock()
        caps="application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"
        line = 'udpsrc caps="%s" port=%s sockfd=%d closefd=false ! .recv_rtp_sink_0 gstrtpbin ! rtppcmadepay ! alawdec ! %s ! filesink location=%s' % (caps, saddr[1], sock.fileno(), config.get_codec(), filename)
        
        debug("Recorder: %s" % line)
        info("Recorder: %s" % line)
        ret = p2pship.media_pipeline_parse(line, self.player_callback)
        if ret > 0:
            return ret
        return None

    def create_streamer(self, filename, addr):

        (sock, saddr) = self.get_sock()

        line = "filesrc location=%s ! decodebin ! audioconvert  ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! alawenc ! rtppcmapay ! udpsink host=%s port=%s sockfd=%d closefd=false" % (filename, addr[0], addr[1], sock.fileno())
        
        debug("Player: %s" % line)
        info("Player: %s" % line)
        ret = p2pship.media_pipeline_parse(line, self.player_callback)
        if ret > 0:
            return ret
        return None

    def get_sock(self, addr = '127.0.0.1', port = 0):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((addr, port))
        return (self.sock, self.sock.getsockname())

    def handle_request(self, req):
        return None

    def handle_response(self, req, resp):
        return None
    
#
#
#
#

class UserCallHandler(CallHandler):
    """Handler for calls between users that may need voicemail injection"""

    def __init__(self, invite):
        CallHandler.__init__(self, invite)

        # For the calls the local user initiates, we need to fetch the greeting!
        info("Tracking call %s" % str(self.id))
        if not self.invite.is_remote:
            self.man.fetch_greeting(self.remote_aor)


    def player_callback(self, handler, msgtype, data):

        #.. when it has played, start recording:
        if msgtype == "eos" and self.msg_recorder is None:

            # ..this causes a deadlock. investigate! not any more..
            if self.msg_player is not None:
                p2pship.media_pipeline_destroy(self.msg_player)
                self.msg_player = None
            
            self.recofile = get_tmpfile()
            info("We will start recording into " + self.recofile)
            self.msg_recorder = self.create_recorder(self.recofile)
            if self.msg_recorder is not None:
                try:
                    p2pship.media_pipeline_start(self.msg_recorder)
                except Exception, ex:
                    self.terminate_call(500)
                    raise ex
            else:
                self.terminate_call(500)
                
    #
    # The SIP message handling
    #
    #

    def handle_request(self, req):
        """return None to indicate no change in message, response code
           otherwise"""

        # let all of our own messages pass unmodified!
        if req.is_internal:
            return None

        if req.msg_type == "BYE" or req.msg_type == "CANCEL":

            del calls[self.id]
            if self.active:

                if self.msg_player is not None:
                    debug("Stopping the message player!")
                    p2pship.media_pipeline_destroy(self.msg_player)
                    self.msg_player = None

                if self.msg_recorder is not None:

                    # disconnect the recordning session
                    # package the voicemail recorded (if any)
                    # publish the voicemail advertizement
                    debug("Stopping the message recorder!")
                    p2pship.media_pipeline_destroy(self.msg_recorder)
                    self.msg_recorder = None

                    # pass the recorder on to the invite manager
                    if self.invite.is_remote:
                        self.man.voicemail_received(self.remote_aor, self.recofile)
                    else:
                        self.man.voicemail_created(self.remote_aor, self.recofile)

                return 200 # ok, but do not forward!

        elif self.active:

            # we need to drop all sorts of messages from the one that
            # did not answer after we've been activated!
            (t, f) = req.get_real_to_from()
            if f != self.initiator:
                warn("Dropping request from the-one-that-did-not-initiate")
                return 400
                
            if req.msg_type == "ACK" and self.msg_player is None:

                info("Starting the message playback")
                remote_addr = None
                if self.invite.call.remote_medias is not None and self.invite.call.remote_medias.has_key('audio'):
                    remote_addr = (str(self.invite.call.remote_medias['audio'][0]), int(self.invite.call.remote_medias['audio'][1]))
                    debug("** audio streaming to " + str(remote_addr))

                filename = self.man.get_greetingfile(self.remote_aor, self.invite.is_remote)
                if filename is not None:
                    self.msg_player = self.create_streamer(filename, remote_addr)
                    
                if self.msg_player is not None:
                    try:
                        p2pship.media_pipeline_start(self.msg_player)
                    except Exception, ex:
                        self.terminate_call(500)
                        raise ex
                else:
                    self.terminate_call(500)

            # todo: an advanced version could handle UPDATEs etc
                    
            debug("Supressing request %s" % req.msg_type)
            return 0

        # let it through otherwise..
        return None


    def handle_response(self, req, resp):

        (t, f) = resp.get_real_to_from()
        if f == self.initiator:

            if self.active:
                # responses by the initiator? What? Perhaps to a BYE
                # or something.. Anywho, just drop it.
                warn("got a response to something we supposedly sent: %s" % str(req))
                return SipFilter.AC_VERDICT_IGNORE
            else:
                # don't touch these until we're active!
                return None

        else:

            # the non-initiating party!
            code_family = int(resp.resp_code / 100)
            if self.active:

                if resp.is_internal:
                    return None
                else:
                    # if we're active, we need to ignore everything so we don't confuse the UA
                    warn("Got response remotely while being active: %s" % str(resp.resp_code))
                    return SipFilter.AC_VERDICT_IGNORE

            elif (resp.resp_code in busy_codes and config.busy()) or (resp.resp_code in decline_codes and config.rejected()) or (resp.resp_code in notfound_codes and config.notfound()):

                # see if we should start at all..
                t = config.get("voicemail_type", "both")
                friendly = not config.is_true("voicemail_friendsonly") or self.man.is_friend(resp.remote_aor)
                if friendly and (t == "both" or (self.invite.is_remote and t == "remote") or (not self.invite.is_remote and t == "local")):
                    caller = "local"
                    if self.invite.is_remote:
                        caller = "remote"
                    info("Got %d response, initiating voice mailing for %s caller!" % (resp.resp_code, caller))
                    req = self.invite
                else:
                    # let it through, delete ourselves!
                    info("Got %d response, but policy prevents voicemail!" % resp.resp_code)
                    del calls[self.id]
                    return None
            
                self.send_response(200)
                self.active = True

                # Send an ACK to the call-rejecting- remote guy
                if not resp.is_internal:

                    ack = resp.create_follow_up("ACK")
                    ack.via = resp.via
                    ack.cseq = resp.cseq
                    # routing info should also be copied!!
                    
                    debug("Sending ACK to the one that did not anwser")
                    #ack.send(as_remote = self.invite.is_remote, filter = False)
                    ack.send(as_remote = not resp.is_remote, filter = False)
                
                return SipFilter.AC_VERDICT_IGNORE

            elif code_family != 1:
                del calls[self.id]
            
        return None

#
#
#

class GreetingRecorderCallHandler(CallHandler):
    """Handler for calls between users that may need voicemail injection"""

    def __init__(self, invite, greeting, man):
        CallHandler.__init__(self, invite)

        self.man = man
        self.recofile = get_tmpfile()
        self.greeting = greeting

        # For the calls the local user initiates, we need to fetch the greeting!
        info("Recording new greeting through call %s" % str(self.id))

    def start_recording(self):

        if self.msg_recorder is not None:
            return
        
        info("We will start recording into " + self.recofile)
        self.msg_recorder = self.create_recorder(self.recofile)
        if self.msg_recorder is not None:
            try:
                p2pship.media_pipeline_start(self.msg_recorder)
            except Exception, ex:
                self.terminate_call(500)
                raise ex
        else:
            self.terminate_call(500)


    def player_callback(self, handler, msgtype, data):

        #.. when it has played, start recording:
        if msgtype == "eos":
            if self.msg_player is not None:
                p2pship.media_pipeline_destroy(self.msg_player)
                self.msg_player = None

            self.start_recording()

    def handle_response(self, req, resp):
        pass

    def handle_request(self, req):

        if req.msg_type == "INVITE":

            self.send_response(200)

        elif req.msg_type == "ACK":

            is_playing = False
            if self.greeting is not None and self.msg_player is None:
                info("Starting the message playback")
                remote_addr = None
                if self.invite.call.remote_medias is not None and self.invite.call.remote_medias.has_key('audio'):
                    remote_addr = (str(self.invite.call.remote_medias['audio'][0]), int(self.invite.call.remote_medias['audio'][1]))
                    debug("** audio streaming to " + str(remote_addr))
                
                self.msg_player = self.create_streamer(self.filename, remote_addr)
                if self.msg_player is not None:
                    try:
                        p2pship.media_pipeline_start(self.msg_player)
                        is_playing = True
                    except Exception, ex:
                        pass
                    
            if not is_playing:
                self.start_recording()
        
        elif req.msg_type == "BYE" or req.msg_type == "CANCEL":
            del calls[self.id]
            req.respond(200, as_remote = True)

            if self.msg_recorder is not None:

                debug("Stopping the message recorder!")
                p2pship.media_pipeline_destroy(self.msg_recorder)
                self.msg_recorder = None

                self.man.greeting_recorded(self.recofile)

#
#
#

class FilePlaybackCallHandler(CallHandler):
    
    def __init__(self, invite, filename):
        CallHandler.__init__(self, invite)
        info("Handling call %s to the voicemail box, playing file %s" % (str(self.id), str(filename)))
        self.filename = filename

    def player_callback(self, handler, msgtype, data):

        #.. when it has played, start recording:
        if msgtype == "eos":
            time.sleep(1)
            self.terminate_call()

    def file_is_playing(self):
        # the call has been answered, and the file is playing ..
        pass
        
    def handle_request(self, req):

        if req.msg_type == "INVITE":

            self.send_response(200)

        elif req.msg_type == "ACK" and self.msg_player is None:

            info("Starting the message playback")
            remote_addr = None
            if self.invite.call.remote_medias is not None and self.invite.call.remote_medias.has_key('audio'):
                remote_addr = (str(self.invite.call.remote_medias['audio'][0]), int(self.invite.call.remote_medias['audio'][1]))
                debug("** audio streaming to " + str(remote_addr))
                
            self.msg_player = self.create_streamer(self.filename, remote_addr)
            if self.msg_player is not None:
                try:
                    p2pship.media_pipeline_start(self.msg_player)
                    self.file_is_playing()
                except Exception, ex:
                    self.terminate_call(500)
                    raise ex
            else:
                self.terminate_call(500)
        
        elif req.msg_type == "BYE" or req.msg_type == "CANCEL":
            del calls[self.id]
            req.respond(200, as_remote = True)

    def handle_response(self, req, resp):
        pass

#
#
#


class VoicemailPlaybackCallHandler(FilePlaybackCallHandler):
    
    def __init__(self, invite, v, man):
        FilePlaybackCallHandler.__init__(self, invite, v.local)
        self.v = v
        self.man = man

    def file_is_playing(self):
        self.v.heard = True
        self.man.update_presence()


class VoicemailRequestHandler(SipHandler):
    """Request processor, post-processor of local messages. This
    captures only the initial INVITEs coming from the local host as"""


    # we capture responses only in the filter, as we're only
    # interested in non-OK ones which don't contain media parameters
    # or anything else that the proxy might process!

    def __init__(self):
        self.filter_duplicates = False

    def response_got(self, req, resp):

        if not resp.is_remote:
            man = get_voicemail_manager(resp.local_aor)
            return man.handle_msg(resp)

    def request_got(self, req):

        if not req.is_remote:
            man = get_voicemail_manager(req.local_aor)
            ret = man.handle_msg(req)
            if ret is not None:
                return ret

        h = calls.get(req.callid)
        if config.enabled() and h is None and req.msg_type == "INVITE":
            h = UserCallHandler(req)
            calls[req.callid] = h

        if h is not None:
            return h.handle_request(req)


# filter: used to capture remotely got messages before they enter the
# system and spoils things (such as tear down the mediaproxies).
#
# return: an int according to the access control enum. None for 'do
# not affect the delivery'
class VoicemailFilter(SipFilter):

    def __init__(self):
        SipFilter.__init__(self)
        self.filter_duplicates = False

    def response_got(self, req, resp):

        h = calls.get(resp.callid)
        if h is not None:
            return h.handle_response(req, resp)

    # now that request handlers also get the remotely generated
    # messages, we don't need this!
    def request_got(self, req):
        pass
    

class VoicemailManager(SipHandler):
    """This handles the voicemail-related things of a local
    AOR. This includes publishing the voicemail invites (hence the
    name), storing the voicemail got as well as publishing the remote
    ones! And Maintaining a cache of the remote invites for this person ..

    All-in-all, this is a sort of a per-user voicemail control center.

    And they should be stateful!"""

    def __init__(self, aor, load = False):

        self.filter_duplicates = False
        self.aor = aor
        self.presence_subscriptions = {}
        if not load:
            self.timeout = 0
            self.start = time.time()
            self.greetings = {}
            self.own = []
            self.announced = {}
        else:
            self.load()

        self.my_aor = config.get("voicemail_prefix", "voicemail") + "@" + self.aor[self.aor.find("@")+1:]
        self.context = SipContext(self.my_aor, self, aor)
        self.ident = Ident(self.aor)
        self.subscribes = {}
        self.resubscribe()
        self.reannounce()

    def is_friend(self, aor):
        buddy = self.ident.buddies.get(aor, None)
        if buddy is not None:
            return buddy.relationship == Buddy.RELATIONSHIP_FRIEND
        return False
                               
    def resubscribe(self):

        self.ident = Ident(self.aor)
        subkey = "voicemail:announce:%s" % self.aor
        if not config.is_true("voicemail_friendsonly"):
            if self.subscribes.get("all") is not None:
                #p2pship.ol_ident_unsubscribe(self.aor, None, subkey, self.voicemail_found)

                info("Subscribing to everybody's voicemail announcements")
                p2pship.ol_ident_subscribe(self.aor, None, subkey, self.voicemail_found)
                self.subscribes["all"] = 0
        else:
            for b in self.ident.buddies.values():

                if b.relationship == Buddy.RELATIONSHIP_FRIEND:
                    info("Subscribing to %s's voicemail announcements" % b.aor)
                    if self.subscribes.get(b.aor) is None:
                        ret = p2pship.ol_ident_subscribe(self.aor, b.aor, subkey, self.voicemail_found)
                        self.subscribes[b.aor] = ret
                else:
                    ret = self.subscribes.get(b.aor)
                    if ret is not None:
                        p2pship.ol_cancel(ret)
                        del self.subscribes[b.aor]

    def save(self):
        try:
            filename = get_datadir() + "/manager_" + self.aor
            f = open(filename, "w")

            data = (self.aor, self.timeout, self.start, self.greetings, self.own, self.announced, self.presence_subscriptions)
            pickle.dump(data, f)
            f.close()
        except Exception, ex:
            warn("Couldn't write voicemail manager state! %s" % str(ex))

    def load(self):
        try:
            filename = get_datadir() + "/manager_" + self.aor
            f = open(filename, "r")
            (self.aor, self.timeout, self.start, self.greetings, self.own, self.announced, self.presence_subscriptions) = pickle.load(f)
            f.close()
        except Exception, ex:
            warn("Couldn't read voicemail manager state! %s" % str(ex))
        
    def update(self):
        self.register(self.start + self.timeout - time.time())
        self.resubscribe()

    def register(self, timeout):
        """handles a registration. timeout is in seconds. -1 for
        forever, 0 on unregister"""

        info("Publishing voicemail invites of %s for %d seconds.." % (self.aor, timeout))
        self.timeout = timeout
        self.start = time.time()
        self.save()

        if not config.enabled() or timeout < 1:
            p2pship.ol_ident_rm(self.aor, None, "voicemail:invite:%s" % self.aor)
            return
        
        data = {}
        data['subject'] = self.aor

        #
        data['accept'] = []

        """
        sub = {}
        sub['format'] = "audio/mp3"
        sub['size'] = 1000000
        data['accept'].append(sub)

        sub = {}
        sub['format'] = "audio/wav"
        sub['size'] = 1000000
        data['accept'].append(sub)

        sub = {}
        sub['format'] = "text/plain"
        data['accept'].append(sub)
        """
        
        #
        data['greeting'] = []
        
        gre = config.get("voicemail_greeting", "")
        if len(gre) > 0:
            sub = {}
            sub['type'] = "text/plain"
            sub['value'] = gre
            data['greeting'].append(sub)
        
        gre = config.get("voicemail_greeting_file", "")
        if len(gre) > 0:
            res = p2pship.resourcefetch_store(gre)
            sub = {}
            sub['type'] = "audio/mp3"
            sub['src'] = "p2p://%s/%s" % (self.aor, res)
            data['greeting'].append(sub)

        """
        gre = config.get("voicemail_greeting_url", "")
        if len(gre) > 0:
            sub = {}
            sub['type'] = "audio/mp3"
            sub['src'] = gre
            data['greeting'].append(sub)
        """
        
        #
        data['storage'] = []

        """
        sub = {}
        sub['type'] = "key"
        sub['value'] = "voicemail:randomkeyvalue"
        data['storage'].append(sub)
        
        sub = {}
        sub['type'] = "peer"
        sub['value'] = "myfriend@p2psip.hiit.fi"
        data['storage'].append(sub)

        sub = {}
        sub['type'] = "webdav"
        sub['value'] = "http://ip92.infrahip.net/webdav"
        data['storage'].append(sub)
        """
        
        datastr = pickle.dumps(data)
        
        # put invites for all!
        p2pship.ol_ident_put(self.aor, None, "voicemail:invite:%s" % self.aor, datastr, timeout)
        
    #
    # The greetings: local and remote
    #

    def greeting_recorded(self, recofile):
        info("We have a new greeting at %s" % recofile)
        config.set("voicemail_greeting_file", recofile)
        self.update()

    def get_greetingfile(self, remote_aor, for_remote = False):
        """Returns the greeting audiofile to use for a remote peer. O
        rfor the local.."""

        ret = None
        if for_remote:
            # a remote caller, play the local user's greeting!
            ret = config.get_path("voicemail_greeting_file", "")
        else:
            l = self.greetings.get(remote_aor, [])
            for g in l:
                if os.path.isfile(g):
                    ret = g
                    break
        
        if ret is not None and not os.path.isfile(ret):
            warn("The greeting file %s does not exist!" % ret)
            ret = None

        if ret is None:
            gre = config.get_path("voicemail_default_greeting_file", "")
            if os.path.isfile(gre):
                ret = gre
            else:
                warn("The default greeting file %s does not exist!" % gre)

        if ret is None:
            error("No valid greeting found by %s for %s (remote: %s)" % (self.aor, remote_aor, str(for_remote)))
        else:
            info("Using %s as the greeting.." % ret)
        return ret

        
    def fetch_greeting(self, remote_aor):
        """Starts the retrieval of a greeting for a remote
        peer. Unless a valid cached copy exists!"""
        
        info("initiating fetch by %s for %s's greeting" % (self.aor, remote_aor));
        p2pship.ol_ident_get(self.aor, remote_aor, "voicemail:invite:%s" % remote_aor, self.greeting_got, remote_aor)

    def greeting_got(self, key, data, from_aor, remote_aor):

        try:
            self.invitation_data = pickle.loads(data)
            info("voicemail invitation got from %s for %s!" % (from_aor, remote_aor))
        except Exception, ex:
            warn("Invalid voicemail invitation got for %s!" % remote_aor)
            return

        greetings = self.greetings.get(remote_aor)
        if greetings is None:
            greetings = []
            self.greetings[remote_aor] = greetings
            
        for g in self.invitation_data['greeting']:

            info("got invitation type %s, value %s/%s" % (str(g.get('type')), str(g.get('value')), str(g.get('src'))))

            t = g.get('type')
            if t == "text/plain":
                # record one ..
                pass
            elif t.startswith("audio/"):
                val = g.get('value')
                src = g.get('src')
                if val is not None:
                    (handle, fn) = get_tmpfile()
                    handle.write(val)
                    handle.close()
                    greetings.insert(0, fn)
                elif src is not None:
                    if not self.fetch_resource(src, self.greeting_resource_got, remote_aor):
                        warn("Couldn't fetch url: %s" % src)
        self.save()

    def greeting_resource_got(self, src, data, remote_aor):

        greetings = self.greetings.get(remote_aor)
        if data is not None and len(data) > 0:
            info("We got data from %s, len %d" % (src, len(data)))
            fn = get_tmpfile()
            f = open(fn, "w")
            f.write(data)
            f.close()
            greetings.insert(0, fn)
        self.save()

    def resource_got(self, remote, id, data, pkg):
        (url, callback, cbdata) = pkg
        callback(url, data, cbdata)
            
    def fetch_resource(self, src, callback, data):
        """Fetch resources based on an URL. P2P, HTTP etc.. """
        
        if src.startswith("p2p://"):
            addr = src[6:].split("/", 1)
            if len(addr) == 2:
                info("fetching p2p resource %s from %s.." % (addr[1], addr[0]))
                p2pship.resourcefetch_get(addr[0], addr[1], self.aor, self.resource_got, (src, callback, data))
                return True
            else:
                warn("invalid url: %s" % src)
        else:
            warn("unsupported url: %s" % src)


    #
    # Remote voicemails
    #

    def get_local_id(self):
        """Returns an unused id for a voicemail for the local user"""
        ret = 1
        while True:
            found = False
            for v in self.own:
                if v.local_id == ret:
                    found = True
                    break
            if not found:
                return ret
            else:
                ret += 1

    def add_voicemail(self, v):
        v.local_id = self.get_local_id()
        self.own.append(v)
        self.update_presence()

        if v.local is not None:
            self.send_im("New voicemail [%d] from %s!" % (v.local_id, v.from_aor))


    def voicemail_resource_got(self, src, data, v):

        if data is None or len(data) == 0:
            self.send_im("Couldn't get voicemail from %s!" % v.from_aor)
        else:
            filename = get_tmpfile()
            f = open(filename, "w")
            f.write(data)
            f.close()

            v.local = filename
            self.send_im("New voicemail [%d] from %s!" % (v.local_id, v.from_aor))

        self.save()

    def voicemail_found(self, key, data, from_aor):

        try:
            v = Voicemail()
            v.load(data)

            info("voicemail found for us from %s, available remotely!" % from_aor)
        except Exception, ex:
            debug("invalid voicemail data got, ignoring")
            return

        if v.from_aor != from_aor:
            warn("Voicemail was not retrieved from source (from: %s, but got from %s)" % (v.from_aor, from_aor))
        if v.to_aor != self.aor:
            warn("Voicemail was not intended for us (for %s)" % v.to_aor)
        
        for ov in self.own:
            if ov.id == v.id:
                info("Skipping voicemail %s as we already have it!" % v.id)
                v = None
                break

        if v is None:
            return

        # .. this needs to be updated ..
        fetched = False
        for sub in v.storage:            
            if self.fetch_resource(sub['src'], self.voicemail_resource_got, v):
                fetched = True
            else:
                warn("Couldn't fetch url: %s" % sub['src'])

        if fetched:
            self.add_voicemail(v)


    #
    # Local voicemails
    # 

    def voicemail_created(self, remote_aor, filename):
        """When we have recorded a voicemail that should now be sent to a remote peer"""
        
        info("recording (for %s) ready at %s" % (remote_aor, filename))

        v = Voicemail()
        v.from_aor = self.aor
        v.to_aor = remote_aor

        res = p2pship.resourcefetch_store(filename)
        sub = {}
        sub['type'] = "audio/mp3"
        sub['src'] = "p2p://%s/%s" % (self.aor, res)
        v.storage.append(sub)

        # the ones we have announced!
        self.announced[v.id] = v
        datastr = v.dump()
        p2pship.ol_ident_put(self.aor, remote_aor, "voicemail:announce:%s" % remote_aor, datastr, 3600)
        v.announced = time.time()
        self.save()

    def reannounce(self):
        for v in self.announced.values():
            if (time.time() - v.announced) > 60:
                datastr = v.dump()
                remote_aor = v.to_aor
                p2pship.ol_ident_put(self.aor, remote_aor, "voicemail:announce:%s" % remote_aor, datastr, 3600)

    def voicemail_received(self, remote_aor, filename):
        """When a remote party has left a voicemail on our machine"""
        
        info("recording for me (%s) from %s ready at %s" % (self.aor, remote_aor, filename))

        v = Voicemail()
        v.from_aor = remote_aor
        v.to_aor = self.aor
        v.local = filename
        
        self.add_voicemail(v)


    #
    # Local user message processing
    #

    def send_im(self, note, from_aor = None):
        m = self.context.create_message(self.aor, note)
        if from_aor is not None:
            m.set_sfrom_aor(from_aor)
        m.send(as_remote = True)

    def handle_im(self, msg, remote_aor):

        ret = "Sorry, couldn't understand! /help for help!"
        cmd, s, param = msg.partition(" ")
        cmd = cmd.lower()
        if cmd == "/list":
            ret = ""
            for v in self.own:
                if not v.heard:
                    ret += "[%d] From %s, recorded %s" % (v.local_id, v.from_aor, str(v.created))
                    if v.local is None:
                        ret += " (fetching data..)\n"
                    else:
                        ret += "\n"
            if len(ret) == 0:
                ret = "You have no pending voice mails"
        elif cmd == "/all":
            ret = ""
            for v in self.own:
                ret += "[%d] From %s, recorded %s" % (v.local_id, v.from_aor, str(v.created))
                if v.heard:
                    ret += " (old)"
                ret += "\n"
            if len(ret) == 0:
                ret = "You have no pending voice mails"
        elif cmd == "/remove":
            i = -1
            try:
                i = int(param)
            except Exception, ex:
                i = -1

            rv = None
            if i != -1:
                for v in self.own:
                    if v.local_id == i:
                        rv = v
                        break
            if rv is not None:
                self.own.remove(rv)
                rv.remove()
                ret = "Voicemail removed"
                self.update_presence()
            else:
                ret = "No such voicemail (%s)" % param

        elif cmd == "/help":
            ret = "/list, /all, /remove #"
        return ret

    def request_got(self, msg):

        h = calls.get(msg.callid)
        if h is not None:
            return h.handle_request(msg)

        if msg.msg_type == "MESSAGE":
            msg.respond(200, as_remote = True)
            self.send_im(self.handle_im(msg.body, msg.remote_aor), msg.remote_aor)

        elif msg.msg_type == "INVITE":

            to = parse_aor(msg.sto)
            rv = None
            suffix = None
            
            #m = re.match(config.get("voicemail_prefix", "voicemail") + "[+]?([0-9]+)@.*", to)
            m = re.match(config.get("voicemail_prefix", "voicemail") + "[+]?(.+)@.*", to)
            if m:
                suffix = m.group(1)
                if re.match("^[0-9]+$", suffix):
                    mid = int(m.group(1))
                    for v in self.own:
                        if v.local_id == mid:
                            rv = v
                            break
                elif suffix == "greeting":
                    h = FilePlaybackCallHandler(msg, self.get_greetingfile("", True))
                    calls[msg.callid] = h
                    return h.handle_request(msg)
                elif suffix == "record":
                    h = GreetingRecorderCallHandler(msg, None, self)
                    calls[msg.callid] = h
                    return h.handle_request(msg)
                else:
                    msg.respond(404, as_remote = True)
                    return
            else:
                for v in self.own:
                    if not v.heard and v.local is not None:
                        rv = v
                        break

            if rv is not None:
                h = VoicemailPlaybackCallHandler(msg, rv, self)
                calls[msg.callid] = h
                self.update_presence()
                return h.handle_request(msg)
            else:
                msg.respond(503, as_remote = True)

        elif msg.msg_type == "ACK":
            pass
        elif msg.msg_type == "SUBSCRIBE":

            resp = msg.respond(202, as_remote = True)
            expire = int(msg.param('Expires', 0))
            if expire > 0:
                self.presence_subscriptions[msg.remote_aor] = resp
                self.notify_presence(msg.remote_aor, resp)
                self.save()
        else:
            msg.respond(405, as_remote = True)

    def notify_presence(self, remote_aor, resp):

        # respond with a simple 'online' notify
        notify = resp.create_as_remote_follow_up("NOTIFY", self.get_pdif_status(remote_aor), "application/pidf+xml")
        notify.set_param("Event", "presence")
        notify.set_param("Subscription-State", "active;expires=%d" % 3600)
        notify.set_param("Contact", get_local_sip_contact(self.aor))
        notify.target = self.aor
        notify.send(filter = False)

    def update_presence(self):
        for remote_aor in self.presence_subscriptions.keys():
            resp = self.presence_subscriptions[remote_aor]
            self.notify_presence(remote_aor, resp)
        self.save()

    def get_pdif_status(self, remote_aor):
        hasnew = False
        for v in self.own:
            if not v.heard and v.local is not None:
                hasnew = True
                break
            
        if hasnew:
            return create_pdif(remote_aor, "abcde", "open")
        else:
            return create_pdif(remote_aor, "abcde", "closed")

    def response_got(self, req, resp):

        h = calls.get(resp.callid)
        if h is not None:
            return h.handle_response(req, resp)

    def handle_msg(self, req):
        """Handles a request from the local aor"""

        local_aor = parse_aor(req.sfrom)
        remote_aor = parse_aor(req.sto)

        if req.remote_aor.startswith(config.get("voicemail_prefix", "voicemail")):
            self.context.msg_got(req)
            return 0
        else:
            return None
        

#
# config handler for the related configuration values. And events!
#
class VoicemailConfigHandler(ConfigHandler):

    def __init__(self):
        self.create("voicemail_enabled", "Enable voicemail", "bool", "yes")
        self.create("voicemail_notfound", "Enable offline (not found) voicemail", "bool", "yes")
        self.create("voicemail_busy", "Enable incoming (busy) voicemail", "bool", "yes")
        self.create("voicemail_rejected", "Enable offline voicemail when call is rejected", "bool", "yes")
        self.create("voicemail_type", "Type of voicemail: for local caller only, remote caller only or both.", "enum:local,remote,both", "both")

        self.create("voicemail_greeting", "Voicemail greeting string", "string", "Hello and please leave a message.")
        self.create("voicemail_greeting_file", "Voicemail greeting audio", "file", "")
        #self.create("voicemail_greeting_url", "Voicemail greeting audio url", "url", "")

        self.create("voicemail_default_greeting_file", "Default greeting file for both local and remote.", "file", "greeting.mp3")

        self.create("voicemail_prefix", "Voicemail identity prefix", "string", "voicemail")
        self.create("voicemail_friendsonly", "Offer voicemail for friends only", "bool", "no")

        # the encoding codecs
        self.codecs = {}
        if p2pship.media_check_element("lame"):
            self.codecs['MP3'] = "lame"
        if p2pship.media_check_element("wavenc"):
            self.codecs['WAV'] = "wavenc"

        cstr = "enum:"
        for c in self.codecs.keys():
            info("found codec %s.." % self.codecs[c])
            cstr += "%s," % c
        cstr = cstr[:-1]
        self.create("voicemail_codec", "Codec to use", cstr, self.codecs.keys()[0])
        info("Using codec %s" % self.get_codec())

        p2pship.event_receive("ident_*", self.events)

    def get_codec(self):
        c = self.get("voicemail_codec", self.codecs.keys()[0])
        return self.codecs[c]

    def enabled(self):
        return self.is_true("voicemail_enabled")

    def notfound(self):
        return self.is_true("voicemail_notfound")
    
    def busy(self):
        return self.is_true("voicemail_busy")

    def rejected(self):
        return self.is_true("voicemail_rejected")

    def events(self, event, eventdata, mydata = None):
        """Handle p2pship identity registration events. Used to plant
        the voicemail invitations."""

        if event == "ident_register" or event == "ident_unregister":
            ident = eventdata[0]
            service = eventdata[1]
            timeout = eventdata[2]

            if service == 1:
                man = get_voicemail_manager(ident['aor'])
                man.register(timeout)            
        elif event.startswith("ident_buddy"):
            ident = eventdata[0]
            info("Got a change in %s's friendships, resubscribing.." % ident['aor'])
            man = get_voicemail_manager(ident['aor'])
            man.resubscribe()
        else:
            warn("Got unknown event: %s" % event)

p2pship.set_name("Voicemail")
config = VoicemailConfigHandler()
filter = VoicemailFilter()
load_voicemail_managers()

# note: instead of using the 'priority' switch of sip_request_handler, we could use the filter for it also!
if install_sip_request_handler(".*", ".*", VoicemailRequestHandler, True):
    info("\n***********\nVoicemail handler is installed!\n***********")
else:
    warn("Error installing multiparty handler!")

