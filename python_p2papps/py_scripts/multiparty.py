import socket
import threading
import select
import time


def empty_socket(sock):
    return
    sock.setblocking(0)
    try:
        while True:
            sock.recv(4096)
    except Exception, ex:
        pass
    
def create_sock(addr = '127.0.0.1', port = 0):
    """Creates a bound IPv4 UDP socket"""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((addr, port))
    return (sock, sock.getsockname())

def create_ext_sock(port = 0):
    """Creates a bound, externally reachable socket"""
    ext_addr = p2pship.sip_get_remote_contact()
    (s, a) = create_sock("0.0.0.0", port)
    return (s, (ext_addr, a[1]))


#
# The different types of video mixers

class VideoConferenceMixer:

    def __init__(self, mixer):
        self.mixer = mixer

    def init(self, param = None):
        return "Mixer %s initialized" % self.__name__

    def mix(self, channels):
        """Should return the gst line for mixing the given ones"""
        return None
    
    def transform_video_input(self, w, h, channel):

        params = [ "video/x-raw-yuv" ]
        if w > 0:
            params.append("width=%d" % w)
        if h > 0:
            params.append("height=%d" % h)
        params.append("framerate=15/1")

        
        line = "%s ! ffmpegcolorspace ! videoscale ! videorate ! %s" % (channel.gst_video_input(), ','.join(params))
        if self.mixer.show_labels:
            line += ' ! textoverlay font-desc="Sans 24" text="%s" valignment=bottom halignment=center shaded-background=true ! ffmpegcolorspace' % channel.get_name()
        return line
            
class SimpleVideoConferenceMixer(VideoConferenceMixer):
    """A simple squares-based video mixer"""

    def init(self, param = None):

        self.bgline = 'videotestsrc pattern=2'
        if param is not None and len(param) > 0:
            if not os.path.isfile(param):
                raise Exception("Invalid background file '%s'" % param)
            else:
                self.bgline = 'multifilesrc location=%s ! decodebin  ! videoscale ! videorate' % param

        # space between frames
        self.xspacer, self.yspacer = 10, 10

        # margin between the frames and the canvas edges
        self.xmargin, self.ymargin = 10, 10

        # default height / width of the canvas
        self.width, self.height = 704, 576


    def find_arrangement(self, w, h, nr, byrows = False):
        """Finds the optimal arrangement for the frames"""

        lastw, lasth, lastx, lastr = 0, 0, 0, 0
        xw, rows = 1, 1
        while True:

            if byrows:
                xw = int(nr / rows)
                if (nr % rows) > 0:
                    xw += 1
            else:
                rows = int(nr / xw)
                if (nr % xw) > 0:
                    rows += 1

            maxh = int((self.height-(self.yspacer*2)-(self.ymargin*(rows-1))) / rows)
            maxw = int((self.width-(self.xspacer*2)-(self.xmargin*(xw-1))) / xw)

            # keep aspect ratio, select the smaller of the two
            if int((w*maxh)/h) > maxw:
                maxh = int((h*maxw)/w)
            else:
                maxw = int((w*maxh)/h)
            
            if lastw > maxw:
                return (lastx, lastr, lastw, lasth)
            else:
                lastw, lasth, lastx, lastr = maxw, maxh, xw, rows

            rows += 1
            xw += 1


    def mix(self, channels):
        
        has_out = False
        line = ''
        mixerline = 'videomixer name=in '

        # do the in channels:
        inc = []
        for channel in channels.values():
            if channel.is_active() and channel.has_video_input():
                inc.append(channel)

        if len(inc) == 0:
            return None

        line += '%s ! video/x-raw-yuv,framerate=15/1,width=%d,height=%d ! ffmpegcolorspace ! queue ! in.sink_0 ' % (self.bgline, self.width, self.height)

        # calc & center
        (xw, rows, w, h) = self.find_arrangement(self.width, self.height, len(inc), False)
        (xm, ym) = (int((self.width - ((xw*(w+self.xspacer))-self.xspacer)) / 2), (int((self.height - ((rows*(h+self.yspacer))-self.yspacer)) / 2)))

        count = 0
        for channel in inc:

            x = ((count % xw) * (w + self.xspacer)) + xm
            y = (int(count / xw) * (h + self.xspacer)) + ym
            
            line += '%s ! in.sink_%d ' % (self.transform_video_input(w, h, channel), channel.get_id())
            mixerline += "sink_%d::xpos=%d sink_%d::ypos=%d sink_%d::zorder=%d " % (channel.get_id(), x,
                                                                                    channel.get_id(), y,
                                                                                    channel.get_id(), 3)
            count += 1
            
        # do the outputs, everyone-sees-everyone
        for channel in channels.values():
            if channel.is_active() and channel.has_video_output():
                line += 'out. ! queue ! %s ' % channel.gst_video_output()
                has_out = True

        if not has_out:
            return None
                
        line += '%s ! tee name=out' % mixerline
        return line


class SingleSourceMixer(VideoConferenceMixer):

    def init(self, param = None):

        channel = self.mixer.get_channel(param)
        if channel is None:
            raise Exception("Invlid channel id '%s'" % param)
        if not channel.has_video_input():
            raise Exception("Channel %s has no video stream" % channel.get_name())
        
        self.chid = int(param)
        
        return "Streaming channel '%s' exclusively" % channel.get_name()
        

    def mix(self, channels):

        has_in = False
        has_out = False
        line = ''
        for channel in channels.values():

            if not channel.is_active():
                continue

            if channel.has_video_output():
                line += 'out. ! queue ! %s ' % channel.gst_video_output()
                has_out = True
                
            if channel.get_id() == self.chid and channel.has_video_input():
                line += '%s ! out. ' % self.transform_video_input(704, 576, channel)
                has_in = True

        line += 'tee name=out'
        if not has_in or not has_out:
            line = None

        return line


video_mixing_modes = { "default" : SimpleVideoConferenceMixer, "single" : SingleSourceMixer }


#
#

class Mixer:
    """Handles the audiomixing"""

    def __init__(self):
        self.pl = None
        self.last_pl = ""
        self.channels = {}

        self.video_pl = None
        self.last_video_pl = ""
        self.video_mixer = None
        self.init_video_mixer()
        self.show_labels = True

    def init_video_mixer(self, param = None):

        cmd = None
        if param is not None:
            cmd, s, param = param.partition(" ")

        new_mixer = None
        if cmd is None:
            new_mixer = video_mixing_modes["default"]
        else:
            new_mixer = video_mixing_modes.get(cmd)

        if new_mixer is not None:
            new_mixer = new_mixer(self)
            ret = new_mixer.init(param)
            self.video_mixer = new_mixer
            self.reinit_video()
            return ret
        else:
            raise Exception("Invalid video mixer '%s'" % str(cmd))
        

    def __del__(self):
        self.stop()
        
    def stop(self, audio=False, video=False):

        if not audio and not video:
            audio = True
            video = True
            
        if audio and self.pl is not None:
            try:
                p2pship.media_pipeline_destroy(self.pl)
            except Exception, ex:
                pass
            self.pl = None

        if video and self.video_pl is not None:
            try:
                p2pship.media_pipeline_destroy(self.video_pl)
            except Exception, ex:
                pass
            self.video_pl = None

    def get_cid(self):

        ids = self.channels.keys()
        cid = 1
        while True:
            if not cid in ids:
                return cid
            cid += 1

    def add(self, channel):

        info("Adding channel %s.." % channel.get_name())
        channel.id = self.get_cid()
        channel.mixer = self
        self.channels[channel.get_id()] = channel
        self.reinit_player()

    def player_callback(self, handler, msgtype, data):

        if handler == self.pl:
            if msgtype == "error":
                warn("Error on audio player %s: %s" % (str(handler), str(data)))
            if msgtype == "eos":
                warn("EOS of content on audio player %s" % str(handler))
                self.reinit_player()

        if handler == self.video_pl:
            if msgtype == "error":
                warn("Error on video player %s: %s" % (str(handler), str(data)))
            if msgtype == "eos":
                warn("EOS on video player %s" % str(handler))
                self.reinit_player()
                

    def reinit_player(self):

        self.reinit_audio()
        self.reinit_video()
        
        
    def reinit_video(self):
        
        # here we could use different layout managers etc..
        line = self.video_mixer.mix(self.channels)

        if self.video_pl is not None and self.last_video_pl == line:
            debug("video pipeline remains unchanged..")
            return True

        self.stop(video = True)
        if line is not None:
            info("Starting pipeline..")
            info('gst pipeline: %s' % line)
            print 'gst pipeline: %s' % line
            for c in self.channels.values():
                c.video_reset()
            self.video_pl = p2pship.media_pipeline_parse(line, self.player_callback)
            if self.video_pl > 0:
                p2pship.media_pipeline_start(self.video_pl)
                self.last_video_pl = line
                return True
            else:
                error("could not create player!")
        else:
            info("not enough participants to create a video player!")

        self.video_pl = None
        return False


    def reinit_audio(self):

        connected_outputs = {}
        start_pipeline = False
        line = ''
        for channel in self.channels.values():

            if not channel.is_active():
                continue

            if channel.has_input():

                # connect this channel's input to the output of others
                connected = False
                for ch2 in self.channels.values():
                    if channel == ch2:
                        continue

                    if ch2.has_output() and ch2.is_active():
                        line += 'src%s. ! queue ! mixer%s. ' % (channel.get_id(), ch2.get_id())
                        connected = True

                        # add that output as well, unless we have it already!
                        if not connected_outputs.has_key(ch2.get_id()):

                            # liveadder mixing 8000rates ok, but mixing the 44.1khz with 8khz makes the 8 sound weird.
                            # adder does a good job mixing all together, but doesn't work with discontinuous streams!
                            line += "liveadder latency=0 name=mixer%s ! %s " % (ch2.get_id(), ch2.gst_output())
                            #line += "adder name=mixer%s ! %s " % (ch2.get_id(), ch2.gst_output())
                            connected_outputs[ch2.get_id()] = True


                # make everything go to the fakesink as well!
                if not connected:
                    line += 'src%s. ! queue ! fakesink ' % (channel.get_id(), )
                    connected = True

                # add the input only if it actually was connected to something!
                if connected:
                    start_pipeline = True
                    if channel.volume < 100:
                        line += "%s ! volume volume=%f ! tee name=src%s " % (channel.gst_input(), channel.volume / 100.0, channel.get_id())
                    else:
                        line += "%s ! tee name=src%s " % (channel.gst_input(), channel.get_id())

        if self.pl is not None and self.last_pl == line:
            debug("pipeline remains unchanged..")
            return True

        self.stop(audio = True)
        if start_pipeline:
            info("Starting pipeline..")
            info('gst pipeline: %s' % line)
            for c in self.channels.values():
                c.audio_reset()
            self.pl = p2pship.media_pipeline_parse(line, self.player_callback)
            if self.pl > 0:
                p2pship.media_pipeline_start(self.pl)
                self.last_pl = line
                return True
            else:
                error("could not create player!")
        else:
            info("not enough participants to create an audio player!")

        self.pl = None
        return False

    def remove(self, channel):

        info("removing mixers for %s" % channel.get_name())
        for i in self.channels.items():
            if i[1] == channel:
                del self.channels[i[0]]
                break
        self.reinit_player()

    def get_channel(self, id):

        ii = -1
        try:
            ii = int(id)
        except Exception, ex:
            return None
        return self.channels.get(ii)


#
#

class MultipartyHandler(SipHandler):
    """Handler for one multiparty session / room"""

    def __init__(self):
        self.verbose = False
        self.members = []
        self.title = "anon session"
        self.mixer = Mixer()

    def send_owner_msg(self, msg):
        """Sends a message to the local, identity owning, user only!"""

        self.send_msg(msg, user = sip_real_aor(self.context.aor))

    def is_owner(self, msg):
        """Checks whether the message received is from the local user"""

        print "is remote: %s, from: %s, local_aor: %s, remote aor: %s" % (str(msg.is_remote), msg.sfrom, msg.local_aor, msg.remote_aor)
        return msg.remote_aor == sip_real_aor(self.context.aor)

    def get_memebers(self):
        
        owner = sip_real_aor(self.context.aor)
        if owner not in ret:
            ret.append(owner)

        
    def send_msg(self, msg, user = None, omit = None):
        if user is not None:
            self.context.create_message(user, msg).send()
        else:
            for u in self.get_users(): #True):
                if u != omit:
                    self.send_msg(msg, u)

    def send_msgs(self, msg1, user, msg2):
        self.send_msg(msg1, user)
        self.send_msg(msg2, omit = user)

    def start_channel(self, channel, user, param = None):

        fp = None
        try:
            if param is not None:
                fp = channel(param, self)
            else:
                fp = channel(self)
                
            self.mixer.add(fp)
            fp.start()
        except Exception, ex:
            self.send_msg("Error creating channel: %s" % str(ex), user)
        return fp

    def message_got(self, message):
        debug("got message: %s" % str(message.body))
        message.respond(200)

        msg = message.body
        if msg == "pl":
            msg = "/play /home/jookos/media/musa.mp3"
        if msg == "pl2":
            msg = "/play /home/jookos/projects/p2pship/p2pship/src/trunk/p2pship/musa.wav"
            
        user = message.remote_aor
        cmd, s, param = msg.partition(" ")
        cmd = cmd.lower()
        if cmd == "/join":
            if user not in self.get_users():
                self.send_msgs("Welcome to %s!" % self.title, user, "%s joined the conversation" % user)
                self.members.append(user)
        elif cmd == "/leave":
            if user in self.members:
                self.members.remove(user)
                self.send_msgs("Goodbye!", user, "%s has left the conversation" % user)
        elif cmd == "/title":
            self.title = param
            self.send_msg("Title of chat changed to %s" % self.title) 
        elif cmd == "/invite":
            self.send_msgs("Your invited to %s by %s. Please type /join to join!" % (self.title, param),
                           param, "%s was invited" % param)


        elif cmd.startswith("/") and self.is_owner(message):

            if cmd == "/play":

                self.start_channel(AudioFileChannel, user, param)

            elif cmd == "/record":

                self.start_channel(AudioRecordChannel, param, user)

            elif cmd == "/listen":

                self.start_channel(AudioOutChannel, user)

            elif cmd == "/show":

                self.start_channel(VideoOutChannel, user)

            elif cmd == "/cam":

                self.start_channel(CamChannel, user)

            elif cmd == "/screen":

                self.start_channel(ScreenCastChannel, user)

            elif cmd == "/volume":

                ch, s, vol = param.partition(" ")
                channel = self.mixer.get_channel(ch)
                if channel is None:
                    msg = "Invalid id (%s)" % str(ch)
                else:
                    msg = "Channel %s volume set to %d" % (channel.get_name(), int(vol))
                    channel.set_volume(int(vol))
                self.send_msg(msg, user)

            elif cmd == "/list":
                msg = "List of channels:\n"
                for c in self.mixer.channels.values():
                    msg += "[%d]: %s" % (c.get_id(), c.get_name())
                    if not c.is_active():
                        msg += " [muted]"
                    else:
                        msg += " [%d%%]" % c.get_volume()
                    msg += "\n"
                self.send_msg(msg, user)

            elif cmd == "/kill":

                if param == "all":
                    for ch in self.mixer.channels.values():
                        ch.kill()
                    self.members = []
                    msg = "Conference killed"
                else:
                    channel = self.mixer.get_channel(param)
                    if channel is None:
                        msg = "Invalid id (%s)" % str(param)
                    else:
                        msg = "Channel %s removed" % channel.get_name()
                        channel.kill()
                self.send_msg(msg, user)

            elif cmd == "/mute":

                channel = self.mixer.get_channel(param)
                if channel is None:
                    msg = "Invalid id (%s)" % str(param)
                else:
                    msg = "Channel %s muted" % channel.get_name()
                    channel.set_active(False)
                self.send_msg(msg, user)

            elif cmd == "/unmute":

                channel = self.mixer.get_channel(param)
                if channel is None:
                    msg = "Invalid id (%s)" % str(param)
                else:
                    msg = "Channel %s unmuted" % channel.get_name()
                    channel.set_active(True)
                self.send_msg(msg, user)

            elif cmd == "/video":

                msg = ""
                try:
                    msg = self.mixer.init_video_mixer(param)
                except Exception, ex:
                    msg = str(ex)
                self.send_msg(msg, user)

            elif cmd == "/labels":

                if param == "off":
                    self.mixer.show_labels = False
                else:
                    self.mixer.show_labels = True
                self.mixer.reinit_video()

            else:
                self.send_msg("Unknown command '%s'" % cmd, user)

        elif self.is_member(user):
            if message.body.startswith("<?xml"):
                pass #self.send_msg(message.body, omit = user)
            else:
                self.send_msg(user + ": " + message.body, omit = user)
        elif not message.body.startswith("<?xml"):
            self.send_msg("Please /join first!", user)

    def ack_got(self, message):

        debug("**** ack got")
        user = self.get_user_channel(message.call.remote_aor)
        if user is not None:
            user.start()
        else:
            warn("ACK got, but no channel for %s" % message.call.remote_aor)

    def cancel_got(self, message):

        info("cancelling user")
        user = self.get_user_channel(message.call.remote_aor)
        if user is not None:
            user.remove()
        message.respond(200)

    def get_user_channel(self, aor):

        for user in self.mixer.channels.values():
            if isinstance(user, UserChannel) and user.aor == aor:
                return user
        return None

    def get_users(self, chat_only = False):

        ret = []
        for user in self.members:
            ret.append(user)

        if not chat_only:
            for user in self.mixer.channels.values():
                if isinstance(user, UserChannel) and user.aor not in ret:
                    ret.append(user.aor)

        # always add the owner to the list of members:
        owner = sip_real_aor(self.context.aor)
        if owner not in ret:
            ret.append(owner)
        return ret

    def is_member(self, user):
        return user in self.get_users()

    def invite_got(self, message):

        user = self.get_user_channel(message.call.remote_aor)
        if user is None:
            user = UserChannel(message.call.remote_aor, self)
            self.mixer.add(user)
            self.send_msg("User %s joined the conference" % message.call.remote_aor, omit = message.call.remote_aor)

        user.handle_invite(message)

    def response_got(self, req, resp):

        if req is None:
            info("response to something already processed or not sent by me!")
            return

        debug("response " + str(resp.resp_code) + " got to my " + req.msg_type + " request")

        if int(resp.resp_code) >= 200 and req.msg_type == "INVITE":
            m = resp.create_follow_up("ACK")
            m.cseq = str(resp.cseq) + " " + m.msg_type
            m.send()

            """
            if resp.call.remote_medias is not None:
                if resp.call.remote_medias.has_key('audio') and resp.call.remote_medias.has_key('video'):
                    debug("** audio streaming to " + str(resp.call.remote_medias['audio'][0]) + " port " + str(resp.call.remote_medias['audio'][1]))
                    debug("** video streaming to " + str(resp.call.remote_medias['video'][0]) + " port " + str(resp.call.remote_medias['video'][1]))
                    self.streamer.stream(resp.call.remote_medias['video'][0], resp.call.remote_medias['audio'][1], resp.call.remote_medias['video'][1], 15, self.streaming_done, resp)
                else:
                    debug("Either audio or video was missing1!")
            """


#
#

class MixerChannel:
    """The baseclass for in/out channel."""

    def __init__(self, handler):
        self.mixer = None
        self.id = -1
        self.active = False
        self.handler = handler
        self.mixer_caps = "audio/x-raw-int,channels=1,rate=8000,depth=16,width=16"
        self.pl = None
        self.volume = 100

        self.socks = {}
        
    def __del__(self):
        self.stop()
        for curr in self.socks.values():
            curr[0].close()

    def require_transfer_channel(self, ex = True):

        return self.require_modules(["audioresample",
                                     "audioconvert",
                                     "rtpL16pay",
                                     "udpsink",
                                     "udpsrc",
                                     "rtpL16depay",
                                     "gstrtpbin",
                                     "rtppcmadepay",
                                     "alawdec",
                                     "alawenc",
                                     "rtppcmapay"], ex)

    def require_modules(self, mods, ex = True):

        missing = []
        for m in mods:
            if not p2pship.media_check_element(m):
                missing.append(m)
        if len(missing) > 0:
            if ex:
                raise Exception("Missing gstreamer modules " + ", ".join(missing))
            else:
                return False
        return True

    def start(self):
        info("Starting channel %s" % self.get_name())
        if not self.active:
            self.handler.send_owner_msg("Channel %s [%d] added to the conference" % (self.get_name(), self.id))
            self.active = True
        self.mixer.reinit_player()

    def stop(self):
        if self.pl is not None:
            p2pship.media_pipeline_destroy(self.pl)
            self.pl = None

    def remove(self):
        self.stop()
        self.active = False
        self.mixer.remove(self)
        self.handler.send_owner_msg("Channel %s removed from the conference" % self.get_name())

    def kill(self):
        self.remove()
        self.die_gracefully()

    def get_id(self):
        return self.id

    def set_active(self, active = True):
        self.active = active
        if self.mixer is not None:
            self.mixer.reinit_player()

    def is_active(self):
        return self.active

    def set_volume(self, volume):
        if volume != self.volume:
            self.volume = volume
            self.mixer.reinit_player()

    def get_volume(self):
        return self.volume

    def get_sock_addr(self, idx = 0):

        curr = self.socks.get(idx)
        if curr is None:
            curr = create_ext_sock()
            self.socks[idx] = curr
        return curr

    def has_output(self):
        return self.gst_output() is not None

    def has_input(self):
        return self.gst_input() is not None

    def has_video_output(self):
        return self.gst_video_output() is not None

    def has_video_input(self):
        return self.gst_video_input() is not None

    #
    # to be overridden:

    def get_name(self):
        return "<empty>"

    # audio
    
    def gst_input(self):
        """Returns the gstreamer string for the input/receiver decoder"""
        return None
    
    def gst_output(self):
        """The gstreamer encoder / output string for this user"""
        return None

    def audio_reset(self):
        pass

    # video

    def get_caption(self):
        """The video caption, if applicable"""
        return None
    
    def gst_video_output(self):
        return None

    def gst_video_input(self):
        return None

    def video_reset(self):
        pass

    # misc
    def get_state(self):
        if self.is_active():
            return "active @ %d%%" % self.get_volume()
        else:
            return "inactive"

    def die_gracefully(self):
        """Called when the owner wishes to kill this channel"""
        pass

    def player_callback(self, handler, msgtype, data):

        if msgtype == "error" and self.pl == handler:
            warn("got error on %s player %s: %s" % (self.get_name(), str(handler), str(data)))
            self.kill()
        if msgtype == "eos" and self.pl == handler:
            warn("got end of content on %s player %s" % (self.get_name(), str(handler)))
            self.kill()


    #
    # transfer channels:

    def gst_transfer_channel_output(self):

        (sock, addr) = self.get_sock_addr()

        # alaw
        #line = 'audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! alawenc ! rtppcmapay ! udpsink sync=false host=%s port=%d sockfd=%d closefd=false' % (addr[0], addr[1], sock.fileno())

        # l16
        line = 'audioresample ! audioconvert ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100 ! rtpL16pay ! udpsink host=%s port=%d sockfd=%d closefd=false' % (addr[0], addr[1], sock.fileno())
        return line

    def create_transfer_channel_output(self, dest):

        (sock, addr) = self.get_sock_addr()

        # alaw
        #caps="application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"
        #line = 'udpsrc caps="%s" port=%s sockfd=%d closefd=false ! gstrtpbin ! rtppcmadepay ! alawdec ! %s' % (caps, addr[1], sock.fileno(), dest)

        # l16
        caps = "application/x-rtp,media=(string)audio,clock-rate=(int)44100,width=16,height=16,encoding-name=(string)L16,encoding-params=(string)1,channels=(int)2,channel-positions=(int)1,payload=(int)96"
        line = 'udpsrc port=%d caps="%s" sockfd=%d closefd=false ! rtpL16depay ! audioconvert ! audioresample ! %s' % (addr[1], caps, sock.fileno(), dest)

        info("Starting transfer pipeline for %s.." % self.get_name())
        pl = p2pship.media_pipeline_parse(line, self.player_callback)
        if pl < 1:
            error("could not create transfer channel!")
        return pl

    def gst_transfer_channel_input(self):

        (sock, addr) = self.get_sock_addr()

        # alaw
        caps="application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"
        decbin = ".recv_rtp_sink_0 gstrtpbin ! rtppcmadepay ! alawdec ! audioconvert ! audioresample"
        src = 'udpsrc sockfd=%d port=%d caps="%s" closefd=false ! %s' % (sock.fileno(), addr[1], caps, decbin)

        # l16
        """
        caps = "application/x-rtp,media=(string)audio,clock-rate=(int)44100,width=16,height=16,encoding-name=(string)L16,encoding-params=(string)1,channels=(int)2,channel-positions=(int)1,payload=(int)96"
        #caps = "application/x-rtp,media=(string)audio,clock-rate=(int)8000,width=16,height=16,encoding-name=(string)L16,encoding-params=(string)1,channels=(int)1,channel-positions=(int)1,payload=(int)96"

        src = 'udpsrc port=%d caps="%s" sockfd=%d closefd=false ! rtpL16depay ! audioconvert ! audioresample' % (addr[1], caps, sock.fileno())
        src = 'udpsrc port=%d caps="%s" sockfd=%d closefd=false ! rtpL16depay ! audioconvert' % (addr[1], caps, sock.fileno())

        #src = 'udpsrc port=%d caps="%s" sockfd=%d closefd=false ! rtpL16depay ! audioconvert ! audioresample ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100' % (addr[1], caps, sock.fileno())
        #src = 'udpsrc port=%d caps="%s" sockfd=%d closefd=false ! rtpL16depay ! audioconvert ! audioresample ! %s' % (addr[1], caps, sock.fileno(), self.mixer_caps)
        #src = 'udpsrc port=%d caps="%s" sockfd=%d closefd=false ! rtpL16depay ! audioconvert ! audioresample ! %s' % (addr[1], caps, sock.fileno(), self.mixer_caps)
        """
        
        return src

    def create_transfer_channel_input(self, src):

        (sock, addr) = self.get_sock_addr()

        # alaw
        line = '%s ! audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! alawenc ! rtppcmapay ! udpsink host=%s port=%d sockfd=%d closefd=false' % (src, addr[0], addr[1], sock.fileno())

        #
        # L16 streaming
        """
        line = 'filesrc location="%s" ! decodebin ! audioresample ! audioconvert ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100 ! rtpL16pay ! udpsink host=%s port=%d sockfd=%d' % (self.filename, addr[0], addr[1], sock.fileno())
        #line = 'filesrc location="%s" ! decodebin ! audioresample ! audioconvert ! audio/x-raw-int,channels=1,depth=16,width=16,rate=8000 ! rtpL16pay ! udpsink host=%s port=%d sockfd=%d' % (self.filename, addr[0], addr[1], sock.fileno())
        #line = 'filesrc location="%s" ! decodebin ! audioresample ! audioconvert ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100 ! rtpL16pay  ! udpsink host=%s port=%d sockfd=%d' % (self.filename, addr[0], 9999, sock.fileno())
        """

        info("Starting transfer pipeline for %s.." % self.get_name())
        info('gst pipeline: %s' % line)
        pl = p2pship.media_pipeline_parse(line, self.player_callback)
        if pl < 1:
            error("could not create transfer channel!")
        return pl


#
#

class AudioFileChannel(MixerChannel):
    """Plays a file"""

    def __init__(self, filename, handler):
        MixerChannel.__init__(self, handler)

        self.require_transfer_channel()
        self.require_modules(["filesrc", "decodebin" ])
        self.filename = filename
        
    def get_name(self):
        return "audiofile:%s" % self.filename
        
    def gst_input(self):
        return self.gst_transfer_channel_input()
    
    def start(self):
        MixerChannel.start(self)

        # start the streamer!
        if self.pl is not None:
            return True

        self.pl = self.create_transfer_channel_input('filesrc location="%s" ! decodebin' % self.filename)
        if self.pl > 0:
            p2pship.media_pipeline_start(self.pl)
            self.handler.send_owner_msg("Started player for %s" % self.filename)
            return True
        else:
            self.handler.send_owner_msg("Error creating player for %s" % self.filename)
            self.pl = None
            return False
            
    def player_callback(self, handler, msgtype, data):
        MixerChannel.player_callback(self, handler, msgtype, data)

        if msgtype == "error" and self.pl == handler:
            self.handler.send_owner_msg("Error occured while starting player for file %s: %s" % (self.filename, str(data)))
        if msgtype == "eos" and self.pl == handler:
            self.handler.send_owner_msg("Player for file %s finished" % self.filename)

    def die_gracefully(self):
        self.handler.send_owner_msg("Player for file %s removed" % self.filename)


#
#

class AudioRecordChannel(MixerChannel):
    """Records the conversation into a file"""

    def __init__(self, filename, handler):
        MixerChannel.__init__(self, handler)

        self.encoder = "lame"
        self.require_transfer_channel()
        self.require_modules(["filesink"])

        if not self.require_modules([self.encoder], False):
            self.encoder = "wavenc"
            self.require_modules([self.encoder])
        
        self.filename = filename
        
    def get_name(self):
        return "audiorecord:%s" % self.filename

    def start(self):
        MixerChannel.start(self)

        if self.pl is not None:
            return True

        self.pl = self.create_transfer_channel_output('%s ! filesink location="%s"' % (self.encoder, self.filename))
        #self.pl = self.create_transfer_channel_output('alsasink sync=false')
        if self.pl > 0:
            p2pship.media_pipeline_start(self.pl)
            self.handler.send_owner_msg("Started recorder for %s" % self.filename)
            return True
        else:
            self.handler.send_owner_msg("Error creating recorder for %s" % self.filename)
            self.pl = None
            return False

    def gst_output(self):
        """The gstreamer encoder / output string for this user"""

        return self.gst_transfer_channel_output()

    def player_callback(self, handler, msgtype, data):
        MixerChannel.player_callback(self, handler, msgtype, data)

        if msgtype == "error" and handler == self.pl:
            self.handler.send_owner_msg("Error occured while recording into file %s: %s" % (self.filename, str(data)))
            #self.stop()
            #self.start()
        if msgtype == "eos" and handler == self.pl:
            self.handler.send_owner_msg("Recorder for file %s finished" % self.filename)
            #self.stop()
            #self.start()

    def die_gracefully(self):
        self.handler.send_owner_msg("Recorder for file %s removed" % self.filename)
    

class AudioOutChannel(MixerChannel):
    """Listens in on the conversation"""

    def __init__(self, handler):
        MixerChannel.__init__(self, handler)

        self.require_modules(["alsasink"])

    def get_name(self):
        return "audioout"

    def gst_output(self):
        return "alsasink sync=false"


class VideoOutChannel(MixerChannel):
    """Displays videostream"""

    def __init__(self, handler):
        MixerChannel.__init__(self, handler)

        self.require_modules(["xvimagesink"])
        
    def get_name(self):
        return "videoout"

    def gst_video_output(self):
        return "xvimagesink sync=false"

class CamChannel(MixerChannel):
    """V4L camera"""

    def __init__(self, handler):
        MixerChannel.__init__(self, handler)

        self.require_modules(["v4l2src", "videorate", "videoscale"])

    def get_name(self):
        return "Webcam"

    def gst_video_input(self):
        return "v4l2src ! videoscale ! videorate ! video/x-raw-yuv,width=176,height=144,framerate=15/1"

class ScreenCastChannel(MixerChannel):
    """Screencasting local desktop"""

    def __init__(self, handler):
        MixerChannel.__init__(self, handler)

        self.require_modules(["ximagesrc"])

    def get_name(self):
        return "Desktop"

    def gst_video_input(self):
        return "ximagesrc show-pointer=true ! video/x-raw-rgb,framerate=15/1"
    
#
#
class UserChannel(MixerChannel):
    """Base class for a remote user"""

    def __init__(self, aor, handler):
        MixerChannel.__init__(self, handler)

        self.require_transfer_channel()

        self.h263_rtp_enc = 'hantro4200enc stream-type=1 profile-and-level=1001 ! video/x-h263,framerate=15/1 ! rtph263ppay mtu=1438'
        if not self.require_modules(["hantro4200enc"], False):
            #self.h263_rtp_enc = "ffenc_h263 ! video/x-h263 ! rtph263ppay pt=96 mtu=1438"
            self.h263_rtp_enc = 'ffenc_h263 ! video/x-h263 ! rtph263ppay pt=96'
            self.require_modules(["ffenc_h263"])

        self.h263_rtp_dec = "queue ! application/x-rtp,clock-rate=90000,payload=34 ! queue ! rtph263depay ! queue ! hantro4100dec tolerant-mode=true"
        if not self.require_modules(["hantro4100dec"], False):
            self.h263_rtp_dec = "decodebin"
            #self.h263_rtp_dec = "udpsrc port=%d sockfd=%d closefd=false ! decodebin ! ffmpegcolorspace ! videoscale ! videorate ! video/x-raw-yuv,width=300,height=200,framerate=15/1"
            self.require_modules(["ffdec_h263"])


        self.aor = aor
        self.name = aor
        self.invite = None
        self.response = None
        
        self.remote_medias = None
        self.remote_addr = None
        self.local_medias = None

        self.remote_video_addr = None
        self.is_streaming = False

    def get_name(self):
        return str(self.name)

    def check_remote_media(self, medias):
        """Checks whether the remote guy has supported media channels."""

        self.remote_medias = medias
        if medias is None:
            return False

        # todo: support different types: no-audio, recvonly audio etc..

        if medias.has_key('audio'):
            self.remote_addr = (str(medias['audio'][0]), int(medias['audio'][1]))
            debug("** audio streaming for %s to %s" % (self.aor, str(self.remote_addr)))

            # check whether the caller supports what we want (8-pcma/8000)
            if medias['audio'][2].get("8") is None:
                return False
        else:
            # we require audio?
            return False
        
        # check video:
        if medias.has_key('video'):
            self.remote_video_addr = (str(medias['video'][0]), int(medias['video'][1]))
            debug("** video streaming for %s to %s" % (self.aor, str(self.remote_video_addr)))

            if medias['video'][2].get("recvonly") is not None:
                self.is_streaming = False
            else:
                self.is_streaming = True

            if medias['video'][2].get("34") is None:
                return False

        else:
            self.is_streaming = False
            self.remote_video_addr = None

        return True

    def get_caption(self):
        return self.aor
    
    def gst_video_output(self):
        
        if self.remote_video_addr is not None:
            (sock, addr) = self.get_sock_addr("video")
            #line = "videoscale ! videorate ! video/x-raw-yuv,width=352,height=288 ! "
            line = "videoscale ! video/x-raw-yuv,width=352,height=288 ! %s ! " % self.h263_rtp_enc
            line += "udpsink sockfd=%d closefd=false host=%s port=%d sync=false" % (sock.fileno(), self.remote_video_addr[0], self.remote_video_addr[1])
            return line
        else:
            return None

    def video_reset(self):

        if self.is_streaming and self.remote_video_addr is not None:
            (sock, addr) = self.get_sock_addr("video")
            empty_socket(sock)
        
    def gst_video_input(self):

        if self.is_streaming and self.remote_video_addr is not None:
            (sock, addr) = self.get_sock_addr("video")
            line = "udpsrc port=%d sockfd=%d closefd=false ! %s" % (addr[1], sock.fileno(), self.h263_rtp_dec)
            return line
        else:
            return None

    def get_local_media(self):

        if self.local_medias is None:

            # http://www.packetizer.com/rfc/rfc3551/

            # todo: adjust the local media according to what the remote supports!

            (sock, local_addr) = self.get_sock_addr()
            formats = {}
            #formats["96"] = { "rtpmap":"iLBC/8000", "fmtp":"mode=30" }
            #formats["18"] = { "rtpmap":"G729/8000" }
            formats["8"] = { "rtpmap":"PCMA/8000" }
            #formats["0"] = { "rtpmap":"PCMU/8000" }
            #formats["13"] = { "rtpmap":"CN/8000" }
            #formats["97"] = { "rtpmap":"telephone-event/8000" }
            self.local_medias = { "audio":[ local_addr[0], local_addr[1], formats ] }

            (sock, local_addr) = self.get_sock_addr("video")
            formats = {}
            formats["34"] = { "rtpmap":"H263/90000", "fmtp": "QCIF=2" }


            #pid = os.spawnlp(os.P_NOWAIT, 'gst-launch', 'gst-launch', 'v4l2src ! video/x-raw-yuv,width=176,height=144,framerate=\(fraction\)15/1 ! hantro4200enc stream-type=1 profile-and-level=1001 ! video/x-h263,framerate=\(fraction\)15/1 ! rtph263ppay mtu=1438 ! udpsink host='+host+' port='+str(aport)+' dsppcmsrc ! queue ! audio/x-raw-int,channels=1,rate=8000 ! mulawenc ! rtppcmupay mtu=1438 ! udpsink host='+host+' port='+str(aport))

            
            self.local_medias["video"] = [ local_addr[0], local_addr[1], formats ]
            #self.local_medias["video"] = [ local_addr[0], 9999, formats ]


        return self.local_medias

    def handle_invite(self, message):

        self.invite = message
        
        self.name = parse_name(message.sfrom)
        if len(self.name) == 0:
            self.name = self.aor
            
        if not self.check_remote_media(message.call.remote_medias):
            m = message.create_response(415) # unsupported media type
            m.send()
            return
        message.call.my_medias = self.get_local_media()

        m = message.create_response(200)
        m.set_body(message.call.get_my_sdp(), "application/sdp")
        m.set_param('Contact', "<sip:whatever@127.0.0.1:5060;transport=udp>")
        m.send()
        self.response = m

    def die_gracefully(self):

        if self.response is not None:
            m = self.response.create_as_remote_follow_up("BYE")
            m.send(as_remote = not self.invite.is_remote, filter = False)

    def gst_input(self):

        (sock, addr) = self.get_sock_addr()

        caps="application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"
        decbin = '.recv_rtp_sink_0 gstrtpbin ! rtppcmadepay ! alawdec ! audioresample ! audioconvert'
        line = 'udpsrc sockfd=%d port=%d caps="%s" closefd=false ! %s' % (sock.fileno(), addr[1], caps, decbin)
        return line

    def gst_output(self):

        if self.remote_addr is None:
            return None

        (sock, local_addr) = self.get_sock_addr()

        encbin = "audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! alawenc ! rtppcmapay"
        line = '%s ! udpsink host=%s port=%d sockfd=%d closefd=false sync=false' % (encbin, self.remote_addr[0], self.remote_addr[1], sock.fileno())
        return line





class RelayingUserChannel(MixerChannel):
    """A channel for a remote user where the traffic is relayed through another port"""

    # create socket. etc

    def __init__(self, aor, handler):
        UserChannel.__init__(self, handler)

    def start(self):
        MixerChannel.start(self)

        # start the streamer!
        if self.pl is not None:
            return True

        (sock, addr) = self.get_sock_addr()
        (sockm, addrm) = self.get_sock_addr("mix")


        # recap: streaming as l16 and mixing everything via liveadder makes n810 sounds sound weird
        # ..but with 'adder' ok, 
        
        caps="application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"

        #decbin = '.recv_rtp_sink_0 gstrtpbin ! rtppcmadepay ! alawdec ! audioconvert ! audioresample ! liveadder ! audioconvert ! audioresample ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100 ! rtpL16pay ! udpsink host=%s port=%d sockfd=%d' % (addrm[0], addrm[1], sockm.fileno())

        # sort of ok, but discontinuous, requiring liveadder in the main mixer, making the sound sound weird:
        decbin = '.recv_rtp_sink_0 gstrtpbin ! rtppcmadepay ! alawdec ! audioresample ! audioconvert ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100 ! rtpL16pay ! udpsink closefd=false host=%s port=%d sockfd=%d' % (addrm[0], addrm[1], sockm.fileno())
        line = 'udpsrc sockfd=%d port=%d caps="%s" closefd=false ! %s' % (sock.fileno(), addr[1], caps, decbin)


        # try to do liveadding before running it over the wire:
        # note: this results in 100% cpu usage!!
        """
        decbin = '.recv_rtp_sink_0 gstrtpbin ! rtppcmadepay ! alawdec ! liveadder name=add0 ! audioresample ! audioconvert ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100 ! rtpL16pay ! udpsink closefd=false host=%s port=%d sockfd=%d' % (addrm[0], addrm[1], sockm.fileno())
        decbin = '.recv_rtp_sink_0 gstrtpbin ! rtppcmadepay ! alawdec ! liveadder name=add0 ! audioresample ! audioconvert ! audio/x-raw-int,channels=2,depth=16,width=16,rate=44100 ! rtpL16pay ! udpsink closefd=false host=%s port=%d sockfd=%d' % (addrm[0], 9999, sockm.fileno())
        line = 'udpsrc sockfd=%d port=%d caps="%s" closefd=false ! %s ! audiotestsrc ! add0.' % (sock.fileno(), addr[1], caps, decbin)
        """
        
        info("Starting pipeline for audiofile..")
        info('gst pipeline: %s' % line)
        self.pl = p2pship.media_pipeline_parse(line, self.player_callback)
        if self.pl > 0:
            p2pship.media_pipeline_start(self.pl)
            return True
        else:
            error("could not create player!")
            self.pl = None


    def gst_input(self):

        (sock, addr) = self.get_sock_addr("mix")

        # l16
        caps = "application/x-rtp,media=(string)audio,clock-rate=(int)44100,width=16,height=16,encoding-name=(string)L16,encoding-params=(string)1,channels=(int)2,channel-positions=(int)1,payload=(int)96"
        src = 'udpsrc port=%d caps="%s" sockfd=%d closefd=false ! rtpL16depay ! audioconvert' % (addr[1], caps, sock.fileno())
        return src

    def gst_output(self):

        (sock, local_addr) = self.get_sock_addr()

        #encbin = "audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000 ! alawenc ! rtppcmapay"
        encbin = "audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000,depth=16,width=16,signed=true,endianness=1234 ! alawenc ! rtppcmapay"

        #encbin = "audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000,depth=8,width=8,signed=true ! audioconvert ! audio/x-raw-int,channels=1,rate=8000,depth=16,width=16,signed=true ! alawenc ! rtppcmapay"

        # this should be ok. not?
        #encbin = "audioconvert ! audioresample ! audio/x-raw-int,channels=1,rate=8000,depth=16,width=16 ! alawenc ! rtppcmapay"

        line = '%s ! udpsink host=%s port=%d sockfd=%d closefd=false sync=false' % (encbin, self.remote_addr[0], self.remote_addr[1], sock.fileno())
        return line

# check for plugins:

plugins = [ "alawdec",
            "alawenc",
            "alsasink",
            "audioconvert",
            "audioresample",
            "decodebin",
            "fakesink",
            "ffenc_h263",
            "ffmpegcolorspace",
            "filesink",
            "filesrc",
            "gstrtpbin",
            "lame",
            "liveadder",
            "multifilesrc",
            "queue",
            "rtph263depay",
            "rtph263ppay",
            "rtpL16depay",
            "rtpL16pay",
            "rtppcmadepay",
            "rtppcmapay",
            "tee",
            "textoverlay",
            "udpsink",
            "udpsrc",
            "v4l2src",
            "videomixer",
            "videorate",
            "videoscale",
            "videotestsrc",
            "volume",
            "ximagesrc",
            "xvimagesink"
            ]

def check_media_plugins(pl):
    for p in pl:
        if not p2pship.media_check_element(p):
            warn("Missing gstreamer plugin '%s'" % p)

check_media_plugins(plugins)

if install_sip_handler(".*", "[^+]+[+][a-z0-9]*@.+", MultipartyHandler):
    info("Multiparty handler is installed!")
else:
    warn("Error installing multiparty handler!")
