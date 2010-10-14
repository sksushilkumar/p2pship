

# start of the sip-client apps:

class MultipartyHandler(SipHandler):

    def __init__(self):
        self.verbose = False
        self.members = []
        self.title = "anon session"

    def send_msg(self, msg, user = None, omit = None):
        if user is not None:
            self.context.create_message(user, msg).send()
        else:
            for u in self.members:
                if u != omit:
                    self.send_msg(msg, u)

    def send_msgs(self, msg1, user, msg2):
        self.send_msg(msg1, user)
        self.send_msg(msg2, omit = user)

    def message_got(self, message):
        print "got message: %s" % str(message.body)
        message.respond(200)

        user = message.remote_aor
        cmd, s, param = message.body.partition(" ")
        cmd = cmd.lower()
        if cmd == "/join":
            if user not in self.members:
                self.send_msgs("Welcome to %s!" % self.title, user, "%s joined the conversation" % user)
                self.members.append(user)
        elif cmd == "/leave":
            if user in self.members:
                self.members.remove(user)
                self.send_msgs("Goodbye!", user, "%s has left" % user)
        elif user in self.members:
            self.send_msg(user + ": " + message.body, omit = user)
        else:
            self.send_msg("Please /join first!", user)
        
if install_sip_handler(".*", "[^+]+[+][a-z0-9]*@.+", MultipartyHandler):
    print "Multiparty handler is installed!"
else:
    print "Error installing multiparty handler!"
