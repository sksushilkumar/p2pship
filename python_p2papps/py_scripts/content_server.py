#
# p2p http content server interface!

import p2pship
import md5

# get the default identity for this
ident = Ident()
#aor = "@"

class ContentServer(FileServerHandler):

    def notify(self, title, message, popup = True):
        """Notifies the user what is happening"""

        message = "[" + str(len(message)) + "]" + message
        if len(message) > 30:
            message = message[0:30]
        if popup:
            p2pship.ui_popup(title + ":\n" + message)
        info(title + ": " + message)

    def post(self, request):
        self.get(request)

    def share_cb(res, request):
        if res:
            request.respond(200, "ok", "ID:"+request.params['type']+"0003343")
        else:
            request.respond(400, "fail", "")
        
    def get(self, request):
        info("Got a content request for " + request.url)
        requester = request.headers['X-P2P-From']
        if request.url == "/addcontent":

            file_type = request.get_param("type")
            suff = ("*.*", )
            if file_type == "image":
                suff = ( "*.jpg", "*.jpeg", "*.png", "*.gif" )
                
            name = None
            title = "Request to share"
            msg = request.headers['X-P2P-From'] + " is requesting you to share content of type "+str(file_type)+ ". Do you want to do that?"

            if p2pship.ui_query_simple(title, msg, "Yes", "No") != 0:
                name = p2pship.ui_query_filechooser("Choose a file to share", "Choose file", "~/", suff)

            if name is not None:
                cid = md5.new(name).hexdigest()
                self.key_map[cid] = name
                request.respond(200, "ok", "id:"+cid)

                # set up the access rights
                buddies = []
                for b in ident.buddies.values():
                    buddies.append( b.aor )

                # easygui multchoicebox
                """
                sel = multchoicebox("Please select the peers with which you want to share this content",
                                    "Select peers", buddies);
                self.access_map[cid] = sel
                """
                # todo: publish the data to the overlay?
                
            else:
                request.respond(400, "Sorry", "Not sharing")
     
        elif request.url == "/get":
            cid = request.get_param("id", "")
            preview = request.get_param("preview")
            ac = self.access_map.get(cid, [])
            allow = False
            try:
                i = ac.index(request.headers['X-P2P-From'])
                allow = True
            except Exception, ex:
                pass

            if self.key_map.has_key(cid) and (allow or (p2pship.ui_query_simple("Allow access?", request.headers['X-P2P-From'] + " wants to have a look at your stuff. allow?", "Allow", "Reject") != 0)):
                if not allow:
                    ac.append(request.headers['X-P2P-From'])
                    self.access_map[cid] = ac
                self.serve_file(request, self.key_map[cid])
            else:
                request.respond(404, "Not Found", "Not found")

        elif request.url == "/info":
            # small info popup
            msg = request.get_param("msg", "")
            if msg != "":
                p2pship.ui_popup("Message from " + requester + ": " + msg)
                request.respond(200, "Ok", "Ok")
            else:
                request.respond(400, "Error", "Error")

        elif request.url == "/query":
            # small info popup
            msg = request.get_param("msg", "")
            yes = request.get_param("yes", "Yes")
            no = request.get_param("no", "No")
            if msg != "":
                ret = p2pship.ui_query_simple("Query from " + requester, msg, yes, no)
                if ret != 0:
                    ret = yes
                else:
                    ret = no
                request.respond(200, "Ok", ret)
            else:
                request.respond(400, "Error", "Error")

        elif request.url == "/":
            request.respond(200, "ok", "Hello to you " + str(request.remote_host)+" too!")
        else:
            request.respond(404, "not found", "")

    appid = "42f09180-a39a-11df-aeee-001c259d03e9"
    key_map = PersistentDict(appid, "files")
    access_map = PersistentDict(appid, "access")

p2pship.set_name("p2phttp content server")
http_address = ident.aor + ":80"
conf_key = "p2phttp_content_server"

# create if not already exists
p2pship.config_create(conf_key, "p2phttp content server address", "string", http_address)

http_address = p2pship.config_get(conf_key)

info("starting content server..")
try:
    servo = ContentServer(http_address, "/")
    p2pship.config_set_update(conf_key, servo.update_address_config)
    info("content server running")
except Exception, ex:
    warn("Error while starting content server at %s: %s" % (str(http_address), str(ex)))
         
