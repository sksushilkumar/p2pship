#
# p2p http content server interface!

import p2pship
import md5

class ContentServer(FileServerHandler):

    def notify(self, title, message, popup = True):
        """Notifies the user what is happening"""

        message = "[" + str(len(message)) + "]" + message
        if len(message) > 30:
            message = message[0:30]
        if popup:
            try:
                import pynotify
                if pynotify.init("OP Server"):
                    n = pynotify.Notification(title, message)
                    n.set_timeout(1000)
                    n.show()
            except Exception, ex:
                pass
        print title + ": " + message

    def post(self, request):
        self.get(request)


    def share_cb(res, request):
        if res:
            request.respond(200, "ok", "ID:"+request.params['type']+"0003343")
        else:
            request.respond(400, "fail", "horribly..")
        
    def get(self, request):
        print "Got a content request for " + request.url
        requester = request.headers['X-P2P-From']
        if request.url == "/addcontent":

            file_type = request.get_param("type")
            suff = None
            if file_type == "image":
                print "jee, requesting images"
                suff = ["*.jpg", "*.jpeg", "*.png", "*.gif", "Image files"]
                
            # easygui!
            name = None
            title = "Request to share"
            msg = request.headers['X-P2P-From'] + " is requesting you to share content of type "+str(file_type)+ ". Do you want to do that?"
            if ccbox(msg, title):
                name = fileopenbox(msg="Choose file", title="Choose a file to share", default='~/*', filetypes=suff)
                # get name, description?
            if name is not None:

                cid = md5.new(name).hexdigest()
                self.key_map[cid] = name
                request.respond(200, "ok", "id:"+cid)
            else:
                request.respond(400, "Sorry", "Not sharing")
     
        elif request.url == "/get":
            cid = request.get_param("id", "")
            preview = request.get_param("preview")
            if self.key_map.has_key(cid) and ccbox(request.headers['X-P2P-From'] + " wants to have a look at your stuff. allow?", "Allow access?"):
                self.serve_file(request, self.key_map[cid])
            else:
                request.respond(404, "Not Found", "Not found")

        elif request.url == "/info":
            # small info popup
            msg = request.get_param("msg", "")
            if msg != "":
                buttonbox(msg, "Message from " + requester, ("Ok", ))
                #msgbox(msg)
                request.respond(200, "Ok", "Ok")
            else:
                request.respond(400, "Error", "Error")

        elif request.url == "/query":
            # small info popup
            msg = request.get_param("msg", "")
            yes = request.get_param("yes", "Yes")
            no = request.get_param("no", "No")
            if msg != "":
                ret = buttonbox(msg, "Query from " + requester, (yes, no))
                request.respond(200, "Ok", ret)
            else:
                request.respond(400, "Error", "Error")

        elif request.url == "/":
            request.respond(200, "ok", "Hello to you " + str(request.remote_host)+" too!")
        else:
            request.respond(404, "not found", "")


    key_map = {}


# aor = p2pship.default_ident().aor
aor = "hafnium@jookos.org"

p2pship.set_name("p2phttp content server")
http_address = aor + ":80"
conf_key = "p2phttp_content_server"

# create if not already exists
p2pship.config_create(conf_key, "p2phttp content server address", "string", http_address)

http_address = p2pship.config_get(conf_key)

info("starting content server..")
servo = ContentServer(http_address, "/")
p2pship.config_set_update(conf_key, servo.update_address_config)
info("content server running")

#ship_start_ui()
