import os
import mimetypes

#
# this is for the library!!
class HttpRequest:
    """Class for containing the requests"""

    req = None
    ref = None
    
    # the ..
    method = None
    url = None
    original_url = None
    url_extras = None
    http_version = None

    params = {}
    headers = {}
    body = None

    remote_host = None

    done = False

    def __init__(self, req):
        self.req = req

        # the request should be in some sort of format..
        # PyTuple_New(9), where the last are Tuples(n) of Tuples(2)
        # http://docs.python.org/c-api/intro.html
        (self.ref,
         self.body,
         self.method,
         self.url,
         self.original_url,
         self.url_extras,
         self.http_version,
         self.remote_host,
         self.params,
         self.headers) = req

    def get_param(self, key, default = None):
        if self.params.has_key(key):
            return self.params[key]
        else:
            return default

    def send(self, data):
        if not self.done:
            p2pship.http_send(ref, data)

    def close(self, data):
        if not self.done:
            p2pship.http_close(ref)
        self.done = True
        
    def respond_unsupported(self):
        self.respond(405, "Method Unsupported", "Method Unsupported")

    def respond(self, code = None, code_str = None,
                body = None, content_type = None):
    
        if self.done:
            return
        
        if code is None:
            code = 200
            code_str = "OK"
        if code_str is None:
            code_str = ""
        if body is None:
            body = ""
            content_type = ""
        if content_type is None:
            content_type = "text/html"
        p2pship.http_respond(self.ref,
                             int(code), code_str,
                             content_type, body)
        self.done = True

class HttpHandler:
    """Base class for http request handlers"""

    address = None
    handle = None

    def __init__(self, address = None):
        if address is not None:
            self.set_address(address)

    def update_address_config(self, key, address):
        self.set_address(address)
        
    def set_address(self, address):
        if self.handle is None:
            self.handle = p2pship.http_register(self.process_request, address)
            info("got handle " + str(self.handle))
        else:
            p2pship.http_modif(self.handle, address)
        self.address = address

    def unregister(self):
        if address is not None:
            p2pship.http_unregister(self.handle)

    def process_request(self, req):
        request = HttpRequest(req)
        debug("got request, " + str(request.method) + ", to " + request.url)
        if request.method == "GET":
            self.get(request)
        elif request.method == "POST":
            self.post(request)
        elif request.method == "CONNECT":
            self.connect(request)
        elif request.method == "PUT":
            self.put(request)
        elif request.method == "HEAD":
            self.head(request)
        elif request.method == "OPTIONS":
            self.options(request)
        elif request.method == "DELETE":
            self.delete(request)
        elif request.method == "TRACE":
            self.trace(request)
        else:
            request.respond_unsupported()
            
        if request.done:
            return 0
        else:
            return 1

    # the ones to be overridden!
    def get(self, req):
        req.respond_unsupported()
    def post(self, req):
        req.respond_unsupported()
    def connect(self, req):
        req.respond_unsupported()
    def put(self, req):
        req.respond_unsupported()
    def head(self, req):
        req.respond_unsupported()
    def options(self, req):
        req.respond_unsupported()
    def delete(self, req):
        req.respond_unsupported()
    def trace(self, req):
        req.respond_unsupported()
    

class FileServerHandler(HttpHandler):

    def __init__(self, address, path):
        HttpHandler.__init__(self, address)
        self.path = path

    def update_path_config(self, key, path):
        self.set_path(path)
        
    def set_path(self, path):
        self.path = path

    def get(self, request):
        if request.url[-1:] == "/":
            fname = self.path + request.url + "index.html"
        else:
            fname = self.path + request.url
        self.serve_file(request, fname)
            
    def serve_file(self, request, fname):
        debug("serving " + fname)
        if os.path.isfile(fname):
            f = open(fname)
            data = f.read()
            f.close()
            (ty, enc) = mimetypes.guess_type(fname)
            request.respond(200, "Ok", data, ty)
        else:
            request.respond(404, "Not Found", "File not found")
        
