from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

class HttpRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        try:
            self.parse_request()
        except:
            self.error_code = 400