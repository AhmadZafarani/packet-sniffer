# # YA HOSSEIN
import http.server
import socketserver
from io import BytesIO


class MyHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, directory=None, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)
    

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
        except TypeError:
            self.send_response(400)
            return
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        response = BytesIO()
        response.write(b'This is POST request. ')
        response.write(b'Received: ')
        response.write(body)
        self.wfile.write(response.getvalue())



PORT = 8000
HOST = "127.0.0.1"
Handler = MyHandler

with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
