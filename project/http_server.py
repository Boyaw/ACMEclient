# Start HTTP server                 
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socketserver
import sys, argparse
# Parse the command
parser = argparse.ArgumentParser()
parser.add_argument('keyAuth')
parser.add_argument('http_addr')

args = parser.parse_args(sys.argv[1:])

keyAuth_list_plus = args.keyAuth.split('+')
keyAs = []
for t in keyAuth_list_plus:
    if t != '':
        keyAs.append(t)

print(keyAs)

class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):

        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()

        for keyA in keyAs:
            kA = keyA
            token = keyA.split('.')[0]
            print(kA)
            if self.path == ('/.well-known/acme-challenge/'+token):
                self.wfile.write(bytes(kA, "utf8"))

            



httpd = HTTPServer((args.http_addr, 5002), RequestHandler)
httpd.serve_forever()
