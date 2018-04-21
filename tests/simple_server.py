# slightly modified from
# https://gist.github.com/trungly/5889154

from BaseHTTPServer import HTTPServer
import urlparse
from SimpleHTTPServer import SimpleHTTPRequestHandler


class GetHandler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        parsed_path = urlparse.urlparse(self.path)
        if parsed_path.path.startswith("/echo"):
            message = '\n'.join([
                'CLIENT VALUES:',
                'client_address=%s (%s)' % (self.client_address, self.address_string()),
                'command=%s' % self.command,
                'path=%s' % self.path,
                'real path=%s' % parsed_path.path,
                'query=%s' % parsed_path.query,
                'request_version=%s' % self.request_version,
                '',
                'HEADERS:',
                '%s' % self.headers,
                ])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(message)
        elif parsed_path.path.startswith("/redirect"):
            self.send_response(301)
            self.send_header('Location', "/echo")
            self.end_headers()
        else:
            SimpleHTTPRequestHandler.do_HEAD(self)

        return

    def do_GET(self):
        parsed_path = urlparse.urlparse(self.path)
        if parsed_path.path.startswith("/echo"):
            message = '\n'.join([
                'CLIENT VALUES:',
                'client_address=%s (%s)' % (self.client_address, self.address_string()),
                'command=%s' % self.command,
                'path=%s' % self.path,
                'real path=%s' % parsed_path.path,
                'query=%s' % parsed_path.query,
                'request_version=%s' % self.request_version,
                '',
                'HEADERS:',
                '%s' % self.headers,
                ])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(message)
        elif parsed_path.path.startswith("/redirect"):
            self.send_response(301)
            self.send_header('Location', "/echo")
            self.end_headers()
        else:
            SimpleHTTPRequestHandler.do_GET(self)

        return

    def do_POST(self):
        parsed_path = urlparse.urlparse(self.path)
        if parsed_path.path.startswith("/echo"):
            content_len = int(self.headers.getheader('content-length'))
            post_body = self.rfile.read(content_len)
            self.send_response(200)
            self.end_headers()

            message = '\n'.join([
                'CLIENT VALUES:',
                'client_address=%s (%s)' % (self.client_address, self.address_string()),
                'command=%s' % self.command,
                'path=%s' % self.path,
                'real path=%s' % parsed_path.path,
                'query=%s' % parsed_path.query,
                'request_version=%s' % self.request_version,
                '',
                'HEADERS:',
                '%s' % self.headers,
                'POST_DATA=%s' % post_body,
                '',
                ])

            self.wfile.write(message)

        return


if __name__ == '__main__':
    server = HTTPServer(('localhost', 8080), GetHandler)
    print 'Starting server at http://localhost:8080'
    server.serve_forever()
