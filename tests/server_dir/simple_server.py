# slightly modified from
# https://gist.github.com/trungly/5889154

from http.server import HTTPServer
from http.server import SimpleHTTPRequestHandler
import urllib.parse


class GetHandler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path.startswith("/echo"):
            message = "\n".join(
                [
                    "CLIENT VALUES:",
                    "client_address=%s (%s)"
                    % (self.client_address, self.address_string()),
                    "command=%s" % self.command,
                    "path=%s" % self.path,
                    "real path=%s" % parsed_path.path,
                    "query=%s" % parsed_path.query,
                    "request_version=%s" % self.request_version,
                    "",
                    "HEADERS:",
                    "%s" % self.headers,
                ]
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(message.encode("utf-8"))
        elif parsed_path.path.startswith("/redirect"):
            self.send_response(301)
            self.send_header("Location", "/echo")
            self.end_headers()
        else:
            SimpleHTTPRequestHandler.do_HEAD(self)

        return

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path.startswith("/echo"):
            message = "\n".join(
                [
                    "CLIENT VALUES:",
                    "client_address=%s (%s)"
                    % (self.client_address, self.address_string()),
                    "command=%s" % self.command,
                    "path=%s" % self.path,
                    "real path=%s" % parsed_path.path,
                    "query=%s" % parsed_path.query,
                    "request_version=%s" % self.request_version,
                    "",
                    "HEADERS:",
                    "%s" % self.headers,
                ]
            )
            self.send_response(200)
            self.end_headers()
            self.wfile.write(message.encode("utf-8"))
        elif parsed_path.path.startswith("/redirect"):
            self.send_response(301)
            self.send_header("Location", "/echo")
            self.end_headers()
        else:
            SimpleHTTPRequestHandler.do_GET(self)

        return

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path.startswith("/echo"):
            content_len = int(self.headers.get("content-length"))
            post_body = self.rfile.read(content_len).decode("utf-8")
            self.send_response(200)
            self.end_headers()

            message = "\n".join(
                [
                    "CLIENT VALUES:",
                    "client_address=%s (%s)"
                    % (self.client_address, self.address_string()),
                    "command=%s" % self.command,
                    "path=%s" % self.path,
                    "real path=%s" % parsed_path.path,
                    "query=%s" % parsed_path.query,
                    "request_version=%s" % self.request_version,
                    "",
                    "HEADERS:",
                    "%s" % self.headers,
                    "POST_DATA=%s" % post_body,
                    "",
                ]
            )

            self.wfile.write(message.encode("utf-8"))

        return


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), GetHandler)
    server.serve_forever()
