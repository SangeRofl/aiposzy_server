import socket
import sys
import os
from email.parser import Parser

from loguru import logger

from functools import lru_cache
from urllib.parse import parse_qs, urlparse
logger.add("debug.log", format = "{time} {level} {message}")

MAX_LINE = 64*1024
MAX_HEADERS = 100

class MyHTTPServer:
    def __init__(self, host, port, server_name):
        self._host = host
        self._port = port
        self._server_name = server_name

    def serve_forever(self):
        serv_sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
            proto=0)
        try:
            serv_sock.bind((self._host, self._port))
            serv_sock.listen()

            while True:
                conn, _ = serv_sock.accept()
                logger.info("Client connected"+ str(_))
                try:
                    self.serve_client(conn)
                    logger.info("Client served successfuly")
                except Exception as e:
                    print('Client serving failed', e)
        finally:
            serv_sock.close()


    def serve_client(self, conn):
        try:
            req = self.parse_request(conn)
            logger.info("Request parserd successfuly:"+req.method+req.target+req.version)
            resp = self.handle_request(req)
            logger.info("Request handled successfuly:"+resp.reason + resp.status)
            self.send_response(conn, resp)
        except ConnectionResetError:
            raise
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.send_error(conn, e)
            logger.error("Error:"+ e.status)

        if conn:
            conn.close()
            logger.info("Connection closed")


    def parse_request(self, conn):
        rfile = conn.makefile('rb')
        method, target, ver = self.parse_request_line(rfile)
        headers = self.parse_headers(rfile)
        host = headers.get('Host')
        if not host:
            raise Exception('Bad request')
        if host not in (self._server_name,
                        f'{self._host}:{self._port}'):
            raise Exception('Not found')
        return Request(method, target, ver, headers, rfile)


    def parse_headers(self, rfile):
        headers = []
        while True:
            line = rfile.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE:
                raise Exception('Header line is too long')

            if line in (b'\r\n', b'\n', b''):
                # завершаем чтение заголовков
                break

            headers.append(line)
            if len(headers) > MAX_HEADERS:
                raise Exception('Too many headers')
        sheaders = b''.join(headers).decode('iso-8859-1')
        print(Parser().parsestr(sheaders))
        return Parser().parsestr(sheaders)


    def parse_request_line(self, rfile):
        raw = rfile.readline(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            raise Exception('Request line is too long')
        req_line = str(raw, 'iso-8859-1')
        req_line = req_line.rstrip('\r\n')
        words =req_line.split()
        if len(words)!=3:
            raise Exception('Malformed request line')
        method, target, ver = words
        if ver != 'HTTP/1.1':
            raise Exception('Unexpected HTTP version')
        return method, target, ver


    def handle_request(self, req):
        allowed_extensions = [".html", ".css", ".js", ".txt", ".py", ".svg", ".png", ]
        body = ""
        contentType = ''
        headers = []
        if req.method == 'GET':
            print(req.path)
            if req.path.endswith(tuple(allowed_extensions)):
                file = open("."+req.path,"rt") if req.path.endswith(tuple(allowed_extensions[:6])) else open("."+req.path,"rb")
                body = file.read()
                file.close()
                if req.path.endswith(".html"):
                    body = body.encode("utf-8")
                    contentType = 'text/html; charset=utf-8'
                elif req.path.endswith(".css"):
                    contentType = 'text/css; charset=utf-8'
                    body = body.encode("utf-8")
                elif req.path.endswith(".js"):
                    body = body.encode("utf-8")
                    contentType = 'text/javascript; charset=utf-8'
                elif req.path.endswith(tuple(allowed_extensions[3:6])):
                    contentType = 'text; charset=utf-8'
                    body = body.encode("utf-8")
                elif req.path.endswith(".svg"):
                    contentType = 'image/svg+xml'
                elif req.path.endswith(".png"):
                    contentType = 'image/png'
            else:
                body+="<html><head></head><body>"
                print(os.path.join(os.path.abspath("."),req.path[1:]))
                path = os.path.relpath(os.path.join(os.path.abspath("."),req.path[1:]), os.path.abspath("."))+"/" if len(req.path) != 1 else "/"
                body+="<base href = http://"+self._host+":"+str(self._port)+"/"+path.replace("\\", "/")+">"
                folder_objects = [i if i.endswith(tuple(allowed_extensions)) else i+"/" for i in os.listdir('.'+req.path)]
                a = ["<a href = " + i + ">" + i + "</a>" for i in os.listdir('.'+req.path)]
                body += "\n<br>".join(a)
                body+="</body></html>"
                body = body.encode('utf-8')
                contentType = 'text/html; charset=utf-8'
        elif req.method == 'POST':
            print(str(req.body()))
        elif req.method == 'OPTIONS':
            headers+=[('Allow', "OPTIONS, GET, POST"),]
        else:
            raise HTTPError(405, "Method not allowed")
        headers += [('Content-Type', contentType),
                ('Content-Length', len(body)),
                ('Access-Control-Allow-Origin', "https://"+self._host+":"+str(self._port)),
                ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'),]
        return Response(200, "OK", headers, body)


    def send_response(self, conn, resp):
        wfile = conn.makefile('wb')
        status_line = f'HTTP/1.1 {resp.status} {resp.reason}\r\n'
        wfile.write(status_line.encode('iso-8859-1'))

        if resp.headers:
            for (key, value) in resp.headers:
                header_line = f'{key}: {value}\r\n'
                wfile.write(header_line.encode('iso-8859-1'))

        wfile.write(b'\r\n')

        if resp.body:
            wfile.write(resp.body)

        wfile.flush()
        wfile.close()


    def send_error(self, conn, err):
        try:
            status = err.status
            reason = err.reason
            body = (err.body or err.reason).encode('utf-8')
        except:
            status = 500
            reason = b'Internal Server Error'
            body = b'Internal Server Error'
        resp = Response(status, reason,
                    [('Content-Length', len(body))],
                    body)
        self.send_response(conn, resp)


class Request:
    def __init__(self, method, target, version, headers, rfile):
        self.method = method
        self.target = target
        self.version = version
        self.headers = headers
        self.rfile = rfile
    def body(self):
        size = self.headers.get('Content-Length')
        if not size:
            return None
        return self.rfile.read(size)

    @property
    def path(self):
        return self.url.path
    
    @property
    @lru_cache(maxsize = None)
    def query(self):
        return parse_qs(self.url.query)

    @property
    @lru_cache(maxsize=None)
    def url(self):
        return urlparse(self.target)

class Response:
  def __init__(self, status, reason, headers=None, body=None):
    self.status = status
    self.reason = reason
    self.headers = headers
    self.body = body

class HTTPError(Exception):
  def __init__(self, status, reason, body=None):
    super()
    self.status = status
    self.reason = reason
    self.body = body

if __name__ == "__main__":
    host = "127.0.0.1"#sys.argv[1]
    port = 9090#int(sys.argv[2])
    name = "example.local"#sys.argv[3]

    serv = MyHTTPServer(host, port, name)
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        raise Exception