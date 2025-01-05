import json
import logging
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from typing import Callable, Any, Type, Optional
from urllib.parse import unquote

_logger = logging.getLogger(__name__)


class _ReuseAddressTcpServer(TCPServer):
    def __init__(self, host: str, port: int, handler_class: Type[BaseHTTPRequestHandler]):
        self.allow_reuse_address = True
        TCPServer.__init__(self, (host, port), handler_class)


def read_request_parameters(path: str) -> dict:
    params_received = dict()
    idx = path.find('?')
    if idx >= 0 and (idx < len(path) - 1):
        for params in path[idx + 1:].split('&'):
            param_splitted = params.split('=')
            if len(param_splitted) == 2:
                params_received[param_splitted[0]] = unquote(param_splitted[1])
    return params_received


def start_http_server(port: int, host: str = '', callback: Optional[Callable[[dict], None]] = None) -> TCPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            _logger.debug('GET - %s' % self.path)
            params_received = read_request_parameters(self.path)
            response = 'Response received (%s). Result was transmitted to the original thread. You can close this window.' % json.dumps(
                params_received)
            self.send_response(HTTPStatus.OK.value, 'OK')
            self.send_header("Content-type", 'text/plain')
            self.send_header("Content-Length", len(response))
            self.end_headers()
            try:
                self.wfile.write(bytes(response, 'UTF-8'))
            finally:
                if callback is not None:
                    callback(params_received)
                self.wfile.flush()

    _logger.debug('start_http_server - instantiating server to listen on "%s:%d"', host, port)
    httpd = _ReuseAddressTcpServer(host, port, Handler)

    def serve():
        _logger.debug('server daemon - starting server')
        httpd.serve_forever()
        _logger.debug('server daemon - server stopped')

    thread_type = threading.Thread(target=serve)
    thread_type.start()
    return httpd


def stop_http_server(httpd: TCPServer):
    _logger.debug('stop_http_server - stopping server')
    httpd.shutdown()
