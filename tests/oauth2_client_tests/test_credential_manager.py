import json
import logging
import threading
import unittest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import requests

from oauth2_client.credentials_manager import CredentialManager, ServiceInformation, OAuthError
from oauth2_client.http_server import read_request_parameters, _ReuseAddressTcpServer

_logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG,
                    format='%(levelname)5s - %(name)s -  %(message)s')

authorize_server_port = 9090
token_server_port = 9091
api_server_port = 9092
redirect_server_port = 9099

service_information = ServiceInformation(
    authorize_service='http://localhost:%d/oauth/authorize' % authorize_server_port,
    token_service='http://localhost:%d/oauth/token' % token_server_port,
    client_id='client_id_test',
    client_secret='client_secret_test',
    scopes=['scope1', 'scope2'])


basic_auth = 'Basic Y2xpZW50X2lkX3Rlc3Q6Y2xpZW50X3NlY3JldF90ZXN0'


class FakeOAuthHandler(BaseHTTPRequestHandler):
    CODE = '123'

    def do_GET(self):
        """
        Handle requests of authorize process
        :return:
        """
        _logger.debug('FakeOAuthHandler - GET - %s' % self.path)
        try:
            authorize_parsed = urlparse(service_information.authorize_service)
            if self.path == authorize_parsed.path \
                    or self.path.index('%s?' % authorize_parsed.path) != 0:
                self.send_response(HTTPStatus.NOT_FOUND.value, 'Not Found')
            else:
                params_received = read_request_parameters(self.path)
                self._check_get_parameters(params_received)
                redirect_uri = params_received.get('redirect_uri', None)
                state = params_received.get('state', '')
                if redirect_uri is not None:
                    _logger.debug('FakeOAuthHandler - redirect - %s', redirect_uri)
                    self.send_response(HTTPStatus.SEE_OTHER.value, 'Redirect')
                    self.send_header("Location", '%s?code=%s&state=%s' % (redirect_uri, FakeOAuthHandler.CODE, state))
                else:
                    self.send_response(HTTPStatus.BAD_REQUEST.value, 'Bad Request')
            self.send_header("Content-Length", 0)
            self.end_headers()
        finally:
            self.wfile.flush()

    def do_POST(self):
        try:
            ctype = self.headers.get_content_type()
            if ctype == 'application/x-www-form-urlencoded':
                length = int(self.headers['content-length'])
                parameters = parse_qs(self.rfile.read(length), keep_blank_values=True)
                self._handle_post(parameters)
            else:
                _logger.debug('FakeOAuthHandler - invalid content type')
                self.send_response(HTTPStatus.BAD_REQUEST.value, 'Invalid content type')
        finally:
            self.wfile.flush()

    def _check_get_parameters(self, parameters):
        pass

    def _handle_post(self, parameters):
        self.send_response(HTTPStatus.OK.value, 'OK')
        self.send_header("Content-type", 'text/plain')
        self.send_header("Content-Length", 0)
        self.end_headers()


class TestServer(object):
    def __init__(self, port, handler_class):
        self.httpd = _ReuseAddressTcpServer('', port, handler_class)

    def __enter__(self):
        def serve():
            self.httpd.serve_forever()

        thread_type = threading.Thread(target=serve)
        thread_type.start()
        _logger.debug('server started on %s', str(self.httpd.server_address))

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.httpd.shutdown()


class TestManager(unittest.TestCase):
    def test_authorize_ok(self):
        test_case = self

        class CheckAuthorizeHandler(FakeOAuthHandler):
            def _check_get_parameters(self, parameters):
                _logger.debug('CheckAuthorizeHandler - _check_parameters - %s', str(parameters))
                test_case.assertEqual(parameters.get('redirect_uri', None),
                                      'http://localhost:%d' % redirect_server_port)
                test_case.assertEqual(parameters.get('state', None), 'state_test')
                test_case.assertEqual(parameters.get('client_id', None), 'client_id_test')
                test_case.assertEqual(parameters.get('scope', None), 'scope1 scope2')
        with TestServer(authorize_server_port, CheckAuthorizeHandler):
            manager = None
            try:
                manager = CredentialManager(service_information, proxies=dict(http=''))
                url = manager.init_authorize_code_process('http://localhost:%d' % redirect_server_port, 'state_test')
                self.assertIsNotNone(url)
                requests.get(url, proxies=dict(http=''))
                code = manager.wait_and_terminate_authorize_code_process()
                manager = None
                self.assertEqual(code, FakeOAuthHandler.CODE)
            finally:
                if manager is not None and manager.authorization_code_context is not None:
                    manager.wait_and_terminate_authorize_code_process(0.1)

    def test_authorize_ko(self):
        test_case = self

        class CheckAuthorizeHandlerbadState(FakeOAuthHandler):
            def _check_get_parameters(self, parameters):
                test_case.assertEqual(parameters.get('redirect_uri', None),
                                      'http://localhost:%d' % redirect_server_port)
                test_case.assertEqual(parameters.get('state', None), 'state_test')
                # send bad state
                parameters['state'] = 'other_state'

        with TestServer(authorize_server_port, CheckAuthorizeHandlerbadState):
            manager = None
            try:
                manager = CredentialManager(service_information, proxies=dict(http=''))
                url = manager.init_authorize_code_process('http://localhost:%d' % redirect_server_port, 'state_test')
                self.assertIsNotNone(url)
                _logger.debug('Url got = %s', url)
                requests.get(url, proxies=dict(http=''))
                self.assertRaises(OAuthError, manager.wait_and_terminate_authorize_code_process)
            finally:
                if manager is not None and manager.authorization_code_context is not None:
                    manager.wait_and_terminate_authorize_code_process(0.1)

    def test_get_token_with_code(self):
        redirect_uri = 'http://somewhere-over-the.rainbow'

        def call_request(manager):
            manager.init_with_authorize_code(redirect_uri, FakeOAuthHandler.CODE)

        self._test_get_token(call_request,
                             dict(redirect_uri=redirect_uri, grant_type='authorization_code',
                                  code=FakeOAuthHandler.CODE, scope=' '.join(service_information.scopes)))

    def test_get_token_with_credentials(self):
        def call_request(manager):
            manager.init_with_client_credentials()

        self._test_get_token(call_request, dict(grant_type='client_credentials',
                                                scope=' '.join(service_information.scopes)),
                             no_refresh_token=True)

    def test_get_token_with_password(self):
        username = 'the username'
        password = 'the password'

        def call_request(manager):
            manager.init_with_user_credentials(username, password)

        self._test_get_token(call_request, dict(grant_type='password',
                                                scope=' '.join(service_information.scopes),
                                                username=username,
                                                password=password))

    def test_get_token_with_token(self):
        refresh_token = 'the refresh token'

        def call_request(manager):
            manager.init_with_token(refresh_token)

        self._test_get_token(call_request, dict(grant_type='refresh_token',
                                                scope=' '.join(service_information.scopes),
                                                refresh_token=refresh_token))

    def test_bearer_requests(self):
        access_token = 'the access token'
        test_case = self

        class BearerHandler(BaseHTTPRequestHandler):
            EXPECTED_METHOD = None

            def do_GET(self):
                test_case.assertEqual('GET', BearerHandler.EXPECTED_METHOD)
                self._handle_request()

            def do_POST(self):
                test_case.assertEqual('POST', BearerHandler.EXPECTED_METHOD)
                self._handle_request()

            def do_PUT(self):
                test_case.assertEqual('PUT', BearerHandler.EXPECTED_METHOD)
                self._handle_request()

            def do_PATCH(self):
                test_case.assertEqual('PATCH', BearerHandler.EXPECTED_METHOD)
                self._handle_request()

            def do_DELETE(self):
                test_case.assertEqual('DELETE', BearerHandler.EXPECTED_METHOD)
                self._handle_request()

            def _handle_request(self):
                try:
                    test_case.assertEqual(self.headers.get('Authorization', None), 'Bearer %s' % access_token)
                    self.send_response(HTTPStatus.OK.value, 'OK')
                    self.send_header("Content-type", 'text/plain')
                    self.send_header("Content-Length", 0)
                    self.end_headers()
                except AssertionError as ex:
                    body = str(ex.message)
                    self.send_response(HTTPStatus.UNAUTHORIZED.value, 'Unauthorized')
                    self.send_header("Content-type", 'text/plain')
                    self.send_header("Content-Length", len(body))
                    self.end_headers()
                    self.wfile.write(bytes(body, 'UTF-8'))

        with TestServer(api_server_port, BearerHandler):
            _logger.debug('test_get_token_with_code - server started')
            api_url = 'http://localhost:%d/api/uri' % api_server_port
            manager = CredentialManager(service_information, proxies=dict(http=''))
            manager._access_token = access_token
            BearerHandler.EXPECTED_METHOD = 'GET'
            manager.get(api_url)
            BearerHandler.EXPECTED_METHOD = 'POST'
            manager.post(api_url)
            BearerHandler.EXPECTED_METHOD = 'PUT'
            manager.put(api_url)
            BearerHandler.EXPECTED_METHOD = 'PATCH'
            manager.patch(api_url)
            BearerHandler.EXPECTED_METHOD = 'DELETE'
            manager.delete(api_url)

    def _test_get_token(self, call_request, required_parameters, no_refresh_token=False):
        test_case = self

        refresh_token = required_parameters['refresh_token'] if 'refresh_token' in required_parameters \
            else 'the refresh token'
        access_token = 'the access token'

        class CheckGetTokenWithCode(FakeOAuthHandler):
            def _handle_post(self, parameters):
                try:
                    test_case.assertEqual(self.headers.get('Authorization', None), basic_auth)
                    for name, expected_value in required_parameters.items():
                        test_case.assertEqual(parameters.get(bytes(name, 'UTF-8'), None),
                                              [bytes(expected_value, 'UTF-8')])
                    response_body = dict(access_token=access_token)
                    if not no_refresh_token:
                        response_body['refresh_token'] = refresh_token
                    response = json.dumps(response_body)
                    self.send_response(HTTPStatus.OK.value, 'OK')
                    self.send_header("Content-type", 'text/plain')
                    self.send_header("Content-Length", len(response))
                    self.end_headers()
                    self.wfile.write(bytes(response, 'UTF-8'))
                except AssertionError as error:
                    _logger.error('error - %s', error)
                    self.send_response(HTTPStatus.BAD_REQUEST.value, 'BAD_REQUEST')
                    self.send_header("Content-type", 'text/plain')
                    self.send_header("Content-Length", 0)
                    self.end_headers()

        with TestServer(token_server_port, CheckGetTokenWithCode):
            manager = CredentialManager(service_information, proxies=dict(http=''))
            call_request(manager)
            if not no_refresh_token:
                self.assertEqual(manager.refresh_token, refresh_token)
            else:
                self.assertIsNone(manager.refresh_token)
            self.assertEqual(manager._access_token, access_token)

    def test_default_user_agent(self):
        manager = CredentialManager(service_information, proxies=dict(http=''))
        manager._access_token = 'a-access-token'
        self.assertIsNone(manager.user_agent)
        self.assertIn("python-requests", manager._session.headers["User-Agent"])

    def test_custom_user_agent(self):
        user_agent = 'custom-agent'
        manager = CredentialManager(service_information, proxies=dict(http=''), user_agent=user_agent)
        manager._access_token = 'a-access-token'
        self.assertEqual(user_agent, manager.user_agent)
        self.assertEqual(user_agent, manager._session.headers["User-Agent"])
