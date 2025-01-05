import logging
import unittest
import json

import requests

from oauth2_client.http_server import start_http_server, stop_http_server

_logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG,
                    format='%(levelname)5s - %(name)s -  %(message)s')


class TestServer(unittest.TestCase):
    PORT = 9090

    SERVER = None

    CALLBACK_CONTAINER = dict()

    @classmethod
    def setUpClass(cls):
        TestServer.SERVER = start_http_server(TestServer.PORT, callback=TestServer.CALLBACK_CONTAINER.update)

    @classmethod
    def tearDownClass(cls):
        if TestServer.SERVER is not None:
            stop_http_server(TestServer.SERVER)

    def test_start(self):
        response = requests.get('http://127.0.0.1:%d' % TestServer.PORT, proxies=dict(http=''))
        self.assertIsNotNone(response)
        self.assertEqual(200, response.status_code)

    def test_response_no_parameter(self):
        response = requests.get('http://127.0.0.1:%d' % TestServer.PORT, proxies=dict(http=''))
        self.assertIsNotNone(response)
        self.assertEqual(200, response.status_code)
        self.assertEqual('text/plain', response.headers['Content-Type'])
        self.assertTrue(response.text.startswith('Response received'))
        self.assertEqual({}, self._extract_response(response.text))

    def test_response_parameter(self):
        response = requests.get('http://127.0.0.1:%d?toto=titi' % TestServer.PORT, proxies=dict(http=''))
        self.assertIsNotNone(response)
        self.assertEqual(200, response.status_code)
        self.assertEqual('text/plain', response.headers['Content-Type'])
        _logger.debug("test_response_parameter - %s", response.text)
        self.assertTrue(response.text.startswith('Response received'))
        obj_response = self._extract_response(response.text)
        self.assertIsNotNone(obj_response)
        self.assertEqual(obj_response.get('toto', None), 'titi')

    def test_callback_parameter(self):
        TestServer.CALLBACK_CONTAINER.clear()
        response = requests.get('http://127.0.0.1:%d?toto=titi' % TestServer.PORT, proxies=dict(http=''))
        self.assertIsNotNone(response)
        self.assertEqual(200, response.status_code)
        self.assertEqual('text/plain', response.headers['Content-Type'])
        self.assertEqual(TestServer.CALLBACK_CONTAINER.get('toto', None), 'titi')

    @staticmethod
    def _extract_response(text):
        idx_start = text.find('{')
        if idx_start >= 0:
            idx_end = text.find('}', idx_start)
            if idx_end >= 0:
                return json.loads(text[idx_start: idx_end + 1])
            else:
                return dict()
        else:
            return dict()
