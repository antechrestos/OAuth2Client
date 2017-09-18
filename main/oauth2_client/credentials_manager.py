import base64
import logging
import json
from threading import Event

from oauth2_client.imported import *
from oauth2_client.http_server import start_http_server, stop_http_server


_logger = logging.getLogger(__name__)


class OAuthError(BaseException):
    def __init__(self, status_code, error, error_description=None):
        self.status_code = status_code
        self.error = error
        self.error_description = error_description

    def __str__(self):
        return '%d  - %s : %s' % (self.status_code, self.error, self.error_description)


class ServiceInformation(object):
    def __init__(self, authorize_service, token_service, client_id, client_secret, scopes,
                 skip_ssl_verifications=False):
        self.authorize_service = authorize_service
        self.token_service = token_service
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.auth = unbufferize_buffer(
            base64.b64encode(bufferize_string('%s:%s' % (self.client_id, self.client_secret))))
        self.skip_ssl_verifications = skip_ssl_verifications


class AuthorizeResponseCallback(dict):
    def __init__(self, *args, **kwargs):
        super(AuthorizeResponseCallback, self).__init__(*args, **kwargs)
        self.response = Event()

    def wait(self, timeout=None):
        self.response.wait(timeout)

    def register_parameters(self, parameters):
        self.update(parameters)
        self.response.set()


class AuthorizationContext(object):
    def __init__(self, state, port, host):
        self.state = state
        self.results = AuthorizeResponseCallback()
        self.server = start_http_server(port, host, self.results.register_parameters)


class CredentialManager(object):
    def __init__(self, service_information, proxies=None):
        self.service_information = service_information
        self.proxies = proxies if proxies is not None else dict(http='', https='')
        self.authorization_code_context = None
        self.refresh_token = None
        self._response_tokens = None
        self._session = None
        if service_information.skip_ssl_verifications:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            import warnings

            warnings.filterwarnings('ignore', 'Unverified HTTPS request is being made.*', InsecureRequestWarning)

    @staticmethod
    def _handle_bad_response(response):
        try:
            error = response.json()
            raise OAuthError(response.status_code, error.get('error'), error.get('error_description'))
        except BaseException as ex:
            if type(ex) != OAuthError:
                _logger.exception('_handle_bad_response - error while getting error as json - %s - %s' % (type(ex), str(ex)))
                raise OAuthError(response.status_code, 'unknown_error', response.text)
            else:
                raise

    def generate_authorize_url(self, redirect_uri, state):
        parameters = dict(client_id=self.service_information.client_id,
                          redirect_uri=redirect_uri,
                          response_type='code',
                          scope=' '.join(self.service_information.scopes),
                          state=state)
        return '%s?%s' % (self.service_information.authorize_service,
                          '&'.join('%s=%s' % (k, quote(v, safe='~()*!.\'')) for k, v in parameters.items()))

    def init_authorize_code_process(self, redirect_uri, state=''):
        uri_parsed = urlparse(redirect_uri)
        if uri_parsed.scheme == 'https':
            raise NotImplementedError("Redirect uri cannot be secured")
        elif uri_parsed.port == '' or uri_parsed.port is None:
            _logger.warn('You should use a port above 1024 for redirect uri server')
            port = 80
        else:
            port = int(uri_parsed.port)
        if uri_parsed.hostname != 'localhost' and uri_parsed.hostname != '127.0.0.1':
            _logger.warn('Remember to put %s in your hosts config to point to loop back address' % uri_parsed.hostname)
        self.authorization_code_context = AuthorizationContext(state, port, uri_parsed.hostname)
        return self.generate_authorize_url(redirect_uri, state)

    def wait_and_terminate_authorize_code_process(self, timeout=None):
        if self.authorization_code_context is None:
            raise Exception('Authorization code not started')
        else:
            try:
                self.authorization_code_context.results.wait(timeout)
                error = self.authorization_code_context.results.get('error', None)
                error_description = self.authorization_code_context.results.get('error_description', '')
                code = self.authorization_code_context.results.get('code', None)
                state = self.authorization_code_context.results.get('state', None)
                if error is not None:
                    raise OAuthError(UNAUTHORIZED, error,error_description)
                elif state != self.authorization_code_context.state:
                    _logger.warn('State received does not match the one that was sent')
                    raise OAuthError(INTERNAL_SERVER_ERROR, 'invalid_state',
                                     'Sate returned does not match: Sent(%s) <> Got(%s)'
                                     % (self.authorization_code_context.state, state))
                elif code is None:
                    raise OAuthError(INTERNAL_SERVER_ERROR, 'no_code', 'No code returned')
                else:
                    return code
            finally:
                stop_http_server(self.authorization_code_context.server)
                self.authorization_code_context = None

    def init_with_authorize_code(self, redirect_uri, code):
        request_parameters = dict(code=code, grant_type="authorization_code",
                                  scope=' '.join(self.service_information.scopes),
                                  redirect_uri=redirect_uri)
        self._token_request(request_parameters)

    def init_with_user_credentials(self, login, password):
        request_parameters = dict(username=login, grant_type="password",
                                  scope=' '.join(self.service_information.scopes),
                                  password=password)
        self._token_request(request_parameters)

    def init_with_client_credentials(self):
        request_parameters = dict(grant_type="client_credentials",
                                  scope=' '.join(self.service_information.scopes))
        self._token_request(request_parameters, False)

    def init_with_token(self, refresh_token):
        request_parameters = dict(grant_type="refresh_token",
                                  scope=' '.join(self.service_information.scopes),
                                  refresh_token=refresh_token)
        self._token_request(request_parameters)

    def _refresh_token(self):
        request_parameters = dict(grant_type="refresh_token",
                                  scope=' '.join(self.service_information.scopes),
                                  refresh_token=self.refresh_token)
        try:
            self._token_request(request_parameters)
        except OAuthError as err:
            if err.status_code == UNAUTHORIZED:
                _logger.debug('refresh_token - unauthorized - cleaning token')
                self._session = None
                self.refresh_token = None
            raise err

    def _token_request(self, request_parameters, contain_refresh_token=True):
        response = requests.post(self.service_information.token_service,
                                 data=request_parameters,
                                 headers=dict(Authorization='Basic %s' % self.service_information.auth),
                                 proxies=self.proxies,
                                 verify=not self.service_information.skip_ssl_verifications)
        if response.status_code != OK:
            CredentialManager._handle_bad_response(response)
        else:
            _logger.debug(response.text)
            self._response_tokens = response.json()
            if contain_refresh_token and 'refresh_token' in request_parameters:
                self.refresh_token = self._response_tokens.get('refresh_token', request_parameters['refresh_token'])
            elif contain_refresh_token:
                self.refresh_token = self._response_tokens['refresh_token']
            self._access_token = self._response_tokens['access_token']

    @property
    def _access_token(self):
        if self._session is not None:
            return self._session.headers['Authorization'][len('Bearer '):]
        else:
            return None

    @_access_token.setter
    def _access_token(self, access_token):
        if self._session is None:
            self._session = requests.Session()
            self._session.proxies = self.proxies
            self._session.verify = not self.service_information.skip_ssl_verifications
            self._session.trust_env = False
        self._session.headers.update(dict(Authorization='Bearer %s' % access_token))

    def get(self, url, params=None, **kwargs):
        kwargs['params'] = params
        return self._bearer_request(self._get_session().get, url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        kwargs['data'] = data
        kwargs['json'] = json
        return self._bearer_request(self._get_session().post, url, **kwargs)

    def put(self, url, data=None, json=None, **kwargs):
        kwargs['data'] = data
        kwargs['json'] = json
        return self._bearer_request(self._get_session().put, url, **kwargs)

    def patch(self, url, data=None, json=None, **kwargs):
        kwargs['data'] = data
        kwargs['json'] = json
        return self._bearer_request(self._get_session().patch, url, **kwargs)

    def delete(self, url, **kwargs):
        return self._bearer_request(self._get_session().delete, url, **kwargs)

    def _get_session(self):
        if self._session is None:
            raise OAuthError(UNAUTHORIZED, 'no_token', "no token provided")
        return self._session

    def _bearer_request(self, method, url, **kwargs):
        headers = kwargs.get('headers', None)
        if headers is None:
            headers = dict()
            kwargs['headers'] = headers
        _logger.debug("_bearer_request on %s - %s" % (method.__name__, url))
        response = method(url, **kwargs)
        if self.refresh_token is not None and self._is_token_expired(response):
            self._refresh_token()
            return method(url, **kwargs)
        else:
            return response

    @staticmethod
    def _is_token_expired(response):
        if response.status_code == UNAUTHORIZED:
            try:
                json_data = response.json()
                return json_data.get('error', '') == 'invalid_token'
            except:
                return False
        else:
            return False
