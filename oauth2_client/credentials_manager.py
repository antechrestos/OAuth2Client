import base64
import logging
from http import HTTPStatus
from threading import Event
from typing import Optional, Any, Callable
from urllib.parse import quote, urlparse

import requests
from requests import Response

from oauth2_client.http_server import start_http_server, stop_http_server

_logger = logging.getLogger(__name__)


class OAuthError(Exception):
    def __init__(self, status_code: HTTPStatus, error: str, error_description: Optional[str] = None):
        self.status_code = status_code
        self.error = error
        self.error_description = error_description

    def __str__(self) -> str:
        return '%d  - %s : %s' % (self.status_code.value, self.error, self.error_description)


class ServiceInformation(object):
    def __init__(self, authorize_service: Optional[str],
                 token_service: Optional[str],
                 client_id: str, client_secret: Optional[str],
                 scopes: list,
                 verify: bool = True):
        self.authorize_service = authorize_service
        self.token_service = token_service
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.verify = verify

    @property
    def authorization_header(self):
        return 'Basic %s' % base64.b64encode(bytes('%s:%s' % (self.client_id, self.client_secret), 'UTF-8'))\
            .decode('UTF-8')

    @property
    def public_api(self):
        return self.client_secret is None


class AuthorizeResponseCallback(dict):
    def __init__(self, *args, **kwargs):
        super(AuthorizeResponseCallback, self).__init__(*args, **kwargs)
        self.response = Event()

    def wait(self, timeout: Optional[float] = None):
        self.response.wait(timeout)

    def register_parameters(self, parameters: dict):
        self.update(parameters)
        self.response.set()


class AuthorizationContext(object):
    def __init__(self, state: str, port: int, host: str):
        self.state = state
        self.results = AuthorizeResponseCallback()
        self.server = start_http_server(port, host, self.results.register_parameters)


class CredentialManager(object):
    def __init__(self, service_information: ServiceInformation, proxies: Optional[dict] = None, user_agent: Optional[str] = None):
        self.service_information = service_information
        self.proxies = proxies if proxies is not None else dict(http='', https='')
        self.user_agent = user_agent
        self.authorization_code_context = None
        self.refresh_token = None
        self._session = None
        if not service_information.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            import warnings

            warnings.filterwarnings('ignore', 'Unverified HTTPS request is being made.*', InsecureRequestWarning)

    @staticmethod
    def _handle_bad_response(response: Response):
        try:
            error = response.json()
            raise OAuthError(HTTPStatus(response.status_code), error.get('error'), error.get('error_description'))
        except BaseException as ex:
            if type(ex) != OAuthError:
                _logger.exception(
                    '_handle_bad_response - error while getting error as json - %s - %s' % (type(ex), str(ex)))
                raise OAuthError(HTTPStatus(response.status_code), 'unknown_error', response.text)
            else:
                raise

    def generate_authorize_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        parameters = dict(client_id=self.service_information.client_id,
                          redirect_uri=redirect_uri,
                          response_type='code',
                          scope=' '.join(self.service_information.scopes),
                          state=state,
                          **kwargs)
        return '%s?%s' % (self.service_information.authorize_service,
                          '&'.join('%s=%s' % (k, quote(v, safe='~()*!.\'')) for k, v in parameters.items()))

    def init_authorize_code_process(self, redirect_uri: str, state: str = '', **kwargs) -> str:
        uri_parsed = urlparse(redirect_uri)
        if uri_parsed.scheme == 'https':
            raise NotImplementedError("Redirect uri cannot be secured")
        elif uri_parsed.port == '' or uri_parsed.port is None:
            _logger.warning('You should use a port above 1024 for redirect uri server')
            port = 80
        else:
            port = int(uri_parsed.port)
        if uri_parsed.hostname != 'localhost' and uri_parsed.hostname != '127.0.0.1':
            _logger.warning(
                'Remember to put %s in your hosts config to point to loop back address' % uri_parsed.hostname)
        self.authorization_code_context = AuthorizationContext(state, port, uri_parsed.hostname)
        return self.generate_authorize_url(redirect_uri, state, **kwargs)

    def wait_and_terminate_authorize_code_process(self, timeout: Optional[float] = None) -> str:
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
                    raise OAuthError(HTTPStatus.UNAUTHORIZED, error, error_description)
                elif state != self.authorization_code_context.state:
                    _logger.warning('State received does not match the one that was sent')
                    raise OAuthError(HTTPStatus.INTERNAL_SERVER_ERROR, 'invalid_state',
                                     'Sate returned does not match: Sent(%s) <> Got(%s)'
                                     % (self.authorization_code_context.state, state))
                elif code is None:
                    raise OAuthError(HTTPStatus.INTERNAL_SERVER_ERROR, 'no_code', 'No code returned')
                else:
                    return code
            finally:
                stop_http_server(self.authorization_code_context.server)
                self.authorization_code_context = None

    def init_with_authorize_code(self, redirect_uri: str, code: str, **kwargs):
        self._token_request(self._grant_code_request(code, redirect_uri, **kwargs),
                            "offline_access" in self.service_information.scopes)

    def init_with_user_credentials(self, login: str, password: str):
        self._token_request(self._grant_password_request(login, password), True)

    def init_with_client_credentials(self):
        self._token_request(self._grant_client_credentials_request(), False)

    def init_with_token(self, refresh_token: str):
        self._token_request(self._grant_refresh_token_request(refresh_token), False)
        if self.refresh_token is None:
            self.refresh_token = refresh_token

    def _grant_code_request(self, code: str, redirect_uri: str, **kwargs) -> dict:
        return dict(grant_type='authorization_code',
                    code=code,
                    scope=' '.join(self.service_information.scopes),
                    redirect_uri=redirect_uri,
                    **kwargs)

    def _grant_password_request(self, login: str, password: str) -> dict:
        return dict(grant_type='password',
                    username=login,
                    scope=' '.join(self.service_information.scopes),
                    password=password)

    def _grant_client_credentials_request(self) -> dict:
        return dict(grant_type="client_credentials", scope=' '.join(self.service_information.scopes))

    def _grant_refresh_token_request(self, refresh_token: str) -> dict:
        return dict(grant_type="refresh_token",
                    scope=' '.join(self.service_information.scopes),
                    refresh_token=refresh_token)

    def _refresh_token(self):
        payload = self._grant_refresh_token_request(self.refresh_token)
        try:
            self._token_request(payload, False)
        except OAuthError as err:
            if err.status_code == HTTPStatus.UNAUTHORIZED:
                _logger.debug('refresh_token - unauthorized - cleaning token')
                self._session = None
                self.refresh_token = None
            raise err

    def _token_request(self, request_parameters: dict, refresh_token_mandatory: bool):
        headers = self._token_request_headers(request_parameters['grant_type'])
        if self.service_information.public_api:
            request_parameters["client_id"] = self.service_information.client_id
        else:
            headers['Authorization'] = self.service_information.authorization_header
        response = requests.post(self.service_information.token_service,
                                 data=request_parameters,
                                 headers=headers,
                                 proxies=self.proxies,
                                 verify=self.service_information.verify)
        if response.status_code != HTTPStatus.OK.value:
            CredentialManager._handle_bad_response(response)
        else:
            _logger.debug(response.text)
            self._process_token_response(response.json(), refresh_token_mandatory)

    def _process_token_response(self, token_response: dict, refresh_token_mandatory: bool):
        self.refresh_token = token_response['refresh_token'] if refresh_token_mandatory \
            else token_response.get('refresh_token')
        self._access_token = token_response['access_token']

    @property
    def _access_token(self) -> Optional[str]:
        authorization_header = self._session.headers.get('Authorization') if self._session is not None else None
        if authorization_header is not None:
            return authorization_header[len('Bearer '):]
        else:
            return None

    @_access_token.setter
    def _access_token(self, access_token: str):
        if self._session is None:
            self._session = requests.Session()
            self._session.proxies = self.proxies
            self._session.verify = self.service_information.verify
            self._session.trust_env = False
            if self.user_agent:
                self._session.headers.update({'User-Agent': self.user_agent})
        if access_token is not None and len(access_token) > 0:
            self._session.headers.update(dict(Authorization='Bearer %s' % access_token))

    def get(self, url: str, params: Optional[dict] = None, **kwargs) -> Response:
        kwargs['params'] = params
        return self._bearer_request(self._get_session().get, url, **kwargs)

    def post(self, url: str, data: Optional[Any] = None, json: Optional[Any] = None, **kwargs) -> Response:
        kwargs['data'] = data
        kwargs['json'] = json
        return self._bearer_request(self._get_session().post, url, **kwargs)

    def put(self, url: str, data: Optional[Any] = None, json: Optional[Any] = None, **kwargs) -> Response:
        kwargs['data'] = data
        kwargs['json'] = json
        return self._bearer_request(self._get_session().put, url, **kwargs)

    def patch(self, url: str, data: Optional[Any] = None, json: Optional[Any] = None, **kwargs) -> Response:
        kwargs['data'] = data
        kwargs['json'] = json
        return self._bearer_request(self._get_session().patch, url, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self._bearer_request(self._get_session().delete, url, **kwargs)

    def _get_session(self) -> requests.Session:
        if self._session is None:
            raise OAuthError(HTTPStatus.UNAUTHORIZED, 'no_token', "no token provided")
        return self._session

    def _bearer_request(self, method: Callable[[Any], Response], url: str, **kwargs) -> Response:
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
    def _token_request_headers(grant_type: str) -> dict:
        return dict()

    @staticmethod
    def _is_token_expired(response: Response) -> bool:
        if response.status_code == HTTPStatus.UNAUTHORIZED.value:
            try:
                json_data = response.json()
                return json_data.get('error') == 'invalid_token'
            except ValueError:
                return False
        else:
            return False
