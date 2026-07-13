class HTTPStatus:
    def __init__(self, value, phrase, description=''):
        self.value = value
        self.phrase = phrase
        self.description = description
        self._value_ = value
        self._name_ = phrase.upper().replace(' ', '_')

    @property
    def name(self):
        return self._name_

    def __int__(self):
        return self.value

    def __eq__(self, other):
        if isinstance(other, int):
            return self.value == other
        return self is other


CONTINUE = HTTPStatus(100, 'Continue')
SWITCHING_PROTOCOLS = HTTPStatus(101, 'Switching Protocols')
PROCESSING = HTTPStatus(102, 'Processing')
EARLY_HINTS = HTTPStatus(103, 'Early Hints')

OK = HTTPStatus(200, 'OK')
CREATED = HTTPStatus(201, 'Created')
ACCEPTED = HTTPStatus(202, 'Accepted')
NON_AUTHORITATIVE_INFORMATION = HTTPStatus(203, 'Non-Authoritative Information')
NO_CONTENT = HTTPStatus(204, 'No Content')
RESET_CONTENT = HTTPStatus(205, 'Reset Content')
PARTIAL_CONTENT = HTTPStatus(206, 'Partial Content')
MULTI_STATUS = HTTPStatus(207, 'Multi-Status')
ALREADY_REPORTED = HTTPStatus(208, 'Already Reported')
IM_USED = HTTPStatus(226, 'IM Used')

MULTIPLE_CHOICES = HTTPStatus(300, 'Multiple Choices')
MOVED_PERMANENTLY = HTTPStatus(301, 'Moved Permanently')
FOUND = HTTPStatus(302, 'Found')
SEE_OTHER = HTTPStatus(303, 'See Other')
NOT_MODIFIED = HTTPStatus(304, 'Not Modified')
USE_PROXY = HTTPStatus(305, 'Use Proxy')
TEMPORARY_REDIRECT = HTTPStatus(307, 'Temporary Redirect')
PERMANENT_REDIRECT = HTTPStatus(308, 'Permanent Redirect')

BAD_REQUEST = HTTPStatus(400, 'Bad Request')
UNAUTHORIZED = HTTPStatus(401, 'Unauthorized')
PAYMENT_REQUIRED = HTTPStatus(402, 'Payment Required')
FORBIDDEN = HTTPStatus(403, 'Forbidden')
NOT_FOUND = HTTPStatus(404, 'Not Found')
METHOD_NOT_ALLOWED = HTTPStatus(405, 'Method Not Allowed')
NOT_ACCEPTABLE = HTTPStatus(406, 'Not Acceptable')
PROXY_AUTHENTICATION_REQUIRED = HTTPStatus(407, 'Proxy Authentication Required')
REQUEST_TIMEOUT = HTTPStatus(408, 'Request Timeout')
CONFLICT = HTTPStatus(409, 'Conflict')
GONE = HTTPStatus(410, 'Gone')
LENGTH_REQUIRED = HTTPStatus(411, 'Length Required')
PRECONDITION_FAILED = HTTPStatus(412, 'Precondition Failed')
REQUEST_ENTITY_TOO_LARGE = HTTPStatus(413, 'Request Entity Too Large')
REQUEST_URI_TOO_LONG = HTTPStatus(414, 'Request-URI Too Long')
UNSUPPORTED_MEDIA_TYPE = HTTPStatus(415, 'Unsupported Media Type')
REQUESTED_RANGE_NOT_SATISFIABLE = HTTPStatus(416, 'Requested Range Not Satisfiable')
EXPECTATION_FAILED = HTTPStatus(417, 'Expectation Failed')
IM_A_TEAPOT = HTTPStatus(418, "I'm a Teapot")
MISDIRECTED_REQUEST = HTTPStatus(421, 'Misdirected Request')
UNPROCESSABLE_ENTITY = HTTPStatus(422, 'Unprocessable Entity')
LOCKED = HTTPStatus(423, 'Locked')
FAILED_DEPENDENCY = HTTPStatus(424, 'Failed Dependency')
TOO_EARLY = HTTPStatus(425, 'Too Early')
UPGRADE_REQUIRED = HTTPStatus(426, 'Upgrade Required')
PRECONDITION_REQUIRED = HTTPStatus(428, 'Precondition Required')
TOO_MANY_REQUESTS = HTTPStatus(429, 'Too Many Requests')
REQUEST_HEADER_FIELDS_TOO_LARGE = HTTPStatus(431, 'Request Header Fields Too Large')
UNAVAILABLE_FOR_LEGAL_REASONS = HTTPStatus(451, 'Unavailable For Legal Reasons')

INTERNAL_SERVER_ERROR = HTTPStatus(500, 'Internal Server Error')
NOT_IMPLEMENTED = HTTPStatus(501, 'Not Implemented')
BAD_GATEWAY = HTTPStatus(502, 'Bad Gateway')
SERVICE_UNAVAILABLE = HTTPStatus(503, 'Service Unavailable')
GATEWAY_TIMEOUT = HTTPStatus(504, 'Gateway Timeout')
HTTP_VERSION_NOT_SUPPORTED = HTTPStatus(505, 'HTTP Version Not Supported')
VARIANT_ALSO_NEGOTIATES = HTTPStatus(506, 'Variant Also Negotiates')
INSUFFICIENT_STORAGE = HTTPStatus(507, 'Insufficient Storage')
LOOP_DETECTED = HTTPStatus(508, 'Loop Detected')
NOT_EXTENDED = HTTPStatus(510, 'Not Extended')
NETWORK_AUTHENTICATION_REQUIRED = HTTPStatus(511, 'Network Authentication Required')


class HTTPMethod:
    def __init__(self, value, description=''):
        self.value = value
        self.description = description
        self._value_ = value
        self._name_ = value

    @property
    def name(self):
        return self._name_

    def __str__(self):
        return self.value


GET = HTTPMethod('GET')
HEAD = HTTPMethod('HEAD')
POST = HTTPMethod('POST')
PUT = HTTPMethod('PUT')
DELETE = HTTPMethod('DELETE')
CONNECT = HTTPMethod('CONNECT')
OPTIONS = HTTPMethod('OPTIONS')
TRACE = HTTPMethod('TRACE')
PATCH = HTTPMethod('PATCH')


class HTTPMessage:
    def __init__(self):
        self._headers = {}

    def get(self, name, failobj=None):
        return self._headers.get(name.lower(), failobj)

    def __getitem__(self, name):
        return self._headers.get(name.lower())

    def __setitem__(self, name, val):
        self._headers[name.lower()] = val

    def __delitem__(self, name):
        del self._headers[name.lower()]

    def __contains__(self, name):
        return name.lower() in self._headers

    def keys(self):
        return self._headers.keys()

    def values(self):
        return self._headers.values()

    def items(self):
        return self._headers.items()

    def get_all(self, name, failobj=None):
        value = self._headers.get(name.lower())
        return [value] if value is not None else failobj

    def get_content_type(self):
        return self.get('content-type', 'text/plain')

    def get_content_maintype(self):
        return self.get_content_type().split('/')[0]

    def get_content_subtype(self):
        ctype = self.get_content_type()
        parts = ctype.split('/')
        return parts[1] if len(parts) > 1 else ''


class HTTPConnection:
    def __init__(self, host, port=None, timeout=None, source_address=None, blocksize=8192):
        self.host = host
        self.port = port or 80
        self.timeout = timeout
        self.source_address = source_address
        self.blocksize = blocksize
        self._response = None

    def request(self, method, url, body=None, headers=None, encode_chunked=False):
        self._method = method
        self._url = url
        self._body = body
        self._headers = headers or {}

    def getresponse(self):
        return HTTPResponse(self)

    def set_debuglevel(self, level):
        pass

    def connect(self):
        pass

    def close(self):
        pass

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        self._method = method
        self._url = url

    def putheader(self, header, *values):
        pass

    def endheaders(self, message_body=None, encode_chunked=False):
        pass

    def send(self, data):
        pass


class HTTPSConnection(HTTPConnection):
    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 timeout=None, source_address=None, context=None, check_hostname=None,
                 blocksize=8192):
        super().__init__(host, port or 443, timeout, source_address, blocksize)
        self.key_file = key_file
        self.cert_file = cert_file
        self.context = context
        self.check_hostname = check_hostname


class HTTPResponse:
    def __init__(self, connection):
        self._connection = connection
        self.status = 200
        self.reason = "OK"
        self.headers = HTTPMessage()
        self.version = 11
        self.closed = False

    def read(self, amt=None):
        return b""

    def readinto(self, b):
        return 0

    def readline(self, limit=-1):
        return b""

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def getheaders(self):
        return list(self.headers.items())

    def info(self):
        return self.headers

    def geturl(self):
        return self._connection._url

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class HTTPException(Exception):
    pass


class NotConnected(HTTPException):
    pass


class InvalidURL(HTTPException):
    pass


class UnknownProtocol(HTTPException):
    pass


class UnknownTransferEncoding(HTTPException):
    pass


class UnimplementedFileMode(HTTPException):
    pass


class IncompleteRead(HTTPException):
    def __init__(self, partial, expected=None):
        self.partial = partial
        self.expected = expected


class ImproperConnectionState(HTTPException):
    pass


class CannotSendRequest(ImproperConnectionState):
    pass


class CannotSendHeader(ImproperConnectionState):
    pass


class ResponseNotReady(ImproperConnectionState):
    pass


class BadStatusLine(HTTPException):
    def __init__(self, line):
        self.line = line


class LineTooLong(HTTPException):
    pass


class RemoteDisconnected(ConnectionResetError, BadStatusLine):
    def __init__(self):
        BadStatusLine.__init__(self, "")


HTTP_PORT = 80
HTTPS_PORT = 443
