class Message:
    def __init__(self, policy=None):
        self._headers = {}
        self._payload = None
        self._charset = None
        self.policy = policy
        self.preamble = None
        self.epilogue = None
        self.defects = []

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

    def get(self, name, failobj=None):
        return self._headers.get(name.lower(), failobj)

    def get_all(self, name, failobj=None):
        val = self._headers.get(name.lower())
        return [val] if val is not None else failobj

    def add_header(self, _name, _value, **_params):
        self._headers[_name.lower()] = _value

    def replace_header(self, _name, _value):
        self._headers[_name.lower()] = _value

    def get_content_type(self):
        return self.get('content-type', 'text/plain')

    def get_content_maintype(self):
        return self.get_content_type().split('/')[0]

    def get_content_subtype(self):
        ctype = self.get_content_type()
        parts = ctype.split('/')
        return parts[1] if len(parts) > 1 else ''

    def get_payload(self, i=None, decode=False):
        if i is not None and isinstance(self._payload, list):
            return self._payload[i]
        return self._payload

    def set_payload(self, payload, charset=None):
        self._payload = payload
        self._charset = charset

    def set_charset(self, charset):
        self._charset = charset

    def get_charset(self):
        return self._charset

    def is_multipart(self):
        return isinstance(self._payload, list)

    def get_boundary(self):
        return None

    def set_boundary(self, boundary):
        pass

    def walk(self):
        yield self
        if isinstance(self._payload, list):
            for part in self._payload:
                yield from part.walk()

    def as_string(self, unixfrom=False, maxheaderlen=0, policy=None):
        result = ""
        for name, value in self._headers.items():
            result += f"{name}: {value}\n"
        result += "\n"
        if self._payload:
            result += str(self._payload)
        return result

    def as_bytes(self, unixfrom=False, policy=None):
        return self.as_string(unixfrom).encode()

    def __str__(self):
        return self.as_string()


class EmailMessage(Message):
    def __init__(self, policy=None):
        super().__init__(policy)
        self._attachments = []

    def get_body(self, preferencelist=('related', 'html', 'plain')):
        return self

    def iter_attachments(self):
        return iter(self._attachments)

    def iter_parts(self):
        if isinstance(self._payload, list):
            return iter(self._payload)
        return iter([])

    def get_content(self, *args, **kwargs):
        return self._payload

    def set_content(self, *args, **kwargs):
        if args:
            self._payload = args[0]

    def add_related(self, *args, **kwargs):
        pass

    def add_alternative(self, *args, **kwargs):
        pass

    def add_attachment(self, *args, **kwargs):
        if args:
            self._attachments.append(args[0])

    def clear(self):
        self._headers.clear()
        self._payload = None

    def clear_content(self):
        self._payload = None


class MIMEBase(Message):
    def __init__(self, _maintype, _subtype, policy=None, **_params):
        super().__init__(policy)
        self._headers['content-type'] = f"{_maintype}/{_subtype}"


class MIMEText(MIMEBase):
    def __init__(self, _text, _subtype='plain', _charset=None, policy=None):
        super().__init__('text', _subtype, policy)
        self._payload = _text
        self._charset = _charset


class MIMEImage(MIMEBase):
    def __init__(self, _imagedata, _subtype=None, _encoder=None, policy=None, **_params):
        super().__init__('image', _subtype or 'octet-stream', policy)
        self._payload = _imagedata


class MIMEAudio(MIMEBase):
    def __init__(self, _audiodata, _subtype=None, _encoder=None, policy=None, **_params):
        super().__init__('audio', _subtype or 'octet-stream', policy)
        self._payload = _audiodata


class MIMEApplication(MIMEBase):
    def __init__(self, _data, _subtype='octet-stream', _encoder=None, policy=None, **_params):
        super().__init__('application', _subtype, policy)
        self._payload = _data


class MIMEMultipart(MIMEBase):
    def __init__(self, _subtype='mixed', boundary=None, _subparts=None, policy=None, **_params):
        super().__init__('multipart', _subtype, policy)
        self._payload = list(_subparts) if _subparts else []
        self._boundary = boundary

    def attach(self, payload):
        if self._payload is None:
            self._payload = []
        self._payload.append(payload)


def message_from_string(s, _class=Message, policy=None):
    msg = _class(policy)
    msg.set_payload(s)
    return msg


def message_from_bytes(s, _class=Message, policy=None):
    msg = _class(policy)
    msg.set_payload(s.decode() if isinstance(s, bytes) else s)
    return msg


def message_from_file(fp, _class=Message, policy=None):
    return message_from_string(fp.read(), _class, policy)


def message_from_binary_file(fp, _class=Message, policy=None):
    return message_from_bytes(fp.read(), _class, policy)


class Parser:
    def __init__(self, _class=Message, policy=None):
        self._class = _class
        self.policy = policy

    def parse(self, fp, headersonly=False):
        return message_from_file(fp, self._class, self.policy)

    def parsestr(self, text, headersonly=False):
        return message_from_string(text, self._class, self.policy)


class BytesParser:
    def __init__(self, _class=Message, policy=None):
        self._class = _class
        self.policy = policy

    def parse(self, fp, headersonly=False):
        return message_from_binary_file(fp, self._class, self.policy)

    def parsebytes(self, text, headersonly=False):
        return message_from_bytes(text, self._class, self.policy)


class FeedParser:
    def __init__(self, _factory=Message, policy=None):
        self._factory = _factory
        self.policy = policy
        self._input = ""

    def feed(self, data):
        self._input += data

    def close(self):
        return message_from_string(self._input, self._factory, self.policy)


class BytesFeedParser(FeedParser):
    def __init__(self, _factory=Message, policy=None):
        super().__init__(_factory, policy)
        self._input = b""

    def feed(self, data):
        self._input += data

    def close(self):
        return message_from_bytes(self._input, self._factory, self.policy)


class Generator:
    def __init__(self, outfp, mangle_from_=None, maxheaderlen=None, policy=None):
        self._fp = outfp
        self.policy = policy

    def flatten(self, msg, unixfrom=False, linesep=None):
        self._fp.write(msg.as_string(unixfrom))


class BytesGenerator:
    def __init__(self, outfp, mangle_from_=None, maxheaderlen=None, policy=None):
        self._fp = outfp
        self.policy = policy

    def flatten(self, msg, unixfrom=False, linesep=None):
        self._fp.write(msg.as_bytes(unixfrom))
