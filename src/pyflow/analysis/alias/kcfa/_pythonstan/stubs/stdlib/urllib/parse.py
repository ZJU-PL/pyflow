class ParseResult:
    def __init__(self, scheme, netloc, path, params, query, fragment):
        self.scheme = scheme
        self.netloc = netloc
        self.path = path
        self.params = params
        self.query = query
        self.fragment = fragment

    def geturl(self):
        return urlunparse(self)

    @property
    def hostname(self):
        return self.netloc.split(':')[0] if self.netloc else None

    @property
    def port(self):
        parts = self.netloc.split(':')
        return int(parts[1]) if len(parts) > 1 else None

    @property
    def username(self):
        if '@' in self.netloc:
            userinfo = self.netloc.split('@')[0]
            return userinfo.split(':')[0]
        return None

    @property
    def password(self):
        if '@' in self.netloc:
            userinfo = self.netloc.split('@')[0]
            parts = userinfo.split(':')
            return parts[1] if len(parts) > 1 else None
        return None

    def __iter__(self):
        return iter((self.scheme, self.netloc, self.path, self.params, self.query, self.fragment))

    def __getitem__(self, index):
        return (self.scheme, self.netloc, self.path, self.params, self.query, self.fragment)[index]


class SplitResult:
    def __init__(self, scheme, netloc, path, query, fragment):
        self.scheme = scheme
        self.netloc = netloc
        self.path = path
        self.query = query
        self.fragment = fragment

    def geturl(self):
        return urlunsplit(self)

    @property
    def hostname(self):
        return self.netloc.split(':')[0] if self.netloc else None

    @property
    def port(self):
        parts = self.netloc.split(':')
        return int(parts[1]) if len(parts) > 1 else None

    def __iter__(self):
        return iter((self.scheme, self.netloc, self.path, self.query, self.fragment))

    def __getitem__(self, index):
        return (self.scheme, self.netloc, self.path, self.query, self.fragment)[index]


class DefragResult:
    def __init__(self, url, fragment):
        self.url = url
        self.fragment = fragment

    def __iter__(self):
        return iter((self.url, self.fragment))

    def __getitem__(self, index):
        return (self.url, self.fragment)[index]


def urlparse(url, scheme='', allow_fragments=True):
    return ParseResult(scheme, "", url, "", "", "")


def urlunparse(components):
    scheme, netloc, path, params, query, fragment = components
    url = ""
    if scheme:
        url = scheme + "://"
    if netloc:
        url += netloc
    url += path
    if params:
        url += ";" + params
    if query:
        url += "?" + query
    if fragment:
        url += "#" + fragment
    return url


def urlsplit(url, scheme='', allow_fragments=True):
    return SplitResult(scheme, "", url, "", "")


def urlunsplit(components):
    scheme, netloc, path, query, fragment = components
    url = ""
    if scheme:
        url = scheme + "://"
    if netloc:
        url += netloc
    url += path
    if query:
        url += "?" + query
    if fragment:
        url += "#" + fragment
    return url


def urljoin(base, url, allow_fragments=True):
    return base + url


def urldefrag(url):
    return DefragResult(url, "")


def quote(string, safe='/', encoding=None, errors=None):
    return string


def quote_plus(string, safe='', encoding=None, errors=None):
    return string


def unquote(string, encoding='utf-8', errors='replace'):
    return string


def unquote_plus(string, encoding='utf-8', errors='replace'):
    return string


def quote_from_bytes(bs, safe=b'/'):
    return bs.decode() if isinstance(bs, bytes) else bs


def unquote_to_bytes(string):
    return string.encode() if isinstance(string, str) else string


def urlencode(query, doseq=False, safe='', encoding=None, errors=None, quote_via=quote_plus):
    if isinstance(query, dict):
        items = query.items()
    else:
        items = query
    return "&".join(f"{k}={v}" for k, v in items)


def parse_qs(qs, keep_blank_values=False, strict_parsing=False, encoding='utf-8',
             errors='replace', max_num_fields=None, separator='&'):
    return {"_": [qs]}


def parse_qsl(qs, keep_blank_values=False, strict_parsing=False, encoding='utf-8',
              errors='replace', max_num_fields=None, separator='&'):
    return [("_", qs)]


def splittype(url):
    return (None, url)


def splithost(url):
    return (None, url)


def splituser(host):
    return (None, host)


def splitpasswd(user):
    return (user, None)


def splitport(host):
    return (host, None)


def splitnport(host, defport=-1):
    return (host, defport)


def splitquery(url):
    return (url, None)


def splittag(url):
    return (url, None)


def splitattr(url):
    return (url, [])


def splitvalue(attr):
    return (attr, None)


def unwrap(url):
    return url


uses_relative = ['ftp', 'http', 'gopher', 'nntp', 'imap', 'wais', 'file', 'https', 'shttp', 'mms', 'prospero', 'rtsp', 'rtspu', 'sftp', 'svn', 'svn+ssh', 'ws', 'wss']
uses_netloc = ['ftp', 'http', 'gopher', 'nntp', 'telnet', 'imap', 'wais', 'file', 'mms', 'https', 'shttp', 'snews', 'prospero', 'rtsp', 'rtspu', 'rsync', 'svn', 'svn+ssh', 'sftp', 'nfs', 'git', 'git+ssh', 'ws', 'wss']
uses_params = ['ftp', 'hdl', 'prospero', 'http', 'imap', 'https', 'shttp', 'rtsp', 'rtspu', 'sip', 'sips', 'mms', 'sftp', 'tel']
uses_query = ['http', 'wais', 'imap', 'https', 'shttp', 'mms', 'gopher', 'rtsp', 'rtspu', 'sip', 'sips']
uses_fragment = ['ftp', 'hdl', 'http', 'gopher', 'news', 'nntp', 'wais', 'https', 'shttp', 'snews', 'file', 'prospero']
