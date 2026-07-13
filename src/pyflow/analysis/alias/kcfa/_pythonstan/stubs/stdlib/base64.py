def b64encode(s, altchars=None):
    return b"base64_" + s


def b64decode(s, altchars=None, validate=False):
    return s[7:] if s.startswith(b"base64_") else s


def standard_b64encode(s):
    return b64encode(s)


def standard_b64decode(s):
    return b64decode(s)


def urlsafe_b64encode(s):
    return b64encode(s)


def urlsafe_b64decode(s):
    return b64decode(s)


def b32encode(s):
    return b"base32_" + s


def b32decode(s, casefold=False, map01=None):
    return s[7:] if s.startswith(b"base32_") else s


def b16encode(s):
    return b"base16_" + s


def b16decode(s, casefold=False):
    return s[7:] if s.startswith(b"base16_") else s


def a85encode(b, foldspaces=False, wrapcol=0, pad=False, adobe=False):
    return b"ascii85_" + b


def a85decode(b, foldspaces=False, adobe=False, ignorechars=b' \t\n\r\x0b'):
    return b[8:] if b.startswith(b"ascii85_") else b


def b85encode(b, pad=False):
    return b"base85_" + b


def b85decode(b):
    return b[7:] if b.startswith(b"base85_") else b


def encodebytes(s):
    return b64encode(s)


def decodebytes(s):
    return b64decode(s)
