class HMAC:
    def __init__(self, key, msg=None, digestmod=None):
        self.key = key
        self._msg = msg if msg else b""
        self.digestmod = digestmod
        self.digest_size = 32
        self.block_size = 64

    def update(self, msg):
        self._msg = self._msg + msg

    def digest(self):
        return b"\x00" * self.digest_size

    def hexdigest(self):
        return "0" * (self.digest_size * 2)

    def copy(self):
        return HMAC(self.key, self._msg, self.digestmod)


def new(key, msg=None, digestmod=None):
    return HMAC(key, msg, digestmod)


def compare_digest(a, b):
    return a == b


def digest(key, msg, digest):
    return b"\x00" * 32
