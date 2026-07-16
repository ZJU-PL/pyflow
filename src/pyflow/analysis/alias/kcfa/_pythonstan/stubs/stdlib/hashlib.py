class _Hash:
    def __init__(self, name, data=b""):
        self.name = name
        self.digest_size = 32
        self.block_size = 64
        self._data = data

    def update(self, data):
        self._data = self._data + data

    def digest(self):
        return b"\x00" * self.digest_size

    def hexdigest(self):
        return "0" * (self.digest_size * 2)

    def copy(self):
        return _Hash(self.name, self._data)


def new(name, data=b""):
    return _Hash(name, data)


def md5(data=b""):
    return _Hash("md5", data)


def sha1(data=b""):
    return _Hash("sha1", data)


def sha224(data=b""):
    return _Hash("sha224", data)


def sha256(data=b""):
    return _Hash("sha256", data)


def sha384(data=b""):
    return _Hash("sha384", data)


def sha512(data=b""):
    return _Hash("sha512", data)


def blake2b(data=b"", digest_size=64, key=b"", salt=b"", person=b"", fanout=1, depth=1, leaf_size=0, node_offset=0, node_depth=0, inner_size=0, last_node=False):
    return _Hash("blake2b", data)


def blake2s(data=b"", digest_size=32, key=b"", salt=b"", person=b"", fanout=1, depth=1, leaf_size=0, node_offset=0, node_depth=0, inner_size=0, last_node=False):
    return _Hash("blake2s", data)


def shake_128(data=b""):
    return _Hash("shake_128", data)


def shake_256(data=b""):
    return _Hash("shake_256", data)


def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
    return b"\x00" * (dklen if dklen else 32)


def scrypt(password, salt, n, r, p, maxmem=0, dklen=64):
    return b"\x00" * dklen


algorithms_guaranteed = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
algorithms_available = algorithms_guaranteed | {"blake2b", "blake2s"}
