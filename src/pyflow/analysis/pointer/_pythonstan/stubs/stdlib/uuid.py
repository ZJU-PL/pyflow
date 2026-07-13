class UUID:
    def __init__(self, hex=None, bytes=None, bytes_le=None, fields=None, int=None, version=None):
        self.hex = hex if hex else "00000000000000000000000000000000"
        self.bytes = bytes if bytes else b"\x00" * 16
        self.int = int if int else 0
        self.version = version

    def __str__(self):
        return self.hex

    def __int__(self):
        return self.int


def uuid1(node=None, clock_seq=None):
    return UUID(hex="00000000000000000000000000000001")


def uuid3(namespace, name):
    return UUID(hex="00000000000000000000000000000003")


def uuid4():
    return UUID(hex="00000000000000000000000000000004")


def uuid5(namespace, name):
    return UUID(hex="00000000000000000000000000000005")


NAMESPACE_DNS = UUID(hex="6ba7b8109dad11d180b400c04fd430c8")
NAMESPACE_URL = UUID(hex="6ba7b8119dad11d180b400c04fd430c8")
NAMESPACE_OID = UUID(hex="6ba7b8129dad11d180b400c04fd430c8")
NAMESPACE_X500 = UUID(hex="6ba7b8149dad11d180b400c04fd430c8")
