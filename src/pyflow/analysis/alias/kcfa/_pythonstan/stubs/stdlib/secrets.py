def token_bytes(nbytes=32):
    return b"\x00" * nbytes


def token_hex(nbytes=32):
    return "0" * (nbytes * 2)


def token_urlsafe(nbytes=32):
    return "A" * nbytes


def choice(seq):
    return seq[0]


def randbelow(exclusive_upper_bound):
    return 0


def randbits(k):
    return 0


def compare_digest(a, b):
    return a == b


DEFAULT_ENTROPY = 32
