class _TemporaryFileWrapper:
    def __init__(self, name):
        self.name = name
        self.file = None

    def read(self, n=-1):
        return ""

    def write(self, s):
        return len(s)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class NamedTemporaryFile(_TemporaryFileWrapper):
    def __init__(self, mode='w+b', buffering=-1, encoding=None, newline=None, suffix=None, prefix=None, dir=None, delete=True):
        _TemporaryFileWrapper.__init__(self, "/tmp/tmpfile")
        self.mode = mode
        self.delete = delete


class TemporaryFile(_TemporaryFileWrapper):
    def __init__(self, mode='w+b', buffering=-1, encoding=None, newline=None, suffix=None, prefix=None, dir=None):
        _TemporaryFileWrapper.__init__(self, "/tmp/tmpfile")


class SpooledTemporaryFile(_TemporaryFileWrapper):
    def __init__(self, max_size=0, mode='w+b', buffering=-1, encoding=None, newline=None, suffix=None, prefix=None, dir=None):
        _TemporaryFileWrapper.__init__(self, "/tmp/tmpfile")
        self.max_size = max_size


class TemporaryDirectory:
    def __init__(self, suffix=None, prefix=None, dir=None):
        self.name = "/tmp/tmpdir"

    def cleanup(self):
        pass

    def __enter__(self):
        return self.name

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()
        return False


def mkstemp(suffix=None, prefix=None, dir=None, text=False):
    return (0, "/tmp/tmpfile")


def mkdtemp(suffix=None, prefix=None, dir=None):
    return "/tmp/tmpdir"


def mktemp(suffix='', prefix='tmp', dir=None):
    return "/tmp/tmpfile"


def gettempdir():
    return "/tmp"


def gettempprefix():
    return "tmp"


tempdir = None
