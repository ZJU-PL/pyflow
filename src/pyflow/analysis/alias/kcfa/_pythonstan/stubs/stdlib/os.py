class _PathModule:
    def join(self, *paths):
        return "/".join(str(p) for p in paths if p)

    def split(self, path):
        path_str = str(path)
        idx = path_str.rfind("/")
        if idx == -1:
            return ("", path_str)
        return (path_str[:idx], path_str[idx+1:])

    def dirname(self, path):
        return self.split(path)[0]

    def basename(self, path):
        return self.split(path)[1]

    def exists(self, path):
        return True

    def isfile(self, path):
        return True

    def isdir(self, path):
        return True

    def islink(self, path):
        return False

    def abspath(self, path):
        return str(path)

    def realpath(self, path):
        return str(path)

    def normpath(self, path):
        return str(path)

    def expanduser(self, path):
        return str(path)

    def expandvars(self, path):
        return str(path)

    def splitext(self, path):
        path_str = str(path)
        idx = path_str.rfind(".")
        if idx == -1:
            return (path_str, "")
        return (path_str[:idx], path_str[idx:])

    def splitdrive(self, path):
        return ("", str(path))

    def getsize(self, path):
        return 0

    def getmtime(self, path):
        return 0.0

    def getatime(self, path):
        return 0.0

    def getctime(self, path):
        return 0.0

    def isabs(self, path):
        return str(path).startswith("/")

    def commonpath(self, paths):
        return paths[0] if paths else ""

    def commonprefix(self, paths):
        return paths[0] if paths else ""

    def relpath(self, path, start=None):
        return str(path)

    def samefile(self, path1, path2):
        return str(path1) == str(path2)


path = _PathModule()


class _StatResult:
    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0.0
        self.st_mtime = 0.0
        self.st_ctime = 0.0


def stat(path):
    return _StatResult()


def lstat(path):
    return _StatResult()


def listdir(path='.'):
    return []


def getcwd():
    return "/"


def chdir(path):
    pass


def mkdir(path, mode=0o777):
    pass


def makedirs(name, mode=0o777, exist_ok=False):
    pass


def remove(path):
    pass


def unlink(path):
    pass


def rmdir(path):
    pass


def removedirs(name):
    pass


def rename(src, dst):
    pass


def renames(old, new):
    pass


def replace(src, dst):
    pass


def walk(top, topdown=True, onerror=None, followlinks=False):
    return [(top, [], [])]


def getenv(key, default=None):
    return default


def putenv(key, value):
    pass


def unsetenv(key):
    pass


environ = {}
name = "posix"
sep = "/"
altsep = None
extsep = "."
pathsep = ":"
linesep = "\n"
devnull = "/dev/null"


class _ScandirIterator:
    def __init__(self, path):
        self.path = path
        self._entries = []

    def __iter__(self):
        return iter(self._entries)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class DirEntry:
    def __init__(self, name, path):
        self.name = name
        self.path = path

    def is_dir(self):
        return True

    def is_file(self):
        return True

    def is_symlink(self):
        return False

    def stat(self):
        return _StatResult()


def scandir(path='.'):
    return _ScandirIterator(path)


def open(file, flags, mode=0o777):
    return 0


def close(fd):
    pass


def read(fd, n):
    return b""


def write(fd, data):
    return len(data)


def dup(fd):
    return fd


def dup2(fd, fd2):
    return fd2


def pipe():
    return (0, 1)


def system(command):
    return 0


def urandom(n):
    return b"\x00" * n


def access(path, mode):
    return True


def chmod(path, mode):
    pass


def chown(path, uid, gid):
    pass


def link(src, dst):
    pass


def symlink(src, dst):
    pass


def readlink(path):
    return str(path)


def utime(path, times=None):
    pass


F_OK = 0
R_OK = 4
W_OK = 2
X_OK = 1
