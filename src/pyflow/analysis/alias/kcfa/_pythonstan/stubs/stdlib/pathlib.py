class PurePath:
    def __init__(self, *pathsegments):
        if pathsegments:
            self._path = "/".join(str(p) for p in pathsegments)
        else:
            self._path = ""
        self._parts = self._path.split("/") if self._path else []

    @property
    def parts(self):
        return tuple(self._parts)

    @property
    def drive(self):
        return ""

    @property
    def root(self):
        return "/" if self._path.startswith("/") else ""

    @property
    def anchor(self):
        return self.root

    @property
    def parents(self):
        return [PurePath("/".join(self._parts[:-i])) for i in range(1, len(self._parts))]

    @property
    def parent(self):
        return PurePath("/".join(self._parts[:-1])) if len(self._parts) > 1 else PurePath()

    @property
    def name(self):
        return self._parts[-1] if self._parts else ""

    @property
    def suffix(self):
        name = self.name
        if "." in name:
            return "." + name.split(".")[-1]
        return ""

    @property
    def suffixes(self):
        name = self.name
        parts = name.split(".")[1:]
        return ["." + p for p in parts]

    @property
    def stem(self):
        name = self.name
        if "." in name:
            return name.rsplit(".", 1)[0]
        return name

    def as_posix(self):
        return self._path

    def __str__(self):
        return self._path

    def __truediv__(self, other):
        return PurePath(self._path, str(other))

    def joinpath(self, *other):
        return PurePath(self._path, *other)

    def match(self, pattern):
        return pattern in self._path

    def relative_to(self, other):
        other_str = str(other)
        if self._path.startswith(other_str):
            return PurePath(self._path[len(other_str):].lstrip("/"))
        raise ValueError(f"{self._path} is not relative to {other_str}")

    def with_name(self, name):
        return PurePath("/".join(self._parts[:-1] + [name]))

    def with_suffix(self, suffix):
        return PurePath("/".join(self._parts[:-1] + [self.stem + suffix]))


class PurePosixPath(PurePath):
    pass


class PureWindowsPath(PurePath):
    pass


class Path(PurePath):
    def __new__(cls, *args, **kwargs):
        return object.__new__(cls)

    def exists(self):
        return True

    def is_dir(self):
        return True

    def is_file(self):
        return True

    def is_symlink(self):
        return False

    def is_absolute(self):
        return self._path.startswith("/")

    def stat(self):
        class StatResult:
            def __init__(self):
                self.st_size = 0
                self.st_mtime = 0
                self.st_mode = 0
        return StatResult()

    def glob(self, pattern):
        return [self]

    def rglob(self, pattern):
        return [self]

    def iterdir(self):
        return [self]

    def open(self, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
        class File:
            def __init__(self, path):
                self.path = path
            def read(self):
                return ""
            def write(self, s):
                return len(s)
            def close(self):
                pass
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
        return File(self)

    def read_text(self, encoding=None, errors=None):
        return ""

    def read_bytes(self):
        return b""

    def write_text(self, data, encoding=None, errors=None):
        return len(data)

    def write_bytes(self, data):
        return len(data)

    def mkdir(self, mode=0o777, parents=False, exist_ok=False):
        pass

    def touch(self, mode=0o666, exist_ok=True):
        pass

    def unlink(self, missing_ok=False):
        pass

    def rmdir(self):
        pass

    def rename(self, target):
        return Path(target)

    def replace(self, target):
        return Path(target)

    def resolve(self, strict=False):
        return self

    def absolute(self):
        return self

    def expanduser(self):
        return self

    def home(self):
        return Path("/home/user")

    def cwd(self):
        return Path("/")


class PosixPath(Path):
    pass


class WindowsPath(Path):
    pass
