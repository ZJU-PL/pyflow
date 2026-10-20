"""Source model for POSIX path operations, also used for os.path."""


def join(*paths):
    # The pointer model summarizes the resulting string, not its spelling.
    return str(paths)


def split(path):
    path_str = str(path)
    idx = path_str.rfind("/")
    if idx == -1:
        return ("", path_str)
    return (path_str[:idx], path_str[idx + 1 :])


def dirname(path):
    return split(path)[0]


def basename(path):
    return split(path)[1]


def exists(path):
    return True


def isfile(path):
    return True


def isdir(path):
    return True


def islink(path):
    return False


def abspath(path):
    return str(path)


def realpath(path):
    return str(path)


def normpath(path):
    return str(path)


def expanduser(path):
    return str(path)


def expandvars(path):
    return str(path)


def splitext(path):
    path_str = str(path)
    idx = path_str.rfind(".")
    if idx == -1:
        return (path_str, "")
    return (path_str[:idx], path_str[idx:])


def splitdrive(path):
    return ("", str(path))


def getsize(path):
    return 0


def getmtime(path):
    return 0.0


def getatime(path):
    return 0.0


def getctime(path):
    return 0.0


def isabs(path):
    return str(path).startswith("/")


def commonpath(paths):
    return paths[0] if paths else ""


def commonprefix(paths):
    return paths[0] if paths else ""


def relpath(path, start=None):
    return str(path)


def samefile(path1, path2):
    return str(path1) == str(path2)
