def copyfileobj(fsrc, fdst, length=None):
    return None


def copyfile(src, dst):
    return dst


def copymode(src, dst):
    return None


def copystat(src, dst):
    return None


def copy(src, dst):
    return dst


def copy2(src, dst):
    return dst


def copytree(src, dst, symlinks=False, ignore=None, copy_function=None, ignore_dangling_symlinks=False, dirs_exist_ok=False):
    return dst


def rmtree(path, ignore_errors=False, onerror=None):
    return None


def move(src, dst, copy_function=None):
    return dst


def disk_usage(path):
    class Usage:
        def __init__(self):
            self.total = 0
            self.used = 0
            self.free = 0
    return Usage()


def chown(path, user=None, group=None):
    return None


def which(cmd, mode=None, path=None):
    return cmd


def make_archive(base_name, format, root_dir=None, base_dir=None, verbose=0, dry_run=0, owner=None, group=None, logger=None):
    return base_name


def unpack_archive(filename, extract_dir=None, format=None):
    return None


def get_archive_formats():
    return [("zip", ""), ("tar", "")]


def get_unpack_formats():
    return [("zip", "", ""), ("tar", "", "")]


def register_archive_format(name, function, extra_args=None, description=''):
    return None


def unregister_archive_format(name):
    return None


def register_unpack_format(name, extensions, function, extra_args=None, description=''):
    return None


def unregister_unpack_format(name):
    return None


class Error(Exception):
    pass


class SameFileError(Error):
    pass


class SpecialFileError(Error):
    pass


class ExecError(Error):
    pass
