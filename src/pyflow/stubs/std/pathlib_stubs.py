from __future__ import absolute_import

from ..stubcollector import stubgenerator

import pathlib


@stubgenerator
def makePathlibStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### PurePath ###
    @export
    @attachPtr(pathlib, "PurePath")
    @llfunc
    def pathlib_PurePath(*args):
        return allocate(pathlib.PurePath)

    @export
    @attachPtr(pathlib, "PurePosixPath")
    @llfunc
    def pathlib_PurePosixPath(*args):
        return allocate(pathlib.PurePosixPath)

    @export
    @attachPtr(pathlib, "PureWindowsPath")
    @llfunc
    def pathlib_PureWindowsPath(*args):
        return allocate(pathlib.PureWindowsPath)

    ### Path ###
    @export
    @attachPtr(pathlib, "Path")
    @llfunc
    def pathlib_Path(*args):
        return allocate(pathlib.Path)

    @export
    @attachPtr(pathlib, "PosixPath")
    @llfunc
    def pathlib_PosixPath(*args):
        return allocate(pathlib.PosixPath)

    @export
    @attachPtr(pathlib, "WindowsPath")
    @llfunc
    def pathlib_WindowsPath(*args):
        return allocate(pathlib.WindowsPath)

    ### Path methods ###
    @attachPtr(pathlib.Path, "exists")
    @llfunc
    def path_exists(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_file")
    @llfunc
    def path_is_file(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_dir")
    @llfunc
    def path_is_dir(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_symlink")
    @llfunc
    def path_is_symlink(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_mount")
    @llfunc
    def path_is_mount(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_socket")
    @llfunc
    def path_is_socket(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_fifo")
    @llfunc
    def path_is_fifo(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_block_device")
    @llfunc
    def path_is_block_device(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_char_device")
    @llfunc
    def path_is_char_device(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_absolute")
    @llfunc
    def path_is_absolute(self):
        return allocate(bool)

    @attachPtr(pathlib.Path, "is_relative_to")
    @llfunc
    def path_is_relative_to(self, other):
        return allocate(bool)

    @attachPtr(pathlib.Path, "stat")
    @llfunc
    def path_stat(self, follow_symlinks=True):
        return allocate(type(pathlib.Path(".").stat()))

    @attachPtr(pathlib.Path, "lstat")
    @llfunc
    def path_lstat(self):
        return allocate(type(pathlib.Path(".").stat()))

    @attachPtr(pathlib.Path, "resolve")
    @llfunc
    def path_resolve(self, strict=False):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "absolute")
    @llfunc
    def path_absolute(self):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "cwd")
    @llfunc
    def path_cwd(cls):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "home")
    @llfunc
    def path_home(cls):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "name")
    @llfunc
    def path_name_get(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "suffix")
    @llfunc
    def path_suffix_get(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "suffixes")
    @llfunc
    def path_suffixes_get(self):
        return allocate(list)

    @attachPtr(pathlib.Path, "stem")
    @llfunc
    def path_stem_get(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "parent")
    @llfunc
    def path_parent_get(self):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "parents")
    @llfunc
    def path_parents_get(self):
        return allocate(type(pathlib.Path(".").parents))

    @attachPtr(pathlib.Path, "parts")
    @llfunc
    def path_parts_get(self):
        return allocate(tuple)

    @attachPtr(pathlib.Path, "anchor")
    @llfunc
    def path_anchor_get(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "drive")
    @llfunc
    def path_drive_get(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "root")
    @llfunc
    def path_root_get(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "joinpath")
    @llfunc
    def path_joinpath(self, *args):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "with_name")
    @llfunc
    def path_with_name(self, name):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "with_stem")
    @llfunc
    def path_with_stem(self, stem):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "with_suffix")
    @llfunc
    def path_with_suffix(self, suffix):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "relative_to")
    @llfunc
    def path_relative_to(self, other, walk_up=False):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "match")
    @llfunc
    def path_match(self, pattern):
        return allocate(bool)

    @attachPtr(pathlib.Path, "glob")
    @llfunc
    def path_glob(self, pattern):
        return allocate(type(pathlib.Path(".").glob("*")))

    @attachPtr(pathlib.Path, "rglob")
    @llfunc
    def path_rglob(self, pattern):
        return allocate(type(pathlib.Path(".").rglob("*")))

    ### File operations ###
    @attachPtr(pathlib.Path, "open")
    @llfunc
    def path_open(self, mode='r', buffering=-1, encoding=None, errors=None, newline=None):
        return allocate(type(open(".")))

    @attachPtr(pathlib.Path, "read_bytes")
    @llfunc
    def path_read_bytes(self):
        return allocate(bytes)

    @attachPtr(pathlib.Path, "read_text")
    @llfunc
    def path_read_text(self, encoding=None, errors=None):
        return allocate(str)

    @attachPtr(pathlib.Path, "write_bytes")
    @llfunc
    def path_write_bytes(self, data):
        return allocate(int)

    @attachPtr(pathlib.Path, "write_text")
    @llfunc
    def path_write_text(self, data, encoding=None, errors=None, newline=None):
        return allocate(int)

    @attachPtr(pathlib.Path, "mkdir")
    @llfunc
    def path_mkdir(self, mode=0o777, parents=False, exist_ok=False):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "rmdir")
    @llfunc
    def path_rmdir(self):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "unlink")
    @llfunc
    def path_unlink(self, missing_ok=False):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "rename")
    @llfunc
    def path_rename(self, target):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "replace")
    @llfunc
    def path_replace(self, target):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "touch")
    @llfunc
    def path_touch(self, mode=0o666, exist_ok=True):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "chmod")
    @llfunc
    def path_chmod(self, mode, follow_symlinks=True):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "lchmod")
    @llfunc
    def path_lchmod(self, mode):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "symlink_to")
    @llfunc
    def path_symlink_to(self, target, target_is_directory=False):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "hardlink_to")
    @llfunc
    def path_hardlink_to(self, target):
        return allocate(type(None))

    @attachPtr(pathlib.Path, "readlink")
    @llfunc
    def path_readlink(self):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "owner")
    @llfunc
    def path_owner(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "group")
    @llfunc
    def path_group(self):
        return allocate(str)

    ### Directory listing ###
    @attachPtr(pathlib.Path, "iterdir")
    @llfunc
    def path_iterdir(self):
        return allocate(type(pathlib.Path(".").iterdir()))

    @attachPtr(pathlib.Path, "__iter__")
    @llfunc
    def path__iter__(self):
        return allocate(type(pathlib.Path(".").iterdir()))

    ### String representation ###
    @attachPtr(pathlib.Path, "__str__")
    @llfunc
    def path__str__(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "__repr__")
    @llfunc
    def path__repr__(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "__fspath__")
    @llfunc
    def path__fspath__(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "as_posix")
    @llfunc
    def path_as_posix(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "as_uri")
    @llfunc
    def path_as_uri(self):
        return allocate(str)

    @attachPtr(pathlib.Path, "__truediv__")
    @llfunc
    def path__truediv__(self, other):
        return allocate(pathlib.Path)

    @attachPtr(pathlib.Path, "__rtruediv__")
    @llfunc
    def path__rtruediv__(self, other):
        return allocate(pathlib.Path)
