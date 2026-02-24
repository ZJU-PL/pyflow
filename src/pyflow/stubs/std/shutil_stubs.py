from __future__ import absolute_import

from ..stubcollector import stubgenerator

import shutil


@stubgenerator
def makeShutilStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### copy ###
    @export
    @attachPtr(shutil, "copy")
    @llfunc
    def shutil_copy(src, dst, follow_symlinks=True):
        return allocate(str)

    ### copy2 ###
    @export
    @attachPtr(shutil, "copy2")
    @llfunc
    def shutil_copy2(src, dst, follow_symlinks=True):
        return allocate(str)

    ### copyfile ###
    @export
    @attachPtr(shutil, "copyfile")
    @llfunc
    def shutil_copyfile(src, dst, follow_symlinks=True):
        return allocate(str)

    ### copyfileobj ###
    @export
    @attachPtr(shutil, "copyfileobj")
    @llfunc
    def shutil_copyfileobj(fsrc, fdst, length=16*1024):
        return allocate(type(None))

    ### copymode ###
    @export
    @attachPtr(shutil, "copymode")
    @llfunc
    def shutil_copymode(src, dst, follow_symlinks=True):
        return allocate(type(None))

    ### copystat ###
    @export
    @attachPtr(shutil, "copystat")
    @llfunc
    def shutil_copystat(src, dst, follow_symlinks=True):
        return allocate(type(None))

    ### copytree ###
    @export
    @attachPtr(shutil, "copytree")
    @llfunc
    def shutil_copytree(src, dst, symlinks=False, ignore=None, copy_function=shutil.copy2, ignore_dangling_symlinks=False, dirs_exist_ok=False):
        return allocate(str)

    ### rmtree ###
    @export
    @attachPtr(shutil, "rmtree")
    @llfunc
    def shutil_rmtree(path, ignore_errors=False, onerror=None, dir_fd=None):
        return allocate(type(None))

    ### move ###
    @export
    @attachPtr(shutil, "move")
    @llfunc
    def shutil_move(src, dst, copy_function=shutil.copy2):
        return allocate(str)

    ### disk_usage ###
    @export
    @attachPtr(shutil, "disk_usage")
    @llfunc
    def shutil_disk_usage(path):
        return allocate(type(shutil.disk_usage(".")))

    @attachPtr(type(shutil.disk_usage(".")), "total")
    @llfunc
    def diskusage_total_get(self):
        return allocate(int)

    @attachPtr(type(shutil.disk_usage(".")), "used")
    @llfunc
    def diskusage_used_get(self):
        return allocate(int)

    @attachPtr(type(shutil.disk_usage(".")), "free")
    @llfunc
    def diskusage_free_get(self):
        return allocate(int)

    ### which ###
    @export
    @attachPtr(shutil, "which")
    @llfunc
    def shutil_which(cmd, mode=1, path=None):
        return allocate(str)

    ### chown ###
    @export
    @attachPtr(shutil, "chown")
    @llfunc
    def shutil_chown(path, user=None, group=None):
        return allocate(type(None))

    ### get_archive_formats ###
    @export
    @attachPtr(shutil, "get_archive_formats")
    @llfunc
    def shutil_get_archive_formats():
        return allocate(list)

    ### get_unpack_formats ###
    @export
    @attachPtr(shutil, "get_unpack_formats")
    @llfunc
    def shutil_get_unpack_formats():
        return allocate(list)

    ### make_archive ###
    @export
    @attachPtr(shutil, "make_archive")
    @llfunc
    def shutil_make_archive(base_name, format, root_dir=None, base_dir=None, verbose=0, dry_run=0, owner=None, group=None, logger=None):
        return allocate(str)

    ### unpack_archive ###
    @export
    @attachPtr(shutil, "unpack_archive")
    @llfunc
    def shutil_unpack_archive(filename, extract_dir=None, format=None):
        return allocate(type(None))

    ### register_archive_format ###
    @export
    @attachPtr(shutil, "register_archive_format")
    @llfunc
    def shutil_register_archive_format(name, function, extra_args=None, description=''):
        return allocate(type(None))

    ### unregister_archive_format ###
    @export
    @attachPtr(shutil, "unregister_archive_format")
    @llfunc
    def shutil_unregister_archive_format(name):
        return allocate(type(None))

    ### register_unpack_format ###
    @export
    @attachPtr(shutil, "register_unpack_format")
    @llfunc
    def shutil_register_unpack_format(name, extensions, function, extra_args=None, description=''):
        return allocate(type(None))

    ### unregister_unpack_format ###
    @export
    @attachPtr(shutil, "unregister_unpack_format")
    @llfunc
    def shutil_unregister_unpack_format(name):
        return allocate(type(None))

    ### get_terminal_size ###
    @export
    @attachPtr(shutil, "get_terminal_size")
    @llfunc
    def shutil_get_terminal_size(fallback=(80, 24)):
        return allocate(type(shutil.get_terminal_size()))

    @attachPtr(type(shutil.get_terminal_size()), "columns")
    @llfunc
    def terminalsize_columns_get(self):
        return allocate(int)

    @attachPtr(type(shutil.get_terminal_size()), "lines")
    @llfunc
    def terminalsize_lines_get(self):
        return allocate(int)

    ### ignore_patterns ###
    @export
    @attachPtr(shutil, "ignore_patterns")
    @llfunc
    def shutil_ignore_patterns(*patterns):
        return allocate(type(lambda d, names: []))

    ### SameFileError ###
    @export
    @attachPtr(shutil, "SameFileError")
    @llfunc
    def shutil_SameFileError(*args):
        return allocate(shutil.SameFileError)

    ### SpecialFileError ###
    @export
    @attachPtr(shutil, "SpecialFileError")
    @llfunc
    def shutil_SpecialFileError(*args):
        return allocate(shutil.SpecialFileError)

    ### ExecError ###
    @export
    @attachPtr(shutil, "ExecError")
    @llfunc
    def shutil_ExecError(*args):
        return allocate(shutil.ExecError)
