from __future__ import absolute_import

from ..stubcollector import stubgenerator

import sys


@stubgenerator
def makeSysStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### sys.argv - list of command line arguments ###
    @llfunc
    def sys_argv_get():
        return allocate(list)

    ### sys.path - module search path ###
    @llfunc
    def sys_path_get():
        return allocate(list)

    ### sys.modules - loaded modules ###
    @llfunc
    def sys_modules_get():
        return allocate(dict)

    ### sys.exit ###
    @export
    @attachPtr(sys.exit)
    @llfunc
    def sys_exit(code=0):
        return allocate(type(None))

    ### sys.version_info ###
    @llfunc
    def sys_version_info_get():
        return allocate(tuple)

    ### sys.version ###
    @llfunc
    def sys_version_get():
        return allocate(str)

    ### sys.platform ###
    @llfunc
    def sys_platform_get():
        return allocate(str)

    ### sys.executable ###
    @llfunc
    def sys_executable_get():
        return allocate(str)

    ### sys.prefix ###
    @llfunc
    def sys_prefix_get():
        return allocate(str)

    ### sys.exec_prefix ###
    @llfunc
    def sys_exec_prefix_get():
        return allocate(str)

    ### sys.stdin ###
    @llfunc
    def sys_stdin_get():
        return allocate(type(sys.stdin))

    @attachPtr(type(sys.stdin), "read")
    @llfunc
    def stdin_read(self, size=-1):
        return allocate(str)

    @attachPtr(type(sys.stdin), "readline")
    @llfunc
    def stdin_readline(self, size=-1):
        return allocate(str)

    @attachPtr(type(sys.stdin), "readlines")
    @llfunc
    def stdin_readlines(self, hint=-1):
        return allocate(list)

    ### sys.stdout ###
    @llfunc
    def sys_stdout_get():
        return allocate(type(sys.stdout))

    @attachPtr(type(sys.stdout), "write")
    @llfunc
    def stdout_write(self, s):
        return allocate(int)

    @attachPtr(type(sys.stdout), "writelines")
    @llfunc
    def stdout_writelines(self, lines):
        return allocate(type(None))

    @attachPtr(type(sys.stdout), "flush")
    @llfunc
    def stdout_flush(self):
        return allocate(type(None))

    ### sys.stderr ###
    @llfunc
    def sys_stderr_get():
        return allocate(type(sys.stderr))

    @attachPtr(type(sys.stderr), "write")
    @llfunc
    def stderr_write(self, s):
        return allocate(int)

    @attachPtr(type(sys.stderr), "flush")
    @llfunc
    def stderr_flush(self):
        return allocate(type(None))

    ### sys.getsizeof ###
    @export
    @attachPtr(sys.getsizeof)
    @llfunc
    def sys_getsizeof(object, default=None):
        return allocate(int)

    ### sys.getrefcount ###
    @export
    @attachPtr(sys.getrefcount)
    @llfunc
    def sys_getrefcount(object):
        return allocate(int)

    ### sys.getrecursionlimit ###
    @export
    @attachPtr(sys.getrecursionlimit)
    @llfunc
    def sys_getrecursionlimit():
        return allocate(int)

    ### sys.setrecursionlimit ###
    @export
    @attachPtr(sys.setrecursionlimit)
    @llfunc
    def sys_setrecursionlimit(limit):
        return allocate(type(None))

    ### sys.maxsize ###
    @llfunc
    def sys_maxsize_get():
        return allocate(int)

    ### sys.maxint (Python 2 compatibility) ###
    @llfunc
    def sys_maxint_get():
        return allocate(int)

    ### sys.float_info ###
    @llfunc
    def sys_float_info_get():
        return allocate(type(sys.float_info))

    ### sys.int_info ###
    @llfunc
    def sys_int_info_get():
        return allocate(type(sys.int_info))

    ### sys.byteorder ###
    @llfunc
    def sys_byteorder_get():
        return allocate(str)

    ### sys.flags ###
    @llfunc
    def sys_flags_get():
        return allocate(type(sys.flags))

    ### sys.exc_info ###
    @export
    @attachPtr(sys.exc_info)
    @llfunc
    def sys_exc_info():
        return allocate(tuple)

    ### sys.settrace ###
    @export
    @attachPtr(sys.settrace)
    @llfunc
    def sys_settrace(tracefunc):
        return allocate(type(None))

    ### sys.setprofile ###
    @export
    @attachPtr(sys.setprofile)
    @llfunc
    def sys_setprofile(profilefunc):
        return allocate(type(None))

    ### sys.setswitchinterval ###
    @export
    @attachPtr(sys.setswitchinterval)
    @llfunc
    def sys_setswitchinterval(interval):
        return allocate(type(None))

    ### sys.getswitchinterval ###
    @export
    @attachPtr(sys.getswitchinterval)
    @llfunc
    def sys_getswitchinterval():
        return allocate(float)

    ### sys.getfilesystemencoding ###
    @export
    @attachPtr(sys.getfilesystemencoding)
    @llfunc
    def sys_getfilesystemencoding():
        return allocate(str)

    ### sys.getdefaultencoding ###
    @export
    @attachPtr(sys.getdefaultencoding)
    @llfunc
    def sys_getdefaultencoding():
        return allocate(str)
