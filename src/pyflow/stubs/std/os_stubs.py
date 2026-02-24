from __future__ import absolute_import

from ..stubcollector import stubgenerator

import os


@stubgenerator
def makeOSStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    fold = collector.fold
    staticFold = collector.staticFold
    attachPtr = collector.attachPtr

    ### os.path operations ###
    @export
    @attachPtr(os.path, "join")
    @llfunc
    def os_path_join(*paths):
        return allocate(str)

    @export
    @attachPtr(os.path, "exists")
    @llfunc
    def os_path_exists(path):
        return allocate(bool)

    @export
    @attachPtr(os.path, "isfile")
    @llfunc
    def os_path_isfile(path):
        return allocate(bool)

    @export
    @attachPtr(os.path, "isdir")
    @llfunc
    def os_path_isdir(path):
        return allocate(bool)

    @export
    @attachPtr(os.path, "islink")
    @llfunc
    def os_path_islink(path):
        return allocate(bool)

    @export
    @attachPtr(os.path, "ismount")
    @llfunc
    def os_path_ismount(path):
        return allocate(bool)

    @export
    @attachPtr(os.path, "isabs")
    @llfunc
    def os_path_isabs(path):
        return allocate(bool)

    @export
    @attachPtr(os.path, "basename")
    @llfunc
    def os_path_basename(path):
        return allocate(str)

    @export
    @attachPtr(os.path, "dirname")
    @llfunc
    def os_path_dirname(path):
        return allocate(str)

    @export
    @attachPtr(os.path, "split")
    @llfunc
    def os_path_split(path):
        return allocate(tuple)

    @export
    @attachPtr(os.path, "splitext")
    @llfunc
    def os_path_splitext(path):
        return allocate(tuple)

    @export
    @attachPtr(os.path, "splitdrive")
    @llfunc
    def os_path_splitdrive(path):
        return allocate(tuple)

    @export
    @attachPtr(os.path, "abspath")
    @llfunc
    def os_path_abspath(path):
        return allocate(str)

    @export
    @attachPtr(os.path, "normpath")
    @llfunc
    def os_path_normpath(path):
        return allocate(str)

    @export
    @attachPtr(os.path, "normcase")
    @llfunc
    def os_path_normcase(path):
        return allocate(str)

    @export
    @attachPtr(os.path, "realpath")
    @llfunc
    def os_path_realpath(path, strict=False):
        return allocate(str)

    @export
    @attachPtr(os.path, "relpath")
    @llfunc
    def os_path_relpath(path, start=None):
        return allocate(str)

    @export
    @attachPtr(os.path, "commonpath")
    @llfunc
    def os_path_commonpath(paths):
        return allocate(str)

    @export
    @attachPtr(os.path, "commonprefix")
    @llfunc
    def os_path_commonprefix(list):
        return allocate(str)

    @export
    @attachPtr(os.path, "getsize")
    @llfunc
    def os_path_getsize(path):
        return allocate(int)

    @export
    @attachPtr(os.path, "getmtime")
    @llfunc
    def os_path_getmtime(path):
        return allocate(float)

    @export
    @attachPtr(os.path, "getatime")
    @llfunc
    def os_path_getatime(path):
        return allocate(float)

    @export
    @attachPtr(os.path, "getctime")
    @llfunc
    def os_path_getctime(path):
        return allocate(float)

    @export
    @attachPtr(os.path, "samefile")
    @llfunc
    def os_path_samefile(path1, path2):
        return allocate(bool)

    @export
    @attachPtr(os.path, "sameopenfile")
    @llfunc
    def os_path_sameopenfile(fp1, fp2):
        return allocate(bool)

    @export
    @attachPtr(os.path, "expanduser")
    @llfunc
    def os_path_expanduser(path):
        return allocate(str)

    @export
    @attachPtr(os.path, "expandvars")
    @llfunc
    def os_path_expandvars(path):
        return allocate(str)

    ### Environment operations ###
    @export
    @attachPtr(os, "getenv")
    @llfunc
    def os_getenv(key, default=None):
        return allocate(str)

    @export
    @attachPtr(os, "putenv")
    @llfunc
    def os_putenv(key, value):
        return allocate(type(None))

    @export
    @attachPtr(os, "unsetenv")
    @llfunc
    def os_unsetenv(key):
        return allocate(type(None))

    @export
    @attachPtr(os, "environ")
    @llfunc
    def os_environ_get(key):
        return allocate(str)

    ### File operations ###
    @export
    @attachPtr(os, "listdir")
    @llfunc
    def os_listdir(path="."):
        return allocate(list)

    @export
    @attachPtr(os, "scandir")
    @llfunc
    def os_scandir(path="."):
        return allocate(type(os.scandir(".")))

    @export
    @attachPtr(os, "walk")
    @llfunc
    def os_walk(top, topdown=True, onerror=None, followlinks=False):
        return allocate(type(os.walk(".")))

    @export
    @attachPtr(os, "mkdir")
    @llfunc
    def os_mkdir(path, mode=0o777):
        return allocate(type(None))

    @export
    @attachPtr(os, "makedirs")
    @llfunc
    def os_makedirs(name, mode=0o777, exist_ok=False):
        return allocate(type(None))

    @export
    @attachPtr(os, "rmdir")
    @llfunc
    def os_rmdir(path):
        return allocate(type(None))

    @export
    @attachPtr(os, "removedirs")
    @llfunc
    def os_removedirs(name):
        return allocate(type(None))

    @export
    @attachPtr(os, "remove")
    @llfunc
    def os_remove(path, dir_fd=None):
        return allocate(type(None))

    @export
    @attachPtr(os, "unlink")
    @llfunc
    def os_unlink(path, dir_fd=None):
        return allocate(type(None))

    @export
    @attachPtr(os, "rename")
    @llfunc
    def os_rename(src, dst, src_dir_fd=None, dst_dir_fd=None):
        return allocate(type(None))

    @export
    @attachPtr(os, "renames")
    @llfunc
    def os_renames(old, new):
        return allocate(type(None))

    @export
    @attachPtr(os, "replace")
    @llfunc
    def os_replace(src, dst, src_dir_fd=None, dst_dir_fd=None):
        return allocate(type(None))

    @export
    @attachPtr(os, "stat")
    @llfunc
    def os_stat(path, dir_fd=None, follow_symlinks=True):
        return allocate(type(os.stat(".")))

    @export
    @attachPtr(os, "lstat")
    @llfunc
    def os_lstat(path, dir_fd=None):
        return allocate(type(os.stat(".")))

    @export
    @attachPtr(os, "access")
    @llfunc
    def os_access(path, mode, dir_fd=None, effective_ids=False, follow_symlinks=True):
        return allocate(bool)

    @export
    @attachPtr(os, "chmod")
    @llfunc
    def os_chmod(path, mode, dir_fd=None, follow_symlinks=True):
        return allocate(type(None))

    @export
    @attachPtr(os, "chown")
    @llfunc
    def os_chown(path, uid, gid, dir_fd=None, follow_symlinks=True):
        return allocate(type(None))

    @export
    @attachPtr(os, "link")
    @llfunc
    def os_link(src, dst, src_dir_fd=None, dst_dir_fd=None):
        return allocate(type(None))

    @export
    @attachPtr(os, "symlink")
    @llfunc
    def os_symlink(src, dst, target_is_directory=False, dir_fd=None):
        return allocate(type(None))

    @export
    @attachPtr(os, "readlink")
    @llfunc
    def os_readlink(path, dir_fd=None):
        return allocate(str)

    @export
    @attachPtr(os, "truncate")
    @llfunc
    def os_truncate(path, length):
        return allocate(type(None))

    @export
    @attachPtr(os, "utime")
    @llfunc
    def os_utime(path, times=None, ns=None, dir_fd=None, follow_symlinks=True):
        return allocate(type(None))

    ### Process operations ###
    @export
    @attachPtr(os, "getpid")
    @llfunc
    def os_getpid():
        return allocate(int)

    @export
    @attachPtr(os, "getppid")
    @llfunc
    def os_getppid():
        return allocate(int)

    @export
    @attachPtr(os, "getcwd")
    @llfunc
    def os_getcwd():
        return allocate(str)

    @export
    @attachPtr(os, "getcwdb")
    @llfunc
    def os_getcwdb():
        return allocate(bytes)

    @export
    @attachPtr(os, "chdir")
    @llfunc
    def os_chdir(path):
        return allocate(type(None))

    @export
    @attachPtr(os, "fork")
    @llfunc
    def os_fork():
        return allocate(int)

    @export
    @attachPtr(os, "forkpty")
    @llfunc
    def os_forkpty():
        return allocate(tuple)

    @export
    @attachPtr(os, "kill")
    @llfunc
    def os_kill(pid, sig):
        return allocate(type(None))

    @export
    @attachPtr(os, "killpg")
    @llfunc
    def os_killpg(pgid, sig):
        return allocate(type(None))

    @export
    @attachPtr(os, "wait")
    @llfunc
    def os_wait():
        return allocate(tuple)

    @export
    @attachPtr(os, "waitpid")
    @llfunc
    def os_waitpid(pid, options):
        return allocate(tuple)

    @export
    @attachPtr(os, "waitid")
    @llfunc
    def os_waitid(idtype, id, options):
        return allocate(type(None))

    @export
    @attachPtr(os, "system")
    @llfunc
    def os_system(command):
        return allocate(int)

    @export
    @attachPtr(os, "spawnl")
    @llfunc
    def os_spawnl(mode, path, *args):
        return allocate(int)

    @export
    @attachPtr(os, "spawnle")
    @llfunc
    def os_spawnle(mode, path, *args, env):
        return allocate(int)

    @export
    @attachPtr(os, "spawnv")
    @llfunc
    def os_spawnv(mode, path, args):
        return allocate(int)

    @export
    @attachPtr(os, "spawnve")
    @llfunc
    def os_spawnve(mode, path, args, env):
        return allocate(int)

    @export
    @attachPtr(os, "popen")
    @llfunc
    def os_popen(cmd, mode='r', buffering=-1):
        return allocate(type(os.popen("echo test")))

    @export
    @attachPtr(os, "getuid")
    @llfunc
    def os_getuid():
        return allocate(int)

    @export
    @attachPtr(os, "getgid")
    @llfunc
    def os_getgid():
        return allocate(int)

    @export
    @attachPtr(os, "geteuid")
    @llfunc
    def os_geteuid():
        return allocate(int)

    @export
    @attachPtr(os, "getegid")
    @llfunc
    def os_getegid():
        return allocate(int)

    @export
    @attachPtr(os, "getgroups")
    @llfunc
    def os_getgroups():
        return allocate(list)

    @export
    @attachPtr(os, "getlogin")
    @llfunc
    def os_getlogin():
        return allocate(str)

    @export
    @attachPtr(os, "getpgrp")
    @llfunc
    def os_getpgrp():
        return allocate(int)

    @export
    @attachPtr(os, "getsid")
    @llfunc
    def os_getsid(pid):
        return allocate(int)

    @export
    @attachPtr(os, "setsid")
    @llfunc
    def os_setsid():
        return allocate(int)

    @export
    @attachPtr(os, "setuid")
    @llfunc
    def os_setuid(uid):
        return allocate(type(None))

    @export
    @attachPtr(os, "setgid")
    @llfunc
    def os_setgid(gid):
        return allocate(type(None))

    @export
    @attachPtr(os, "seteuid")
    @llfunc
    def os_seteuid(euid):
        return allocate(type(None))

    @export
    @attachPtr(os, "setegid")
    @llfunc
    def os_setegid(egid):
        return allocate(type(None))

    @export
    @attachPtr(os, "setreuid")
    @llfunc
    def os_setreuid(ruid, euid):
        return allocate(type(None))

    @export
    @attachPtr(os, "setregid")
    @llfunc
    def os_setregid(rgid, egid):
        return allocate(type(None))

    @export
    @attachPtr(os, "setpgid")
    @llfunc
    def os_setpgid(pid, pgrp):
        return allocate(type(None))

    @export
    @attachPtr(os, "umask")
    @llfunc
    def os_umask(mask):
        return allocate(int)

    @export
    @attachPtr(os, "chroot")
    @llfunc
    def os_chroot(path):
        return allocate(type(None))

    @export
    @attachPtr(os, "nice")
    @llfunc
    def os_nice(increment):
        return allocate(int)

    ### File descriptor operations ###
    @export
    @attachPtr(os, "open")
    @llfunc
    def os_open(path, flags, mode=0o777, dir_fd=None):
        return allocate(int)

    @export
    @attachPtr(os, "close")
    @llfunc
    def os_close(fd):
        return allocate(type(None))

    @export
    @attachPtr(os, "closerange")
    @llfunc
    def os_closerange(fd_low, fd_high):
        return allocate(type(None))

    @export
    @attachPtr(os, "dup")
    @llfunc
    def os_dup(fd):
        return allocate(int)

    @export
    @attachPtr(os, "dup2")
    @llfunc
    def os_dup2(fd, fd2, inheritable=True):
        return allocate(int)

    @export
    @attachPtr(os, "fdopen")
    @llfunc
    def os_fdopen(fd, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
        return allocate(type(os.fdopen(0)))

    @export
    @attachPtr(os, "read")
    @llfunc
    def os_read(fd, n):
        return allocate(bytes)

    @export
    @attachPtr(os, "write")
    @llfunc
    def os_write(fd, data):
        return allocate(int)

    @export
    @attachPtr(os, "fstat")
    @llfunc
    def os_fstat(fd):
        return allocate(type(os.stat(".")))

    @export
    @attachPtr(os, "fchmod")
    @llfunc
    def os_fchmod(fd, mode):
        return allocate(type(None))

    @export
    @attachPtr(os, "fchown")
    @llfunc
    def os_fchown(fd, uid, gid):
        return allocate(type(None))

    @export
    @attachPtr(os, "ftruncate")
    @llfunc
    def os_ftruncate(fd, length):
        return allocate(type(None))

    @export
    @attachPtr(os, "fsync")
    @llfunc
    def os_fsync(fd):
        return allocate(type(None))

    @export
    @attachPtr(os, "fdatasync")
    @llfunc
    def os_fdatasync(fd):
        return allocate(type(None))

    @export
    @attachPtr(os, "fpathconf")
    @llfunc
    def os_fpathconf(fd, name):
        return allocate(int)

    @export
    @attachPtr(os, "pathconf")
    @llfunc
    def os_pathconf(path, name):
        return allocate(int)

    @export
    @attachPtr(os, "isatty")
    @llfunc
    def os_isatty(fd):
        return allocate(bool)

    @export
    @attachPtr(os, "pipe")
    @llfunc
    def os_pipe():
        return allocate(tuple)

    @export
    @attachPtr(os, "mkfifo")
    @llfunc
    def os_mkfifo(path, mode=0o666, dir_fd=None):
        return allocate(type(None))

    @export
    @attachPtr(os, "mknod")
    @llfunc
    def os_mknod(path, mode=0o600, device=0, dir_fd=None):
        return allocate(type(None))

    ### Terminal operations ###
    @export
    @attachPtr(os, "ttyname")
    @llfunc
    def os_ttyname(fd):
        return allocate(str)

    @export
    @attachPtr(os, "ctermid")
    @llfunc
    def os_ctermid():
        return allocate(str)

    ### CPU count ###
    @export
    @attachPtr(os, "cpu_count")
    @llfunc
    def os_cpu_count():
        return allocate(int)

    ### uname ###
    @export
    @attachPtr(os, "uname")
    @llfunc
    def os_uname():
        return allocate(type(os.uname()))

    ### urandom ###
    @export
    @attachPtr(os, "urandom")
    @llfunc
    def os_urandom(size):
        return allocate(bytes)

    ### confstr ###
    @export
    @attachPtr(os, "confstr")
    @llfunc
    def os_confstr(name):
        return allocate(str)

    ### sysconf ###
    @export
    @attachPtr(os, "sysconf")
    @llfunc
    def os_sysconf(name):
        return allocate(int)
