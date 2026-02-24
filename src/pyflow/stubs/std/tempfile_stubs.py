from __future__ import absolute_import

from ..stubcollector import stubgenerator

import tempfile


@stubgenerator
def makeTempfileStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### TemporaryFile ###
    @export
    @attachPtr(tempfile, "TemporaryFile")
    @llfunc
    def tempfile_TemporaryFile(mode='w+b', buffering=-1, encoding=None, newline=None, suffix=None, prefix=None, dir=None, errors=None):
        return allocate(type(tempfile.TemporaryFile()))

    ### NamedTemporaryFile ###
    @export
    @attachPtr(tempfile, "NamedTemporaryFile")
    @llfunc
    def tempfile_NamedTemporaryFile(mode='w+b', buffering=-1, encoding=None, newline=None, suffix=None, prefix=None, dir=None, delete=True, errors=None):
        return allocate(type(tempfile.NamedTemporaryFile()))

    @attachPtr(type(tempfile.NamedTemporaryFile()), "name")
    @llfunc
    def namedtempfile_name_get(self):
        return allocate(str)

    @attachPtr(type(tempfile.NamedTemporaryFile()), "delete")
    @llfunc
    def namedtempfile_delete_get(self):
        return allocate(bool)

    ### SpooledTemporaryFile ###
    @export
    @attachPtr(tempfile, "SpooledTemporaryFile")
    @llfunc
    def tempfile_SpooledTemporaryFile(max_size=0, mode='w+b', buffering=-1, encoding=None, newline=None, suffix=None, prefix=None, dir=None, errors=None):
        return allocate(type(tempfile.SpooledTemporaryFile()))

    @attachPtr(type(tempfile.SpooledTemporaryFile()), "rollover")
    @llfunc
    def spooledtempfile_rollover(self):
        return allocate(type(None))

    @attachPtr(type(tempfile.SpooledTemporaryFile()), "_rolled")
    @llfunc
    def spooledtempfile__rolled_get(self):
        return allocate(bool)

    ### TemporaryDirectory ###
    @export
    @attachPtr(tempfile, "TemporaryDirectory")
    @llfunc
    def tempfile_TemporaryDirectory(suffix=None, prefix=None, dir=None, ignore_cleanup_errors=False):
        return allocate(tempfile.TemporaryDirectory)

    @attachPtr(tempfile.TemporaryDirectory, "name")
    @llfunc
    def temporarydirectory_name_get(self):
        return allocate(str)

    @attachPtr(tempfile.TemporaryDirectory, "cleanup")
    @llfunc
    def temporarydirectory_cleanup(self):
        return allocate(type(None))

    ### mkstemp ###
    @export
    @attachPtr(tempfile, "mkstemp")
    @llfunc
    def tempfile_mkstemp(suffix=None, prefix=None, dir=None, text=False):
        return allocate(tuple)

    ### mkdtemp ###
    @export
    @attachPtr(tempfile, "mkdtemp")
    @llfunc
    def tempfile_mkdtemp(suffix=None, prefix=None, dir=None):
        return allocate(str)

    ### mktemp (deprecated) ###
    @export
    @attachPtr(tempfile, "mktemp")
    @llfunc
    def tempfile_mktemp(suffix='', prefix='tmp', dir=None):
        return allocate(str)

    ### gettempdir ###
    @export
    @attachPtr(tempfile, "gettempdir")
    @llfunc
    def tempfile_gettempdir():
        return allocate(str)

    ### gettempdirb ###
    @export
    @attachPtr(tempfile, "gettempdirb")
    @llfunc
    def tempfile_gettempdirb():
        return allocate(bytes)

    ### gettempprefix ###
    @export
    @attachPtr(tempfile, "gettempprefix")
    @llfunc
    def tempfile_gettempprefix():
        return allocate(str)

    ### gettempprefixb ###
    @export
    @attachPtr(tempfile, "gettempprefixb")
    @llfunc
    def tempfile_gettempprefixb():
        return allocate(bytes)

    ### tempdir ###
    @llfunc
    def tempfile_tempdir_get():
        return allocate(str)

    ### template (deprecated) ###
    @llfunc
    def tempfile_template_get():
        return allocate(str)
