from __future__ import absolute_import

from ..stubcollector import stubgenerator

import io


@stubgenerator
def makeIOStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### open() builtin ###
    @export
    @attachPtr(open)
    @llfunc
    def builtin_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
        return allocate(io.TextIOWrapper)

    ### io module functions ###
    @export
    @attachPtr(io, "open")
    @llfunc
    def io_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
        return allocate(io.TextIOWrapper)

    ### StringIO ###
    @export
    @attachPtr(io, "StringIO")
    @llfunc
    def io_StringIO(initial_value='', newline='\n'):
        return allocate(io.StringIO)

    @attachPtr(io.StringIO, "read")
    @llfunc
    def stringio_read(self, size=-1):
        return allocate(str)

    @attachPtr(io.StringIO, "readline")
    @llfunc
    def stringio_readline(self, size=-1):
        return allocate(str)

    @attachPtr(io.StringIO, "readlines")
    @llfunc
    def stringio_readlines(self, hint=-1):
        return allocate(list)

    @attachPtr(io.StringIO, "write")
    @llfunc
    def stringio_write(self, s):
        return allocate(int)

    @attachPtr(io.StringIO, "writelines")
    @llfunc
    def stringio_writelines(self, lines):
        return allocate(type(None))

    @attachPtr(io.StringIO, "seek")
    @llfunc
    def stringio_seek(self, pos, whence=0):
        return allocate(int)

    @attachPtr(io.StringIO, "tell")
    @llfunc
    def stringio_tell(self):
        return allocate(int)

    @attachPtr(io.StringIO, "close")
    @llfunc
    def stringio_close(self):
        return allocate(type(None))

    @attachPtr(io.StringIO, "getvalue")
    @llfunc
    def stringio_getvalue(self):
        return allocate(str)

    @attachPtr(io.StringIO, "truncate")
    @llfunc
    def stringio_truncate(self, size=None):
        return allocate(int)

    ### BytesIO ###
    @export
    @attachPtr(io, "BytesIO")
    @llfunc
    def io_BytesIO(initial_bytes=b''):
        return allocate(io.BytesIO)

    @attachPtr(io.BytesIO, "read")
    @llfunc
    def bytesio_read(self, size=-1):
        return allocate(bytes)

    @attachPtr(io.BytesIO, "readline")
    @llfunc
    def bytesio_readline(self, size=-1):
        return allocate(bytes)

    @attachPtr(io.BytesIO, "readlines")
    @llfunc
    def bytesio_readlines(self, hint=-1):
        return allocate(list)

    @attachPtr(io.BytesIO, "write")
    @llfunc
    def bytesio_write(self, b):
        return allocate(int)

    @attachPtr(io.BytesIO, "writelines")
    @llfunc
    def bytesio_writelines(self, lines):
        return allocate(type(None))

    @attachPtr(io.BytesIO, "seek")
    @llfunc
    def bytesio_seek(self, pos, whence=0):
        return allocate(int)

    @attachPtr(io.BytesIO, "tell")
    @llfunc
    def bytesio_tell(self):
        return allocate(int)

    @attachPtr(io.BytesIO, "close")
    @llfunc
    def bytesio_close(self):
        return allocate(type(None))

    @attachPtr(io.BytesIO, "getvalue")
    @llfunc
    def bytesio_getvalue(self):
        return allocate(bytes)

    @attachPtr(io.BytesIO, "getbuffer")
    @llfunc
    def bytesio_getbuffer(self):
        return allocate(memoryview)

    ### FileIO (low-level) ###
    @export
    @attachPtr(io, "FileIO")
    @llfunc
    def io_FileIO(file, mode='r', closefd=True, opener=None):
        return allocate(io.FileIO)

    @attachPtr(io.FileIO, "read")
    @llfunc
    def fileio_read(self, size=-1):
        return allocate(bytes)

    @attachPtr(io.FileIO, "readall")
    @llfunc
    def fileio_readall(self):
        return allocate(bytes)

    @attachPtr(io.FileIO, "readinto")
    @llfunc
    def fileio_readinto(self, b):
        return allocate(int)

    @attachPtr(io.FileIO, "write")
    @llfunc
    def fileio_write(self, b):
        return allocate(int)

    @attachPtr(io.FileIO, "seek")
    @llfunc
    def fileio_seek(self, pos, whence=0):
        return allocate(int)

    @attachPtr(io.FileIO, "tell")
    @llfunc
    def fileio_tell(self):
        return allocate(int)

    @attachPtr(io.FileIO, "close")
    @llfunc
    def fileio_close(self):
        return allocate(type(None))

    @attachPtr(io.FileIO, "fileno")
    @llfunc
    def fileio_fileno(self):
        return allocate(int)

    ### BufferedReader ###
    @export
    @attachPtr(io, "BufferedReader")
    @llfunc
    def io_BufferedReader(raw, buffer_size=io.DEFAULT_BUFFER_SIZE):
        return allocate(io.BufferedReader)

    @attachPtr(io.BufferedReader, "read")
    @llfunc
    def bufferedreader_read(self, size=-1):
        return allocate(bytes)

    @attachPtr(io.BufferedReader, "read1")
    @llfunc
    def bufferedreader_read1(self, size=-1):
        return allocate(bytes)

    @attachPtr(io.BufferedReader, "readinto")
    @llfunc
    def bufferedreader_readinto(self, b):
        return allocate(int)

    @attachPtr(io.BufferedReader, "peek")
    @llfunc
    def bufferedreader_peek(self, size=0):
        return allocate(bytes)

    ### BufferedWriter ###
    @export
    @attachPtr(io, "BufferedWriter")
    @llfunc
    def io_BufferedWriter(raw, buffer_size=io.DEFAULT_BUFFER_SIZE):
        return allocate(io.BufferedWriter)

    @attachPtr(io.BufferedWriter, "write")
    @llfunc
    def bufferedwriter_write(self, b):
        return allocate(int)

    @attachPtr(io.BufferedWriter, "flush")
    @llfunc
    def bufferedwriter_flush(self):
        return allocate(type(None))

    ### TextIOWrapper ###
    @export
    @attachPtr(io, "TextIOWrapper")
    @llfunc
    def io_TextIOWrapper(buffer, encoding=None, errors=None, newline=None, line_buffering=False, write_through=False):
        return allocate(io.TextIOWrapper)

    @attachPtr(io.TextIOWrapper, "read")
    @llfunc
    def textiowrapper_read(self, size=-1):
        return allocate(str)

    @attachPtr(io.TextIOWrapper, "readline")
    @llfunc
    def textiowrapper_readline(self, size=-1):
        return allocate(str)

    @attachPtr(io.TextIOWrapper, "readlines")
    @llfunc
    def textiowrapper_readlines(self, hint=-1):
        return allocate(list)

    @attachPtr(io.TextIOWrapper, "write")
    @llfunc
    def textiowrapper_write(self, s):
        return allocate(int)

    @attachPtr(io.TextIOWrapper, "writelines")
    @llfunc
    def textiowrapper_writelines(self, lines):
        return allocate(type(None))

    @attachPtr(io.TextIOWrapper, "seek")
    @llfunc
    def textiowrapper_seek(self, offset, whence=0):
        return allocate(int)

    @attachPtr(io.TextIOWrapper, "tell")
    @llfunc
    def textiowrapper_tell(self):
        return allocate(int)

    @attachPtr(io.TextIOWrapper, "flush")
    @llfunc
    def textiowrapper_flush(self):
        return allocate(type(None))

    @attachPtr(io.TextIOWrapper, "close")
    @llfunc
    def textiowrapper_close(self):
        return allocate(type(None))

    @attachPtr(io.TextIOWrapper, "fileno")
    @llfunc
    def textiowrapper_fileno(self):
        return allocate(int)

    @attachPtr(io.TextIOWrapper, "detach")
    @llfunc
    def textiowrapper_detach(self):
        return allocate(io.BufferedIOBase)

    @attachPtr(io.TextIOWrapper, "__iter__")
    @llfunc
    def textiowrapper__iter__(self):
        return self

    @attachPtr(io.TextIOWrapper, "__next__")
    @llfunc
    def textiowrapper__next__(self):
        return allocate(str)

    ### IOBase common methods ###
    @attachPtr(io.IOBase, "close")
    @llfunc
    def iobase_close(self):
        return allocate(type(None))

    @attachPtr(io.IOBase, "flush")
    @llfunc
    def iobase_flush(self):
        return allocate(type(None))

    @attachPtr(io.IOBase, "fileno")
    @llfunc
    def iobase_fileno(self):
        return allocate(int)

    @attachPtr(io.IOBase, "isatty")
    @llfunc
    def iobase_isatty(self):
        return allocate(bool)

    @attachPtr(io.IOBase, "readable")
    @llfunc
    def iobase_readable(self):
        return allocate(bool)

    @attachPtr(io.IOBase, "writable")
    @llfunc
    def iobase_writable(self):
        return allocate(bool)

    @attachPtr(io.IOBase, "seekable")
    @llfunc
    def iobase_seekable(self):
        return allocate(bool)
