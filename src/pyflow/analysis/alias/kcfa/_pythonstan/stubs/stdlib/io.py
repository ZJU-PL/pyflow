DEFAULT_BUFFER_SIZE = 8192
SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2


class IOBase:
    def __init__(self):
        self._closed = False

    def close(self):
        self._closed = True

    @property
    def closed(self):
        return self._closed

    def fileno(self):
        raise OSError("fileno")

    def flush(self):
        pass

    def isatty(self):
        return False

    def readable(self):
        return False

    def readline(self, size=-1):
        return b""

    def readlines(self, hint=-1):
        return []

    def seek(self, offset, whence=SEEK_SET):
        raise OSError("seek")

    def seekable(self):
        return False

    def tell(self):
        raise OSError("tell")

    def truncate(self, size=None):
        raise OSError("truncate")

    def writable(self):
        return False

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line


class RawIOBase(IOBase):
    def read(self, size=-1):
        return b""

    def readall(self):
        return b""

    def readinto(self, b):
        return 0

    def write(self, b):
        return len(b)


class BufferedIOBase(IOBase):
    def detach(self):
        raise OSError("detach")

    def read(self, size=-1):
        return b""

    def read1(self, size=-1):
        return b""

    def readinto(self, b):
        return 0

    def readinto1(self, b):
        return 0

    def write(self, b):
        return len(b)


class FileIO(RawIOBase):
    def __init__(self, name, mode='r', closefd=True, opener=None):
        super().__init__()
        self.name = name
        self.mode = mode
        self._closefd = closefd

    def readable(self):
        return 'r' in self.mode

    def writable(self):
        return 'w' in self.mode or 'a' in self.mode

    def seekable(self):
        return True

    def seek(self, offset, whence=SEEK_SET):
        return 0

    def tell(self):
        return 0


class BufferedReader(BufferedIOBase):
    def __init__(self, raw, buffer_size=DEFAULT_BUFFER_SIZE):
        super().__init__()
        self.raw = raw
        self._buffer_size = buffer_size

    @property
    def name(self):
        return self.raw.name

    @property
    def mode(self):
        return self.raw.mode

    def readable(self):
        return True

    def seekable(self):
        return self.raw.seekable()

    def seek(self, offset, whence=SEEK_SET):
        return self.raw.seek(offset, whence)

    def tell(self):
        return self.raw.tell()


class BufferedWriter(BufferedIOBase):
    def __init__(self, raw, buffer_size=DEFAULT_BUFFER_SIZE):
        super().__init__()
        self.raw = raw
        self._buffer_size = buffer_size

    @property
    def name(self):
        return self.raw.name

    @property
    def mode(self):
        return self.raw.mode

    def writable(self):
        return True

    def seekable(self):
        return self.raw.seekable()

    def seek(self, offset, whence=SEEK_SET):
        return self.raw.seek(offset, whence)

    def tell(self):
        return self.raw.tell()


class BufferedRandom(BufferedIOBase):
    def __init__(self, raw, buffer_size=DEFAULT_BUFFER_SIZE):
        super().__init__()
        self.raw = raw
        self._buffer_size = buffer_size

    @property
    def name(self):
        return self.raw.name

    @property
    def mode(self):
        return self.raw.mode

    def readable(self):
        return True

    def writable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=SEEK_SET):
        return self.raw.seek(offset, whence)

    def tell(self):
        return self.raw.tell()


class BufferedRWPair(BufferedIOBase):
    def __init__(self, reader, writer, buffer_size=DEFAULT_BUFFER_SIZE):
        super().__init__()
        self._reader = reader
        self._writer = writer

    def readable(self):
        return True

    def writable(self):
        return True


class TextIOBase(IOBase):
    def detach(self):
        raise OSError("detach")

    def read(self, size=-1):
        return ""

    def readline(self, size=-1):
        return ""

    def write(self, s):
        return len(s)

    @property
    def encoding(self):
        return None

    @property
    def errors(self):
        return None

    @property
    def newlines(self):
        return None


class TextIOWrapper(TextIOBase):
    def __init__(self, buffer, encoding=None, errors=None, newline=None,
                 line_buffering=False, write_through=False):
        super().__init__()
        self.buffer = buffer
        self._encoding = encoding or 'utf-8'
        self._errors = errors or 'strict'
        self._newline = newline
        self._line_buffering = line_buffering
        self._write_through = write_through

    @property
    def name(self):
        return self.buffer.name

    @property
    def mode(self):
        return self.buffer.mode

    @property
    def encoding(self):
        return self._encoding

    @property
    def errors(self):
        return self._errors

    @property
    def newlines(self):
        return self._newline

    def readable(self):
        return self.buffer.readable()

    def writable(self):
        return self.buffer.writable()

    def seekable(self):
        return self.buffer.seekable()

    def seek(self, offset, whence=SEEK_SET):
        return self.buffer.seek(offset, whence)

    def tell(self):
        return self.buffer.tell()

    def detach(self):
        buf = self.buffer
        self.buffer = None
        return buf


class StringIO(TextIOBase):
    def __init__(self, initial_value='', newline='\n'):
        super().__init__()
        self._value = initial_value
        self._pos = 0
        self._newline = newline

    def getvalue(self):
        return self._value

    def read(self, size=-1):
        if size < 0:
            result = self._value[self._pos:]
            self._pos = len(self._value)
        else:
            result = self._value[self._pos:self._pos + size]
            self._pos += len(result)
        return result

    def readline(self, size=-1):
        end = self._value.find('\n', self._pos)
        if end < 0:
            end = len(self._value)
        else:
            end += 1
        if size >= 0:
            end = min(end, self._pos + size)
        result = self._value[self._pos:end]
        self._pos = end
        return result

    def write(self, s):
        self._value = self._value[:self._pos] + s + self._value[self._pos + len(s):]
        self._pos += len(s)
        return len(s)

    def seek(self, offset, whence=SEEK_SET):
        if whence == SEEK_SET:
            self._pos = offset
        elif whence == SEEK_CUR:
            self._pos += offset
        elif whence == SEEK_END:
            self._pos = len(self._value) + offset
        return self._pos

    def tell(self):
        return self._pos

    def readable(self):
        return True

    def writable(self):
        return True

    def seekable(self):
        return True

    def truncate(self, size=None):
        if size is None:
            size = self._pos
        self._value = self._value[:size]
        return size


class BytesIO(BufferedIOBase):
    def __init__(self, initial_bytes=b''):
        super().__init__()
        self._value = initial_bytes
        self._pos = 0

    def getvalue(self):
        return self._value

    def getbuffer(self):
        return memoryview(bytearray(self._value))

    def read(self, size=-1):
        if size < 0:
            result = self._value[self._pos:]
            self._pos = len(self._value)
        else:
            result = self._value[self._pos:self._pos + size]
            self._pos += len(result)
        return result

    def read1(self, size=-1):
        return self.read(size)

    def readline(self, size=-1):
        end = self._value.find(b'\n', self._pos)
        if end < 0:
            end = len(self._value)
        else:
            end += 1
        if size >= 0:
            end = min(end, self._pos + size)
        result = self._value[self._pos:end]
        self._pos = end
        return result

    def readinto(self, b):
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def write(self, b):
        self._value = self._value[:self._pos] + bytes(b) + self._value[self._pos + len(b):]
        self._pos += len(b)
        return len(b)

    def seek(self, offset, whence=SEEK_SET):
        if whence == SEEK_SET:
            self._pos = offset
        elif whence == SEEK_CUR:
            self._pos += offset
        elif whence == SEEK_END:
            self._pos = len(self._value) + offset
        return self._pos

    def tell(self):
        return self._pos

    def readable(self):
        return True

    def writable(self):
        return True

    def seekable(self):
        return True

    def truncate(self, size=None):
        if size is None:
            size = self._pos
        self._value = self._value[:size]
        return size


def open(file, mode='r', buffering=-1, encoding=None, errors=None,
         newline=None, closefd=True, opener=None):
    binary = 'b' in mode
    raw = FileIO(file, mode, closefd, opener)
    if buffering == 0:
        return raw
    if buffering < 0:
        buffering = DEFAULT_BUFFER_SIZE
    if binary:
        if 'r' in mode and 'w' not in mode:
            return BufferedReader(raw, buffering)
        elif 'w' in mode and 'r' not in mode:
            return BufferedWriter(raw, buffering)
        else:
            return BufferedRandom(raw, buffering)
    else:
        buf = BufferedRandom(raw, buffering)
        return TextIOWrapper(buf, encoding, errors, newline)


class UnsupportedOperation(OSError, ValueError):
    pass


class BlockingIOError(OSError):
    pass


IncrementalNewlineDecoder = object
