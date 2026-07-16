def print_tb(tb, limit=None, file=None):
    pass


def print_exception(exc, value=None, tb=None, limit=None, file=None, chain=True):
    pass


def print_exc(limit=None, file=None, chain=True):
    pass


def print_last(limit=None, file=None, chain=True):
    pass


def print_stack(f=None, limit=None, file=None):
    pass


def extract_tb(tb, limit=None):
    return StackSummary()


def extract_stack(f=None, limit=None):
    return StackSummary()


def format_list(extracted_list):
    return [str(item) for item in extracted_list]


def format_exception_only(exc, value=None):
    if value is None:
        return [f"{exc.__name__}\n"]
    return [f"{exc.__name__}: {value}\n"]


def format_exception(exc, value=None, tb=None, limit=None, chain=True):
    return format_exception_only(exc, value)


def format_exc(limit=None, chain=True):
    return ""


def format_tb(tb, limit=None):
    return []


def format_stack(f=None, limit=None):
    return []


def clear_frames(tb):
    pass


def walk_stack(f):
    while f is not None:
        yield f, f.f_lineno
        f = f.f_back


def walk_tb(tb):
    while tb is not None:
        yield tb.tb_frame, tb.tb_lineno
        tb = tb.tb_next


class FrameSummary:
    __slots__ = ('filename', 'lineno', 'name', 'line', 'locals', '_line')

    def __init__(self, filename, lineno, name, lookup_line=True, locals=None, line=None):
        self.filename = filename
        self.lineno = lineno
        self.name = name
        self._line = line
        self.locals = locals

    @property
    def line(self):
        return self._line

    def __iter__(self):
        return iter((self.filename, self.lineno, self.name, self.line))

    def __getitem__(self, index):
        return (self.filename, self.lineno, self.name, self.line)[index]

    def __repr__(self):
        return f"<FrameSummary file {self.filename}, line {self.lineno} in {self.name}>"


class StackSummary(list):
    @classmethod
    def extract(cls, frame_gen, limit=None, lookup_lines=True, capture_locals=False):
        result = cls()
        for f, lineno in frame_gen:
            co = f.f_code
            filename = co.co_filename
            name = co.co_name
            locals_ = f.f_locals if capture_locals else None
            result.append(FrameSummary(filename, lineno, name, lookup_lines, locals_))
            if limit is not None and len(result) >= limit:
                break
        return result

    @classmethod
    def from_list(cls, a_list):
        result = cls()
        for item in a_list:
            if isinstance(item, FrameSummary):
                result.append(item)
            else:
                result.append(FrameSummary(item[0], item[1], item[2], line=item[3] if len(item) > 3 else None))
        return result

    def format(self):
        result = []
        for frame in self:
            result.append(f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}\n')
            if frame.line:
                result.append(f'    {frame.line.strip()}\n')
        return result


class TracebackException:
    def __init__(self, exc_type, exc_value, exc_traceback, limit=None,
                 lookup_lines=True, capture_locals=False, compact=False, _seen=None):
        self.exc_type = exc_type
        self._str = str(exc_value) if exc_value else ""
        self.stack = StackSummary()
        self.__cause__ = None
        self.__context__ = None
        self.__suppress_context__ = False
        self.__notes__ = getattr(exc_value, '__notes__', None)

    @classmethod
    def from_exception(cls, exc, limit=None, lookup_lines=True, capture_locals=False):
        return cls(type(exc), exc, exc.__traceback__, limit, lookup_lines, capture_locals)

    def format(self, chain=True):
        result = []
        result.append(f"Traceback (most recent call last):\n")
        result.extend(self.stack.format())
        result.extend(format_exception_only(self.exc_type, self._str))
        return result

    def format_exception_only(self):
        return format_exception_only(self.exc_type, self._str)
