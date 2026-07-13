class LogRecord:
    def __init__(self, name, level, pathname, lineno, msg, args, exc_info, func=None):
        self.name = name
        self.level = level
        self.pathname = pathname
        self.lineno = lineno
        self.msg = msg
        self.args = args
        self.exc_info = exc_info
        self.func = func

    def getMessage(self):
        return str(self.msg)


class Formatter:
    def __init__(self, fmt=None, datefmt=None, style='%'):
        self.fmt = fmt
        self.datefmt = datefmt
        self.style = style

    def format(self, record):
        return record.getMessage()


class Filter:
    def __init__(self, name=''):
        self.name = name

    def filter(self, record):
        return True


class Handler:
    def __init__(self, level=0):
        self.level = level
        self.formatter = None
        self.filters = []

    def setLevel(self, level):
        self.level = level

    def setFormatter(self, formatter):
        self.formatter = formatter

    def addFilter(self, filter):
        self.filters.append(filter)

    def removeFilter(self, filter):
        self.filters.remove(filter)

    def emit(self, record):
        pass

    def handle(self, record):
        return self.emit(record)


class StreamHandler(Handler):
    def __init__(self, stream=None):
        Handler.__init__(self)
        self.stream = stream


class FileHandler(StreamHandler):
    def __init__(self, filename, mode='a', encoding=None, delay=False):
        StreamHandler.__init__(self, None)
        self.filename = filename
        self.mode = mode
        self.encoding = encoding


class NullHandler(Handler):
    def emit(self, record):
        pass


class Logger:
    def __init__(self, name, level=0):
        self.name = name
        self.level = level
        self.parent = None
        self.handlers = []
        self.disabled = False

    def setLevel(self, level):
        self.level = level

    def addHandler(self, hdlr):
        self.handlers.append(hdlr)

    def removeHandler(self, hdlr):
        self.handlers.remove(hdlr)

    def addFilter(self, filter):
        pass

    def removeFilter(self, filter):
        pass

    def _log(self, level, msg, args, exc_info=None, extra=None):
        record = LogRecord(self.name, level, "", 0, msg, args, exc_info)
        for hdlr in self.handlers:
            hdlr.handle(record)

    def debug(self, msg, *args, **kwargs):
        self._log(DEBUG, msg, args, kwargs.get('exc_info'))

    def info(self, msg, *args, **kwargs):
        self._log(INFO, msg, args, kwargs.get('exc_info'))

    def warning(self, msg, *args, **kwargs):
        self._log(WARNING, msg, args, kwargs.get('exc_info'))

    def warn(self, msg, *args, **kwargs):
        self.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._log(ERROR, msg, args, kwargs.get('exc_info'))

    def critical(self, msg, *args, **kwargs):
        self._log(CRITICAL, msg, args, kwargs.get('exc_info'))

    def fatal(self, msg, *args, **kwargs):
        self.critical(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        kwargs['exc_info'] = True
        self.error(msg, *args, **kwargs)

    def log(self, level, msg, *args, **kwargs):
        self._log(level, msg, args, kwargs.get('exc_info'))


_loggers = {}


def getLogger(name=None):
    if name is None:
        name = "root"
    if name not in _loggers:
        _loggers[name] = Logger(name)
    return _loggers[name]


def basicConfig(**kwargs):
    pass


def debug(msg, *args, **kwargs):
    getLogger().debug(msg, *args, **kwargs)


def info(msg, *args, **kwargs):
    getLogger().info(msg, *args, **kwargs)


def warning(msg, *args, **kwargs):
    getLogger().warning(msg, *args, **kwargs)


def warn(msg, *args, **kwargs):
    warning(msg, *args, **kwargs)


def error(msg, *args, **kwargs):
    getLogger().error(msg, *args, **kwargs)


def critical(msg, *args, **kwargs):
    getLogger().critical(msg, *args, **kwargs)


def fatal(msg, *args, **kwargs):
    critical(msg, *args, **kwargs)


def exception(msg, *args, **kwargs):
    getLogger().exception(msg, *args, **kwargs)


def log(level, msg, *args, **kwargs):
    getLogger().log(level, msg, *args, **kwargs)


CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0
