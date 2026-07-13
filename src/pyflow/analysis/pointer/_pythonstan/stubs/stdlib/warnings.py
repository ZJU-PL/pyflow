filters = []
_filters_mutated = lambda: None


def warn(message, category=None, stacklevel=1, source=None):
    pass


def warn_explicit(message, category, filename, lineno, module=None, registry=None,
                  module_globals=None, source=None):
    pass


def showwarning(message, category, filename, lineno, file=None, line=None):
    pass


def formatwarning(message, category, filename, lineno, line=None):
    return f"{filename}:{lineno}: {category.__name__}: {message}\n"


def filterwarnings(action, message='', category=Warning, module='', lineno=0, append=False):
    entry = (action, message, category, module, lineno)
    if append:
        filters.append(entry)
    else:
        filters.insert(0, entry)


def simplefilter(action, category=Warning, lineno=0, append=False):
    filterwarnings(action, '', category, '', lineno, append)


def resetwarnings():
    filters.clear()


class catch_warnings:
    def __init__(self, *, record=False, module=None):
        self._record = record
        self._module = module
        self._entered = False
        self._filters = None
        self._log = []

    def __enter__(self):
        self._entered = True
        self._filters = filters.copy()
        if self._record:
            return self._log
        return None

    def __exit__(self, exc_type, exc, tb):
        filters.clear()
        filters.extend(self._filters)
        return False


class WarningMessage:
    def __init__(self, message, category, filename, lineno, file=None, line=None, source=None):
        self.message = message
        self.category = category
        self.filename = filename
        self.lineno = lineno
        self.file = file
        self.line = line
        self.source = source

    def __str__(self):
        return f"{self.filename}:{self.lineno}: {self.category.__name__}: {self.message}"


def _formatwarnmsg(msg):
    return formatwarning(msg.message, msg.category, msg.filename, msg.lineno, msg.line)


def _showwarnmsg(msg):
    showwarning(msg.message, msg.category, msg.filename, msg.lineno, msg.file, msg.line)


default_action = "default"
once_registry = {}
