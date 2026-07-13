class Parameter:
    POSITIONAL_ONLY = 0
    POSITIONAL_OR_KEYWORD = 1
    VAR_POSITIONAL = 2
    KEYWORD_ONLY = 3
    VAR_KEYWORD = 4
    empty = object()

    def __init__(self, name, kind, default=None, annotation=None):
        self.name = name
        self.kind = kind
        self.default = default if default is not None else Parameter.empty
        self.annotation = annotation if annotation is not None else Parameter.empty


class Signature:
    empty = Parameter.empty

    def __init__(self, parameters=None, return_annotation=None):
        self.parameters = {} if parameters is None else {p.name: p for p in parameters}
        self.return_annotation = return_annotation if return_annotation is not None else Signature.empty

    def bind(self, *args, **kwargs):
        return BoundArguments(self, args, kwargs)

    def bind_partial(self, *args, **kwargs):
        return BoundArguments(self, args, kwargs)


class BoundArguments:
    def __init__(self, signature, args, kwargs):
        self.signature = signature
        self.arguments = dict(kwargs)
        self.args = args
        self.kwargs = kwargs


def signature(obj, follow_wrapped=True):
    return Signature()


def getmembers(obj, predicate=None):
    result = []
    for name in dir(obj):
        value = getattr(obj, name)
        if predicate is None or predicate(value):
            result.append((name, value))
    return result


def getmembers_static(obj, predicate=None):
    return getmembers(obj, predicate)


def getmodule(obj, _filename=None):
    return obj.__module__ if hasattr(obj, '__module__') else None


def getfile(obj):
    return obj.__file__ if hasattr(obj, '__file__') else ""


def getsourcefile(obj):
    return getfile(obj)


def getsourcelines(obj):
    return ([""], 1)


def getsource(obj):
    return ""


def getdoc(obj):
    return obj.__doc__ if hasattr(obj, '__doc__') else None


def getcomments(obj):
    return None


def getmodulename(path):
    return path.rpartition('/')[2].rpartition('.')[0]


def ismodule(obj):
    return hasattr(obj, '__name__') and hasattr(obj, '__file__')


def isclass(obj):
    return isinstance(obj, type)


def ismethod(obj):
    return hasattr(obj, '__self__') and hasattr(obj, '__func__')


def isfunction(obj):
    return callable(obj) and hasattr(obj, '__code__')


def isgeneratorfunction(obj):
    return False


def isgenerator(obj):
    return hasattr(obj, '__next__') and hasattr(obj, 'send')


def iscoroutinefunction(obj):
    return False


def iscoroutine(obj):
    return False


def isasyncgenfunction(obj):
    return False


def isasyncgen(obj):
    return False


def isawaitable(obj):
    return False


def isbuiltin(obj):
    return False


def isroutine(obj):
    return callable(obj)


def isabstract(obj):
    return getattr(obj, '__abstractmethods__', False)


def isdatadescriptor(obj):
    return hasattr(obj, '__get__') and hasattr(obj, '__set__')


def isgetsetdescriptor(obj):
    return False


def ismemberdescriptor(obj):
    return False


def getmro(cls):
    return cls.__mro__


def getclasstree(classes, unique=False):
    return [(cls, getmro(cls)) for cls in classes]


def getargspec(func):
    return ArgSpec([], None, None, None)


def getfullargspec(func):
    return FullArgSpec([], None, None, None, [], {}, {})


class ArgSpec:
    def __init__(self, args, varargs, keywords, defaults):
        self.args = args
        self.varargs = varargs
        self.keywords = keywords
        self.defaults = defaults


class FullArgSpec:
    def __init__(self, args, varargs, varkw, defaults, kwonlyargs, kwonlydefaults, annotations):
        self.args = args
        self.varargs = varargs
        self.varkw = varkw
        self.defaults = defaults
        self.kwonlyargs = kwonlyargs
        self.kwonlydefaults = kwonlydefaults
        self.annotations = annotations


def currentframe():
    return _Frame()


def stack(context=1):
    return [FrameInfo(_Frame(), "", 0, "", [], 0)]


def trace(context=1):
    return [FrameInfo(_Frame(), "", 0, "", [], 0)]


def getouterframes(frame, context=1):
    return [FrameInfo(frame, "", 0, "", [], 0)]


def getinnerframes(tb, context=1):
    return [FrameInfo(_Frame(), "", 0, "", [], 0)]


class FrameInfo:
    def __init__(self, frame, filename, lineno, function, code_context, index):
        self.frame = frame
        self.filename = filename
        self.lineno = lineno
        self.function = function
        self.code_context = code_context
        self.index = index


class _Frame:
    def __init__(self):
        self.f_locals = {}
        self.f_globals = {}
        self.f_code = _Code()
        self.f_back = None
        self.f_lineno = 0


class _Code:
    def __init__(self):
        self.co_filename = ""
        self.co_name = ""
        self.co_varnames = ()
        self.co_argcount = 0


def unwrap(func, stop=None):
    while hasattr(func, '__wrapped__'):
        if stop is not None and stop(func):
            break
        func = func.__wrapped__
    return func


def get_annotations(obj, globals=None, locals=None, eval_str=False):
    return getattr(obj, '__annotations__', {})
