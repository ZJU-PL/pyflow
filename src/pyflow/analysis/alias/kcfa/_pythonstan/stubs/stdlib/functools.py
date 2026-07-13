class partial:
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def __call__(self, *a, **kw):
        return self.func(*self.args, *a, **self.kwargs, **kw)


class _CacheInfo:
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.maxsize = 128
        self.currsize = 0


def lru_cache(maxsize=128, typed=False):
    def decorator(func):
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper.__wrapped__ = func
        wrapper.cache_info = lambda: _CacheInfo()
        wrapper.cache_clear = lambda: None
        return wrapper
    return decorator


def wraps(wrapped, assigned=None, updated=None):
    def decorator(wrapper):
        wrapper.__wrapped__ = wrapped
        wrapper.__name__ = wrapped.__name__
        return wrapper
    return decorator


def reduce(function, iterable, initializer=None):
    it = iter(iterable)
    if initializer is None:
        value = next(it)
    else:
        value = initializer
    for element in it:
        value = function(value, element)
    return value


def update_wrapper(wrapper, wrapped, assigned=None, updated=None):
    wrapper.__wrapped__ = wrapped
    wrapper.__name__ = wrapped.__name__
    return wrapper


def cached_property(func):
    class _CachedProperty:
        def __init__(self, f):
            self.func = f
            self.__wrapped__ = f

        def __get__(self, obj, objtype=None):
            return self.func(obj)
    return _CachedProperty(func)


def singledispatch(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    wrapper.__wrapped__ = func
    wrapper.register = lambda typ: lambda f: f
    return wrapper


def cmp_to_key(mycmp):
    class K:
        def __init__(self, obj):
            self.obj = obj
        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0
    return K


def total_ordering(cls):
    return cls
