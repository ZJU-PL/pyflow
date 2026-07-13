class ABCMeta(type):
    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        cls.__abstractmethods__ = frozenset(
            name for name, value in namespace.items()
            if getattr(value, '__isabstractmethod__', False)
        )
        cls._abc_registry = set()
        cls._abc_cache = set()
        cls._abc_negative_cache = set()
        return cls

    def register(cls, subclass):
        cls._abc_registry.add(subclass)
        return subclass

    def __instancecheck__(cls, instance):
        return cls.__subclasscheck__(type(instance))

    def __subclasscheck__(cls, subclass):
        if subclass in cls._abc_cache:
            return True
        if subclass in cls._abc_negative_cache:
            return False
        if issubclass(subclass, cls):
            cls._abc_cache.add(subclass)
            return True
        if subclass in cls._abc_registry:
            cls._abc_cache.add(subclass)
            return True
        cls._abc_negative_cache.add(subclass)
        return False


class ABC(metaclass=ABCMeta):
    __slots__ = ()


def abstractmethod(funcobj):
    funcobj.__isabstractmethod__ = True
    return funcobj


class abstractclassmethod(classmethod):
    __isabstractmethod__ = True

    def __init__(self, callable):
        callable.__isabstractmethod__ = True
        super().__init__(callable)


class abstractstaticmethod(staticmethod):
    __isabstractmethod__ = True

    def __init__(self, callable):
        callable.__isabstractmethod__ = True
        super().__init__(callable)


class abstractproperty(property):
    __isabstractmethod__ = True


def get_cache_token():
    return 0


def update_abstractmethods(cls):
    abstracts = set()
    for name in dir(cls):
        value = getattr(cls, name, None)
        if getattr(value, '__isabstractmethod__', False):
            abstracts.add(name)
    for base in cls.__bases__:
        for name in getattr(base, '__abstractmethods__', ()):
            value = getattr(cls, name, None)
            if getattr(value, '__isabstractmethod__', False):
                abstracts.add(name)
    cls.__abstractmethods__ = frozenset(abstracts)
    return cls
