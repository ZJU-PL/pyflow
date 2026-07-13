class _EnumMeta(type):
    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        cls._member_map_ = {}
        cls._member_names_ = []
        cls._value2member_map_ = {}
        for key, value in namespace.items():
            if not key.startswith('_') and not callable(value):
                member = object.__new__(cls)
                member._name_ = key
                member._value_ = value
                cls._member_map_[key] = member
                cls._member_names_.append(key)
                cls._value2member_map_[value] = member
                setattr(cls, key, member)
        return cls

    def __iter__(cls):
        return iter(cls._member_map_.values())

    def __getitem__(cls, name):
        return cls._member_map_[name]

    def __len__(cls):
        return len(cls._member_map_)

    def __contains__(cls, member):
        return member in cls._member_map_.values()


class Enum(metaclass=_EnumMeta):
    @property
    def name(self):
        return self._name_

    @property
    def value(self):
        return self._value_

    def __repr__(self):
        return f"<{self.__class__.__name__}.{self._name_}: {self._value_!r}>"

    def __str__(self):
        return f"{self.__class__.__name__}.{self._name_}"

    def __hash__(self):
        return hash(self._name_)

    def __eq__(self, other):
        return self is other


class IntEnum(int, Enum):
    def __new__(cls, value):
        obj = int.__new__(cls, value)
        obj._value_ = value
        return obj


class StrEnum(str, Enum):
    def __new__(cls, value):
        obj = str.__new__(cls, value)
        obj._value_ = value
        return obj


class Flag(Enum):
    def __or__(self, other):
        return self.__class__(self._value_ | other._value_)

    def __and__(self, other):
        return self.__class__(self._value_ & other._value_)

    def __xor__(self, other):
        return self.__class__(self._value_ ^ other._value_)

    def __invert__(self):
        return self.__class__(~self._value_)


class IntFlag(int, Flag):
    def __new__(cls, value):
        obj = int.__new__(cls, value)
        obj._value_ = value
        return obj


def unique(enumeration):
    return enumeration


def auto():
    return _Auto()


class _Auto:
    pass


def verify(verification):
    def decorator(cls):
        return cls
    return decorator


STRICT = 'STRICT'
CONFORM = 'CONFORM'
EJECT = 'EJECT'
KEEP = 'KEEP'
UNIQUE = 'UNIQUE'
CONTINUOUS = 'CONTINUOUS'
NAMED_FLAGS = 'NAMED_FLAGS'


class property:
    def __init__(self, fget=None, fset=None, fdel=None, doc=None):
        self.fget = fget
        self.fset = fset
        self.fdel = fdel
        self.__doc__ = doc

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return self.fget(obj)

    def __set__(self, obj, value):
        self.fset(obj, value)

    def __delete__(self, obj):
        self.fdel(obj)

    def getter(self, fget):
        return type(self)(fget, self.fset, self.fdel, self.__doc__)

    def setter(self, fset):
        return type(self)(self.fget, fset, self.fdel, self.__doc__)

    def deleter(self, fdel):
        return type(self)(self.fget, self.fset, fdel, self.__doc__)


member = property
nonmember = lambda x: x
