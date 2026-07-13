MISSING = object()
KW_ONLY = object()


class Field:
    def __init__(self, default=MISSING, default_factory=MISSING, repr=True,
                 hash=None, init=True, compare=True, metadata=None, kw_only=MISSING):
        self.name = None
        self.type = None
        self.default = default
        self.default_factory = default_factory
        self.repr = repr
        self.hash = hash
        self.init = init
        self.compare = compare
        self.metadata = metadata or {}
        self.kw_only = kw_only


def field(default=MISSING, default_factory=MISSING, repr=True, hash=None,
          init=True, compare=True, metadata=None, kw_only=MISSING):
    return Field(default, default_factory, repr, hash, init, compare, metadata, kw_only)


def dataclass(cls=None, *, init=True, repr=True, eq=True, order=False,
              unsafe_hash=False, frozen=False, match_args=True,
              kw_only=False, slots=False, weakref_slot=False):
    def wrap(cls):
        cls.__dataclass_fields__ = {}
        annotations = getattr(cls, '__annotations__', {})
        for name, type_ in annotations.items():
            f = getattr(cls, name, MISSING)
            if isinstance(f, Field):
                f.name = name
                f.type = type_
                cls.__dataclass_fields__[name] = f
            else:
                new_field = Field(default=f if f is not MISSING else MISSING)
                new_field.name = name
                new_field.type = type_
                cls.__dataclass_fields__[name] = new_field

        if init:
            original_init = cls.__init__ if hasattr(cls, '__init__') else None
            def __init__(self, *args, **kwargs):
                for i, (name, f) in enumerate(cls.__dataclass_fields__.items()):
                    if i < len(args):
                        setattr(self, name, args[i])
                    elif name in kwargs:
                        setattr(self, name, kwargs[name])
                    elif f.default is not MISSING:
                        setattr(self, name, f.default)
                    elif f.default_factory is not MISSING:
                        setattr(self, name, f.default_factory())
            cls.__init__ = __init__

        if repr:
            def __repr__(self):
                fields_str = ", ".join(
                    f"{name}={getattr(self, name)!r}"
                    for name in cls.__dataclass_fields__
                )
                return f"{cls.__name__}({fields_str})"
            cls.__repr__ = __repr__

        if eq:
            def __eq__(self, other):
                if other.__class__ is not self.__class__:
                    return NotImplemented
                return all(
                    getattr(self, name) == getattr(other, name)
                    for name in cls.__dataclass_fields__
                )
            cls.__eq__ = __eq__

        if match_args:
            cls.__match_args__ = tuple(cls.__dataclass_fields__.keys())

        return cls

    return wrap(cls) if cls is not None else wrap


def fields(class_or_instance):
    if isinstance(class_or_instance, type):
        cls = class_or_instance
    else:
        cls = type(class_or_instance)
    return tuple(cls.__dataclass_fields__.values())


def asdict(obj, dict_factory=dict):
    result = {}
    for name in obj.__dataclass_fields__:
        result[name] = getattr(obj, name)
    return dict_factory(result.items()) if dict_factory is not dict else result


def astuple(obj, tuple_factory=tuple):
    return tuple_factory(getattr(obj, name) for name in obj.__dataclass_fields__)


def make_dataclass(cls_name, fields, *, bases=(), namespace=None, init=True,
                   repr=True, eq=True, order=False, unsafe_hash=False,
                   frozen=False, match_args=True, kw_only=False, slots=False,
                   weakref_slot=False):
    ns = namespace or {}
    annotations = {}
    for item in fields:
        if isinstance(item, str):
            annotations[item] = object
        elif isinstance(item, tuple):
            name = item[0]
            type_ = item[1] if len(item) > 1 else object
            default = item[2] if len(item) > 2 else MISSING
            annotations[name] = type_
            if default is not MISSING:
                ns[name] = default
    ns['__annotations__'] = annotations
    cls = type(cls_name, bases, ns)
    return dataclass(cls, init=init, repr=repr, eq=eq, order=order,
                     unsafe_hash=unsafe_hash, frozen=frozen, match_args=match_args,
                     kw_only=kw_only, slots=slots, weakref_slot=weakref_slot)


def replace(obj, **changes):
    new_obj = object.__new__(type(obj))
    for name in obj.__dataclass_fields__:
        if name in changes:
            setattr(new_obj, name, changes[name])
        else:
            setattr(new_obj, name, getattr(obj, name))
    return new_obj


def is_dataclass(obj):
    cls = obj if isinstance(obj, type) else type(obj)
    return hasattr(cls, '__dataclass_fields__')


class InitVar:
    def __init__(self, type):
        self.type = type

    def __class_getitem__(cls, type):
        return InitVar(type)


class FrozenInstanceError(AttributeError):
    pass
