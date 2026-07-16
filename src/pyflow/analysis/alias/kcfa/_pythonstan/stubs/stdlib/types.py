class ModuleType:
    def __init__(self, name, doc=None):
        self.__name__ = name
        self.__doc__ = doc
        self.__dict__ = {}
        self.__loader__ = None
        self.__package__ = None
        self.__spec__ = None


class FunctionType:
    def __init__(self, code, globals, name=None, argdefs=None, closure=None):
        self.__code__ = code
        self.__globals__ = globals
        self.__name__ = name or ""
        self.__defaults__ = argdefs
        self.__closure__ = closure


class LambdaType(FunctionType):
    pass


class CodeType:
    def __init__(self, argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,
                 flags, codestring, constants, names, varnames, filename, name,
                 firstlineno, linetable, freevars=(), cellvars=()):
        self.co_argcount = argcount
        self.co_posonlyargcount = posonlyargcount
        self.co_kwonlyargcount = kwonlyargcount
        self.co_nlocals = nlocals
        self.co_stacksize = stacksize
        self.co_flags = flags
        self.co_code = codestring
        self.co_consts = constants
        self.co_names = names
        self.co_varnames = varnames
        self.co_filename = filename
        self.co_name = name
        self.co_firstlineno = firstlineno
        self.co_linetable = linetable
        self.co_freevars = freevars
        self.co_cellvars = cellvars


class MethodType:
    def __init__(self, func, obj):
        self.__func__ = func
        self.__self__ = obj

    def __call__(self, *args, **kwargs):
        return self.__func__(self.__self__, *args, **kwargs)


class BuiltinFunctionType:
    pass


class BuiltinMethodType:
    pass


class WrapperDescriptorType:
    pass


class MethodWrapperType:
    pass


class MethodDescriptorType:
    pass


class ClassMethodDescriptorType:
    pass


class GeneratorType:
    def __init__(self, frame):
        self.gi_frame = frame
        self.gi_code = frame.f_code if hasattr(frame, 'f_code') else None
        self.gi_running = False
        self.gi_yieldfrom = None

    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration

    def send(self, value):
        return next(self)

    def throw(self, typ, val=None, tb=None):
        raise typ(val)

    def close(self):
        pass


class CoroutineType:
    def __init__(self, cr_frame):
        self.cr_frame = cr_frame
        self.cr_code = None
        self.cr_running = False
        self.cr_await = None

    def send(self, value):
        pass

    def throw(self, typ, val=None, tb=None):
        raise typ(val)

    def close(self):
        pass


class AsyncGeneratorType:
    def __init__(self, ag_frame):
        self.ag_frame = ag_frame
        self.ag_code = None
        self.ag_running = False
        self.ag_await = None

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration

    async def asend(self, value):
        return await self.__anext__()

    async def athrow(self, typ, val=None, tb=None):
        raise typ(val)

    async def aclose(self):
        pass


class FrameType:
    def __init__(self):
        self.f_back = None
        self.f_code = None
        self.f_locals = {}
        self.f_globals = {}
        self.f_builtins = {}
        self.f_lineno = 0
        self.f_trace = None


class TracebackType:
    def __init__(self, tb_next, tb_frame, tb_lasti, tb_lineno):
        self.tb_next = tb_next
        self.tb_frame = tb_frame
        self.tb_lasti = tb_lasti
        self.tb_lineno = tb_lineno


class GetSetDescriptorType:
    pass


class MemberDescriptorType:
    pass


class MappingProxyType:
    def __init__(self, mapping):
        self._mapping = mapping

    def __getitem__(self, key):
        return self._mapping[key]

    def __iter__(self):
        return iter(self._mapping)

    def __len__(self):
        return len(self._mapping)

    def keys(self):
        return self._mapping.keys()

    def values(self):
        return self._mapping.values()

    def items(self):
        return self._mapping.items()

    def get(self, key, default=None):
        return self._mapping.get(key, default)


class SimpleNamespace:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        items = (f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"namespace({', '.join(items)})"

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class DynamicClassAttribute:
    def __init__(self, fget=None, fset=None, fdel=None, doc=None):
        self.fget = fget
        self.fset = fset
        self.fdel = fdel
        self.__doc__ = doc

    def __get__(self, instance, ownerclass=None):
        if instance is None:
            return self
        return self.fget(instance)


def new_class(name, bases=(), kwds=None, exec_body=None):
    meta = kwds.get('metaclass', type) if kwds else type
    ns = {}
    if exec_body is not None:
        exec_body(ns)
    return meta(name, bases, ns)


def prepare_class(name, bases=(), kwds=None):
    meta = kwds.get('metaclass', type) if kwds else type
    ns = {}
    return meta, ns, {}


def resolve_bases(bases):
    return bases


def coroutine(func):
    func._is_coroutine = True
    return func


NoneType = type(None)
EllipsisType = type(...)
NotImplementedType = type(NotImplemented)
UnionType = type
GenericAlias = type
