"""Python object protocols expressed using only the seven MIR instructions.

These routines *generate MIR*. They are not callbacks executed by the analyzer
or the MIR interpreter. In particular, lookup, binding, reflected operators,
and calling a callable object remain visible in a dumped program.
"""

from __future__ import annotations

from .builder import Builder, field
from .model import (
    Alloc,
    Binary,
    Delete,
    DictExpr,
    Lambda,
    Length,
    ListExpr,
    Literal,
    NewObject,
    Not,
    Var,
)


class Runtime:
    TYPES = (
        "object",
        "type",
        "function",
        "method",
        "module",
        "NoneType",
        "NotImplementedType",
        "int",
        "bool",
        "str",
        "list",
        "tuple",
        "dict",
        "set",
        "iterator",
        "generator",
        "super",
        "property",
        "staticmethod",
        "classmethod",
        "BaseException",
        "Exception",
        "TypeError",
        "ValueError",
        "AttributeError",
        "IndexError",
        "KeyError",
        "NameError",
        "RuntimeError",
        "AssertionError",
        "StopIteration",
        "ZeroDivisionError",
        "ImportError",
    )

    def __init__(self, program):
        self.program = program
        self.serial = 0
        self.helpers = {}

    @staticmethod
    def builtin(name):
        return field(Var("$builtins"), name)

    @property
    def none(self):
        return self.builtin("None")

    @property
    def missing(self):
        return self.builtin("$missing")

    @property
    def not_implemented(self):
        return self.builtin("NotImplemented")

    @property
    def exception(self):
        return field(self.builtin("$state"), "exception")

    def raw(self, b, value):
        return b.alloc(Literal(value), "literal")

    def obj(self, b, cls="object"):
        value = b.alloc(NewObject(), "object")
        identity = b.alloc(NewObject(), "identity")
        b.assign(field(value, "$identity"), identity)
        b.assign(field(value, "__class__"), self.builtin(cls) if isinstance(cls, str) else cls)
        return value

    def box(self, b, value, cls=None):
        if cls is None:
            cls = "bool" if isinstance(value, bool) else "int" if isinstance(value, int) else "str"
        result = self.obj(b, cls)
        raw = self.raw(b, value) if isinstance(value, (str, bool, int)) else b.alloc(value, "value")
        b.assign(field(result, "$value"), raw)
        if cls == "str" and isinstance(value, str):
            chars = []
            for character in value:
                char = self.obj(b, "str")
                b.assign(field(char, "$value"), self.raw(b, character))
                b.assign(field(char, "$chars"), b.alloc(ListExpr((char,)), "char"))
                chars.append(char)
            b.assign(field(result, "$chars"), b.alloc(ListExpr(tuple(chars)), "chars"))
        return result

    def sequence(self, b, items, cls="list"):
        return self.box(b, ListExpr(tuple(items)), cls)

    def function(self, b, body):
        result = self.obj(b, "function")
        closure = b.alloc(Lambda("$args", "$kwargs", "$parent", body, "$return"), "code")
        b.assign(field(result, "$function"), self.raw(b, True))
        b.assign(field(result, "__call__"), closure)
        return result

    def prologue(self, b):
        b.assign("$builtins", field(Var("$parent"), "$builtins"))
        b.assign("$return", self.none)

    def error(self, b, name="TypeError"):
        exc = self.obj(b, name)
        b.assign(self.exception, exc)
        b.ret(self.none)

    def checked(self, b):
        """Propagate an exception from a generated helper to its caller."""
        good, bad = b.branch(Binary("=", self.exception, self.none))
        b.use(bad)
        b.ret(self.none)
        b.use(good)

    def helper(self, kind, owner, operator=None):
        # One instance per requesting CFG and protocol keeps helper merging
        # from joining unrelated call sites in the context-insensitive solver.
        key = (owner, kind, operator)
        if key in self.helpers:
            return self.helpers[key]
        self.serial += 1
        name = f"{owner}.$mir_{kind}_{self.serial}"
        self.helpers[key] = name
        b = Builder(self.program, name, synthetic=True)
        self.prologue(b)
        getattr(self, "build_" + kind)(b, operator)
        b.finish()
        return name

    def invoke(self, b, kind, args, operator=None, unique=True):
        owner = f"{b.name}.{b.temp('site')}" if unique else b.name
        return b.invoke(self.helper(kind, owner, operator), args)

    def call(self, b, callee, args=(), kwargs=None, raw_args=None):
        positional = raw_args if raw_args is not None else b.alloc(ListExpr(tuple(args)), "args")
        keywords = kwargs if kwargs is not None else b.alloc(DictExpr(()), "kwargs")
        return self.invoke(b, "call", (callee, positional, keywords))

    def lookup(self, b, cls, key, after=None):
        """Raw special-method lookup along an explicit MRO (no descriptors)."""
        result = b.bind(self.missing, "lookup")
        sequence = b.bind(field(cls, "__mro__"), "mro")
        index = b.alloc(Literal(1), "index")
        enabled = b.alloc(Literal(after is None), "enabled")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", Length(sequence), index)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        base = b.bind(field(sequence, index), "base")
        enabled_yes, enabled_no = b.branch(enabled)
        b.use(enabled_no)
        if after is not None:
            match, mismatch = b.branch(Binary("=", base, after))
            b.use(match)
            b.emit(Alloc(enabled.name, Literal(True)))
            skipped = set(b.tails)
            b.join(skipped, mismatch)
        skipped = set(b.tails)
        b.use(enabled_yes)
        found, absent = b.branch(
            Binary("in", key if not isinstance(key, str) else Literal(key), base)
        )
        b.use(found)
        b.assign(result, field(base, key))
        b.jump(done)
        b.join(skipped, absent)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        return result

    def contains_class(self, b, cls, candidate):
        sequence = b.bind(field(cls, "__mro__"), "mro")
        found = b.alloc(Literal(False), "subclass")
        index = b.alloc(Literal(1), "index")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", Length(sequence), index)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        match, no = b.branch(Binary("=", field(sequence, index), candidate))
        b.use(match)
        b.emit(Alloc(found.name, Literal(True)))
        b.jump(done)
        b.use(no)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        return found

    def bind_method(self, b, method, receiver, cls):
        result = b.bind(method, "bound")
        function, other = b.branch(Binary("in", Literal("$function"), method))
        b.use(function)
        bound = self.obj(b, "method")
        b.assign(field(bound, "$bound"), method)
        b.assign(field(bound, "$self"), receiver)
        b.assign(result, bound)
        fn_tails = set(b.tails)
        b.use(other)
        static, nonstatic = b.branch(Binary("in", Literal("$staticmethod"), method))
        b.use(static)
        b.assign(result, field(method, "$staticmethod"))
        static_tails = set(b.tails)
        b.use(nonstatic)
        classmethod, ordinary = b.branch(Binary("in", Literal("$classmethod"), method))
        b.use(classmethod)
        bound = self.obj(b, "method")
        b.assign(field(bound, "$bound"), field(method, "$classmethod"))
        b.assign(field(bound, "$self"), cls)
        b.assign(result, bound)
        cm_tails = set(b.tails)
        b.join(fn_tails, static_tails, cm_tails, ordinary)
        return result

    def build_call(self, b, mode):
        callee = b.bind(field(Var("$args"), 1), "callee")
        args = b.bind(field(Var("$args"), 2), "positional")
        kwargs = b.bind(field(Var("$args"), 3), "keywords")
        loop = b.node()
        b.jump(loop)
        b.use({loop})
        function, notfunction = b.branch(Binary("in", Literal("$function"), callee))
        b.use(function)
        result = b.call(field(callee, "__call__"), args, kwargs)
        b.ret(result)
        b.use(notfunction)
        bound, notbound = b.branch(Binary("in", Literal("$bound"), callee))
        b.use(bound)
        prefix = b.alloc(ListExpr((field(callee, "$self"),)), "receiver")
        b.emit(Alloc(args.name, Binary("+", prefix, args)))
        b.assign(callee, field(callee, "$bound"))
        b.jump(loop)
        b.use(notbound)
        isclass, notclass = b.branch(Binary("in", Literal("$class"), callee))
        b.use(isclass)
        constructor = self.lookup(b, callee, "__new__")
        hasnew, nonew = b.branch(Not(Binary("=", constructor, self.missing)))
        instance = Var(b.temp("instance"))
        b.use(nonew)
        b.assign(instance, self.obj(b, callee))
        default_tails = set(b.tails)
        b.use(hasnew)
        prefix = b.alloc(ListExpr((callee,)), "classarg")
        newargs = b.alloc(Binary("+", prefix, args), "newargs")
        raw_constructor = b.bind(constructor, "constructor")
        static, nonstatic = b.branch(Binary("in", Literal("$staticmethod"), constructor))
        b.use(static)
        b.assign(raw_constructor, field(constructor, "$staticmethod"))
        static_tails = set(b.tails)
        b.join(static_tails, nonstatic)
        constructor_dispatch = (
            b.name if mode == "recursive" else self.helper("call", b.name + ".$new", "recursive")
        )
        result = b.invoke(constructor_dispatch, (raw_constructor, newargs, kwargs))
        self.checked(b)
        b.assign(instance, result)
        b.join(default_tails, b.tails)
        # __init__ is called only when __new__ returns an instance of this class.
        subclass = self.contains_class(b, field(instance, "__class__"), callee)
        initialize, finish = b.branch(subclass)
        b.use(finish)
        b.ret(instance)
        b.use(initialize)
        actual_class = field(instance, "__class__")
        init = self.lookup(b, actual_class, "__init__")
        exists, absent = b.branch(Not(Binary("=", init, self.missing)))
        b.use(absent)
        b.ret(instance)
        b.use(exists)
        method = self.bind_method(b, init, instance, actual_class)
        init_dispatch = (
            b.name if mode == "recursive" else self.helper("call", b.name + ".$init", "recursive")
        )
        initialized = b.invoke(init_dispatch, (method, args, kwargs))
        self.checked(b)
        valid, invalid = b.branch(Binary("=", initialized, self.none))
        b.use(invalid)
        self.error(b)
        b.use(valid)
        b.ret(instance)
        b.use(notclass)
        method = self.lookup(b, field(callee, "__class__"), "__call__")
        exists, absent = b.branch(Not(Binary("=", method, self.missing)))
        b.use(absent)
        self.error(b)
        b.use(exists)
        # For a non-function __call__, repeat dispatch without injecting self.
        b.assign(callee, self.bind_method(b, method, callee, field(callee, "__class__")))
        b.jump(loop)

    def descriptor(self, b, descriptor, receiver, owner):
        getter = self.lookup(b, field(descriptor, "__class__"), "__get__")
        result = b.bind(descriptor, "descriptor")
        yes, no = b.branch(Not(Binary("=", getter, self.missing)))
        b.use(yes)
        bound = self.bind_method(b, getter, descriptor, field(descriptor, "__class__"))
        b.assign(result, self.call(b, bound, (receiver, owner)))
        self.checked(b)
        b.join(b.tails, no)
        return result

    def build_getattr(self, b, _):
        obj = b.bind(field(Var("$args"), 1), "receiver")
        name = b.bind(field(Var("$args"), 2), "attribute")  # raw MIR string
        cls = b.bind(field(obj, "__class__"), "class")
        ismodule, rest = b.branch(Binary("in", Literal("$module"), obj))
        b.use(ismodule)
        exists, absent = b.branch(Binary("in", name, field(obj, "$env")))
        b.use(exists)
        b.ret(field(field(obj, "$env"), name))
        b.use(absent)
        self.error(b, "AttributeError")
        b.use(rest)
        issuper, normal = b.branch(Binary("in", Literal("$super"), obj))
        b.use(issuper)
        receiver = b.bind(field(obj, "$self"), "self")
        owner = b.bind(field(receiver, "__class__"), "owner")
        class_receiver, ordinary_receiver = b.branch(Binary("in", Literal("$class"), receiver))
        b.use(class_receiver)
        b.assign(owner, receiver)
        b.join(b.tails, ordinary_receiver)
        method = self.lookup(b, owner, name, after=field(obj, "$super"))
        yes, no = b.branch(Not(Binary("=", method, self.missing)))
        b.use(no)
        self.error(b, "AttributeError")
        b.use(yes)
        b.ret(self.bind_method(b, method, receiver, owner))
        b.use(normal)
        custom = self.lookup(b, cls, "__getattribute__")
        yes, no = b.branch(Not(Binary("=", custom, self.missing)))
        b.use(yes)
        bound = self.bind_method(b, custom, obj, cls)
        result = self.call(b, bound, (self.box(b, name, "str"),))
        success, failure = b.branch(Binary("=", self.exception, self.none))
        b.use(success)
        b.ret(result)
        b.use(failure)
        exception = b.bind(self.exception, "attribute_exception")
        attr_error = self.contains_class(
            b, field(exception, "__class__"), self.builtin("AttributeError")
        )
        fallback_path, other_error = b.branch(attr_error)
        b.use(other_error)
        b.ret(self.none)
        b.use(fallback_path)
        fallback = self.lookup(b, cls, "__getattr__")
        exists, absent = b.branch(Not(Binary("=", fallback, self.missing)))
        b.use(absent)
        b.ret(self.none)
        b.use(exists)
        b.assign(self.exception, self.none)
        fallback = self.bind_method(b, fallback, obj, cls)
        b.ret(self.call(b, fallback, (self.box(b, name, "str"),)))
        b.use(no)
        classobj, instance = b.branch(Binary("in", Literal("$class"), obj))
        b.use(classobj)
        value = self.lookup(b, obj, name)
        exists, absent = b.branch(Not(Binary("=", value, self.missing)))
        b.use(absent)
        self.error(b, "AttributeError")
        b.use(exists)
        # Ordinary functions accessed on a class stay unbound.
        cm, notcm = b.branch(Binary("in", Literal("$classmethod"), value))
        b.use(cm)
        b.ret(self.bind_method(b, value, self.none, obj))
        b.use(notcm)
        sm, notsm = b.branch(Binary("in", Literal("$staticmethod"), value))
        b.use(sm)
        b.ret(field(value, "$staticmethod"))
        b.use(notsm)
        b.ret(self.descriptor(b, value, self.none, obj))
        b.use(instance)
        class_value = self.lookup(b, cls, name)
        exists, absent = b.branch(Not(Binary("=", class_value, self.missing)))
        b.use(exists)
        setter = self.lookup(b, field(class_value, "__class__"), "__set__")
        deleter = self.lookup(b, field(class_value, "__class__"), "__delete__")
        data, nondata = b.branch(
            Binary(
                "or",
                Not(Binary("=", setter, self.missing)),
                Not(Binary("=", deleter, self.missing)),
            )
        )
        b.use(data)
        b.ret(self.descriptor(b, class_value, obj, cls))
        b.join(nondata, absent)
        own, notown = b.branch(Binary("in", name, obj))
        b.use(own)
        b.ret(field(obj, name))
        b.use(notown)
        exists, absent = b.branch(Not(Binary("=", class_value, self.missing)))
        b.use(exists)
        value = self.bind_method(b, class_value, obj, cls)
        bound, notbound = b.branch(Binary("in", Literal("$bound"), value))
        b.use(bound)
        b.ret(value)
        b.use(notbound)
        b.ret(self.descriptor(b, value, obj, cls))
        b.use(absent)
        fallback = self.lookup(b, cls, "__getattr__")
        exists, absent = b.branch(Not(Binary("=", fallback, self.missing)))
        b.use(absent)
        self.error(b, "AttributeError")
        b.use(exists)
        bound = self.bind_method(b, fallback, obj, cls)
        b.ret(self.call(b, bound, (self.box(b, name, "str"),)))

    def build_setattr(self, b, operation):
        obj = b.bind(field(Var("$args"), 1), "receiver")
        name = b.bind(field(Var("$args"), 2), "attribute")
        value = field(Var("$args"), 3) if operation != "delete" else None
        cls = field(obj, "__class__")
        method = self.lookup(b, cls, "__delattr__" if value is None else "__setattr__")
        exists, absent = b.branch(Not(Binary("=", method, self.missing)))
        b.use(exists)
        bound = self.bind_method(b, method, obj, cls)
        args = (self.box(b, name, "str"),) + (() if value is None else (value,))
        b.ret(self.call(b, bound, args))
        b.use(absent)
        descriptor = self.lookup(b, cls, name)
        exists, absent = b.branch(Not(Binary("=", descriptor, self.missing)))
        b.use(exists)
        setter = self.lookup(
            b, field(descriptor, "__class__"), "__delete__" if value is None else "__set__"
        )
        yes, no = b.branch(Not(Binary("=", setter, self.missing)))
        b.use(yes)
        bound = self.bind_method(b, setter, descriptor, field(descriptor, "__class__"))
        b.ret(self.call(b, bound, (obj,) + (() if value is None else (value,))))
        b.join(no, absent)
        if value is None:
            exists, absent = b.branch(Binary("in", name, obj))
            b.use(absent)
            self.error(b, "AttributeError")
            b.use(exists)
            b.emit(Delete(field(obj, name)))
        else:
            b.assign(field(obj, name), value)
        b.ret(self.none)

    def build_truth(self, b, _):
        obj = b.bind(field(Var("$args"), 1), "value")
        isnone, other = b.branch(Binary("=", obj, self.none))
        b.use(isnone)
        b.ret(self.raw(b, False))
        b.use(other)
        cls = field(obj, "__class__")
        method = self.lookup(b, cls, "__bool__")
        exists, absent = b.branch(Not(Binary("=", method, self.missing)))
        b.use(exists)
        bound = self.bind_method(b, method, obj, cls)
        result = self.call(b, bound)
        self.checked(b)
        valid, invalid = b.branch(Binary("=", field(result, "__class__"), self.builtin("bool")))
        b.use(invalid)
        self.error(b)
        b.use(valid)
        b.ret(field(result, "$value"))
        b.use(absent)
        method = self.lookup(b, cls, "__len__")
        exists, absent = b.branch(Not(Binary("=", method, self.missing)))
        b.use(exists)
        result = self.call(b, self.bind_method(b, method, obj, cls))
        self.checked(b)
        valid = self.contains_class(b, field(result, "__class__"), self.builtin("int"))
        good, bad = b.branch(valid)
        b.use(bad)
        self.error(b)
        b.use(good)
        boolean, integer = b.branch(Binary("=", field(result, "__class__"), self.builtin("bool")))
        b.use(boolean)
        b.ret(field(result, "$value"))
        b.use(integer)
        negative, nonnegative = b.branch(Binary("<", field(result, "$value"), Literal(0)))
        b.use(negative)
        self.error(b, "ValueError")
        b.use(nonnegative)
        b.ret(b.alloc(Not(Binary("=", field(result, "$value"), Literal(0))), "truth"))
        b.use(absent)
        b.ret(self.raw(b, True))

    def build_binary(self, b, operator):
        left = b.bind(field(Var("$args"), 1), "left")
        right = b.bind(field(Var("$args"), 2), "right")
        names = {
            "+": ("__add__", "__radd__"),
            "-": ("__sub__", "__rsub__"),
            "*": ("__mul__", "__rmul__"),
            "/": ("__truediv__", "__rtruediv__"),
            "//": ("__floordiv__", "__rfloordiv__"),
            "%": ("__mod__", "__rmod__"),
            "**": ("__pow__", "__rpow__"),
            "@": ("__matmul__", "__rmatmul__"),
            "&": ("__and__", "__rand__"),
            "|": ("__or__", "__ror__"),
            "^": ("__xor__", "__rxor__"),
            "<<": ("__lshift__", "__rlshift__"),
            ">>": ("__rshift__", "__rrshift__"),
            "==": ("__eq__", "__eq__"),
            "!=": ("__ne__", "__ne__"),
            "<": ("__lt__", "__gt__"),
            "<=": ("__le__", "__ge__"),
            ">": ("__gt__", "__lt__"),
            ">=": ("__ge__", "__le__"),
        }
        forward_name, reflected_name = names[operator]
        leftcls, rightcls = field(left, "__class__"), field(right, "__class__")
        forward = self.lookup(b, leftcls, forward_name)
        reflected = self.lookup(b, rightcls, reflected_name)
        tried = b.alloc(Literal(False), "reflected_tried")
        different, same = b.branch(Not(Binary("=", leftcls, rightcls)))
        b.use(different)
        subclass = self.contains_class(b, rightcls, leftcls)
        prefer, ordinary = b.branch(subclass)
        b.use(prefer)
        inherited = self.lookup(b, leftcls, reflected_name)
        priority = (
            Literal(True)
            if operator in {"==", "!=", "<", "<=", ">", ">="}
            else Not(Binary("=", reflected, inherited))
        )
        override, nooverride = b.branch(priority)
        b.use(override)
        exists, missing = b.branch(Not(Binary("=", reflected, self.missing)))
        b.use(exists)
        b.emit(Alloc(tried.name, Literal(True)))
        result = self.call(b, self.bind_method(b, reflected, right, rightcls), (left,))
        self.checked(b)
        implemented, failed = b.branch(Not(Binary("=", result, self.not_implemented)))
        b.use(implemented)
        b.ret(result)
        b.join(failed, missing, nooverride, ordinary, same)
        exists, missing = b.branch(Not(Binary("=", forward, self.missing)))
        b.use(exists)
        result = self.call(b, self.bind_method(b, forward, left, leftcls), (right,))
        self.checked(b)
        implemented, failed = b.branch(Not(Binary("=", result, self.not_implemented)))
        b.use(implemented)
        b.ret(result)
        b.join(failed, missing)
        retry, noretry = b.branch(Not(tried))
        b.use(retry)
        different, same = b.branch(Not(Binary("=", leftcls, rightcls)))
        # Rich comparisons try the reflected operation for same-type values too.
        if operator in {"==", "!=", "<", "<=", ">", ">="}:
            b.join(different, same)
            same = set()
        else:
            b.use(different)
        exists, missing = b.branch(Not(Binary("=", reflected, self.missing)))
        b.use(exists)
        result = self.call(b, self.bind_method(b, reflected, right, rightcls), (left,))
        self.checked(b)
        implemented, failed = b.branch(Not(Binary("=", result, self.not_implemented)))
        b.use(implemented)
        b.ret(result)
        b.join(noretry, same, missing, failed)
        if operator in {"==", "!="}:
            eq = Binary("=", left, right)
            b.ret(self.box(b, Not(eq) if operator == "!=" else eq, "bool"))
        else:
            self.error(b)

    def build_special(self, b, name):
        obj = b.bind(field(Var("$args"), 1), "receiver")
        args = b.bind(field(Var("$args"), 2), "arguments")
        cls = field(obj, "__class__")
        method = self.lookup(b, cls, name)
        exists, absent = b.branch(Not(Binary("=", method, self.missing)))
        b.use(absent)
        self.error(b)
        b.use(exists)
        b.ret(self.call(b, self.bind_method(b, method, obj, cls), raw_args=args))

    def special(self, b, obj, name, args=()):
        positional = b.alloc(ListExpr(tuple(args)), "arguments")
        return self.invoke(b, "special", (obj, positional), name)

    def build_mro(self, b, _):
        from .mro import emit_mro

        cls, bases = field(Var("$args"), 1), field(Var("$args"), 2)
        b.ret(emit_mro(b, self, cls, bases))

    def build_contains(self, b, _):
        item, container = field(Var("$args"), 1), field(Var("$args"), 2)
        cls = field(container, "__class__")
        method = self.lookup(b, cls, "__contains__")
        exists, absent = b.branch(Not(Binary("=", method, self.missing)))
        b.use(exists)
        value = self.call(b, self.bind_method(b, method, container, cls), (item,))
        self.checked(b)
        truth = self.invoke(b, "truth", (value,))
        self.checked(b)
        b.ret(self.box(b, truth, "bool"))
        b.use(absent)
        iterator = self.call(b, self.builtin("iter"), (container,))
        self.checked(b)
        head = b.node()
        b.jump(head)
        b.use({head})
        value = self.call(b, self.builtin("next"), (iterator,))
        good, failed = b.branch(Binary("=", self.exception, self.none))
        b.use(failed)
        exhausted = self.contains_class(
            b, field(self.exception, "__class__"), self.builtin("StopIteration")
        )
        stopped, error = b.branch(exhausted)
        b.use(error)
        b.ret(self.none)
        b.use(stopped)
        b.assign(self.exception, self.none)
        b.ret(self.box(b, False))
        b.use(good)
        equal = self.invoke(b, "binary", (value, item), "==")
        self.checked(b)
        truth = self.invoke(b, "truth", (equal,))
        self.checked(b)
        found, different = b.branch(truth)
        b.use(found)
        b.ret(self.box(b, True))
        b.use(different)
        b.jump(head)
