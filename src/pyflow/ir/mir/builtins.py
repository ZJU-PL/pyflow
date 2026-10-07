"""Executable Python builtin models written entirely in core MIR.

This module is a code generator, not a table of host-language callbacks.  Every
operation it installs is a synthetic CFG made from the seven MIR instructions.
Python objects contain reference-valued fields; sequence payloads are raw MIR
lists.  A dictionary payload is a raw list of immutable ``key``/``value`` pair
objects, allowing Python objects to serve as keys.

The models deliberately cover a bounded Python subset.  Range is eager, strings
need frontend-provided character metadata for indexing/length, and dictionary
lookup uses equality rather than a hash table.  Unsupported builtin argument
forms raise a modeled exception rather than executing host Python.
"""

from __future__ import annotations

from .builder import Builder, field
from .model import Alloc, Binary, Delete, DictExpr, Length, ListExpr, Literal, NewObject, Not, Var


def _arg(b, index):
    return b.bind(field(Var("$args"), index), "argument")


def _guard(rt, b, condition, error="TypeError"):
    good, bad = b.branch(condition)
    b.use(bad)
    rt.error(b, error)
    b.use(good)


def _arity(rt, b, minimum, maximum=None, keywords=False):
    count = Length(Var("$args"))
    invalid = Binary("<", count, Literal(minimum))
    if maximum is not None:
        invalid = Binary("or", invalid, Binary("<", Literal(maximum), count))
    if not keywords:
        invalid = Binary("or", invalid, Not(Binary("=", Length(Var("$kwargs")), Literal(0))))
    _guard(rt, b, Not(invalid))


def _same_class(rt, b, obj, name):
    return rt.contains_class(b, field(obj, "__class__"), rt.builtin(name))


def _require_class(rt, b, obj, name):
    _guard(rt, b, _same_class(rt, b, obj, name))


def _as_int(rt, b, obj):
    """Extract an already-validated integer, converting Boolean payloads."""
    value = b.bind(field(obj, "$value"), "integer")
    boolean, integer = b.branch(_same_class(rt, b, obj, "bool"))
    b.use(boolean)
    yes, no = b.branch(value)
    b.use(yes)
    b.emit(Alloc(value.name, Literal(1)))
    true_tails = set(b.tails)
    b.use(no)
    b.emit(Alloc(value.name, Literal(0)))
    b.join(true_tails, b.tails, integer)
    return value


def _index_value(rt, b, obj):
    direct, special = b.branch(_same_class(rt, b, obj, "int"))
    value = Var(b.temp("indexobj"))
    b.use(direct)
    b.assign(value, obj)
    direct_tails = set(b.tails)
    b.use(special)
    converted = rt.special(b, obj, "__index__")
    rt.checked(b)
    _require_class(rt, b, converted, "int")
    b.assign(value, converted)
    b.join(direct_tails, b.tails)
    return _as_int(rt, b, value)


def _normalize_index(rt, b, raw, index):
    index = b.alloc(index, "index")
    negative, positive = b.branch(Binary("<", index, Literal(0)))
    b.use(negative)
    b.emit(Alloc(index.name, Binary("+", index, Length(raw))))
    b.join(b.tails, positive)
    invalid = Binary("or", Binary("<", index, Literal(0)), Not(Binary("<", index, Length(raw))))
    _guard(rt, b, Not(invalid), "IndexError")
    return b.alloc(Binary("+", index, Literal(1)), "position")


def _append(b, owner, item):
    raw = b.alloc(Binary("+", field(owner, "$value"), ListExpr((item,))), "extended")
    b.assign(field(owner, "$value"), raw)


def _equal(rt, b, left, right):
    result = b.alloc(Literal(True), "equal")
    identical, different = b.branch(Binary("=", left, right))
    b.use(different)
    comparison = rt.invoke(b, "binary", (left, right), "==")
    rt.checked(b)
    b.assign(result, rt.invoke(b, "truth", (comparison,)))
    rt.checked(b)
    b.join(identical, b.tails)
    return result


def _search(rt, b, raw, wanted, pairs=False):
    """Return a one-based slot or zero, invoking user equality when necessary."""
    result = b.alloc(Literal(0), "found")
    index = b.alloc(Literal(1), "search")
    head, done = b.node(), b.node()
    b.jump(head)
    b.use({head})
    inside, outside = b.branch(Not(Binary("<", Length(raw), index)))
    b.use(outside)
    b.jump(done)
    b.use(inside)
    item = b.bind(field(raw, index), "item")
    if pairs:
        item = b.bind(field(item, "key"), "key")
    equal, different = b.branch(_equal(rt, b, item, wanted))
    b.use(equal)
    b.assign(result, index)
    b.jump(done)
    b.use(different)
    b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
    b.jump(head)
    b.use({done})
    return result


def _iterate(rt, b, iterable, consume):
    """Generate the iter/next/StopIteration protocol around a callback emitter."""
    iterator = rt.special(b, iterable, "__iter__")
    rt.checked(b)
    head, done = b.node(), b.node()
    b.jump(head)
    b.use({head})
    item = rt.special(b, iterator, "__next__")
    success, failure = b.branch(Binary("=", rt.exception, rt.none))
    b.use(failure)
    stopped, other = b.branch(_same_class(rt, b, rt.exception, "StopIteration"))
    b.use(other)
    b.ret(rt.none)
    b.use(stopped)
    b.assign(rt.exception, rt.none)
    b.jump(done)
    b.use(success)
    consume(item)
    b.jump(head)
    b.use({done})


def _multiply(b, left, right):
    total = b.alloc(Literal(0), "product")
    count = b.alloc(right, "factor")
    term = b.alloc(left, "term")
    negative, nonnegative = b.branch(Binary("<", count, Literal(0)))
    b.use(negative)
    b.emit(Alloc(count.name, Binary("-", Literal(0), count)))
    b.emit(Alloc(term.name, Binary("-", Literal(0), term)))
    b.join(b.tails, nonnegative)
    head, done = b.node(), b.node()
    b.jump(head)
    b.use({head})
    again, end = b.branch(Binary("<", Literal(0), count))
    b.use(end)
    b.jump(done)
    b.use(again)
    b.emit(Alloc(total.name, Binary("+", total, term)))
    b.emit(Alloc(count.name, Binary("-", count, Literal(1))))
    b.jump(head)
    b.use({done})
    return total


def _positive_divmod(b, numerator, denominator):
    """Integer division using addition/subtraction and doubling, not native hooks."""
    quotient = b.alloc(Literal(0), "quotient")
    remainder = b.alloc(numerator, "remainder")
    head, done = b.node(), b.node()
    b.jump(head)
    b.use({head})
    again, end = b.branch(Not(Binary("<", remainder, denominator)))
    b.use(end)
    b.jump(done)
    b.use(again)
    chunk = b.alloc(denominator, "chunk")
    factor = b.alloc(Literal(1), "factor")
    double, subtract = b.node(), b.node()
    b.jump(double)
    b.use({double})
    fits, stop = b.branch(Not(Binary("<", remainder, Binary("+", chunk, chunk))))
    b.use(stop)
    b.jump(subtract)
    b.use(fits)
    b.emit(Alloc(chunk.name, Binary("+", chunk, chunk)))
    b.emit(Alloc(factor.name, Binary("+", factor, factor)))
    b.jump(double)
    b.use({subtract})
    b.emit(Alloc(remainder.name, Binary("-", remainder, chunk)))
    b.emit(Alloc(quotient.name, Binary("+", quotient, factor)))
    b.jump(head)
    b.use({done})
    return quotient, remainder


def _define(rt, parent, owner, name, implementation, visible=False):
    scope = f"builtins.{owner + '.' if owner else ''}{name}"
    b = Builder(rt.program, scope, synthetic=not visible)
    rt.prologue(b)
    # Source calls carry a collision-free key enumeration sidecar.  Internal
    # MIR helper calls retain the paper's ordinary empty dictionary ABI.
    b.assign("$keyword_keys", b.alloc(ListExpr(()), "keyword_keys"))
    nested, flat = b.branch(Binary("in", Literal("$values"), Var("$kwargs")))
    b.use(nested)
    b.assign("$keyword_keys", field(Var("$kwargs"), "$keys"))
    b.assign("$kwargs", field(Var("$kwargs"), "$values"))
    b.join(b.tails, flat)
    implementation(b)
    b.finish()
    target = rt.builtin(owner) if owner else Var("$builtins")
    parent.assign(field(target, name), rt.function(parent, scope))


def _bootstrap(rt, b):
    b.assign("$builtins", b.alloc(NewObject(), "builtins"))
    for name in rt.TYPES:
        cls = b.alloc(NewObject(), "class")
        b.assign(rt.builtin(name), cls)
        b.assign(field(cls, "$identity"), b.alloc(NewObject(), "identity"))
        b.assign(field(cls, "$class"), rt.raw(b, True))
    for name in rt.TYPES:
        cls = rt.builtin(name)
        b.assign(field(cls, "__class__"), rt.builtin("type"))
        if name == "object":
            ancestors = ()
        elif name == "bool":
            ancestors = ("int", "object")
        elif name == "BaseException":
            ancestors = ("object",)
        elif name == "Exception":
            ancestors = ("BaseException", "object")
        elif name.endswith("Error") or name in {"StopIteration"}:
            ancestors = ("Exception", "BaseException", "object")
        else:
            ancestors = ("object",)
        b.assign(
            field(cls, "__mro__"),
            b.alloc(ListExpr(tuple(rt.builtin(item) for item in (name, *ancestors))), "mro"),
        )
    b.assign(field(Var("$builtins"), "__class__"), rt.builtin("module"))
    for name, cls in (
        ("None", "NoneType"),
        ("NotImplemented", "NotImplementedType"),
        ("$missing", "object"),
    ):
        b.assign(rt.builtin(name), rt.obj(b, cls))
    state = b.alloc(NewObject(), "state")
    b.assign(rt.builtin("$state"), state)
    b.assign(field(state, "exception"), rt.none)
    b.assign(rt.builtin("True"), rt.box(b, True))
    b.assign(rt.builtin("False"), rt.box(b, False))
    for name in rt.TYPES:
        b.assign(field(rt.builtin(name), "__name__"), rt.box(b, name))


def _objects(rt, root):
    def new(b):
        _arity(rt, b, 1, keywords=True)
        b.ret(rt.obj(b, _arg(b, 1)))

    def init(b):
        _arity(rt, b, 1, 1)
        b.ret(rt.none)

    def equal(b):
        _arity(rt, b, 2, 2)
        yes, no = b.branch(Binary("=", _arg(b, 1), _arg(b, 2)))
        b.use(yes)
        b.ret(rt.box(b, True))
        b.use(no)
        b.ret(rt.not_implemented)

    def unequal(b):
        _arity(rt, b, 2, 2)
        result = rt.special(b, _arg(b, 1), "__eq__", (_arg(b, 2),))
        rt.checked(b)
        unsupported, implemented = b.branch(Binary("=", result, rt.not_implemented))
        b.use(unsupported)
        b.ret(rt.not_implemented)
        b.use(implemented)
        truth = rt.invoke(b, "truth", (result,))
        rt.checked(b)
        b.ret(rt.box(b, Not(truth), "bool"))

    def type_new(b):
        _arity(rt, b, 2, 2)
        b.ret(field(_arg(b, 2), "__class__"))

    def exception_init(b):
        _arity(rt, b, 1, keywords=False)
        self = _arg(b, 1)
        args = b.alloc(ListExpr(()), "arguments")
        index = b.alloc(Literal(2), "index")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        more, end = b.branch(Not(Binary("<", Length(Var("$args")), index)))
        b.use(end)
        b.jump(done)
        b.use(more)
        b.emit(Alloc(args.name, Binary("+", args, ListExpr((field(Var("$args"), index),)))))
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        b.assign(field(self, "args"), rt.box(b, args, "tuple"))
        b.ret(rt.none)

    _define(rt, root, "object", "__new__", new)
    _define(rt, root, "object", "__init__", init)
    _define(rt, root, "object", "__eq__", equal)
    _define(rt, root, "object", "__ne__", unequal)
    _define(rt, root, "type", "__new__", type_new)
    _define(rt, root, "type", "__init__", lambda b: b.ret(rt.none))
    _define(rt, root, "BaseException", "__init__", exception_init)
    for cls, singleton in (("NoneType", rt.none), ("NotImplementedType", rt.not_implemented)):

        def singleton_new(b, value=singleton):
            _arity(rt, b, 1, 1)
            b.ret(value)

        _define(rt, root, cls, "__new__", singleton_new)


def _integers(rt, root):
    def constructor(b):
        _arity(rt, b, 1, 2)
        cls = _arg(b, 1)
        empty, supplied = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(empty)
        b.ret(rt.box(b, 0, cls))
        b.use(supplied)
        value = _arg(b, 2)
        _require_class(rt, b, value, "int")
        b.ret(rt.box(b, _as_int(rt, b, value), cls))

    def bool_constructor(b):
        _arity(rt, b, 1, 2)
        cls = _arg(b, 1)
        empty, supplied = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(empty)
        b.ret(rt.box(b, False, cls))
        b.use(supplied)
        raw = rt.invoke(b, "truth", (_arg(b, 2),))
        rt.checked(b)
        b.ret(rt.box(b, raw, cls))

    def unary(b, operator):
        _arity(rt, b, 1, 1)
        value = _arg(b, 1)
        _require_class(rt, b, value, "int")
        raw = _as_int(rt, b, value)
        if operator == "bool":
            b.ret(rt.box(b, Not(Binary("=", raw, Literal(0))), "bool"))
        else:
            expr = Binary("-", Literal(-1 if operator == "invert" else 0), raw)
            b.ret(rt.box(b, raw if operator == "positive" else expr, "int"))

    def binary(b, operator, reflected=False):
        _arity(rt, b, 2, 2)
        left, right = _arg(b, 1), _arg(b, 2)
        compatible, other = b.branch(_same_class(rt, b, right, "int"))
        b.use(other)
        b.ret(rt.not_implemented)
        b.use(compatible)
        left, right = _as_int(rt, b, left), _as_int(rt, b, right)
        if reflected:
            left, right = right, left
        if operator in {"+", "-"}:
            raw, cls = Binary(operator, left, right), "int"
        elif operator == "*":
            raw, cls = _multiply(b, left, right), "int"
        elif operator in {"//", "%"}:
            _guard(rt, b, Not(Binary("=", right, Literal(0))), "ZeroDivisionError")
            a, denominator = b.alloc(left, "numerator"), b.alloc(right, "denominator")
            neg_a = b.alloc(Binary("<", a, Literal(0)), "negative")
            neg_b = b.alloc(Binary("<", denominator, Literal(0)), "negative")
            yes, no = b.branch(neg_a)
            b.use(yes)
            b.emit(Alloc(a.name, Binary("-", Literal(0), a)))
            b.join(b.tails, no)
            yes, no = b.branch(neg_b)
            b.use(yes)
            b.emit(Alloc(denominator.name, Binary("-", Literal(0), denominator)))
            b.join(b.tails, no)
            quotient, remainder = _positive_divmod(b, a, denominator)
            opposite, same = b.branch(Not(Binary("=", neg_a, neg_b)))
            b.use(opposite)
            b.emit(Alloc(quotient.name, Binary("-", Literal(0), quotient)))
            has_remainder, exact = b.branch(Not(Binary("=", remainder, Literal(0))))
            b.use(has_remainder)
            b.emit(Alloc(quotient.name, Binary("-", quotient, Literal(1))))
            b.emit(Alloc(remainder.name, Binary("-", denominator, remainder)))
            b.join(b.tails, exact, same)
            yes, no = b.branch(neg_b)
            b.use(yes)
            b.emit(Alloc(remainder.name, Binary("-", Literal(0), remainder)))
            b.join(b.tails, no)
            raw, cls = quotient if operator == "//" else remainder, "int"
        elif operator == "**":
            _guard(rt, b, Not(Binary("<", right, Literal(0))))
            result = b.alloc(Literal(1), "power")
            exponent = b.alloc(right, "exponent")
            head, done = b.node(), b.node()
            b.jump(head)
            b.use({head})
            again, end = b.branch(Binary("<", Literal(0), exponent))
            b.use(end)
            b.jump(done)
            b.use(again)
            b.assign(result, _multiply(b, result, left))
            b.emit(Alloc(exponent.name, Binary("-", exponent, Literal(1))))
            b.jump(head)
            b.use({done})
            raw, cls = result, "int"
        else:
            cls = "bool"
            if operator == "==":
                raw = Binary("=", left, right)
            elif operator == "!=":
                raw = Not(Binary("=", left, right))
            elif operator == "<":
                raw = Binary("<", left, right)
            elif operator == ">":
                raw = Binary("<", right, left)
            elif operator == "<=":
                raw = Not(Binary("<", right, left))
            else:
                raw = Not(Binary("<", left, right))
        b.ret(rt.box(b, raw, cls))

    _define(rt, root, "int", "__new__", constructor)
    _define(rt, root, "bool", "__new__", bool_constructor)
    for cls in ("int", "bool"):
        _define(rt, root, cls, "__init__", lambda b: b.ret(rt.none))
    for name, operation in (
        ("__bool__", "bool"),
        ("__neg__", "negative"),
        ("__pos__", "positive"),
        ("__index__", "positive"),
        ("__int__", "positive"),
        ("__invert__", "invert"),
    ):
        _define(rt, root, "int", name, lambda b, op=operation: unary(b, op))
    for name, operation in (
        ("add", "+"),
        ("sub", "-"),
        ("mul", "*"),
        ("floordiv", "//"),
        ("mod", "%"),
        ("pow", "**"),
    ):
        _define(rt, root, "int", f"__{name}__", lambda b, op=operation: binary(b, op))
        _define(rt, root, "int", f"__r{name}__", lambda b, op=operation: binary(b, op, True))
    for name, operation in (
        ("eq", "=="),
        ("ne", "!="),
        ("lt", "<"),
        ("le", "<="),
        ("gt", ">"),
        ("ge", ">="),
    ):
        _define(rt, root, "int", f"__{name}__", lambda b, op=operation: binary(b, op))


def _sequences(rt, root):
    def constructor(b, kind):
        _arity(rt, b, 1, 2)
        cls = _arg(b, 1)
        result = rt.box(b, ListExpr(()), cls)
        empty, supplied = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(empty)
        b.ret(result)
        b.use(supplied)

        def append(item):
            if kind == "set":
                index = _search(rt, b, field(result, "$value"), item)
                absent, present = b.branch(Binary("=", index, Literal(0)))
                b.use(absent)
                _append(b, result, item)
                b.join(b.tails, present)
            else:
                _append(b, result, item)

        _iterate(rt, b, _arg(b, 2), append)
        b.ret(result)

    def length(b):
        _arity(rt, b, 1, 1)
        b.ret(rt.box(b, Length(field(_arg(b, 1), "$value")), "int"))

    def concatenate(b, kind):
        _arity(rt, b, 2, 2)
        left, right = _arg(b, 1), _arg(b, 2)
        compatible, other = b.branch(_same_class(rt, b, right, kind))
        b.use(other)
        b.ret(rt.not_implemented)
        b.use(compatible)
        b.ret(rt.box(b, Binary("+", field(left, "$value"), field(right, "$value")), kind))

    def getitem(b):
        _arity(rt, b, 2, 2)
        self, key = _arg(b, 1), _arg(b, 2)
        raw = field(self, "$value")
        position = _normalize_index(rt, b, raw, _index_value(rt, b, key))
        b.ret(field(raw, position))

    def setitem(b, delete=False):
        _arity(rt, b, 2 if delete else 3, 2 if delete else 3)
        self, key = _arg(b, 1), _arg(b, 2)
        raw = field(self, "$value")
        position = _normalize_index(rt, b, raw, _index_value(rt, b, key))
        if delete:
            b.emit(Delete(field(raw, position)))
        else:
            b.assign(field(raw, position), _arg(b, 3))
        b.ret(rt.none)

    def append(b, unique=False):
        _arity(rt, b, 2, 2)
        self, item = _arg(b, 1), _arg(b, 2)
        present = set()
        if unique:
            index = _search(rt, b, field(self, "$value"), item)
            absent, present = b.branch(Binary("=", index, Literal(0)))
            b.use(absent)
        _append(b, self, item)
        b.join(b.tails, present)
        b.ret(rt.none)

    def pop(b):
        _arity(rt, b, 1, 2)
        self = _arg(b, 1)
        index = b.alloc(Literal(-1), "index")
        default, explicit = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(explicit)
        b.assign(index, _index_value(rt, b, _arg(b, 2)))
        b.join(default, b.tails)
        raw = field(self, "$value")
        position = _normalize_index(rt, b, raw, index)
        value = b.bind(field(raw, position), "popped")
        b.emit(Delete(field(raw, position)))
        b.ret(value)

    def contains(b):
        _arity(rt, b, 2, 2)
        index = _search(rt, b, field(_arg(b, 1), "$value"), _arg(b, 2))
        b.ret(rt.box(b, Not(Binary("=", index, Literal(0))), "bool"))

    def iterator(b):
        _arity(rt, b, 1, 1)
        value = rt.obj(b, "iterator")
        b.assign(field(value, "$iterable"), _arg(b, 1))
        b.assign(field(value, "$index"), rt.raw(b, 1))
        b.ret(value)

    def extend(b):
        _arity(rt, b, 2, 2)
        self = _arg(b, 1)
        _iterate(rt, b, _arg(b, 2), lambda item: _append(b, self, item))
        b.ret(rt.none)

    def clear(b):
        _arity(rt, b, 1, 1)
        b.assign(field(_arg(b, 1), "$value"), b.alloc(ListExpr(()), "empty"))
        b.ret(rt.none)

    def equal(b, kind):
        _arity(rt, b, 2, 2)
        left, right = _arg(b, 1), _arg(b, 2)
        compatible, other = b.branch(_same_class(rt, b, right, kind))
        b.use(other)
        b.ret(rt.not_implemented)
        b.use(compatible)
        left, right = field(left, "$value"), field(right, "$value")
        same_length, different = b.branch(Binary("=", Length(left), Length(right)))
        b.use(different)
        b.ret(rt.box(b, False))
        b.use(same_length)
        index = b.alloc(Literal(1), "index")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", Length(left), index)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        equal, unequal = b.branch(_equal(rt, b, field(left, index), field(right, index)))
        b.use(unequal)
        b.ret(rt.box(b, False))
        b.use(equal)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        b.ret(rt.box(b, True))

    for kind in ("list", "tuple", "set"):
        _define(rt, root, kind, "__new__", lambda b, k=kind: constructor(b, k))
        _define(rt, root, kind, "__init__", lambda b: b.ret(rt.none))
        _define(rt, root, kind, "__len__", length)
        _define(rt, root, kind, "__contains__", contains)
        _define(rt, root, kind, "__iter__", iterator)
        if kind != "set":
            _define(rt, root, kind, "__getitem__", getitem)
            _define(rt, root, kind, "__add__", lambda b, k=kind: concatenate(b, k))
            _define(rt, root, kind, "__eq__", lambda b, k=kind: equal(b, k))
    _define(rt, root, "list", "__setitem__", setitem)
    _define(rt, root, "list", "__delitem__", lambda b: setitem(b, True))
    _define(rt, root, "list", "append", append)
    _define(rt, root, "list", "pop", pop)
    _define(rt, root, "list", "extend", extend)
    _define(rt, root, "list", "clear", clear)
    _define(rt, root, "set", "add", lambda b: append(b, True))
    _define(rt, root, "set", "clear", clear)


def _dictionaries(rt, root):
    def pair(b, key, value):
        result = b.alloc(NewObject(), "pair")
        b.assign(field(result, "key"), key)
        b.assign(field(result, "value"), value)
        return result

    def constructor(b):
        _arity(rt, b, 1, 2, keywords=True)
        cls = _arg(b, 1)
        result = rt.box(b, ListExpr(()), cls)
        empty, supplied = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(supplied)
        value = _arg(b, 2)
        mapping, iterable = b.branch(_same_class(rt, b, value, "dict"))
        b.use(mapping)
        b.assign(field(result, "$value"), b.alloc(field(value, "$value"), "pairs"))
        mapping_tails = set(b.tails)
        b.use(iterable)

        def consume(item):
            items = rt.box(b, ListExpr(()), "list")
            _iterate(rt, b, item, lambda value: _append(b, items, value))
            _guard(rt, b, Binary("=", Length(field(items, "$value")), Literal(2)), "ValueError")
            raw = field(items, "$value")
            rt.special(b, result, "__setitem__", (field(raw, 1), field(raw, 2)))
            rt.checked(b)

        _iterate(rt, b, value, consume)
        b.join(empty, mapping_tails, b.tails)
        # A flat nonempty kwargs dictionary cannot enumerate its keys in the
        # core grammar; the frontend's sidecar supplies that enumeration.
        _guard(rt, b, Binary("=", Length(Var("$kwargs")), Length(Var("$keyword_keys"))))
        index = b.alloc(Literal(1), "keyword_index")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", Length(Var("$keyword_keys")), index)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        key = b.bind(field(Var("$keyword_keys"), index), "keyword")
        value = field(Var("$kwargs"), field(key, "$value"))
        rt.special(b, result, "__setitem__", (key, value))
        rt.checked(b)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        b.ret(result)

    def setitem(b):
        _arity(rt, b, 3, 3)
        self, key, value = _arg(b, 1), _arg(b, 2), _arg(b, 3)
        raw = field(self, "$value")
        index = _search(rt, b, raw, key, pairs=True)
        new_pair = pair(b, key, value)
        absent, present = b.branch(Binary("=", index, Literal(0)))
        b.use(absent)
        _append(b, self, new_pair)
        absent_tails = set(b.tails)
        b.use(present)
        # Replace the pair rather than mutating it, preserving shallow dict copies.
        b.assign(field(new_pair, "key"), field(field(raw, index), "key"))
        b.assign(field(raw, index), new_pair)
        b.join(absent_tails, b.tails)
        b.ret(rt.none)

    def getitem(b, operation="get"):
        _arity(rt, b, 2, 3 if operation in {"default", "pop"} else 2)
        self, key = _arg(b, 1), _arg(b, 2)
        raw = field(self, "$value")
        index = _search(rt, b, raw, key, pairs=True)
        present, absent = b.branch(Not(Binary("=", index, Literal(0))))
        b.use(absent)
        if operation in {"default", "pop"}:
            supplied, missing = b.branch(Binary("=", Length(Var("$args")), Literal(3)))
            b.use(supplied)
            b.ret(_arg(b, 3))
            b.use(missing)
            if operation == "default":
                b.ret(rt.none)
            else:
                rt.error(b, "KeyError")
        else:
            rt.error(b, "KeyError")
        b.use(present)
        value = b.bind(field(field(raw, index), "value"), "value")
        if operation in {"delete", "pop"}:
            b.emit(Delete(field(raw, index)))
        b.ret(rt.none if operation == "delete" else value)

    def contains(b):
        _arity(rt, b, 2, 2)
        index = _search(rt, b, field(_arg(b, 1), "$value"), _arg(b, 2), pairs=True)
        b.ret(rt.box(b, Not(Binary("=", index, Literal(0))), "bool"))

    def length(b):
        _arity(rt, b, 1, 1)
        b.ret(rt.box(b, Length(field(_arg(b, 1), "$value")), "int"))

    def view(b, what):
        _arity(rt, b, 1, 1)
        self = _arg(b, 1)
        result = rt.sequence(b, (), "list")
        raw = field(self, "$value")
        index = b.alloc(Literal(1), "index")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", Length(raw), index)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        entry = field(raw, index)
        item = (
            rt.sequence(b, (field(entry, "key"), field(entry, "value")), "tuple")
            if what == "items"
            else field(entry, "key" if what == "keys" else "value")
        )
        _append(b, result, item)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        b.ret(result)

    def iterator(b):
        _arity(rt, b, 1, 1)
        result = rt.obj(b, "iterator")
        b.assign(field(result, "$iterable"), _arg(b, 1))
        b.assign(field(result, "$index"), rt.raw(b, 1))
        b.ret(result)

    _define(rt, root, "dict", "__new__", constructor)
    _define(rt, root, "dict", "__init__", lambda b: b.ret(rt.none))
    _define(rt, root, "dict", "__len__", length)
    _define(rt, root, "dict", "__getitem__", getitem)
    _define(rt, root, "dict", "__setitem__", setitem)
    _define(rt, root, "dict", "__delitem__", lambda b: getitem(b, "delete"))
    _define(rt, root, "dict", "get", lambda b: getitem(b, "default"))
    _define(rt, root, "dict", "pop", lambda b: getitem(b, "pop"))
    _define(rt, root, "dict", "__contains__", contains)
    _define(rt, root, "dict", "__iter__", iterator)
    for operation in ("keys", "values", "items"):
        _define(rt, root, "dict", operation, lambda b, op=operation: view(b, op))


def _strings(rt, root):
    def chars(b, obj):
        _guard(rt, b, Binary("in", Literal("$chars"), obj))
        return field(obj, "$chars")

    def constructor(b):
        _arity(rt, b, 1, 2)
        cls = _arg(b, 1)
        empty, supplied = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(empty)
        result = rt.box(b, "", cls)
        b.assign(field(result, "$chars"), b.alloc(ListExpr(()), "characters"))
        b.ret(result)
        b.use(supplied)
        value = _arg(b, 2)
        string, other = b.branch(_same_class(rt, b, value, "str"))
        b.use(other)
        b.ret(rt.special(b, value, "__str__"))
        b.use(string)
        result = rt.box(b, field(value, "$value"), cls)
        haschars, missing = b.branch(Binary("in", Literal("$chars"), value))
        b.use(haschars)
        b.assign(field(result, "$chars"), field(value, "$chars"))
        b.join(b.tails, missing)
        b.ret(result)

    def binary(b, operation):
        _arity(rt, b, 2, 2)
        left, right = _arg(b, 1), _arg(b, 2)
        string, other = b.branch(_same_class(rt, b, right, "str"))
        b.use(other)
        b.ret(rt.not_implemented)
        b.use(string)
        if operation == "=":
            b.ret(rt.box(b, Binary("=", field(left, "$value"), field(right, "$value")), "bool"))
        else:
            result = rt.box(b, Binary("+", field(left, "$value"), field(right, "$value")), "str")
            has_left, missing_left = b.branch(Binary("in", Literal("$chars"), left))
            b.use(has_left)
            has_right, missing_right = b.branch(Binary("in", Literal("$chars"), right))
            b.use(has_right)
            b.assign(
                field(result, "$chars"),
                b.alloc(Binary("+", field(left, "$chars"), field(right, "$chars")), "characters"),
            )
            b.join(b.tails, missing_left, missing_right)
            b.ret(result)

    def length(b):
        _arity(rt, b, 1, 1)
        b.ret(rt.box(b, Length(chars(b, _arg(b, 1))), "int"))

    def getitem(b):
        _arity(rt, b, 2, 2)
        raw = chars(b, _arg(b, 1))
        index = _normalize_index(rt, b, raw, _index_value(rt, b, _arg(b, 2)))
        b.ret(field(raw, index))

    def iterator(b):
        _arity(rt, b, 1, 1)
        self = _arg(b, 1)
        chars(b, self)
        result = rt.obj(b, "iterator")
        b.assign(field(result, "$iterable"), self)
        b.assign(field(result, "$index"), rt.raw(b, 1))
        b.ret(result)

    _define(rt, root, "str", "__new__", constructor)
    _define(rt, root, "str", "__init__", lambda b: b.ret(rt.none))
    _define(rt, root, "str", "__str__", lambda b: b.ret(_arg(b, 1)))
    _define(rt, root, "str", "__eq__", lambda b: binary(b, "="))
    _define(rt, root, "str", "__add__", lambda b: binary(b, "+"))
    _define(rt, root, "str", "__len__", length)
    _define(rt, root, "str", "__getitem__", getitem)
    _define(rt, root, "str", "__iter__", iterator)


def _iterators(rt, root):
    def iterator(b):
        _arity(rt, b, 1, 1)
        b.ret(_arg(b, 1))

    def next_(b):
        _arity(rt, b, 1, 1)
        self = _arg(b, 1)
        callable_iterator, sequence_iterator = b.branch(Binary("in", Literal("$callable"), self))
        b.use(callable_iterator)
        item = rt.call(b, field(self, "$callable"))
        rt.checked(b)
        stopped, more = b.branch(_equal(rt, b, item, field(self, "$sentinel")))
        b.use(stopped)
        rt.error(b, "StopIteration")
        b.use(more)
        b.ret(item)
        b.use(sequence_iterator)
        source = b.bind(field(self, "$iterable"), "source")
        raw = Var(b.temp("sequence"))
        string, nonstring = b.branch(_same_class(rt, b, source, "str"))
        b.use(string)
        _guard(rt, b, Binary("in", Literal("$chars"), source))
        b.assign(raw, field(source, "$chars"))
        string_tails = set(b.tails)
        b.use(nonstring)
        b.assign(raw, field(source, "$value"))
        b.join(string_tails, b.tails)
        index = b.bind(field(self, "$index"), "index")
        inside, end = b.branch(Not(Binary("<", Length(raw), index)))
        b.use(end)
        rt.error(b, "StopIteration")
        b.use(inside)
        value = b.bind(field(raw, index), "element")
        b.assign(field(self, "$index"), b.alloc(Binary("+", index, Literal(1)), "index"))
        dictionary, ordinary = b.branch(_same_class(rt, b, source, "dict"))
        b.use(dictionary)
        b.ret(field(value, "key"))
        b.use(ordinary)
        b.ret(value)

    _define(rt, root, "iterator", "__iter__", iterator)
    _define(rt, root, "iterator", "__next__", next_)


def _generators(rt, root):
    def stop_init(b):
        _arity(rt, b, 1, keywords=False)
        self = _arg(b, 1)
        rt.call(
            b,
            field(rt.builtin("BaseException"), "__init__"),
            raw_args=Var("$args"),
            kwargs=Var("$kwargs"),
        )
        rt.checked(b)
        supplied, absent = b.branch(Binary("<", Literal(1), Length(Var("$args"))))
        b.use(supplied)
        b.assign(field(self, "value"), _arg(b, 2))
        supplied_tails = set(b.tails)
        b.use(absent)
        b.assign(field(self, "value"), rt.none)
        b.join(supplied_tails, b.tails)
        b.ret(rt.none)

    def stop(b):
        exception = rt.obj(b, "StopIteration")
        b.assign(field(exception, "value"), rt.none)
        b.assign(field(exception, "args"), rt.sequence(b, (), "tuple"))
        b.assign(rt.exception, exception)
        b.ret(rt.none)

    def iterator(b):
        _arity(rt, b, 1, 1)
        b.ret(_arg(b, 1))

    def resume(b, send=False):
        _arity(rt, b, 2 if send else 1, 2 if send else 1)
        self = _arg(b, 1)
        _guard(rt, b, Not(field(self, "$running")), "ValueError")
        done, active = b.branch(field(self, "$done"))
        b.use(done)
        stop(b)
        b.use(active)
        value = _arg(b, 2) if send else rt.none
        if send:
            valid = Binary("or", field(self, "$started"), Binary("=", value, rt.none))
            _guard(rt, b, valid)
        b.assign(field(field(self, "$frame"), "$sent"), value)
        b.assign(field(self, "$started"), rt.raw(b, True))
        b.assign(field(self, "$running"), rt.raw(b, True))
        args, kwargs = b.alloc(ListExpr(())), b.alloc(DictExpr(()))
        result = b.call(field(self, "$resume"), args, kwargs)
        b.assign(field(self, "$running"), rt.raw(b, False))
        b.ret(result)

    _define(rt, root, "generator", "__iter__", iterator)
    _define(rt, root, "generator", "__next__", resume)
    _define(rt, root, "generator", "send", lambda b: resume(b, True))
    _define(rt, root, "StopIteration", "__init__", stop_init)


def _descriptors(rt, root):
    for kind, marker in (("staticmethod", "$staticmethod"), ("classmethod", "$classmethod")):

        def constructor(b, marker=marker):
            _arity(rt, b, 2, 2)
            result = rt.obj(b, _arg(b, 1))
            b.assign(field(result, marker), _arg(b, 2))
            b.ret(result)

        def getter(b, kind=kind, marker=marker):
            _arity(rt, b, 3, 3)
            self, instance, owner = _arg(b, 1), _arg(b, 2), _arg(b, 3)
            b.ret(
                field(self, marker)
                if kind == "staticmethod"
                else rt.bind_method(b, self, instance, owner)
            )

        _define(rt, root, kind, "__new__", constructor)
        _define(rt, root, kind, "__init__", lambda b: b.ret(rt.none))
        _define(rt, root, kind, "__get__", getter)

    def property_new(b):
        _arity(rt, b, 1, 5, keywords=True)
        result = rt.obj(b, _arg(b, 1))
        for index, name in enumerate(("fget", "fset", "fdel", "doc"), start=2):
            value = b.bind(rt.none, "accessor")
            supplied, absent = b.branch(Not(Binary("<", Length(Var("$args")), Literal(index))))
            b.use(supplied)
            b.assign(value, _arg(b, index))
            supplied_tails = set(b.tails)
            b.use(absent)
            keyword, missing = b.branch(Binary("in", Literal(name), Var("$kwargs")))
            b.use(keyword)
            b.assign(value, field(Var("$kwargs"), name))
            b.join(supplied_tails, b.tails, missing)
            b.assign(field(result, "$" + name), value)
        b.ret(result)

    def access(b, operation):
        _arity(rt, b, 3 if operation != "fdel" else 2, 3 if operation != "fdel" else 2)
        self, receiver = _arg(b, 1), _arg(b, 2)
        if operation == "fget":
            class_access, instance = b.branch(Binary("=", receiver, rt.none))
            b.use(class_access)
            b.ret(self)
            b.use(instance)
        accessor = field(self, "$" + operation)
        _guard(rt, b, Not(Binary("=", accessor, rt.none)), "AttributeError")
        result = rt.call(b, accessor, (receiver,) + ((_arg(b, 3),) if operation == "fset" else ()))
        rt.checked(b)
        b.ret(result if operation == "fget" else rt.none)

    def replace(b, operation):
        _arity(rt, b, 2, 2)
        self, function = _arg(b, 1), _arg(b, 2)
        result = rt.obj(b, field(self, "__class__"))
        for name in ("fget", "fset", "fdel", "doc"):
            b.assign(
                field(result, "$" + name),
                function if name == operation else field(self, "$" + name),
            )
        b.ret(result)

    _define(rt, root, "property", "__new__", property_new)
    _define(rt, root, "property", "__init__", lambda b: b.ret(rt.none))
    for name, operation in (("__get__", "fget"), ("__set__", "fset"), ("__delete__", "fdel")):
        _define(rt, root, "property", name, lambda b, op=operation: access(b, op))
    for name, operation in (("getter", "fget"), ("setter", "fset"), ("deleter", "fdel")):
        _define(rt, root, "property", name, lambda b, op=operation: replace(b, op))

    def super_new(b):
        _arity(rt, b, 3, 3)
        cls, start, receiver = _arg(b, 1), _arg(b, 2), _arg(b, 3)
        _guard(rt, b, Binary("in", Literal("$class"), start))
        owner = b.bind(field(receiver, "__class__"), "super_owner")
        class_receiver, instance_receiver = b.branch(Binary("in", Literal("$class"), receiver))
        b.use(class_receiver)
        b.assign(owner, receiver)
        b.join(b.tails, instance_receiver)
        _guard(rt, b, rt.contains_class(b, owner, start))
        result = rt.obj(b, cls)
        b.assign(field(result, "$super"), start)
        b.assign(field(result, "$self"), receiver)
        b.ret(result)

    _define(rt, root, "super", "__new__", super_new)
    _define(rt, root, "super", "__init__", lambda b: b.ret(rt.none))


def _functions(rt, root):
    def special(b, name):
        _arity(rt, b, 1, 1)
        result = rt.special(b, _arg(b, 1), name)
        rt.checked(b)
        b.ret(result)

    def iter_(b):
        _arity(rt, b, 1, 2)
        normal, sentinel = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(normal)
        b.ret(rt.special(b, _arg(b, 1), "__iter__"))
        b.use(sentinel)
        result = rt.obj(b, "iterator")
        b.assign(field(result, "$callable"), _arg(b, 1))
        b.assign(field(result, "$sentinel"), _arg(b, 2))
        b.ret(result)

    def next_(b):
        _arity(rt, b, 1, 2)
        result = rt.special(b, _arg(b, 1), "__next__")
        success, exception = b.branch(Binary("=", rt.exception, rt.none))
        b.use(success)
        b.ret(result)
        b.use(exception)
        hasdefault, missing = b.branch(Binary("=", Length(Var("$args")), Literal(2)))
        b.use(missing)
        b.ret(rt.none)
        b.use(hasdefault)
        stopped, other = b.branch(_same_class(rt, b, rt.exception, "StopIteration"))
        b.use(other)
        b.ret(rt.none)
        b.use(stopped)
        b.assign(rt.exception, rt.none)
        b.ret(_arg(b, 2))

    def instance(b, subclass=False):
        _arity(rt, b, 2, 2)
        value, target = _arg(b, 1), _arg(b, 2)
        cls = value if subclass else field(value, "__class__")
        if subclass:
            _guard(rt, b, Binary("in", Literal("$class"), cls))
        tuple_target, class_target = b.branch(_same_class(rt, b, target, "tuple"))
        b.use(tuple_target)
        raw = field(target, "$value")
        index = b.alloc(Literal(1), "index")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", Length(raw), index)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        result = b.invoke(b.name, (value, field(raw, index)))
        rt.checked(b)
        match, no = b.branch(field(result, "$value"))
        b.use(match)
        b.ret(rt.box(b, True))
        b.use(no)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        b.ret(rt.box(b, False))
        b.use(class_target)
        _guard(rt, b, Binary("in", Literal("$class"), target))
        hook = rt.lookup(
            b, field(target, "__class__"), "__subclasscheck__" if subclass else "__instancecheck__"
        )
        customized, default = b.branch(Not(Binary("=", hook, rt.missing)))
        b.use(customized)
        b.ret(rt.call(b, rt.bind_method(b, hook, target, field(target, "__class__")), (value,)))
        b.use(default)
        b.ret(rt.box(b, rt.contains_class(b, cls, target), "bool"))

    def attribute(b, operation):
        _arity(rt, b, 3 if operation == "set" else 2, 3 if operation in {"get", "set"} else 2)
        obj, name = _arg(b, 1), _arg(b, 2)
        _require_class(rt, b, name, "str")
        raw = field(name, "$value")
        if operation == "set":
            b.ret(rt.invoke(b, "setattr", (obj, raw, _arg(b, 3))))
            return
        if operation == "delete":
            b.ret(rt.invoke(b, "setattr", (obj, raw), "delete"))
            return
        result = rt.invoke(b, "getattr", (obj, raw))
        success, exception = b.branch(Binary("=", rt.exception, rt.none))
        b.use(success)
        b.ret(rt.box(b, True) if operation == "has" else result)
        b.use(exception)
        absent, other = b.branch(_same_class(rt, b, rt.exception, "AttributeError"))
        b.use(other)
        b.ret(rt.none)
        b.use(absent)
        if operation == "has":
            b.assign(rt.exception, rt.none)
            b.ret(rt.box(b, False))
        else:
            supplied, missing = b.branch(Binary("=", Length(Var("$args")), Literal(3)))
            b.use(missing)
            b.ret(rt.none)
            b.use(supplied)
            b.assign(rt.exception, rt.none)
            b.ret(_arg(b, 3))

    def range_(b):
        _arity(rt, b, 1, 3)
        start, stop, step = b.alloc(Literal(0)), b.alloc(Literal(0)), b.alloc(Literal(1))
        one, more = b.branch(Binary("=", Length(Var("$args")), Literal(1)))
        b.use(one)
        b.assign(stop, _index_value(rt, b, _arg(b, 1)))
        one_tails = set(b.tails)
        b.use(more)
        b.assign(start, _index_value(rt, b, _arg(b, 1)))
        b.assign(stop, _index_value(rt, b, _arg(b, 2)))
        three, two = b.branch(Binary("=", Length(Var("$args")), Literal(3)))
        b.use(three)
        b.assign(step, _index_value(rt, b, _arg(b, 3)))
        b.join(one_tails, b.tails, two)
        _guard(rt, b, Not(Binary("=", step, Literal(0))), "ValueError")
        result = rt.sequence(b, (), "list")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        positive = Binary("<", Literal(0), step)
        continues = Binary(
            "or",
            Not(Binary("or", Not(positive), Not(Binary("<", start, stop)))),
            Not(Binary("or", positive, Not(Binary("<", stop, start)))),
        )
        again, end = b.branch(continues)
        b.use(end)
        b.jump(done)
        b.use(again)
        _append(b, result, rt.box(b, start, "int"))
        b.emit(Alloc(start.name, Binary("+", start, step)))
        b.jump(head)
        b.use({done})
        b.ret(result)

    _define(rt, root, None, "len", lambda b: special(b, "__len__"))
    _define(rt, root, None, "iter", iter_)
    _define(rt, root, None, "next", next_)
    _define(rt, root, None, "isinstance", instance)
    _define(rt, root, None, "issubclass", lambda b: instance(b, True))
    for name, operation in (
        ("getattr", "get"),
        ("setattr", "set"),
        ("hasattr", "has"),
        ("delattr", "delete"),
    ):
        _define(rt, root, None, name, lambda b, op=operation: attribute(b, op))
    _define(rt, root, None, "range", range_)
    # print's external output is intentionally abstracted; its call edge remains visible.
    _define(rt, root, None, "print", lambda b: b.ret(rt.none), visible=True)


def initialize(runtime, b: Builder) -> None:
    """Emit the builtin object graph and executable MIR method definitions."""
    _bootstrap(runtime, b)
    _objects(runtime, b)
    _integers(runtime, b)
    _sequences(runtime, b)
    _dictionaries(runtime, b)
    _strings(runtime, b)
    _iterators(runtime, b)
    _generators(runtime, b)
    _descriptors(runtime, b)
    _functions(runtime, b)


__all__ = ["initialize"]
