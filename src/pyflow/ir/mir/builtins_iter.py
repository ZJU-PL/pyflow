"""Iteration utilities compiled to the seven core MIR instructions."""

from .builder import field
from .model import Alloc, Binary, Length, ListExpr, Literal, Not, Var
from .builtins import (
    _append,
    _arg,
    _arity,
    _define,
    _guard,
    _index_value,
    _iterate,
    _same_class,
)


def install(rt, root):
    def quantify(b, all_):
        _arity(rt, b, 1, 1)

        def consume(item):
            truth = rt.invoke(b, "truth", (item,))
            rt.checked(b)
            decisive, more = b.branch(Not(truth) if all_ else truth)
            b.use(decisive)
            b.ret(rt.box(b, not all_))
            b.use(more)

        _iterate(rt, b, _arg(b, 1), consume)
        b.ret(rt.box(b, all_))

    def enumerate_(b):
        _arity(rt, b, 1, 3, keywords=True)
        iterable = b.bind(rt.missing, "iterable")
        start = b.bind(rt.box(b, 0), "start")
        used = b.alloc(Literal(0))
        for index, name, target in ((2, "iterable", iterable), (3, "start", start)):
            positional, keyword = b.branch(Not(Binary("<", Length(Var("$args")), Literal(index))))
            b.use(positional)
            _guard(rt, b, Not(Binary("in", Literal(name), Var("$kwargs"))))
            b.assign(target, _arg(b, index))
            positional_tails = set(b.tails)
            b.use(keyword)
            supplied, absent = b.branch(Binary("in", Literal(name), Var("$kwargs")))
            b.use(supplied)
            b.assign(target, field(Var("$kwargs"), name))
            b.emit(Alloc(used.name, Binary("+", used, Literal(1))))
            b.join(b.tails, absent, positional_tails)
        _guard(rt, b, Binary("=", used, Length(Var("$kwargs"))))
        _guard(rt, b, Not(Binary("=", iterable, rt.missing)))
        result = rt.obj(b, _arg(b, 1))
        index = _index_value(rt, b, start)
        iterator = rt.special(b, iterable, "__iter__")
        rt.checked(b)
        b.assign(field(result, "$iterator"), iterator)
        b.assign(field(result, "$index"), index)
        b.ret(result)

    def enumerate_next(b):
        _arity(rt, b, 1, 1)
        self = _arg(b, 1)
        item = rt.special(b, field(self, "$iterator"), "__next__")
        rt.checked(b)
        index = b.bind(field(self, "$index"))
        result = rt.sequence(b, (rt.box(b, index, "int"), item), "tuple")
        b.assign(field(self, "$index"), b.alloc(Binary("+", index, Literal(1))))
        b.ret(result)

    def zip_(b):
        _arity(rt, b, 1, keywords=True)
        strict = b.alloc(Literal(False), "strict")
        supplied, absent = b.branch(Not(Binary("=", Length(Var("$kwargs")), Literal(0))))
        b.use(supplied)
        _guard(rt, b, Binary("=", Length(Var("$kwargs")), Literal(1)))
        _guard(rt, b, Binary("in", Literal("strict"), Var("$kwargs")))
        b.assign(strict, rt.invoke(b, "truth", (field(Var("$kwargs"), "strict"),)))
        rt.checked(b)
        b.join(b.tails, absent)
        iterators = rt.sequence(b, ())
        index = b.alloc(Literal(2))
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        more, end = b.branch(Not(Binary("<", Length(Var("$args")), index)))
        b.use(end)
        b.jump(done)
        b.use(more)
        iterator = rt.special(b, field(Var("$args"), index), "__iter__")
        rt.checked(b)
        _append(b, iterators, iterator)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        result = rt.obj(b, _arg(b, 1))
        b.assign(field(result, "$iterators"), field(iterators, "$value"))
        b.assign(field(result, "$strict"), strict)
        b.assign(field(result, "$done"), rt.raw(b, False))
        b.ret(result)

    def zip_next(b):
        _arity(rt, b, 1, 1)
        self = _arg(b, 1)
        iterators = field(self, "$iterators")
        done, active = b.branch(
            Binary("or", field(self, "$done"), Binary("=", Length(iterators), Literal(0)))
        )
        b.use(done)
        rt.error(b, "StopIteration")
        b.use(active)
        result = rt.sequence(b, (), "tuple")
        index, checking = b.alloc(Literal(1)), b.alloc(Literal(False))
        head, finished = b.node(), b.node()
        b.jump(head)
        b.use({head})
        more, end = b.branch(Not(Binary("<", Length(iterators), index)))
        b.use(end)
        b.jump(finished)
        b.use(more)
        item = rt.special(b, field(iterators, index), "__next__")
        success, failed = b.branch(Binary("=", rt.exception, rt.none))
        b.use(failed)
        stopped, other = b.branch(_same_class(rt, b, rt.exception, "StopIteration"))
        b.use(other)
        b.ret(rt.none)
        b.use(stopped)
        b.assign(rt.exception, rt.none)
        strict, ordinary = b.branch(field(self, "$strict"))
        b.use(ordinary)
        b.assign(field(self, "$done"), rt.raw(b, True))
        rt.error(b, "StopIteration")
        b.use(strict)
        _guard(rt, b, Binary("=", Length(field(result, "$value")), Literal(0)), "ValueError")
        b.emit(Alloc(checking.name, Literal(True)))
        stopped_tails = set(b.tails)
        b.use(success)
        _guard(rt, b, Not(checking), "ValueError")
        _append(b, result, item)
        b.join(b.tails, stopped_tails)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({finished})
        stopped, row = b.branch(checking)
        b.use(stopped)
        b.assign(field(self, "$done"), rt.raw(b, True))
        rt.error(b, "StopIteration")
        b.use(row)
        b.ret(result)

    def sorted_(b):
        _arity(rt, b, 1, 1, keywords=True)
        kwargs = Var("$kwargs")
        count = b.alloc(Literal(0))
        key, reverse = b.bind(rt.none), b.alloc(Literal(False))
        for name, target in (("key", key), ("reverse", reverse)):
            yes, no = b.branch(Binary("in", Literal(name), kwargs))
            b.use(yes)
            value = field(kwargs, name)
            b.assign(target, rt.invoke(b, "truth", (value,)) if name == "reverse" else value)
            rt.checked(b)
            b.emit(Alloc(count.name, Binary("+", count, Literal(1))))
            b.join(b.tails, no)
        _guard(rt, b, Binary("=", count, Length(kwargs)))
        result, keys = rt.sequence(b, ()), rt.sequence(b, ())

        def consume(item):
            value = b.bind(item)
            customized, identity = b.branch(Not(Binary("=", key, rt.none)))
            b.use(customized)
            b.assign(value, rt.call(b, key, (item,)))
            rt.checked(b)
            b.join(b.tails, identity)
            _append(b, result, item)
            _append(b, keys, value)

        _iterate(rt, b, _arg(b, 1), consume)
        values, key_values = field(result, "$value"), field(keys, "$value")
        index = b.alloc(Literal(2))
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        more, end = b.branch(Not(Binary("<", Length(values), index)))
        b.use(end)
        b.jump(done)
        b.use(more)
        item, item_key = b.bind(field(values, index)), b.bind(field(key_values, index))
        position = b.alloc(index)
        inner, place = b.node(), b.node()
        b.jump(inner)
        b.use({inner})
        more, first = b.branch(Binary("<", Literal(1), position))
        b.use(first)
        b.jump(place)
        b.use(more)
        previous = b.alloc(Binary("-", position, Literal(1)))
        left, right = b.bind(item_key), b.bind(field(key_values, previous))
        descending, ascending = b.branch(reverse)
        b.use(descending)
        b.assign(left, field(key_values, previous))
        b.assign(right, item_key)
        b.join(b.tails, ascending)
        less = rt.invoke(b, "binary", (left, right), "<")
        rt.checked(b)
        truth = rt.invoke(b, "truth", (less,))
        rt.checked(b)
        shift, stop = b.branch(truth)
        b.use(stop)
        b.jump(place)
        b.use(shift)
        b.assign(field(values, position), field(values, previous))
        b.assign(field(key_values, position), field(key_values, previous))
        b.emit(Alloc(position.name, previous))
        b.jump(inner)
        b.use({place})
        b.assign(field(values, position), item)
        b.assign(field(key_values, position), item_key)
        b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
        b.jump(head)
        b.use({done})
        b.ret(result)

    for name, implementation in (
        ("any", lambda b: quantify(b, False)),
        ("all", lambda b: quantify(b, True)),
        ("sorted", sorted_),
    ):
        _define(rt, root, None, name, implementation)
    for name, constructor, next_ in (
        ("enumerate", enumerate_, enumerate_next),
        ("zip", zip_, zip_next),
    ):
        _define(rt, root, name, "__new__", constructor)
        _define(rt, root, name, "__init__", lambda b: b.ret(rt.none))
        _define(rt, root, name, "__iter__", lambda b: b.ret(_arg(b, 1)))
        _define(rt, root, name, "__next__", next_)
