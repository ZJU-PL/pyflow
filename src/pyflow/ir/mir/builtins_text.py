"""String conversions and text operations emitted as ordinary core MIR."""

from .builder import field
from .model import Alloc, Binary, Length, ListExpr, Literal, Not, Var
from .builtins import (
    _arg,
    _arity,
    _as_int,
    _define,
    _guard,
    _iterate,
    _positive_divmod,
    _require_class,
    _same_class,
)


def concatenate(rt, b, result, value):
    """Append a modeled string, retaining its character references."""
    for key in ("$value", "$chars"):
        b.assign(field(result, key), b.alloc(Binary("+", field(result, key), field(value, key))))


def install(rt, root):
    def integer(b):
        _arity(rt, b, 1, 1)
        number = b.alloc(_as_int(rt, b, _arg(b, 1)), "number")
        negative = b.alloc(Binary("<", number, Literal(0)), "negative")
        yes, no = b.branch(negative)
        b.use(yes)
        b.emit(Alloc(number.name, Binary("-", Literal(0), number)))
        b.join(b.tails, no)
        digits = field(rt.box(b, "0123456789"), "$chars")
        result = rt.box(b, "")
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        quotient, remainder = _positive_divmod(b, number, Literal(10))
        digit = field(digits, Binary("+", remainder, Literal(1)))
        b.assign(
            field(result, "$value"),
            b.alloc(Binary("+", field(digit, "$value"), field(result, "$value"))),
        )
        b.assign(
            field(result, "$chars"),
            b.alloc(Binary("+", ListExpr((digit,)), field(result, "$chars"))),
        )
        b.emit(Alloc(number.name, quotient))
        more, end = b.branch(Not(Binary("=", number, Literal(0))))
        b.use(more)
        b.jump(head)
        b.use(end)
        b.jump(done)
        b.use({done})
        yes, no = b.branch(negative)
        b.use(yes)
        prefix = rt.box(b, "-")
        concatenate(rt, b, prefix, result)
        b.ret(prefix)
        b.use(no)
        b.ret(result)

    def boolean(b):
        _arity(rt, b, 1, 1)
        yes, no = b.branch(field(_arg(b, 1), "$value"))
        b.use(yes)
        b.ret(rt.box(b, "True"))
        b.use(no)
        b.ret(rt.box(b, "False"))

    def string_repr(b):
        _arity(rt, b, 1, 1)
        value = _arg(b, 1)
        single, double = b.alloc(Literal(False)), b.alloc(Literal(False))

        def scan(char):
            # Reject unmodeled Unicode character categories rather than
            # emitting an incorrect representation for non-printable text.
            _guard(rt, b, Binary("<", field(char, "$value"), Literal("\x80")))
            for flag, quote in ((single, "'"), (double, '"')):
                b.emit(
                    Alloc(
                        flag.name,
                        Binary("or", flag, Binary("=", field(char, "$value"), Literal(quote))),
                    )
                )

        _iterate(rt, b, value, scan)
        quote = b.bind(rt.box(b, "'"), "quote")
        yes, no = b.branch(Not(Binary("or", Not(single), double)))
        b.use(yes)
        b.assign(quote, rt.box(b, '"'))
        b.join(b.tails, no)
        result = rt.box(b, "")
        concatenate(rt, b, result, quote)

        def append(char):
            matched = []
            escapes = [("\\", "\\\\"), ("\n", "\\n"), ("\r", "\\r"), ("\t", "\\t")]
            escapes.extend(
                (chr(code), f"\\x{code:02x}")
                for code in (*range(32), 127)
                if code not in (9, 10, 13)
            )
            for raw, escaped in escapes:
                yes, no = b.branch(Binary("=", field(char, "$value"), Literal(raw)))
                b.use(yes)
                concatenate(rt, b, result, rt.box(b, escaped))
                matched.append(set(b.tails))
                b.use(no)
            yes, no = b.branch(Binary("=", field(char, "$value"), field(quote, "$value")))
            b.use(yes)
            concatenate(rt, b, result, rt.box(b, "\\"))
            b.join(b.tails, no)
            concatenate(rt, b, result, char)
            b.join(b.tails, *matched)

        _iterate(rt, b, value, append)
        concatenate(rt, b, result, quote)
        b.ret(result)

    def sequence_repr(b, kind):
        _arity(rt, b, 1, 1)
        value = _arg(b, 1)
        result = rt.box(b, "(" if kind == "tuple" else "[")
        count = b.alloc(Literal(0))

        def append(item):
            yes, no = b.branch(Not(Binary("=", count, Literal(0))))
            b.use(yes)
            concatenate(rt, b, result, rt.box(b, ", "))
            b.join(b.tails, no)
            text = rt.special(b, item, "__repr__")
            rt.checked(b)
            _require_class(rt, b, text, "str")
            concatenate(rt, b, result, text)
            b.emit(Alloc(count.name, Binary("+", count, Literal(1))))

        _iterate(rt, b, value, append)
        if kind == "tuple":
            yes, no = b.branch(Binary("=", count, Literal(1)))
            b.use(yes)
            concatenate(rt, b, result, rt.box(b, ","))
            b.join(b.tails, no)
        concatenate(rt, b, result, rt.box(b, ")" if kind == "tuple" else "]"))
        b.ret(result)

    def exception(b):
        _arity(rt, b, 1, 1)
        self = _arg(b, 1)
        absent, present = b.branch(Not(Binary("in", Literal("args"), self)))
        b.use(absent)
        b.ret(rt.box(b, ""))
        b.use(present)
        args = field(self, "args")
        raw = field(args, "$value")
        empty, nonempty = b.branch(Binary("=", Length(raw), Literal(0)))
        b.use(empty)
        b.ret(rt.box(b, ""))
        b.use(nonempty)
        one, many = b.branch(Binary("=", Length(raw), Literal(1)))
        b.use(one)
        b.ret(rt.call(b, rt.builtin("str"), (field(raw, 1),)))
        b.use(many)
        b.ret(rt.special(b, args, "__repr__"))

    def join(b):
        _arity(rt, b, 2, 2)
        separator, values = _arg(b, 1), _arg(b, 2)
        result = rt.box(b, "")
        first = b.alloc(Literal(True))

        def append(item):
            _require_class(rt, b, item, "str")
            yes, no = b.branch(first)
            b.use(no)
            concatenate(rt, b, result, separator)
            b.join(yes, b.tails)
            concatenate(rt, b, result, item)
            b.emit(Alloc(first.name, Literal(False)))

        _iterate(rt, b, values, append)
        b.ret(result)

    def format_(b):
        _arity(rt, b, 2, 2)
        template, values = _arg(b, 1), _arg(b, 2)
        arguments = b.alloc(ListExpr((values,)))
        yes, no = b.branch(_same_class(rt, b, values, "tuple"))
        b.use(yes)
        b.assign(arguments, field(values, "$value"))
        b.join(b.tails, no)
        result = rt.box(b, "")
        index, escaped = b.alloc(Literal(1)), b.alloc(Literal(False))

        def append(char):
            code = field(char, "$value")
            conversion, ordinary = b.branch(escaped)
            b.use(ordinary)
            percent, literal = b.branch(Binary("=", code, Literal("%")))
            b.use(percent)
            b.emit(Alloc(escaped.name, Literal(True)))
            percent_tails = set(b.tails)
            b.use(literal)
            concatenate(rt, b, result, char)
            literal_tails = set(b.tails)
            b.use(conversion)
            b.emit(Alloc(escaped.name, Literal(False)))
            percent, specifier = b.branch(Binary("=", code, Literal("%")))
            b.use(percent)
            concatenate(rt, b, result, char)
            escaped_tails = set(b.tails)
            b.use(specifier)
            _guard(rt, b, Not(Binary("<", Length(arguments), index)))
            item = field(arguments, index)
            text = Var(b.temp("formatted"))
            choices = []
            for spec in ("s", "r", "d", "i"):
                yes, no = b.branch(Binary("=", code, Literal(spec)))
                b.use(yes)
                if spec in {"d", "i"}:
                    _require_class(rt, b, item, "int")
                    b.assign(text, rt.call(b, field(rt.builtin("int"), "__str__"), (item,)))
                else:
                    b.assign(
                        text, rt.call(b, rt.builtin("str" if spec == "s" else "repr"), (item,))
                    )
                rt.checked(b)
                choices.append(set(b.tails))
                b.use(no)
            rt.error(b, "ValueError")
            b.join(*choices)
            concatenate(rt, b, result, text)
            b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
            b.join(b.tails, percent_tails, literal_tails, escaped_tails)

        _iterate(rt, b, template, append)
        _guard(rt, b, Not(escaped), "ValueError")
        _guard(rt, b, Binary("=", index, Binary("+", Length(arguments), Literal(1))))
        b.ret(result)

    def repr_(b):
        _arity(rt, b, 1, 1)
        value = rt.special(b, _arg(b, 1), "__repr__")
        rt.checked(b)
        _require_class(rt, b, value, "str")
        b.ret(value)

    for owner, implementation in (("int", integer), ("bool", boolean)):
        for method in ("__str__", "__repr__"):
            _define(rt, root, owner, method, implementation)
    for owner, text in (("NoneType", "None"), ("NotImplementedType", "NotImplemented")):
        for method in ("__str__", "__repr__"):
            _define(rt, root, owner, method, lambda b, text=text: b.ret(rt.box(b, text)))
    for owner in ("list", "tuple"):
        for method in ("__str__", "__repr__"):
            _define(rt, root, owner, method, lambda b, kind=owner: sequence_repr(b, kind))
    _define(rt, root, "BaseException", "__str__", exception)
    _define(rt, root, "str", "__repr__", string_repr)
    _define(rt, root, "str", "join", join)
    _define(rt, root, "str", "__mod__", format_)
    _define(rt, root, None, "repr", repr_)
