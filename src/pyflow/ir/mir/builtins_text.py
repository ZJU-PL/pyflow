"""String conversions and text operations emitted as ordinary core MIR."""

from .builder import field
from .model import Alloc, Binary, Length, ListExpr, Literal, Not, Var
from .builtins import (
    _append,
    _arg,
    _arity,
    _as_int,
    _define,
    _guard,
    _index_value,
    _iterate,
    _positive_divmod,
    _require_class,
    _search,
    _same_class,
)


def concatenate(rt, b, result, value):
    """Append a modeled string, retaining its character references."""
    for key in ("$value", "$chars"):
        b.assign(field(result, key), b.alloc(Binary("+", field(result, key), field(value, key))))


def _match_at(rt, b, text, pattern, start):
    """Allocate a Boolean variable: *pattern* occurs in *text* at 1-based *start*."""
    result = b.alloc(Literal(True), "match")
    done = b.node()

    def fail():
        b.emit(Alloc(result.name, Literal(False)))
        b.jump(done)

    positive, nonpositive = b.branch(Binary("<", Literal(0), start))
    b.use(nonpositive)
    fail()
    b.use(positive)
    end = Binary("+", Binary("-", start, Literal(1)), Length(pattern))
    fits, overflows = b.branch(Not(Binary("<", Length(text), end)))
    b.use(overflows)
    fail()
    b.use(fits)
    index = b.alloc(Literal(1), "match_index")
    head = b.node()
    b.jump(head)
    b.use({head})
    more, finished = b.branch(Not(Binary("<", Length(pattern), index)))
    b.use(finished)
    b.jump(done)
    b.use(more)
    position = b.alloc(Binary("+", Binary("-", start, Literal(1)), index), "position")
    same, different = b.branch(
        Binary(
            "=",
            field(field(text, position), "$value"),
            field(field(pattern, index), "$value"),
        )
    )
    b.use(different)
    fail()
    b.use(same)
    b.emit(Alloc(index.name, Binary("+", index, Literal(1))))
    b.jump(head)
    b.use({done})
    return result


def _whitespace_test(char):
    code = field(char, "$value")
    result = Binary("=", code, Literal(" "))
    for whitespace in ("\t", "\n", "\r", "\f", "\v"):
        result = Binary("or", result, Binary("=", code, Literal(whitespace)))
    return result


def _slice_text(rt, b, chars, start, end):
    """Build a new string from 1-based inclusive character positions."""
    piece = rt.box(b, "")
    b.assign(field(piece, "$chars"), b.alloc(ListExpr(()), "characters"))
    finish = b.node()
    position = b.alloc(start, "slice_position")
    head = b.node()
    b.jump(head)
    b.use({head})
    more, done = b.branch(Not(Binary("<", end, position)))
    b.use(done)
    b.jump(finish)
    b.use(more)
    concatenate(rt, b, piece, field(chars, position))
    b.emit(Alloc(position.name, Binary("+", position, Literal(1))))
    b.jump(head)
    b.use({finish})
    return piece


def _skip_whitespace(rt, b, chars, position):
    """Advance *position* past a run of ASCII whitespace."""
    finish = b.node()
    head = b.node()
    b.jump(head)
    b.use({head})
    more, done = b.branch(Not(Binary("<", Length(chars), position)))
    b.use(done)
    b.jump(finish)
    b.use(more)
    space, text = b.branch(_whitespace_test(field(chars, position)))
    b.use(text)
    b.jump(finish)
    b.use(space)
    b.emit(Alloc(position.name, Binary("+", position, Literal(1))))
    b.jump(head)
    b.use({finish})


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

    def case_map(b, source, target):
        _arity(rt, b, 1, 1)
        value = _arg(b, 1)
        keys = field(rt.box(b, source), "$chars")
        replacements = field(rt.box(b, target), "$chars")
        result = rt.box(b, "")
        b.assign(field(result, "$chars"), b.alloc(ListExpr(()), "characters"))

        def append(char):
            found = _search(rt, b, keys, char)
            absent, present = b.branch(Binary("=", found, Literal(0)))
            b.use(absent)
            concatenate(rt, b, result, char)
            absent_tails = set(b.tails)
            b.use(present)
            concatenate(rt, b, result, field(replacements, found))
            b.join(b.tails, absent_tails)

        _iterate(rt, b, value, append)
        b.ret(result)

    def startswith(b):
        _arity(rt, b, 2, 2)
        text, prefix = _arg(b, 1), _arg(b, 2)
        _require_class(rt, b, prefix, "str")
        match = _match_at(rt, b, field(text, "$chars"), field(prefix, "$chars"), Literal(1))
        b.ret(rt.box(b, match, "bool"))

    def endswith(b):
        _arity(rt, b, 2, 2)
        text, suffix = _arg(b, 1), _arg(b, 2)
        _require_class(rt, b, suffix, "str")
        chars, pattern = field(text, "$chars"), field(suffix, "$chars")
        start = Binary("-", Binary("+", Length(chars), Literal(1)), Length(pattern))
        match = _match_at(rt, b, chars, pattern, b.alloc(start, "suffix_start"))
        b.ret(rt.box(b, match, "bool"))

    def find(b):
        _arity(rt, b, 2, 2)
        text, needle = _arg(b, 1), _arg(b, 2)
        _require_class(rt, b, needle, "str")
        chars, pattern = field(text, "$chars"), field(needle, "$chars")
        result = b.alloc(Literal(-1), "found")
        position = b.alloc(Literal(1), "scan")
        limit = Binary("-", Binary("+", Length(chars), Literal(1)), Length(pattern))
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", limit, position)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        match = _match_at(rt, b, chars, pattern, position)
        found, missing = b.branch(match)
        b.use(found)
        b.emit(Alloc(result.name, Binary("-", position, Literal(1))))
        b.jump(done)
        b.use(missing)
        b.emit(Alloc(position.name, Binary("+", position, Literal(1))))
        b.jump(head)
        b.use({done})
        b.ret(rt.box(b, result, "int"))

    def count(b):
        _arity(rt, b, 2, 2)
        text, needle = _arg(b, 1), _arg(b, 2)
        _require_class(rt, b, needle, "str")
        chars, pattern = field(text, "$chars"), field(needle, "$chars")
        total = b.alloc(Literal(0), "total")
        position = b.alloc(Literal(1), "scan")
        limit = Binary("-", Binary("+", Length(chars), Literal(1)), Length(pattern))
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", limit, position)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        match = _match_at(rt, b, chars, pattern, position)
        found, missing = b.branch(match)
        b.use(found)
        b.emit(Alloc(total.name, Binary("+", total, Literal(1))))
        b.emit(Alloc(position.name, Binary("+", position, Length(pattern))))
        found_tails = set(b.tails)
        b.use(missing)
        b.emit(Alloc(position.name, Binary("+", position, Literal(1))))
        b.join(found_tails, b.tails)
        b.jump(head)
        b.use({done})
        b.ret(rt.box(b, total, "int"))

    def replace(b):
        _arity(rt, b, 3, 3)
        text, old, new = _arg(b, 1), _arg(b, 2), _arg(b, 3)
        _require_class(rt, b, old, "str")
        _require_class(rt, b, new, "str")
        chars, pattern = field(text, "$chars"), field(old, "$chars")
        result = rt.box(b, "")
        b.assign(field(result, "$chars"), b.alloc(ListExpr(()), "characters"))
        empty, filled = b.branch(Binary("=", Length(pattern), Literal(0)))
        b.use(empty)
        concatenate(rt, b, result, new)

        def pad(char):
            concatenate(rt, b, result, char)
            concatenate(rt, b, result, new)

        _iterate(rt, b, text, pad)
        b.ret(result)
        b.use(filled)
        position = b.alloc(Literal(1), "scan")
        limit = Binary("-", Binary("+", Length(chars), Literal(1)), Length(pattern))
        head, done = b.node(), b.node()
        b.jump(head)
        b.use({head})
        inside, outside = b.branch(Not(Binary("<", limit, position)))
        b.use(outside)
        b.jump(done)
        b.use(inside)
        match = _match_at(rt, b, chars, pattern, position)
        found, missing = b.branch(match)
        b.use(found)
        concatenate(rt, b, result, new)
        b.emit(Alloc(position.name, Binary("+", position, Length(pattern))))
        b.jump(head)
        b.use(missing)
        concatenate(rt, b, result, field(chars, position))
        b.emit(Alloc(position.name, Binary("+", position, Literal(1))))
        b.jump(head)
        b.use({done})
        b.ret(result)

    def strip(b):
        _arity(rt, b, 1, 1)
        value = _arg(b, 1)
        chars = field(value, "$chars")
        start = b.alloc(Literal(1), "start")
        located = b.node()
        head = b.node()
        b.jump(head)
        b.use({head})
        inside, exhausted = b.branch(Not(Binary("<", Length(chars), start)))
        b.use(exhausted)
        b.ret(rt.box(b, ""))
        b.use(inside)
        space, text = b.branch(_whitespace_test(field(chars, start)))
        b.use(text)
        b.jump(located)
        b.use(space)
        b.emit(Alloc(start.name, Binary("+", start, Literal(1))))
        b.jump(head)
        b.use({located})
        end = b.alloc(Length(chars), "end")
        trimmed = b.node()
        head2 = b.node()
        b.jump(head2)
        b.use({head2})
        empty, overlap = b.branch(Binary("<", end, start))
        b.use(empty)
        b.ret(rt.box(b, ""))
        b.use(overlap)
        space, text = b.branch(_whitespace_test(field(chars, end)))
        b.use(text)
        b.jump(trimmed)
        b.use(space)
        b.emit(Alloc(end.name, Binary("-", end, Literal(1))))
        b.jump(head2)
        b.use({trimmed})
        b.ret(_slice_text(rt, b, chars, start, end))

    def split(b):
        _arity(rt, b, 1, 3, keywords=True)
        value = _arg(b, 1)
        chars = field(value, "$chars")
        separator = b.bind(rt.none, "sep")
        limit = b.bind(rt.box(b, -1), "maxsplit")
        used = b.alloc(Literal(0))
        for index, name, target in ((2, "sep", separator), (3, "maxsplit", limit)):
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
        limit = b.bind(_index_value(rt, b, limit))
        result = rt.sequence(b, (), "list")
        produced = b.alloc(Literal(0), "produced")
        position = b.alloc(Literal(1), "scan")

        whitespace, explicit = b.branch(_same_class(rt, b, separator, "NoneType"))
        b.use(whitespace)
        head = b.node()
        b.jump(head)
        b.use({head})
        _skip_whitespace(rt, b, chars, position)
        more, exhausted = b.branch(Not(Binary("<", Length(chars), position)))
        b.use(exhausted)
        b.ret(result)
        b.use(more)
        unbounded = Binary("<", limit, Literal(0))
        room, remainder = b.branch(Binary("or", unbounded, Binary("<", produced, limit)))
        b.use(room)
        start = b.alloc(position, "word_start")
        word_done = b.node()
        head2 = b.node()
        b.jump(head2)
        b.use({head2})
        more, done = b.branch(Not(Binary("<", Length(chars), position)))
        b.use(done)
        b.jump(word_done)
        b.use(more)
        space, text = b.branch(_whitespace_test(field(chars, position)))
        b.use(space)
        b.jump(word_done)
        b.use(text)
        b.emit(Alloc(position.name, Binary("+", position, Literal(1))))
        b.jump(head2)
        b.use({word_done})
        _append(
            b,
            result,
            _slice_text(rt, b, chars, start, Binary("-", position, Literal(1))),
        )
        b.emit(Alloc(produced.name, Binary("+", produced, Literal(1))))
        b.jump(head)
        b.use(remainder)
        _append(b, result, _slice_text(rt, b, chars, position, Length(chars)))
        b.ret(result)

        b.use(explicit)
        _require_class(rt, b, separator, "str")
        pattern = field(separator, "$chars")
        _guard(rt, b, Not(Binary("=", Length(pattern), Literal(0))), "ValueError")
        tail = b.node()
        piece = b.alloc(Literal(1), "piece")
        head3 = b.node()
        b.jump(head3)
        b.use({head3})
        room, remainder = b.branch(
            Binary("or", Binary("<", limit, Literal(0)), Binary("<", produced, limit))
        )
        b.use(room)
        last_start = Binary("-", Binary("+", Length(chars), Literal(1)), Length(pattern))
        inside, outside = b.branch(Not(Binary("<", last_start, position)))
        b.use(outside)
        b.jump(tail)
        b.use(inside)
        match = _match_at(rt, b, chars, pattern, position)
        found, missing = b.branch(match)
        b.use(missing)
        b.emit(Alloc(position.name, Binary("+", position, Literal(1))))
        b.jump(head3)
        b.use(found)
        _append(
            b,
            result,
            _slice_text(rt, b, chars, piece, Binary("-", position, Literal(1))),
        )
        b.emit(Alloc(position.name, Binary("+", position, Length(pattern))))
        b.emit(Alloc(piece.name, position))
        b.emit(Alloc(produced.name, Binary("+", produced, Literal(1))))
        b.jump(head3)
        b.use({tail, *remainder})
        _append(b, result, _slice_text(rt, b, chars, piece, Length(chars)))
        b.ret(result)

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
    _define(
        rt,
        root,
        "str",
        "upper",
        lambda b: case_map(b, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    )
    _define(
        rt,
        root,
        "str",
        "lower",
        lambda b: case_map(b, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"),
    )
    _define(rt, root, "str", "strip", strip)
    _define(rt, root, "str", "split", split)
    _define(rt, root, "str", "startswith", startswith)
    _define(rt, root, "str", "endswith", endswith)
    _define(rt, root, "str", "find", find)
    _define(rt, root, "str", "count", count)
    _define(rt, root, "str", "replace", replace)
    _define(rt, root, "str", "join", join)
    _define(rt, root, "str", "__mod__", format_)
    _define(rt, root, None, "repr", repr_)
