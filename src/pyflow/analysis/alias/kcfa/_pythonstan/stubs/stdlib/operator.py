def lt(a, b):
    return a < b


def le(a, b):
    return a <= b


def eq(a, b):
    return a == b


def ne(a, b):
    return a != b


def ge(a, b):
    return a >= b


def gt(a, b):
    return a > b


def not_(a):
    return not a


def truth(a):
    return True if a else False


def is_(a, b):
    return a is b


def is_not(a, b):
    return a is not b


def abs(a):
    return a.__abs__()


def add(a, b):
    return a + b


def and_(a, b):
    return a & b


def floordiv(a, b):
    return a // b


def index(a):
    return a.__index__()


def inv(a):
    return ~a


def invert(a):
    return ~a


def lshift(a, b):
    return a << b


def mod(a, b):
    return a % b


def mul(a, b):
    return a * b


def matmul(a, b):
    return a @ b


def neg(a):
    return -a


def or_(a, b):
    return a | b


def pos(a):
    return +a


def pow(a, b):
    return a ** b


def rshift(a, b):
    return a >> b


def sub(a, b):
    return a - b


def truediv(a, b):
    return a / b


def xor(a, b):
    return a ^ b


def concat(a, b):
    return a + b


def contains(a, b):
    return b in a


def countOf(a, b):
    count = 0
    for item in a:
        if item == b:
            count += 1
    return count


def delitem(a, b):
    del a[b]


def getitem(a, b):
    return a[b]


def indexOf(a, b):
    for i, item in enumerate(a):
        if item == b:
            return i
    raise ValueError("sequence.index(x): x not in sequence")


def setitem(a, b, c):
    a[b] = c


def length_hint(obj, default=0):
    return len(obj) if hasattr(obj, '__len__') else default


def call(obj, *args, **kwargs):
    return obj(*args, **kwargs)


class attrgetter:
    def __init__(self, attr, *attrs):
        self._attrs = (attr,) + attrs

    def __call__(self, obj):
        if len(self._attrs) == 1:
            return _get_nested_attr(obj, self._attrs[0])
        return tuple(_get_nested_attr(obj, attr) for attr in self._attrs)


def _get_nested_attr(obj, attr):
    for name in attr.split('.'):
        obj = getattr(obj, name)
    return obj


class itemgetter:
    def __init__(self, item, *items):
        self._items = (item,) + items

    def __call__(self, obj):
        if len(self._items) == 1:
            return obj[self._items[0]]
        return tuple(obj[item] for item in self._items)


class methodcaller:
    def __init__(self, name, *args, **kwargs):
        self._name = name
        self._args = args
        self._kwargs = kwargs

    def __call__(self, obj):
        return getattr(obj, self._name)(*self._args, **self._kwargs)


def iadd(a, b):
    a += b
    return a


def iand(a, b):
    a &= b
    return a


def iconcat(a, b):
    a += b
    return a


def ifloordiv(a, b):
    a //= b
    return a


def ilshift(a, b):
    a <<= b
    return a


def imod(a, b):
    a %= b
    return a


def imul(a, b):
    a *= b
    return a


def imatmul(a, b):
    a @= b
    return a


def ior(a, b):
    a |= b
    return a


def ipow(a, b):
    a **= b
    return a


def irshift(a, b):
    a >>= b
    return a


def isub(a, b):
    a -= b
    return a


def itruediv(a, b):
    a /= b
    return a


def ixor(a, b):
    a ^= b
    return a


__lt__ = lt
__le__ = le
__eq__ = eq
__ne__ = ne
__ge__ = ge
__gt__ = gt
__not__ = not_
__abs__ = abs
__add__ = add
__and__ = and_
__floordiv__ = floordiv
__index__ = index
__inv__ = inv
__invert__ = invert
__lshift__ = lshift
__mod__ = mod
__mul__ = mul
__matmul__ = matmul
__neg__ = neg
__or__ = or_
__pos__ = pos
__pow__ = pow
__rshift__ = rshift
__sub__ = sub
__truediv__ = truediv
__xor__ = xor
__concat__ = concat
__contains__ = contains
__delitem__ = delitem
__getitem__ = getitem
__setitem__ = setitem
__iadd__ = iadd
__iand__ = iand
__iconcat__ = iconcat
__ifloordiv__ = ifloordiv
__ilshift__ = ilshift
__imod__ = imod
__imul__ = imul
__imatmul__ = imatmul
__ior__ = ior
__ipow__ = ipow
__irshift__ = irshift
__isub__ = isub
__itruediv__ = itruediv
__ixor__ = ixor
