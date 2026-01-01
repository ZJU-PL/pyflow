from __future__ import absolute_import

from ..stubcollector import stubgenerator

import operator


@stubgenerator
def makeOperatorStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    # Arithmetic operators
    @export
    @attachPtr(operator, "add")
    @llfunc
    def operator_add(a, b):
        return allocate(type(a + b))  # Return type depends on operands

    @export
    @attachPtr(operator, "sub")
    @llfunc
    def operator_sub(a, b):
        return allocate(type(a - b))

    @export
    @attachPtr(operator, "mul")
    @llfunc
    def operator_mul(a, b):
        return allocate(type(a * b))

    @export
    @attachPtr(operator, "truediv")
    @llfunc
    def operator_truediv(a, b):
        return allocate(float)  # Always returns float in Python 3

    @export
    @attachPtr(operator, "floordiv")
    @llfunc
    def operator_floordiv(a, b):
        return allocate(int)  # Integer division

    @export
    @attachPtr(operator, "mod")
    @llfunc
    def operator_mod(a, b):
        return allocate(type(a % b))

    @export
    @attachPtr(operator, "pow")
    @llfunc
    def operator_pow(a, b):
        return allocate(type(a**b))

    # Comparison operators
    @export
    @attachPtr(operator, "eq")
    @llfunc
    def operator_eq(a, b):
        return allocate(bool)

    @export
    @attachPtr(operator, "ne")
    @llfunc
    def operator_ne(a, b):
        return allocate(bool)

    @export
    @attachPtr(operator, "lt")
    @llfunc
    def operator_lt(a, b):
        return allocate(bool)

    @export
    @attachPtr(operator, "le")
    @llfunc
    def operator_le(a, b):
        return allocate(bool)

    @export
    @attachPtr(operator, "gt")
    @llfunc
    def operator_gt(a, b):
        return allocate(bool)

    @export
    @attachPtr(operator, "ge")
    @llfunc
    def operator_ge(a, b):
        return allocate(bool)

    # Logical operators
    @export
    @attachPtr(operator, "and_")
    @llfunc
    def operator_and_(a, b):
        return allocate(bool)

    @export
    @attachPtr(operator, "or_")
    @llfunc
    def operator_or_(a, b):
        return allocate(bool)

    @export
    @attachPtr(operator, "not_")
    @llfunc
    def operator_not_(a):
        return allocate(bool)

    # Sequence operators
    @export
    @attachPtr(operator, "getitem")
    @llfunc
    def operator_getitem(a, b):
        return allocate(object)  # Return type depends on a[b]

    @export
    @attachPtr(operator, "setitem")
    @llfunc
    def operator_setitem(a, b, c):
        return allocate(type(None))

    @export
    @attachPtr(operator, "delitem")
    @llfunc
    def operator_delitem(a, b):
        return allocate(type(None))

    @export
    @attachPtr(operator, "getslice")
    @llfunc
    def operator_getslice(a, b, c):
        return allocate(type(a[b:c]))

    @export
    @attachPtr(operator, "setslice")
    @llfunc
    def operator_setslice(a, b, c, d):
        return allocate(type(None))

    @export
    @attachPtr(operator, "delslice")
    @llfunc
    def operator_delslice(a, b, c):
        return allocate(type(None))
