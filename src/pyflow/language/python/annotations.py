"""Source and transformation metadata attached to Python AST syntax.

Context-sensitive analysis results live in :mod:`pyflow.ir.core.facts`, never
on mutable AST annotations.
"""

from pyflow.language.asttools.origin import Origin
from pyflow.language.asttools.annotation import noMod


def codeOrigin(code, line=None, col=None):
    if line is None:
        line = code.co_firstlineno
    return Origin(code.co_name, code.co_filename, line, col)


def functionOrigin(func, line=None, col=None):
    return codeOrigin(func.__code__, line, col)


class Annotation:
    __slots__ = ()


class CodeAnnotation(Annotation):
    __slots__ = (
        "descriptive",
        "primitive",
        "staticFold",
        "dynamicFold",
        "origin",
        "lowered",
        "runtime",
        "interpreter",
    )

    def __init__(
        self,
        descriptive=False,
        primitive=False,
        staticFold=None,
        dynamicFold=None,
        origin=None,
        lowered=False,
        runtime=False,
        interpreter=False,
    ):
        self.descriptive = descriptive
        self.primitive = primitive
        self.staticFold = staticFold
        self.dynamicFold = dynamicFold
        self.origin = origin
        self.lowered = lowered
        self.runtime = runtime
        self.interpreter = interpreter

    def rewrite(
        self,
        descriptive=noMod,
        primitive=noMod,
        staticFold=noMod,
        dynamicFold=noMod,
        origin=noMod,
        lowered=noMod,
        runtime=noMod,
        interpreter=noMod,
    ):
        values = {
            "descriptive": descriptive,
            "primitive": primitive,
            "staticFold": staticFold,
            "dynamicFold": dynamicFold,
            "origin": origin,
            "lowered": lowered,
            "runtime": runtime,
            "interpreter": interpreter,
        }
        for name, value in tuple(values.items()):
            if value is noMod:
                values[name] = getattr(self, name)
        return CodeAnnotation(**values)


class OpAnnotation(Annotation):
    __slots__ = ("origin",)

    def __init__(self, origin=(None,)):
        self.origin = origin

    def rewrite(self, origin=noMod):
        return OpAnnotation(self.origin if origin is noMod else origin)


class SlotAnnotation(Annotation):
    __slots__ = ()

    def rewrite(self):
        return self


emptyCodeAnnotation = CodeAnnotation()
emptyOpAnnotation = OpAnnotation()
emptySlotAnnotation = SlotAnnotation()


__all__ = [
    "Annotation",
    "CodeAnnotation",
    "OpAnnotation",
    "SlotAnnotation",
    "codeOrigin",
    "functionOrigin",
    "emptyCodeAnnotation",
    "emptyOpAnnotation",
    "emptySlotAnnotation",
]
