"""
Boolean Conversion Elimination Optimization for PyFlow.

This module eliminates redundant boolean conversions by tracking which
expressions are known to return boolean values.

The optimization:
- Tracks boolean values through assignments
- Identifies ConvertToBool operations on boolean expressions
- Eliminates redundant conversions
- Note: This is a simple analysis that doesn't propagate through all assignments

TODO: This should be a proper dataflow analysis for better precision.
"""

from pyflow.util.typedispatch import *

from pyflow.language.python import ast

from pyflow.optimization.rewrite import rewrite


# TODO this does not propagate through assignments.
# This should be a proper dataflow analysis?
class InferBoolean(TypeDispatcher):
    """Infers which expressions are boolean values.

    Tracks boolean values through assignments to identify redundant
    ConvertToBool operations. This is a simple analysis that doesn't
    handle all cases (e.g., propagation through assignments).
    """

    def __init__(self):
        self.lut = {}
        self.converts = []

    @dispatch(
        ast.leafTypes,
        ast.Local,
        ast.Existing,
        ast.Code,
        ast.DoNotCare,
        ast.Break,
        ast.Continue,
        ast.GlobalDecl,
        ast.NonlocalDecl,
        ast.TypeParam,
        ast.TypeParams,
        ast.TypeAlias,
    )
    def visitLeaf(self, node):
        pass

    @dispatch(list, tuple)
    def visitSequence(self, node):
        for item in node:
            self(item)

    @dispatch(ast.Suite)
    def visitSuite(self, node):
        node.visitChildren(self)

    @dispatch(ast.ConvertToBool)
    def visitConvertToBool(self, node):
        self.converts.append(node)
        node.visitChildren(self)

    @dispatch(
        ast.Switch,
        ast.Condition,
        ast.TypeSwitch,
        ast.TypeSwitchCase,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.TryExceptFinally,
        ast.TryStar,
        ast.ExceptionHandler,
        ast.ShortCircutAnd,
        ast.ShortCircutOr,
        ast.ConditionalExpr,
    )
    def visitBranching(self, node):
        # Conservative barrier: this lightweight analysis is not path-sensitive.
        # Avoid propagating boolean facts across control-flow joins where a
        # local may be undefined or have non-boolean values on some paths.
        node.visitChildren(self)
        for lcl in list(self.lut.keys()):
            self.lut[lcl] = False

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        self(node.expr)

        for lcl in node.lcls:
            self.undef(lcl)

        if (
            hasattr(node.expr, "alwaysReturnsBoolean")
            and node.expr.alwaysReturnsBoolean()
            and len(node.lcls) == 1
        ):
            self.define(node.lcls[0])

    @dispatch(ast.Delete)
    def visitDelete(self, node):
        self.undef(node.lcl)

    @dispatch(ast.UnpackSequence)
    def visitUnpackSequence(self, node):
        self(node.expr)
        for target in node.targets:
            self.undef(target)

    @dispatch(ast.AnnAssign)
    def visitAnnAssign(self, node):
        if node.value is not None:
            self(node.value)
        self.undef(node.target)

    @dispatch(ast.NamedExpr)
    def visitNamedExpr(self, node):
        self(node.value)
        self.undef(node.target)

    @dispatch(ast.CodeParameters)
    def visitCodeParameters(self, node):
        self.undef(node.selfparam)
        for p in node.posonlyparams:
            self.undef(p)
        for p in node.params:
            self.undef(p)
        self.undef(node.vparam)
        self.undef(node.kparam)

    @defaultdispatch
    def visitOther(self, node):
        if isinstance(node, ast.PythonASTNode):
            node.visitChildren(self)

    def process(self, code):
        code.visitChildrenForced(self)

    def define(self, lcl):
        self.lut[lcl] = True

    def undef(self, lcl):
        self.lut[lcl] = False

    def isBoolean(self, expr):
        if hasattr(expr, "alwaysReturnsBoolean") and expr.alwaysReturnsBoolean():
            return True

        return self.lut.get(expr, False)


def evaluateCode(compiler, code):
    """Eliminate redundant boolean conversions in code.

    Args:
        compiler: Compiler context
        code: Code node to optimize

    Soundness policy: only remove ConvertToBool when the wrapped
    expression is intrinsically boolean (alwaysReturnsBoolean). This
    avoids eliminating conversions based on path-sensitive local facts.
    """
    infer = InferBoolean()
    infer.process(code)

    if infer.converts:
        # Eliminate ConvertToBool nodes that take booleans as arguments
        replace = {}
        for convert in infer.converts:
            if (
                hasattr(convert.expr, "alwaysReturnsBoolean")
                and convert.expr.alwaysReturnsBoolean()
            ):
                replace[convert] = convert.expr

        if replace:
            rewrite(compiler, code, replace)
