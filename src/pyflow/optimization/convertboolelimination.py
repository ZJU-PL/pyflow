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

    @dispatch(str, type(None), ast.Return, ast.Local, ast.Store, ast.Discard)
    def visitLeaf(self, node):
        pass

    @dispatch(ast.Suite, ast.Switch, ast.Condition)
    def visitOK(self, node):
        node.visitChildren(self)

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        if isinstance(node.expr, ast.ConvertToBool):
            self.converts.append(node.expr)

        if node.expr.alwaysReturnsBoolean() and len(node.lcls) == 1:
            self.define(node.lcls[0])

    @dispatch(ast.CodeParameters)
    def visitCodeParameters(self, node):
        self.undef(node.selfparam)
        for p in node.params:
            self.undef(p)
        self.undef(node.vparam)
        self.undef(node.kparam)

    def process(self, code):
        code.visitChildrenForced(self)

    def define(self, lcl):
        if not lcl in self.lut:
            self.lut[lcl] = True

    def undef(self, lcl):
        self.lut[lcl] = False

    def isBoolean(self, expr):
        if expr.alwaysReturnsBoolean():
            return True

        return self.lut.get(expr, False)


def evaluateCode(compiler, code):
    """Eliminate redundant boolean conversions in code.
    
    Args:
        compiler: Compiler context
        code: Code node to optimize
        
    Note: This transformation is slightly unsound, as conversions of
    possibly undefined locals will be eliminated. A proper dataflow
    analysis would be needed for full soundness.
    """
    infer = InferBoolean()
    infer.process(code)

    if infer.converts:
        # Eliminate ConvertToBool nodes that take booleans as arguments
        replace = {}
        for convert in infer.converts:
            if infer.isBoolean(convert.expr):
                replace[convert] = convert.expr

        if replace:
            rewrite(compiler, code, replace)
