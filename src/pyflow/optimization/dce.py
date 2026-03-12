"""Dead Code Elimination (DCE) optimization pass.

This module implements dead code elimination for PyFlow, removing code that
does not affect the program's output or side effects.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

from pyflow.optimization.dataflow.reverse import *
from pyflow.optimization.dataflow.base import top, undefined, MutateCodeReversed

from pyflow.analysis import tools


def _snapshot_code(node):
    """Capture a structural snapshot for change detection."""

    def snapshot_value(value):
        if isinstance(value, list):
            return tuple(snapshot_value(item) for item in value)
        if isinstance(value, tuple):
            return tuple(snapshot_value(item) for item in value)
        if isinstance(value, ast.DoNotCare):
            return ("DoNotCare",)
        if isinstance(value, ast.Local):
            return ("Local", value.name)
        if isinstance(value, ast.Existing):
            return ("Existing", repr(value.object))
        if isinstance(value, ast.leafTypes):
            return value
        if hasattr(value, "children"):
            return (
                type(value).__name__,
                tuple(snapshot_value(child) for child in value.children()),
            )
        return repr(value)

    return snapshot_value(node)


def liveMeet(values):
    """Meet function for liveness analysis.

    Args:
        values: Set of liveness values.

    Returns:
        top: If any values are present (variable is live).
        undefined: If no values are present (variable is dead).
    """
    if values:
        return top
    else:
        return undefined


class MarkLocals(TypeDispatcher):
    """Marks local variables as used in an AST subtree.

    This dispatcher traverses the AST and marks local variables as live
    when they are referenced, enabling dead code elimination.
    """

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        """Visit leaf nodes (no action needed)."""
        pass

    @dispatch(ast.Local)
    def visitLocal(self, node):
        """Mark a local variable as live when referenced.

        Args:
            node: Local variable node being referenced.
        """
        if self.flow._current is not None:
            self.flow.define(node, top)

    @dispatch(ast.GetGlobal, ast.SetGlobal)
    def visitGlobalOp(self, node):
        """Handle global variable operations.

        Args:
            node: Global variable operation node.
        """
        if self.flow._current is not None:
            self.flow.define(self.selfparam, top)
        node.visitChildren(self)

    @dispatch(list, tuple)
    def visitContainer(self, node):
        """Visit Python lists in AST.

        Handles raw Python lists that might appear in the AST structure
        (e.g., args and kwds in Call nodes).

        Args:
            node: List node

        Returns:
            None (lists are just containers, no side effects)
        """
        for item in node:
            self(item)

    @defaultdispatch
    def default(self, node):
        """Default handler for unhandled node types.

        Args:
            node: AST node to process.
        """
        node.visitChildren(self)


# AST node types that have no side effects and can be safely eliminated
nodesWithNoSideEffects = (
    ast.Existing,
    ast.Local,
    ast.Is,
    ast.Load,
    ast.Allocate,
    ast.BuildTuple,
    ast.BuildList,
    ast.BuildMap,
)


class MarkLive(TypeDispatcher):
    """Performs live variable analysis and marks code for elimination.

    This class implements the core dead code elimination logic by analyzing
    which variables are live and which statements can be safely removed.

    Attributes:
        code: Code object being analyzed.
        marker: MarkLocals instance for marking variable usage.
    """

    def __init__(self, code):
        """Initialize the live variable marker.

        Args:
            code: Code object to analyze for liveness.
        """
        self.code = code
        self.marker = MarkLocals()

    def hasNoSideEffects(self, node):
        """Check if a node has no side effects and can be eliminated.

        Args:
            node: AST node to check.

        Returns:
            bool: True if the node has no side effects.
        """
        if self.descriptive():
            return isinstance(node, (ast.Local, ast.Existing))
        else:
            return isinstance(
                node, nodesWithNoSideEffects
            ) or not tools.mightHaveSideEffect(node)

    def descriptive(self):
        """Check if we're in descriptive mode.

        Returns:
            bool: True if in descriptive mode.
        """
        return self.code.annotation.descriptive

    @dispatch(ast.Condition)
    def visitCondition(self, node):
        self.marker(node.conditional)
        return node

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        if self.hasNoSideEffects(node.expr):
            return []
        else:
            self.marker(node)
            return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        used = any([self.flow.lookup(lcl) is not undefined for lcl in node.lcls])
        if used:
            for lcl in node.lcls:
                self.flow.undefine(lcl)
            self.marker(node.expr)
            return node

        elif self.hasNoSideEffects(node.expr):
            return []
        else:
            node = ast.Discard(node.expr)
            node = self(node)
            return node

    @dispatch(ast.Delete)
    def visitDelete(self, node):
        self.flow.undefine(node.lcl)
        return node

    @defaultdispatch
    def default(self, node):
        if isinstance(node, ast.SimpleStatement):
            self.marker(node)
        return node

    @dispatch(ast.InputBlock)
    def visitInputBlock(self, node):
        inputs = []
        for input in node.inputs:
            if self.flow.lookup(input.lcl) is not undefined:
                inputs.append(input)
        return ast.InputBlock(inputs)

    @dispatch(ast.OutputBlock)
    def visitOutputBlock(self, node):
        for output in node.outputs:
            self.flow.define(output.expr, top)
        return node

    @dispatch(ast.Return)
    def visitReturn(self, node):
        for lcl in self.initialLive:
            self.flow.define(lcl, top)
        self.marker(node)
        return node

    def filterParam(self, p):
        """
        Filter unused parameters to DoNotCare.

        If a parameter is never used (not live), replaces it with DoNotCare
        to indicate it can be ignored. This enables call site optimizations.

        Args:
            p: Parameter to filter (may be None)

        Returns:
            Parameter if used, DoNotCare if unused, None if p was None
        """
        if p is None:
            return None
        elif self.flow.lookup(p) is undefined:
            # Parameter is unused, mark as DoNotCare
            return ast.DoNotCare()
        else:
            return p

    @dispatch(ast.CodeParameters)
    def visitCodeParameters(self, node):
        """
        Visit code parameters and filter unused ones.

        Replaces unused parameters with DoNotCare to enable optimizations
        at call sites. In descriptive mode, preserves all parameters to
        maintain behavioral information.

        Args:
            node: CodeParameters node to process

        Returns:
            CodeParameters with unused parameters replaced by DoNotCare
        """
        selfparam = self.filterParam(node.selfparam)

        if self.descriptive():
            params = node.params
            posonlyparams = node.posonlyparams
            vparam = node.vparam
            kparam = node.kparam
        else:
            params = [self.filterParam(p) for p in node.params]
            posonlyparams = [self.filterParam(p) for p in node.posonlyparams]
            vparam = self.filterParam(node.vparam)
            kparam = self.filterParam(node.kparam)

        return ast.CodeParameters(
            selfparam=selfparam,
            posonlyparams=posonlyparams,
            posonlynames=node.posonlynames,
            params=params,
            paramnames=node.paramnames,
            defaults=node.defaults,
            vparam=vparam,
            kparam=kparam,
            returnparams=node.returnparams,
            type_params=node.type_params,
        )


def evaluateCode(compiler, node, initialLive=None):
    """Evaluate code for dead code elimination.

    Performs live variable analysis and eliminates dead code from the given
    AST node.

    Args:
        compiler: Compiler context.
        node: AST node to analyze and optimize.
        initialLive: Set of initially live variables (optional).

    Returns:
        AST node with dead code eliminated.
    """
    rewrite = MarkLive(node)
    traverse = ReverseFlowTraverse(liveMeet, rewrite)

    # HACK: Set up flow analysis
    rewrite.flow = traverse.flow
    rewrite.marker.flow = traverse.flow
    rewrite.marker.selfparam = node.codeparameters.selfparam

    t = MutateCodeReversed(traverse)

    # Locals may be used as outputs.
    # We need to retain these locals.
    rewrite.initialLive = initialLive if initialLive != None else ()

    result = t(node)

    return result


def evaluate(compiler, prgm, outputAnchors=None):
    """Run DCE across all live code in a program."""
    with compiler.console.scope("dead code elimination"):
        changed = False
        for code in prgm.liveCode:
            if code.isStandardCode() and not code.annotation.descriptive:
                before = _snapshot_code(code)
                evaluateCode(compiler, code, outputAnchors)
                if _snapshot_code(code) != before:
                    changed = True
        return changed
