"""
Argument Normalization Optimization for PyFlow.

This module normalizes function arguments by eliminating *args (variable
positional arguments) when their length is statically known.

The optimization:
- Analyzes functions with *args to determine if length is constant
- Checks if *args is used in ways that allow normalization
- Transforms *args into explicit positional parameters when existing callers
  already match the specialized positional arity

This enables better optimization by making argument passing explicit.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.analysis.tools import codeOps
from pyflow.ir.core import AnalysisFacts


class _ContainsLocalRef(TypeDispatcher):
    """Identity-based local reference finder.

    CRITICAL FIX #3: Enhanced to detect closure capture and other unsafe references.
    """

    def __init__(self, target):
        self.target = target
        self.found = False
        self.in_closure = False
        self.found_in_closure = False

    @dispatch(ast.Local)
    def visitLocal(self, node):
        if node is self.target:
            self.found = True
            if self.in_closure:
                self.found_in_closure = True

    @dispatch(list, tuple)
    def visitContainer(self, node):
        if self.found:
            return
        for child in node:
            self(child)

    @dispatch(ast.Code)
    def visitCode(self, node):
        """Check if target is captured by nested function (closure)."""
        # If we encounter a nested Code node, check if target is in its free variables
        if self.found:
            return
        # Mark that we're inside a nested function
        old_in_closure = self.in_closure
        self.in_closure = True
        node.visitChildren(self)
        self.in_closure = old_in_closure

    @defaultdispatch
    def visitDefault(self, node):
        if self.found:
            return
        node.visitChildren(self)


class ArgumentNormalizationAnalysis(TypeDispatcher):
    """Analyzes whether argument normalization is applicable.

    Checks if a function's *args parameter can be normalized into explicit
    positional parameters by verifying the length is constant and usage
    patterns allow transformation.

    Args:
        storeGraph: Store graph for analyzing object relationships
    """

    def __init__(self, storeGraph, facts):
        TypeDispatcher.__init__(self)
        self.storeGraph = storeGraph
        self.facts = facts
        self.applicable = True
        self.vparam = None

    @dispatch(ast.Local)
    def visitLocal(self, node):
        if node is self.vparam:
            self.applicable = False

    @dispatch(ast.Call, ast.MethodCall)
    def visitCall(self, node):
        if self.applicable:
            self(node.expr)
            self(node.args)
            self(node.kwds)

            if node.vargs is self.vparam:
                self.applicable = False

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        if self.applicable:
            self(node.selfarg)
            self(node.args)
            self(node.kwds)

            if node.vargs is self.vparam:
                self.applicable = False

    @dispatch(list, tuple)
    def visitContainer(self, node):
        for child in node:
            self(child)

    @dispatch(ast.leafTypes, ast.Existing)
    def visitLeaf(self, node):
        pass

    @defaultdispatch
    def visitDefault(self, node):
        if self.applicable:
            node.visitChildren(self)

    def process(self, node):
        """
        Analyze a code node to determine if argument normalization is applicable.

        Checks if the function's *args parameter can be normalized by:
        1. Verifying it's standard code (not a stub)
        2. Checking if *args length is constant
        3. Ensuring *args is not used in ways that prevent normalization
           (e.g., passed as *args to another function, used in loops)

        Args:
            node: Code node to analyze

        Returns:
            tuple: (applicable, vparam_length)
                   - applicable: True if normalization can be applied
                   - vparam_length: Length of *args if constant, 0 otherwise
        """
        if not node.isStandardCode():
            return False, 0

        if node.annotation.descriptive:
            return False, 0

        p = node.codeparameters
        if p.vparam:
            refs = self.facts.merged_references(node, p.vparam)

            lengths = set()
            for ref in refs:
                length = ref.knownField(self.storeGraph.lengthSlotName)
                for obj in length:
                    obj = obj.xtype
                    if not obj.isExisting():
                        return False, 0
                    obj = obj.obj
                    if not obj.isConstant():
                        return False, 0
                    lengths.add(obj.pyobj)

            # We don't "partially" optimize variable length vparams
            # as this would require rewriting the heap.
            if len(lengths) != 1:
                return False, 0

            vparamLen = lengths.pop()

            self.applicable = True
            self.vparam = p.vparam
            self(node.ast)
            return self.applicable, vparamLen
        else:
            return False, 0


class ArgumentNormalizationTransform(TypeDispatcher):
    """Transforms code to normalize arguments.

    Replaces *args with explicit positional parameters when existing call
    sites are already positionally compatible.

    Args:
        storeGraph: Store graph for analyzing object relationships
    """

    def __init__(self, storeGraph):
        self.storeGraph = storeGraph
        self.last_skip_reason = None

    @defaultdispatch
    def visitDefault(self, node):
        return node.rewriteChildren(self)

    @dispatch(list, tuple)
    def visitContainer(self, node):
        items = [self(child) for child in node]
        if isinstance(node, tuple):
            return tuple(items)
        return items

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        return node

    @dispatch(ast.Call)
    def visitCall(self, node):
        if node.vargs is self.vparam:
            expr = self(node.expr)
            args = self.extend(self(node.args), self.newParams)
            kwds = self(node.kwds)
            kargs = self(node.kargs)
            result = ast.Call(expr, args, kwds, None, kargs)

            result.annotation = node.annotation
            return result
        else:
            return node.rewriteChildren(self)

    @dispatch(ast.MethodCall)
    def visitMethodCall(self, node):
        if node.vargs is self.vparam:
            expr = self(node.expr)
            args = self.extend(self(node.args), self.newParams)
            kwds = self(node.kwds)
            kargs = self(node.kargs)
            result = ast.MethodCall(expr, node.name, args, kwds, None, kargs)

            result.annotation = node.annotation
            return result
        else:
            return node.rewriteChildren(self)

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        if node.vargs is self.vparam:
            selfarg = self(node.selfarg)
            args = self.extend(self(node.args), self.newParams)
            kwds = self(node.kwds)
            kargs = self(node.kargs)
            result = ast.DirectCall(node.code, selfarg, args, kwds, None, kargs)

            result.annotation = node.annotation
            return result

        else:
            return node.rewriteChildren(self)

    def extend(self, old, new):
        return list(old) + new

    # Generic heap.field -> local transfer
    # TODO refactor into library?
    def process(self, node, vparamLen):
        self.last_skip_reason = None
        p = node.codeparameters

        self.code = node
        self.vparam = p.vparam

        # Conservative safety gate: if the variadic parameter is still referenced
        # directly in the body, skipping normalization avoids stale local metadata.
        finder = _ContainsLocalRef(self.vparam)
        finder(node.ast)
        if finder.found_in_closure:
            self.last_skip_reason = "closure_capture"
            return False

        self.newParams = [ast.Local(None) for i in range(vparamLen)]
        self.newNames = [None for i in range(vparamLen)]

        if vparamLen > 0:
            # Defaults are never used
            defaults = ()
        else:
            # Number of arguments unchanged, defaults may be used, do nothing
            defaults = p.defaults

        selfparam = p.selfparam
        parameters = self.extend(p.params, self.newParams)
        parameternames = self.extend(p.paramnames, self.newNames)
        vparam = None
        kparam = p.kparam
        returnparams = p.returnparams

        node.codeparameters = ast.CodeParameters(
            selfparam=selfparam,
            posonlyparams=p.posonlyparams,
            posonlynames=p.posonlynames,
            params=parameters,
            paramnames=parameternames,
            defaults=defaults,
            vparam=vparam,
            kparam=kparam,
            returnparams=returnparams,
            type_params=p.type_params,
        )
        node.ast = self(node.ast)
        return True


def _iter_incoming_call_sites(prgm, facts, target_code):
    for code in prgm.liveCode:
        for op in codeOps(code):
            invokes = facts.merged_call_targets(code, op)
            if not invokes:
                continue

            targets = {func for func, _context in invokes}
            if target_code in targets:
                yield code, op, targets


def _expected_positional_arity(code, vparam_len):
    params = code.codeparameters
    return len(params.posonlyparams) + len(params.params) + vparam_len


def _normalization_blocker(prgm, facts, code, vparam_len):
    """Check if argument normalization is safe for this code object.

    CRITICAL FIX #3: Enhanced safety checks for Python semantic hazards.

    Returns:
        str or None: Reason for blocking normalization, or None if safe
    """
    codeparameters = getattr(code, "codeparameters", None)
    if codeparameters is None:
        return "missing_codeparameters"

    # Check if this is an entry point (cannot normalize entry points)
    interface = getattr(prgm, "interface", None)
    if interface is not None:
        entry_code = getattr(interface, "entryCode", None)
        if callable(entry_code):
            if any(entry is code for entry in entry_code()):
                return "entry_point"

    # CRITICAL FIX #3: Check for closure capture
    # If *args is captured by a nested function, normalization changes closure semantics
    vparam = codeparameters.vparam
    if vparam is not None:
        code_ast = getattr(code, "ast", None)
        if code_ast is None:
            return "missing_ast"
        checker = _ContainsLocalRef(vparam)
        checker(code_ast)
        if checker.found_in_closure:
            return "closure_capture"

    # CRITICAL FIX #3: Check for descriptor protocol interactions
    # If this is a method (has selfparam), normalization may break descriptor binding
    if codeparameters.selfparam is not None:
        # Conservative: block normalization for methods
        # A more precise check would verify descriptor protocol usage
        return "method_descriptor_risk"

    # Check all incoming call sites for compatibility
    for _caller, op, targets in _iter_incoming_call_sites(prgm, facts, code):
        if not isinstance(op, (ast.Call, ast.DirectCall, ast.MethodCall)):
            return "unsupported_caller_shape"
        if targets != {code}:
            return "polymorphic_callsite"
        if op.vargs is not None or op.kargs is not None or op.kwds:
            return "unsupported_call_convention"
        expected_arity = _expected_positional_arity(code, vparam_len)
        if len(op.args) != expected_arity:
            return "arity_mismatch"

    return None


def evaluate(compiler, prgm):
    """Main entry point for argument normalization.

    Args:
        compiler: Compiler context
        prgm: Program to optimize

    Analyzes functions and transforms those where normalization is applicable.
    """
    with compiler.console.scope("argument normalization"):
        facts = AnalysisFacts(prgm.ir)
        analysis = ArgumentNormalizationAnalysis(prgm.storeGraph, facts)
        transform = ArgumentNormalizationTransform(prgm.storeGraph)
        changed = False
        safety_blocked = 0

        for code in prgm.liveCode:
            applicable, vparamLen = analysis.process(code)
            if applicable:
                blocker = _normalization_blocker(prgm, facts, code, vparamLen)
                if blocker is not None:
                    safety_blocked += 1
                    continue

                transformed = bool(transform.process(code, vparamLen))
                changed = transformed or changed
                if not transformed and transform.last_skip_reason is not None:
                    safety_blocked += 1

        if safety_blocked:
            compiler.console.output(
                f"Argument normalization skipped for {safety_blocked} code objects due to safety guards."
            )

        return changed
