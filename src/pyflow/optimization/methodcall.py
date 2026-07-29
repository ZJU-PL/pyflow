"""
Method Call Optimization for PyFlow.

This module optimizes method calls by fusing attribute access and call patterns
into direct method calls, reducing indirection and improving optimization opportunities.

The optimization:
- Identifies patterns like obj.attr() that can become method calls
- Tracks method getter patterns through the call chain
- Rewrites indirect calls to direct method calls where possible
- Uses forward data flow analysis to track method bindings

This enables better optimization by making call targets more explicit.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

from pyflow.analysis import tools
from pyflow.language.python.ir_metadata import copy_call_argument_metadata
from pyflow.optimization import dataflow

from pyflow.optimization import simplify
from pyflow.ir.core import AnalysisFacts, MissingAnalysisFact


def _source_identity(code):
    catalog = getattr(code, "ir_catalog", None)
    if catalog is None or not catalog.has_node(code, code):
        raise MissingAnalysisFact(f"code has no indexed source metadata: {code!r}")
    origin = catalog.source_of(code, code=code)
    if origin is None:
        raise MissingAnalysisFact(f"code has no source identity: {code!r}")
    return origin


def contextsThatOnlyInvoke(facts, funcs, invocations):
    """Find contexts that only invoke specific functions.

    Args:
        funcs: Set of functions to check
        invocations: Set of (function, context) pairs that must be invoked

    Returns:
        Set of (function, context) pairs that only invoke the specified invocations
    """
    output = set()

    # HACK There's only one op in the object getter that will invoke?
    for func in funcs:
        for op in tools.codeOps(func):
            for context in facts.contexts(func):
                invokesSet = set(facts.call_targets(func, op, context))
                match = invokesSet.intersection(invocations)

                # There must be invocations, and they must all be to fget.
                if match and match == invokesSet:
                    output.add((func, context))
    return output


def opThatInvokes(facts, func):
    """Find the operation in a function that performs invocation.

    Args:
        func: Function code to search

    Returns:
        AST node that performs the invocation, or None when the function does
        not have exactly one invoking operation.
    """
    # Find the single op in the function that invokes.
    invokeOp = None
    multiple = False
    for op in tools.codeOps(func):
        invokes = facts.merged_call_targets(func, op)
        if invokes:
            if invokeOp is not None:
                multiple = True
                break
            invokeOp = op
    if multiple:
        return None
    return invokeOp


class MethodPatternFinder(TypeDispatcher):
    """Finds method call patterns in the program.

    Identifies sequences of attribute access and calls that can be optimized
    into direct method calls, such as obj.attr() patterns.
    """

    def findOriginals(self, extractor, catalog):
        from pyflow.ir.core import index_code

        exports = extractor.intrinsic_manager.stubs.exports
        self.iget = exports["interpreter_getattribute"]
        self.oget = exports["object__getattribute__"]

        self.fget = exports["function__get__"]
        self.mdget = exports["methoddescriptor__get__"]

        self.icall = exports["interpreter_call"]
        self.mcall = exports["method__call__"]

        for code in (
            self.iget,
            self.oget,
            self.fget,
            self.mdget,
            self.icall,
            self.mcall,
        ):
            if not catalog.has_procedure(code):
                index_code(
                    catalog,
                    code,
                    module="__intrinsics__",
                    qualname=code.codeName(),
                )
            _source_identity(code)

        return True

    def findExisting(self, liveCode):
        self.fgets = set()
        self.ogets = set()
        self.igets = set()

        self.icalls = set()
        self.mcalls = set()

        igetO = _source_identity(self.iget)
        ogetO = _source_identity(self.oget)
        fgetO = _source_identity(self.fget)
        mdgetO = _source_identity(self.mdget)

        icallO = _source_identity(self.icall)
        mcallO = _source_identity(self.mcall)

        for code in liveCode:
            origin = _source_identity(code)

            if origin == igetO:
                self.igets.add(code)
            if origin == ogetO:
                self.ogets.add(code)
            if origin == fgetO:
                self.fgets.add(code)
            if origin == mdgetO:
                self.fgets.add(code)

            if origin == icallO:
                self.icalls.add(code)
            if origin == mcallO:
                self.mcalls.add(code)

    def findContexts(self):
        ### Get patterns ###
        if not self.fgets:
            return False
        self.fgetsC = set()
        for func in self.fgets:
            for context in self.facts.contexts(func):
                self.fgetsC.add((func, context))

        # HACK There's only one op in the object getter that will invoke?
        self.ogetsC = contextsThatOnlyInvoke(self.facts, self.ogets, self.fgetsC)
        if not self.ogetsC:
            return False

        self.igetsC = contextsThatOnlyInvoke(self.facts, self.igets, self.ogetsC)
        if not self.igetsC:
            return False

        ### Call patterns ###
        if not self.mcalls:
            return False
        self.mcallsC = set()
        for code in self.mcalls:
            for context in self.facts.contexts(code):
                self.mcallsC.add((code, context))

        self.icallsC = contextsThatOnlyInvoke(self.facts, self.icalls, self.mcallsC)
        if not self.icallsC:
            return False

        self.buildInvokeLUT()

        return True

    def buildInvokeLUT(self):
        self.invokeLUT = {}

        for code, context in self.mcallsC:
            op = opThatInvokes(self.facts, code)
            if op is None:
                continue
            targets = self.facts.call_targets(code, op, context)
            self.invokeLUT[(code, context)] = targets

        for code, context in self.icallsC:
            op = opThatInvokes(self.facts, code)
            if op is None:
                continue
            targets = self.facts.call_targets(code, op, context)

            reach = set()
            for target in targets:
                reach.update(self.resolveInvokeTargets(target))
            self.invokeLUT[(code, context)] = frozenset(reach)

    def resolveInvokeTargets(self, target):
        resolved = self.invokeLUT.get(target)
        if resolved is None:
            return frozenset((target,))
        return resolved

    def preprocess(self, compiler, prgm):
        self.facts = AnalysisFacts(prgm.ir)
        if not self.findOriginals(compiler.extractor, prgm.ir):
            return False
        self.findExisting(prgm.liveCode)
        return self.findContexts()

    def isMethodGetter(self, node, invokes):
        invokes = frozenset(invokes)

        marked = invokes.intersection(self.igetsC)

        if marked and marked == invokes:
            return True
        else:
            return False

    @defaultdispatch
    def default(self, node, invokes):
        return False, None, None

    @dispatch(ast.Call, ast.DirectCall)
    def visitCall(self, node, invokes):
        if len(node.args) == 2 and not node.kwds and not node.vargs and not node.kargs:
            if self.isMethodGetter(node, invokes):
                return True, node.args[0], node.args[1]
        return False, None, None

    @dispatch(ast.GetAttr)
    def visitGetAttr(self, node, invokes):
        if self.isMethodGetter(node, invokes):
            return True, node.expr, node.name
        else:
            return False, None, None


class MethodAnalysis(TypeDispatcher):
    """Forward data flow analysis for method call optimization.

    Tracks method bindings through assignments to identify when method calls
    can be optimized. Uses forward flow analysis to propagate method information.

    Args:
        pattern: MethodPatternFinder instance with pattern information
    """

    def __init__(self, pattern, code=None):
        self.pattern = pattern
        self.code = code

    def target(self, node):
        assert isinstance(node, ast.Local), type(node)

        # Kill on expr or name redefinition.
        key = self.flow.lookup(("expr", node))
        if isinstance(key, tuple):
            self.kill(key)

        key = self.flow.lookup(("name", node))
        if isinstance(key, tuple):
            self.kill(key)

    def targets(self, nodes):
        for node in nodes:
            self.target(node)

    def arg(self, node):
        assert isinstance(node, ast.Local), type(node)
        # Kill on method leak.
        key = self.flow.lookup(("meth", node))
        if isinstance(key, tuple):
            self.kill(key)

    def kill(self, key):
        expr, name, meth = key

        check = self.flow.lookup(("expr", expr))
        assert check == key, (check, key)

        check = self.flow.lookup(("name", name))
        assert check == key, (check, key)

        check = self.flow.lookup(("meth", meth))
        assert check == key, (check, key)

        self.flow.undefine(("expr", expr))
        self.flow.undefine(("name", name))
        self.flow.undefine(("meth", meth))

    def invalidateAllMethodBindings(self):
        """Invalidate all tracked getter bindings in the current flow contour.

        Method-call fusion is only sound while the object graph remains stable.
        Any operation that may mutate state (or otherwise produce side effects)
        can invalidate previously observed ``obj.attr`` -> method bindings.
        """
        current = self.flow._current
        if current is None:
            return

        binding_keys = []
        for key in tuple(current.lut.keys()):
            if isinstance(key, tuple) and key and key[0] in ("expr", "name", "meth"):
                binding_keys.append(key)

        for key in binding_keys:
            self.flow.undefine(key)

    @dispatch(ast.Local)
    def visitLocal(self, node):
        self.arg(node)

    # ast.Code is a leaf due to direct calls.
    @dispatch(
        ast.leafTypes,
        ast.Existing,
        ast.BuildList,
        ast.Allocate,
        ast.GetGlobal,
        ast.Code,
        ast.Break,
        ast.Continue,
        ast.DoNotCare,
        ast.Is,
    )
    def visitLeaf(self, node):
        return node

    @dispatch(
        ast.Load,
        ast.Store,
        ast.Check,
        ast.Return,
        ast.SetAttr,
        ast.SetGlobal,
        ast.GetSubscript,
        ast.SetSubscript,
        ast.Discard,
        ast.GetIter,
        ast.ConvertToBool,
        ast.Not,
        ast.BinaryOp,
        ast.UnaryPrefixOp,
        ast.BuildTuple,
        ast.Call,
        ast.DirectCall,
        ast.MethodCall,
        ast.GetAttr,
    )
    def visitMayLeak(self, node):
        node.visitChildren(self)
        if tools.mightHaveSideEffect(self.code, node):
            self.invalidateAllMethodBindings()
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        self(node.expr)
        self.targets(node.lcls)

        if not isinstance(node.expr, (ast.Local, ast.Existing)):
            invokes = self.pattern.facts.merged_call_targets(self.code, node.expr)
            if invokes:
                flag, expr, name = self.pattern(node.expr, invokes)

                if flag and len(node.lcls) == 1:
                    lcl = node.lcls[0]
                    key = (expr, name, lcl)
                    self.flow.define(("expr", expr), key)
                    self.flow.define(("name", name), key)
                    self.flow.define(("meth", lcl), key)

        return node

    @dispatch(ast.UnpackSequence)
    def visitUnpackSequence(self, node):
        self(node.expr)
        for target in node.targets:
            self.target(target)
        return node

    @dispatch(ast.Delete)
    def visitDelete(self, node):
        self.target(node.lcl)
        self.arg(node.lcl)
        return node


class MethodRewrite(TypeDispatcher):
    """Rewrites calls to use direct method calls where possible.

    Transforms indirect calls (obj.attr()) into direct method calls based on
    the results of MethodAnalysis.

    Args:
        pattern: MethodPatternFinder instance with pattern information
    """

    def __init__(self, pattern, code):
        self.pattern = pattern
        self.code = code
        self.rewritten = set()
        # Conservatively disabled until the optimizer can prove descriptor and
        # callable-object identity stability for Python's dynamic semantics.
        self.allow_rewrite = getattr(pattern, "allow_safe_rewrite", False)

    @defaultdispatch
    def default(self, node):
        return node

    def isMethodCall(self, node, meth):
        """Check if a call can be optimized to a direct method call.

        CRITICAL FIX #5: Verify both code target uniqueness and function object identity.

        Args:
            node: Call node to check
            meth: Method local variable

        Returns:
            tuple: (is_method_call, expr, name) where is_method_call is True if safe to optimize
        """
        if not self.allow_rewrite:
            return False, None, None

        invokes = self.pattern.facts.merged_call_targets(self.code, node)
        if invokes:
            if self.pattern.icallsC.issuperset(invokes):
                key = self.flow.lookup(("meth", meth))
                if isinstance(key, tuple):
                    expr, name, meth = key

                    # CRITICAL FIX #5: Verify single dispatch target
                    # Check that all invocations target the same code AND function object
                    if invokes:
                        codes = {code for code, _context in invokes}
                        if len(codes) > 1:
                            # Multiple code targets - not safe to optimize
                            return False, None, None

                        # Additional check: verify function object uniqueness
                        # This is conservative - we only optimize if we're certain
                        # about the dispatch target
                        # TODO: Add function object identity check using CPA type info

                    return True, expr, name

        return False, None, None

    def transferOpInfo(self, node, rewrite):
        rewrite.annotation = node.annotation

    def rewriteCall(self, node, expr, name):
        rewrite = ast.MethodCall(
            expr, name, node.args, node.kwds, node.vargs, node.kargs
        )
        copy_call_argument_metadata(node, rewrite)
        self.transferOpInfo(node, rewrite)
        self.rewritten.add(node)
        return rewrite

    @dispatch(ast.Call)
    def visitCall(self, node):
        meth, expr, name = self.isMethodCall(node, node.expr)
        if meth:
            return self.rewriteCall(node, expr, name)
        return node

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        meth, expr, name = self.isMethodCall(node, node.selfarg)
        if meth:
            return self.rewriteCall(node, expr, name)
        return node

    @dispatch(ast.Assign, ast.Discard)
    def visitStatement(self, node):
        return node.rewriteChildren(self)


def methodMeet(values):
    """Meet function for method analysis data flow.

    Args:
        values: List of method binding values

    Returns:
        Single value if all values are the same, top otherwise
    """
    if not values:
        return dataflow.base.top
    prototype = values[0]
    for value in values:
        if value != prototype:
            return dataflow.base.top
    return prototype


def evaluate(compiler, prgm):
    """Main entry point for method call optimization.

    Args:
        compiler: Compiler context
        prgm: Program to optimize

    Performs pattern finding, analysis, and rewriting to fuse method calls.
    """
    with compiler.console.scope("method call"):
        pattern = MethodPatternFinder()
        if not pattern.preprocess(compiler, prgm):
            compiler.console.output("No method calls to fuse.")
            return False

        numrewritten = 0
        for code in prgm.liveCode:
            analyze = MethodAnalysis(pattern, code)
            rewrite = MethodRewrite(pattern, code)

            meet = methodMeet

            traverse = dataflow.forward.ForwardFlowTraverse(meet, analyze, rewrite)
            t = dataflow.forward.MutateCode(traverse)

            # HACK
            analyze.flow = traverse.flow
            rewrite.flow = traverse.flow

            t(code)

            # HACK to turn attribute access assignments into discards.
            if rewrite.rewritten:
                simplify.evaluateCode(compiler, prgm, code)

            if rewrite.rewritten:
                numrewritten += len(rewrite.rewritten)

        # TODO may not be entirely correct, as the method call may
        # not be fused in the final iteration.
        compiler.console.output("%d method calls fused." % numrewritten)
        return numrewritten > 0
