"""
Code Inlining Optimization for PyFlow.

This module implements function inlining, replacing function calls with the
function body at the call site to eliminate call overhead and enable further
optimizations.

The optimization:
- Analyzes functions to determine if they can be inlined
- Checks for constraints like returns in loops, variable arguments, etc.
- Inlines small, frequently-called functions
- Performs inlining in reverse postorder to handle dependencies correctly

This is a whole-program optimization that requires call graph information.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.language.python.default_markers import MISSING_DEFAULT

import pyflow.optimization.simplify as simplify

from pyflow.analysis.astcollector import getOps
from pyflow.ir.core import (
    AnalysisFacts,
    RebuildProvenanceSeed,
    rebuild_program_ir,
)


def _supports_inline_default_value(default_expr):
    pyobj = getattr(getattr(default_expr, "object", None), "pyobj", None)
    return isinstance(default_expr, ast.Existing) or pyobj is MISSING_DEFAULT


_EXPRESSION_CONTEXT = object()


class CodeInliningAnalysis(TypeDispatcher):
    """Determines the technical feasibility of inlining functions.

    Analyzes functions to check if they can be safely inlined, considering
    factors like control flow, variable arguments, and complexity.
    """

    def __init__(self, facts):
        self.facts = facts
        self.canInline = {}
        self.invokeCount = {}
        self.numOps = {}
        self.returnArity = {}

    @dispatch(
        ast.leafTypes,
        ast.Local,
        ast.Existing,
        ast.Code,
        ast.DoNotCare,
        ast.Break,
        ast.Continue,
        ast.CodeParameters,
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

    @dispatch(
        ast.Suite,
        ast.Condition,
        ast.Assign,
        ast.Discard,
        ast.TypeSwitchCase,
        ast.ExceptionHandler,
        ast.InputBlock,
        ast.OutputBlock,
        ast.Input,
        ast.Output,
        ast.AnnAssign,
        ast.Delete,
        ast.Assert,
        ast.Print,
        ast.EndFinally,
    )
    def visitOK(self, node):
        node.visitChildren(self)

    @dispatch(
        ast.Call,
        ast.DirectCall,
        ast.MethodCall,
        ast.Allocate,
        ast.Load,
        ast.Store,
        ast.Check,
    )
    def visitOp(self, node):
        node.visitChildren(self)
        self.ops += 1

        invokes = self.facts.merged_call_targets(self.code, node)
        if invokes:
            targets = {code for code, _context in invokes}

            # Increment the count of each target
            for code in targets:
                if code not in self.invokeCount:
                    self.invokeCount[code] = 1
                else:
                    self.invokeCount[code] += 1

        if self.terminal:
            # Op after return prevents inlining
            self.inlinable = False

    @dispatch(ast.Return)
    def visitReturn(self, node):
        node.visitChildren(self)
        arity = len(node.exprs)
        if self._return_arity is None:
            self._return_arity = arity
        elif self._return_arity != arity:
            self.inlinable = False

        if self.terminal:
            # Return after return
            self.inlinable = False
        elif self.level > 0:
            # No returns from inside loops/trys/etc.
            # They would require manually unwinding the stack if inlined.
            self.inlinable = False

        # No more ops after return
        self.terminal = True

    def processSwitch(self, cases):
        """Analyse a set of switch cases for terminal/inlinability.

        A switch is only terminal if every branch is terminal. Branch-local
        returns are also not safe for this inliner: lowering ``return`` to
        assignments only preserves semantics for tail returns.
        """
        original = self.terminal
        allterminal = True
        anyterminal = False

        for case in cases:
            self.terminal = original
            self(case)
            anyterminal = anyterminal or self.terminal
            allterminal = allterminal and self.terminal

        if anyterminal and not allterminal:
            self.inlinable = False

        # Restore the pre-switch terminal state, then apply the switch result.
        self.terminal = original or allterminal

    @dispatch(ast.Switch)
    def visitSwitch(self, node):
        self(node.condition)
        self.processSwitch((node.t, node.f))

    @dispatch(ast.TypeSwitch)
    def visitTypeSwitch(self, node):
        self(node.conditional)
        self.processSwitch(node.cases)

    @dispatch(ast.For, ast.AsyncFor, ast.While)
    def visitControlFlow(self, node):
        self.level += 1
        node.visitChildren(self)
        self.level -= 1

    @dispatch(ast.TryExceptFinally, ast.TryStar)
    def visitTry(self, node):
        # Exception handling in inlined callees is not supported; still traverse
        # children so invoke counts and op counts remain accurate.
        self.inlinable = False
        self.level += 1
        node.visitChildren(self)
        self.level -= 1

    @dispatch(
        ast.Yield,
        ast.YieldFrom,
        ast.AsyncYield,
        ast.Await,
        ast.Raise,
        ast.MakeFunction,
        ast.FunctionDef,
        ast.ClassDef,
        ast.GetCell,
        ast.GetCellDeref,
        ast.SetCellDeref,
        ast.Cell,
    )
    def visitUnsupportedForInlining(self, node):
        self.inlinable = False
        node.visitChildren(self)

    @defaultdispatch
    def visitOther(self, node):
        if isinstance(node, ast.PythonASTNode):
            node.visitChildren(self)
            if isinstance(node, (ast.Expression, ast.SimpleStatement)):
                self.ops += 1
                if self.terminal:
                    self.inlinable = False
            return
        return None

    def process(self, node):
        self.code = node
        self.level = 0
        self.ops = 0
        self._return_arity = None

        # Terminal indicates
        self.terminal = False

        # Initial value
        callee = node.codeParameters()
        self.inlinable = (
            node.isStandardCode()
            and not isinstance(callee.vparam, ast.Local)
            and not isinstance(callee.kparam, ast.Local)
            and not node.annotation.descriptive
        )

        if node.isStandardCode():
            self(node.ast)

        self.canInline[node] = self.inlinable
        self.numOps[node] = self.ops
        self.returnArity[node] = self._return_arity if self.terminal else None


class OpInliningTransform(TypeDispatcher):
    """Transforms code for inlining at a specific call site.

    Emulates calling convention assignments by cloning the code and translating
    the inlined contexts. Handles argument passing and return value handling.

    Args:
        analysis: CodeInliningAnalysis instance with feasibility information
    """

    def __init__(self, analysis, catalog, provenance_seeds):
        self.analysis = analysis
        self.catalog = catalog
        self.provenance_seeds = provenance_seeds

    def translateLocal(self, node):
        if not node in self.localMap:
            lcl = ast.Local(node.name)
            self.localMap[node] = lcl
            self.transferLocal(node, lcl)
        else:
            lcl = self.localMap[node]
        return lcl

    def transferAnalysisData(self, original, replacement):
        if not isinstance(original, ast.PythonASTNode):
            return
        if not isinstance(replacement, ast.PythonASTNode):
            return
        assert original is not replacement, original
        if (
            self.dst is None
            or self.originalNode is None
            or self.source_code is None
            or self.catalog is None
        ):
            return
        if hasattr(self.catalog, "has_node"):
            if not (
                self.catalog.has_node(self.originalNode, self.dst)
                and self.catalog.has_node(original, self.source_code)
            ):
                return
        call_id = self.catalog.node_id(self.originalNode, self.dst)
        source_id = self.catalog.node_id(original, self.source_code)
        self.provenance_seeds.append(
            RebuildProvenanceSeed(
                replacement,
                self.dst,
                self.catalog.source_of(source_id),
                (call_id, source_id),
                "inline",
            )
        )

    def transferLocal(self, original, replacement):
        assert original is not replacement, original

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        return node

    @dispatch(list, tuple)
    def visitContainer(self, node):
        items = []
        for child in node:
            rewritten = self(child)
            if isinstance(node, list) and isinstance(rewritten, list):
                items.extend(rewritten)
            else:
                items.append(rewritten)
        return tuple(items) if isinstance(node, tuple) else items

    @defaultdispatch
    def default(self, node):
        result = node.rewriteCloned(self)
        self.transferAnalysisData(node, result)
        return result

    @dispatch(ast.Local)
    def visitLocal(self, node):
        return self.translateLocal(node)

    @dispatch(ast.DoNotCare)
    def visitDoNotCare(self, node):
        return ast.DoNotCare()

    @dispatch(ast.Code)
    def visitCode(self, node):
        return node

    @dispatch(ast.Return)
    def visitReturn(self, node):
        if self.returnargs is not None:
            # Inlined into assignment
            assert len(self.returnargs) == len(node.exprs)
            assignments = [
                ast.Assign(self(src), [dst]) for src, dst in zip(node.exprs, self.returnargs)
            ]
            for assignment in assignments:
                self.transferAnalysisData(node, assignment)
            return assignments
        else:
            # Inlined into discard
            return []

    def process(self, dst, originalNode, code, selfarg, args, returnargs):
        self.localMap = {}

        self.dst = dst
        self.originalNode = originalNode
        self.source_code = code
        self.returnargs = returnargs
        outp = []

        p = code.codeparameters
        positional_params = list(p.posonlyparams) + list(p.params)

        # Do argument transfer
        if isinstance(p.selfparam, ast.Local):
            assignment = ast.Assign(selfarg, [self(p.selfparam)])
            self.transferAnalysisData(p.selfparam, assignment)
            outp.append(assignment)

        for arg, param in zip(args, positional_params):
            if isinstance(param, ast.Local):
                assignment = ast.Assign(arg, [self(param)])
                self.transferAnalysisData(param, assignment)
                outp.append(assignment)

        if len(args) < len(positional_params) and p.defaults:
            default_offset = len(positional_params) - len(p.defaults)
            start = max(len(args), default_offset)
            for index in range(start, len(positional_params)):
                param = positional_params[index]
                default_expr = p.defaults[index - default_offset]
                pyobj = getattr(getattr(default_expr, "object", None), "pyobj", None)
                if pyobj is MISSING_DEFAULT:
                    continue
                if isinstance(param, ast.Local):
                    assignment = ast.Assign(default_expr, [self(param)])
                    self.transferAnalysisData(param, assignment)
                    outp.append(assignment)

        assert not isinstance(p.vparam, ast.Local), p.vparam
        # assert len(args) == len(p.params), "TODO: default arguments."

        outp.append(self(code.ast))

        return outp


class CodeInliningTransform(TypeDispatcher):
    """Performs code inlining transformation.

    Performs depth-first traversal of call graph, inlining code in reverse
    postorder to handle dependencies correctly. Only inlines functions that
    meet size and call frequency criteria.

    Args:
        analysis: CodeInliningAnalysis instance
        compiler: Compiler context
        prgm: Program being optimized
        intrinsics: Intrinsic rewriter (for future use)
    """

    def __init__(self, analysis, compiler, prgm, intrinsics):
        self.analysis = analysis
        self.compiler = compiler
        self.prgm = prgm
        self.intrinsics = intrinsics
        self.facts = AnalysisFacts(prgm.ir)
        self.provenance_seeds = []
        self.opinline = OpInliningTransform(analysis, prgm.ir, self.provenance_seeds)
        self.processed = set()
        self.trace = set()

        self.maxInvokes = 1
        self.maxOps = 4
        self.exhaustive = True
        self.preserveContexts = not self.exhaustive
        self.changed = False

    # May contain inlinable nodes
    @dispatch(
        ast.Suite,
        ast.Condition,
        ast.Switch,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.TypeSwitch,
        ast.TypeSwitchCase,
        ast.TryExceptFinally,
        ast.TryStar,
        ast.ExceptionHandler,
    )
    def visitOK(self, node, returnargs=_EXPRESSION_CONTEXT):
        before = self.modified
        rewritten = node.rewriteChildren(self)
        return rewritten if self.modified != before else node

    @dispatch(list, tuple)
    def visitContainer(self, node, returnargs=_EXPRESSION_CONTEXT):
        items = []
        changed = False
        for child in node:
            rewritten = self(child)
            if isinstance(node, list) and isinstance(rewritten, list):
                items.extend(rewritten)
                changed = True
            else:
                if rewritten is not child:
                    changed = True
                items.append(rewritten)
        if not changed:
            return node
        return tuple(items) if isinstance(node, tuple) else items

    # Contains no inlinable nodes
    @dispatch(
        ast.leafTypes,
        ast.Load,
        ast.Store,
        ast.Check,
        ast.Allocate,
        ast.Local,
        ast.Existing,
        ast.Code,
        ast.DoNotCare,
        ast.Break,
        ast.Continue,
        ast.CodeParameters,
        ast.GlobalDecl,
        ast.NonlocalDecl,
        ast.TypeParam,
        ast.TypeParams,
        ast.TypeAlias,
    )
    def visitInlineLeaf(self, node, returnargs=_EXPRESSION_CONTEXT):
        return node

    @defaultdispatch
    def visitOther(self, node, returnargs=_EXPRESSION_CONTEXT):
        if isinstance(node, ast.PythonASTNode):
            node.visitChildren(self)
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node, returnargs=_EXPRESSION_CONTEXT):
        result = self(node.expr, node.lcls)
        return result if isinstance(result, list) else node

    @dispatch(ast.Discard)
    def visitDiscard(self, node, returnargs=_EXPRESSION_CONTEXT):
        result = self(node.expr, None)
        return result if isinstance(result, list) else node

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node, returnargs=_EXPRESSION_CONTEXT):
        self.processInvocations(node)

        if (
            returnargs is not _EXPRESSION_CONTEXT
            and not node.kargs
            and not node.vargs
            and not node.kwds
        ):
            inlined = self.tryInline(node, node.selfarg, node.args, returnargs)
            if inlined is not None:
                return inlined
        node.visitChildren(self)
        return node

    @dispatch(ast.Call)
    def visitCall(self, node, returnargs=_EXPRESSION_CONTEXT):
        self.processInvocations(node)

        if (
            returnargs is not _EXPRESSION_CONTEXT
            and not node.kargs
            and not node.vargs
            and not node.kwds
        ):
            inlined = self.tryInline(node, node.expr, node.args, returnargs)
            if inlined is not None:
                return inlined
        node.visitChildren(self)
        return node

    @dispatch(ast.MethodCall)
    def visitMethodCall(self, node, returnargs=_EXPRESSION_CONTEXT):
        self.processInvocations(node)

        # TODO inline method calls?  This may require a bit of effort,
        # primarily in finding the correct value(s) for selfarg...
        node.visitChildren(self)
        return node

    def tryInline(self, node, selfarg, args, returnargs):
        # Don't inline anything into descriptive stubs
        if self.code.annotation.descriptive:
            return None

        # Do we have invocation information?
        caller_contexts = self.facts.contexts(self.code)
        allCode = None
        for caller_context in caller_contexts:
            invs = self.facts.call_targets(self.code, node, caller_context)
            if len(invs) == 0:
                continue
            elif len(invs) == 1:
                code, _context = next(iter(invs))

                # Must only invoke one code
                if allCode is None:
                    # It must be possible to inline the code
                    if not self.analysis.canInline.get(code, False):
                        return None
                    allCode = code
                elif allCode != code:
                    return None

            else:
                # Don't merge contexts, as precision will be lost?
                if self.preserveContexts:
                    return None

                for code, _context in invs:
                    if allCode is None:
                        # It must be possible to inline the code
                        if not self.analysis.canInline.get(code, False):
                            return None
                        allCode = code
                    elif allCode != code:
                        return None

        # No invocation
        if allCode is None:
            return None

        # Prevent recursive inlining
        if allCode in self.trace:
            return None

        # Only one calling point, or it's a small function
        tooManyInvokes = self.analysis.invokeCount.get(allCode, 0) > self.maxInvokes
        tooManyOps = self.analysis.numOps.get(allCode, 0) > self.maxOps

        if not self.exhaustive and tooManyInvokes and tooManyOps:
            return None

        p = allCode.codeparameters
        if isinstance(p.selfparam, ast.Local) and selfarg is None:
            return None

        positional_params = list(p.posonlyparams) + list(p.params)
        if len(args) > len(positional_params):
            return None
        num_defaults = len(p.defaults) if p.defaults else 0
        if len(args) < len(positional_params) - num_defaults:
            return None
        if len(args) < len(positional_params) and p.defaults:
            default_offset = len(positional_params) - len(p.defaults)
            start = max(len(args), default_offset)
            for index in range(start, len(positional_params)):
                default_expr = p.defaults[index - default_offset]
                if not _supports_inline_default_value(default_expr):
                    return None

        if returnargs is not None:
            expected_arity = self.analysis.returnArity.get(allCode)
            if expected_arity is None or expected_arity != len(returnargs):
                return None

        # Prevent the inlining of potential intrinsics.
        if self.intrinsics(None, node) is not None:
            return None

        result = self.opinline.process(self.code, node, allCode, selfarg, args, returnargs)

        self.analysis.numOps[self.code] = (
            self.analysis.numOps.get(self.code, 0) - 1 + self.analysis.numOps.get(allCode, 0)
        )

        self.modified = True

        return result

    def processInvocations(self, node):
        invokes = self.facts.merged_call_targets(self.code, node)
        if invokes:
            old = self.code
            oldM = self.modified
            for code, _context in invokes:
                self.process(code)
            self.code = old
            self.modified = oldM

    def process(self, node):
        if node not in self.processed:
            assert node.isCode(), type(node)

            self.processed.add(node)
            self.trace.add(node)
            self.modified = False
            self.code = node

            if node.isStandardCode():
                result = self(node.ast)
                if self.modified:
                    node.ast = result
                    self.changed = True
            else:
                ops, lcls = getOps(node)
                for op in ops:
                    self.processInvocations(op)

            self.code = None
            self.trace.remove(node)


def evaluate(compiler, prgm):
    """Main entry point for code inlining optimization.

    CRITICAL FIX #6: This pass is EXPERIMENTAL and has known limitations.
    It should only be used with the --experimental-inlining flag and with
    full understanding of the risks.

    Known Limitations:
    - Complex calling conventions (default args, *args, **kwargs)
    - Descriptor protocol interactions
    - Closure semantics
    - Exception handling in inlined code
    - Recursive functions

    Args:
        compiler: Compiler context
        prgm: Program to optimize

    Returns:
        bool: True if any inlining was performed

    Raises:
        RuntimeError: If inlining encounters unsupported patterns
    """
    with compiler.console.scope("code inlining"):
        compiler.console.output(
            "WARNING: Code inlining is experimental and may produce incorrect results. "
            "Use with caution and verify output."
        )

        facts = AnalysisFacts(prgm.ir)
        analysis = CodeInliningAnalysis(facts)
        for code in prgm.liveCode:
            analysis.process(code)

        # Create a simple no-op intrinsic rewriter
        class NoOpIntrinsicRewriter:
            def __call__(self, strategy, node):
                return None

        intrinsics = NoOpIntrinsicRewriter()

        transform = CodeInliningTransform(analysis, compiler, prgm, intrinsics)

        for code in prgm.interface.entryCode():
            try:
                transform.process(code)
            except Exception as e:
                compiler.console.output("Failed to transform %r" % code)
                raise RuntimeError(
                    f"Code inlining failed on {code}. This is a known limitation. "
                    f"Consider disabling inlining for this code."
                ) from e

        if transform.changed:
            rebuild_program_ir(
                prgm,
                provenance_seeds=transform.provenance_seeds,
            )
        return transform.changed
