"""
Forward data flow analysis framework.

This module provides infrastructure for forward data flow analysis, where
information flows from program entry toward exit. Forward analysis is used
for optimizations like:
- Constant propagation: Track constant values as they flow through assignments
- Reaching definitions: Track which definitions reach each use
- Method binding: Track which methods are bound at each point

The framework handles:
- Control flow structures (loops, conditionals, switches)
- Exception handling (try/except blocks)
- Merging information at control flow merge points
"""

from . import base
from .base import meet
from pyflow.util.typedispatch import TypeDispatcher, dispatch
from pyflow.language.python import ast

from pyflow.language.python.fold import existingConstant
from pyflow.ir.core import MissingAnalysisFact


class ForwardFlowTraverse(TypeDispatcher):
    """
    Traverser for forward data flow analysis.

    This class implements forward data flow analysis by traversing the AST
    in forward order (top to bottom, left to right) and applying analysis
    and rewrite strategies. It manages flow-sensitive information using a
    FlowDict and handles control flow structures.

    The traverser:
    1. Processes expressions and applies rewrite transformations
    2. Updates flow information based on analysis results
    3. Handles control flow (conditionals, loops, switches)
    4. Manages exception handling (try/except)
    5. Merges information at control flow merge points

    Attributes:
        analyze: Analysis strategy that updates flow information
        rewrite: Rewrite strategy that transforms nodes
        flow: FlowDict for tracking flow-sensitive information
        tryLevel: Nesting level of try blocks
        mayRaise: MayRaise dispatcher for exception analysis
        meetF: Meet function for combining information from paths
    """

    __slots__ = (
        "analyze",
        "rewrite",
        "flow",
        "tryLevel",
        "mayRaise",
        "meetF",
        "maxLoopIterations",
    )

    def __init__(self, meetF, analyze, rewrite):
        """
        Initialize forward flow traverser.

        Args:
            meetF: Meet function for combining values from multiple paths
            analyze: Analysis strategy (updates flow information)
            rewrite: Rewrite strategy (transforms AST nodes)
        """
        self.analyze = analyze
        self.rewrite = rewrite
        self.flow = base.FlowDict()
        self.tryLevel = 0

        self.mayRaise = base.MayRaise()

        self.meetF = meetF
        # Safety guard: prevents pathological loops in abstract interpretation
        # from causing non-terminating optimization passes.
        self.maxLoopIterations = 128

    # TODO expose CodeParameters to the strategies?
    @dispatch(str, type(None), ast.CodeParameters)
    def visitLeaf(self, node):
        return node

    def recordFactSource(self, original, replacement):
        """Tell a rewrite strategy which analyzed node a fresh node replaces."""
        recorder = getattr(self.rewrite, "recordFactSource", None)
        if recorder is not None:
            recorder(original, replacement)
        return replacement

    def processExpr(self, node, fact_source=None):
        if fact_source is not None and node is not fact_source:
            self.recordFactSource(fact_source, node)
        node = self.rewrite(node)

        # Assuming exception handing only cares about locals, save the state before the assign.
        # TODO make sound for heap modificaions/interprocedural?
        if self.flow.tryLevel > 0 and self.mayRaise(node):
            normal, exceptional = self.flow.popSplit()
            self.flow.restore(exceptional)
            self.flow.save("raise")
            self.flow.restore(normal)

        self.analyze(node)
        return node

    # HACK to verify types.
    @dispatch(
        ast.Assign,
        ast.Discard,
        # ast.ConvertToBool,
        ast.Local,
        ast.Cell,
        ast.UnpackSequence,
        ast.SetAttr,
        ast.Store,
        ast.Print,
        ast.SetSubscript,
        ast.Delete,
        ast.SetSlice,
        ast.DeleteAttr,
        ast.SetGlobal,
        ast.DeleteGlobal,
        ast.DeleteSlice,
        ast.DeleteSubscript,
        ast.SetCellDeref,
        ast.Assert,
        ast.BuildList,
        ast.BuildTuple,
        ast.BuildMap,
        ast.BuildSlice,
    )
    def visitOK(self, node):
        return self.processExpr(node)

    @dispatch(ast.ExceptionHandler)
    def visitFlow(self, node):
        return node.rewriteChildren(self)

    @dispatch(list, tuple)
    def visitContainer(self, node):
        items = [self(child) for child in node]
        if isinstance(node, tuple):
            return tuple(items)
        return items

    def visitKwds(self, kwds):
        output = []
        for item in kwds:
            if isinstance(item, tuple) and len(item) == 2:
                name, value = item
                output.append((name, self(value)))
            else:
                output.append(self(item))
        return output

    def processShortCircuit(self, node, short_circuit_on_true):
        newterms = []
        exits = []
        current = self.flow.pop()

        if not node.terms:
            self.flow.restore(current)
            return node

        for index, term in enumerate(node.terms):
            if current is None:
                break

            self.flow.restore(current)
            newterm = self(term)
            current = self.flow.pop()
            newterms.append(newterm)

            if current is None:
                break

            is_last = index == len(node.terms) - 1
            constant = existingConstant(newterm)
            if is_last:
                exits.append(current)
                current = None
                break

            if constant:
                value = bool(newterm.object.pyobj)
                if value == short_circuit_on_true:
                    exits.append(current)
                    current = None
                    break
            else:
                exits.append(current)
                current = current.split()

        merged, changed = meet(self.meetF, *exits)
        self.flow.restore(merged)
        result = type(node)(newterms)
        result.annotation = node.annotation
        return result

    @dispatch(ast.Suite)
    def visitSuite(self, node):
        newblocks = []
        for block in node.blocks:
            newblocks.append(self(block))
            if not self.flow._current:
                # Folding control structures can kill subsequent blocks.
                break

        if newblocks != node.blocks:
            return ast.Suite(newblocks)
        else:
            return node

    @dispatch(ast.Condition)
    def visitCondition(self, node):
        return ast.Condition(self(node.preamble), self.processExpr(node.conditional))

    @dispatch(ast.Switch)
    def visitSwitch(self, node):
        condition = self(node.condition)

        # Can the switch be constant folded?
        # Done inside dataflow analysis, as it can
        # greatly improve precision

        cond = condition.conditional
        if existingConstant(cond):
            value = cond.object.pyobj
            taken = node.t if value else node.f
            # Note: condtion.conditional is killed, as
            # it is assumed to be a reference.
            return ast.Suite([condition.preamble, self(taken)])

        # Split
        tf, ff = self.flow.popSplit()

        self.flow.restore(tf)
        t = self(node.t)
        tf = self.flow.pop()

        self.flow.restore(ff)
        f = self(node.f)
        ff = self.flow.pop()

        # Merge
        merged, changed = meet(self.meetF, tf, ff)
        self.flow.restore(merged)

        result = ast.Switch(condition, t, f)

        return result

    def simplifyTypeSwitch(self, node):
        cases = node.cases
        changed = False
        code = getattr(self.rewrite, "code", None) or getattr(self.analyze, "code", None)
        facts = getattr(self.rewrite, "facts", None)
        if facts is None:
            facts = getattr(getattr(self.analyze, "pattern", None), "facts", None)
        try:
            refs = facts.merged_references(code, node.conditional) if facts else None
        except MissingAnalysisFact:
            refs = None

        # Filter out types and cases that are dead.
        # Requires knowing what node.conditional may point to.
        if refs is not None:
            reftypes = frozenset(ref.xtype.obj.type for ref in refs)

            newcases = []
            for case in cases:
                # Filter out the existing nodes that point to types
                # that are not pointed to by the conditional.
                newtypes = [e for e in case.types if e.object in reftypes]
                if len(newtypes) == len(case.types):
                    newcases.append(case)
                else:
                    changed = True
                    if len(newtypes) > 0:
                        # Some, but not all of the types have been eliminated.
                        newcases.append(
                            ast.TypeSwitchCase(newtypes, case.expr, case.body)
                        )
            cases = newcases

        # Filter out degenerate forms (less than 2 cases)
        count = len(cases)
        if count == 0:
            # Null op
            return ast.Suite([])
        elif count == 1:
            # One case, no need for a type switch
            case = cases[0]
            statements = []
            if case.expr is not None:
                statements.append(ast.Assign(node.conditional, [case.expr]))
            statements.append(case.body)
            return ast.Suite(statements)
        elif changed:
            # Types or cases have been filtered out, but it's still a type switch.
            return ast.TypeSwitch(node.conditional, cases)
        else:
            # No simplifications can be applied.
            return node

    @dispatch(ast.TypeSwitch)
    def visitTypeSwitch(self, node):
        # Try to simplify the type switch, first.
        node = self.simplifyTypeSwitch(node)
        if not isinstance(node, ast.TypeSwitch):
            return self(node)

        conditional = self.processExpr(node.conditional)
        cases = node.cases
        count = len(cases)
        newcases = []
        newframes = []

        frames = self.flow.popSplit(count)
        for case, frame in zip(cases, frames):
            self.flow.restore(frame)

            # HACK the analysis doesn't know about the conditional -> expr transfer.
            newcases.append(ast.TypeSwitchCase(case.types, case.expr, self(case.body)))
            newframes.append(self.flow.pop())

        merged, changed = meet(self.meetF, *newframes)
        self.flow.restore(merged)

        return ast.TypeSwitch(conditional, newcases)

    @dispatch(ast.While)
    def visitWhile(self, node):
        conditionEntry = self.flow.pop()
        if conditionEntry is None:
            return ast.While(node.condition, node.body, node.else_)

        originalbags = self.flow.saveBags()
        iterations = 0
        condition = node.condition
        body = node.body
        conditionExit = conditionEntry
        b = None
        loopbags = {}

        # Iterate until convergence
        while 1:
            iterations += 1
            if conditionEntry is None:
                break
            self.flow.restore(conditionEntry.split())

            condition = self(node.condition)
            conditionExit, bodyEntry = self.flow.popSplit()

            self.flow.restore(bodyEntry)
            body = self(node.body)

            # Construct the state at loop exit
            self.flow.save("continue")
            self.flow.mergeCurrent(self.meetF, "continue")

            if self.flow._current:
                bodyExit = self.flow.pop()

                # Has a fixed point been reached for loop exit?
                # Check merge(current, "normal exit") == current

                conditionEntry, changed = meet(self.meetF, conditionEntry, bodyExit)
                shouldTerminate = not changed
            else:
                # Degenerate loop.
                # Leave current alone, as the loop may not be taken.
                shouldTerminate = True

            if shouldTerminate:
                # Construct the state at loop break
                self.flow.mergeCurrent(self.meetF, "break")
                b = self.flow.pop()

                # Save the exceptional flow
                loopbags = self.flow.saveBags()
                assert "continue" not in loopbags
                assert "break" not in loopbags

                break
            else:
                if iterations >= self.maxLoopIterations:
                    # Conservative bailout if fixpoint does not converge quickly.
                    self.flow.mergeCurrent(self.meetF, "break")
                    b = self.flow.pop()
                    loopbags = self.flow.saveBags()
                    break
                # Clears the bags
                self.flow.saveBags()

        # Merge in newly create bages (raise, return, etc.)
        self.flow.restoreAndMergeBags(originalbags, loopbags)

        # TODO If loop must be taken, do not merge in current.
        # Use "c" instead.
        out = conditionExit

        # Evaluate else.
        if out:
            self.flow.restore(out)
            else_ = self(node.else_)
            out = self.flow.pop()
        else:
            # Else never taken.
            else_ = ast.Suite([])

        # Merge in breaks
        out, changed = meet(self.meetF, out, b)
        self.flow.restore(out)

        result = ast.While(condition, body, else_)

        return result

    @dispatch(ast.For)
    def visitFor(self, node):
        loopPreamble = self(node.loopPreamble)
        iterator = self(node.iterator)
        # index = self(node.index)

        originalbags = self.flow.saveBags()
        current = self.flow.pop()
        if current is None:
            return ast.For(
                iterator,
                node.index,
                loopPreamble,
                node.bodyPreamble,
                node.body,
                node.else_,
            )
        iterations = 0
        bodyPreamble = node.bodyPreamble
        index = node.index
        body = node.body
        b = None
        loopbags = {}

        # Iterate until convergence
        while 1:
            iterations += 1
            if current is None:
                break
            self.flow.restore(current.split())

            # TODO Need to invalidate index every iteration.
            # Really, we're evaluating index = next(iterator)

            # HACK
            # self.flow.undefine(node.index)
            # index = node.index

            bodyPreamble = self(node.bodyPreamble)
            index = self(node.index)

            body = self(node.body)

            # Construct the state at loop exit
            self.flow.save("continue")
            self.flow.mergeCurrent(self.meetF, "continue")
            c = self.flow.pop()

            # Has a fixed point been reached for loop exit?
            # Check merge(current, "normal exit") == current

            current, changed = meet(self.meetF, current, c)

            if not changed:
                # Construct the state at loop break
                self.flow.mergeCurrent(self.meetF, "break")
                b = self.flow.pop()

                # Save the exceptional flow
                loopbags = self.flow.saveBags()
                assert "continue" not in loopbags
                assert "break" not in loopbags

                break
            else:
                if iterations >= self.maxLoopIterations:
                    self.flow.mergeCurrent(self.meetF, "break")
                    b = self.flow.pop()
                    loopbags = self.flow.saveBags()
                    break
                # Clears the bags
                self.flow.saveBags()

        # Merge in newly create bages (raise, return, etc.)
        self.flow.restoreAndMergeBags(originalbags, loopbags)

        # TODO If loop must be taken, do not merge in current.
        # Use "c" instead.
        out = current

        # Evaluate else.
        self.flow.restore(out)
        else_ = self(node.else_)

        # Merge in breaks
        out = self.flow.pop()
        out, changed = meet(self.meetF, out, b)
        self.flow.restore(out)

        result = ast.For(iterator, index, loopPreamble, bodyPreamble, body, else_)
        return result

    @dispatch(ast.ShortCircutOr)
    def visitShortCircutOr(self, node):
        return self.processShortCircuit(node, True)

    @dispatch(ast.ShortCircutAnd)
    def visitShortCircutAnd(self, node):
        return self.processShortCircuit(node, False)

    @dispatch(ast.TryExceptFinally)
    def visitTryExceptFinally(self, node):
        oldRaise = self.flow.bags.get("raise", [])
        self.flow.bags["raise"] = []

        self.flow.tryLevel += 1
        body = self(node.body)
        self.flow.tryLevel -= 1

        normalF = self.flow.pop()

        self.flow.mergeCurrent(self.meetF, "raise")
        raiseF = self.flow.pop()

        self.flow.bags["raise"] = oldRaise

        normalExits = []
        handlers = []
        defaultHandler = None

        if raiseF is not None:
            for handler in node.handlers:
                self.flow.restore(raiseF.split())
                handlers.append(self(handler))
                normalExits.append(self.flow.pop())

            if node.defaultHandler is not None:
                self.flow.restore(raiseF)
                defaultHandler = self(node.defaultHandler)
                normalExits.append(self.flow.pop())
            else:
                # No default handler, raises my propigate.
                self.flow.restore(raiseF)
                self.flow.save("raise")

        if node.else_ is not None and normalF is not None:
            self.flow.restore(normalF)
            else_ = self(node.else_)
            normalExits.append(self.flow.pop())
        else:
            else_ = None
            normalExits.append(normalF)

        normalF, changed = meet(self.meetF, *normalExits)

        originalbags = self.flow.saveBags()
        mergedbags = {}
        allF = [normalF]

        for name, bag in originalbags.items():
            if bag:
                merged, changed = meet(self.meetF, *bag)

                if merged is not None:
                    mergedbags[name] = merged
                    allF.append(merged)

        # Generate the code by evaluating the superposition

        superF, changed = meet(self.meetF, *allF)
        self.flow.restore(superF)
        finally_ = self(node.finally_)

        # Clear the analysis state
        self.flow.pop()
        self.flow.saveBags()

        # Evaluate each contour seperately to maintain precision.
        if normalF is not None:
            self.flow.restore(normalF)
            self(node.finally_)
            normalF = self.flow.pop()

        for name, frame in mergedbags.items():
            frame = frame.split() if frame is not None else None
            self.flow.restore(frame)
            self(node.finally_)
            self.flow.save(name)

        self.flow.restore(normalF)

        result = ast.TryExceptFinally(body, handlers, defaultHandler, else_, finally_)

        return result

    @dispatch(ast.Break)
    def visitBreak(self, node):
        result = self.processExpr(node)
        self.flow.save("break")
        return result

    @dispatch(ast.Continue)
    def visitContinue(self, node):
        result = self.processExpr(node)
        self.flow.save("continue")
        return result

    @dispatch(ast.Call)
    def visitCall(self, node):
        expr = self(node.expr)
        args = self(node.args)
        kwds = self.visitKwds(node.kwds)
        vargs = self(node.vargs)
        kargs = self(node.kargs)
        result = ast.Call(expr, args, kwds, vargs, kargs)
        result.annotation = node.annotation
        return self.processExpr(result, node)

    @dispatch(ast.DirectCall)
    def visitDirectCall(self, node):
        selfarg = self(node.selfarg)
        args = self(node.args)
        kwds = self.visitKwds(node.kwds)
        vargs = self(node.vargs)
        kargs = self(node.kargs)
        result = ast.DirectCall(node.code, selfarg, args, kwds, vargs, kargs)
        result.annotation = node.annotation
        return self.processExpr(result, node)

    @dispatch(ast.Existing)
    def visitExisting(self, node):
        # Handle existing objects (literals, globals, etc.)
        return node

    @dispatch(ast.InputBlock)
    def visitInputBlock(self, node):
        # HACK not exposed?
        return node

    @dispatch(ast.OutputBlock)
    def visitOutputBlock(self, node):
        outputs = [
            ast.Output(self.processExpr(output.expr), output.dst)
            for output in node.outputs
        ]
        return ast.OutputBlock(outputs)

    @dispatch(ast.Return)
    def visitReturn(self, node):
        exprs = self(node.exprs)
        result = ast.Return(exprs)
        result.annotation = node.annotation
        result = self.processExpr(result, node)
        self.flow.save("return")
        return result

    @dispatch(ast.Raise)
    def visitRaise(self, node):
        exception = self(node.exception)
        parameter = self(node.parameter)
        traceback = self(node.traceback)
        result = ast.Raise(exception, parameter, traceback)
        result.annotation = node.annotation
        result = self.processExpr(result, node)
        self.flow.save("raise")
        return result

    @dispatch(ast.FunctionDef)
    def visitFunctionDef(self, node):
        # Function definitions are handled during extraction, not dataflow
        # Just process the body for any side effects
        return node.rewriteChildren(self)

    @dispatch(ast.ClassDef)
    def visitClassDef(self, node):
        # Class definitions are handled during extraction, not dataflow
        # Just process for any side effects
        return node.rewriteChildren(self)

    @dispatch(ast.Code)
    def visitCode(self, node):
        # Code nodes (function/lambda bodies) are processed during extraction
        # Skip here to avoid double processing
        return node
