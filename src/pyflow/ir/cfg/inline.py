"""CFG inlining functionality.

This module provides functionality to inline function calls in CFGs,
including AST cloning and inlining transformations.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.ir.cfg import graph as cfg
from pyflow.ir.cfg.dfs import CFGDFS

from . import simplify
from .revision import CFGTransformTransaction


def memoizeMethod(getter):
    """Decorator to memoize method calls.

    Args:
        getter: Function to get the cache for memoization.

    Returns:
        Decorator function for memoization.
    """

    def memodecorator(func):
        def memowrap(self, *args):
            cache = getter(self)
            if args not in cache:
                result = func(self, *args)
                cache[args] = result
            else:
                result = cache[args]
            return result

        return memowrap

    return memodecorator


class ASTCloner(TypeDispatcher):
    """Clone AST nodes while recording explicit provenance edges.

    This class provides functionality to clone AST nodes while preserving
    and updating origin information for debugging and analysis purposes.

    Attributes:
        origin: Origin information for cloned nodes.
        cache: Cache for memoized cloning operations.
    """

    def __init__(self):
        self.cache = {}
        self.generated_from = {}

    def record_clone(self, original, node):
        if node is not original and isinstance(node, ast.PythonASTNode):
            self.generated_from[node] = (original,)
        return node

    @dispatch(str, type(None))
    def visitLeaf(self, node):
        """Visit leaf nodes (no cloning needed).

        Args:
            node: Leaf node to visit.

        Returns:
            Original node.
        """
        return node

    @dispatch(ast.Local)
    @memoizeMethod(lambda self: self.cache)
    def visitLocal(self, node):
        """Visit local variable nodes.

        Bug B fix: ``ast.Local`` has no ``.type`` attribute in PyFlow's AST.
        The original code called ``self(node.type)`` which raised AttributeError
        at runtime.  Local nodes only carry a name; we clone them directly.

        Args:
            node: Local variable AST node.

        Returns:
            Cloned local variable node.
        """
        result = ast.Local(node.name)
        return self.record_clone(node, result)

    @dispatch(ast.Existing)
    def visitExisting(self, node):
        """Visit existing object nodes.

        Args:
            node: Existing object AST node.

        Returns:
            Cloned existing object node.
        """
        return node.clone()

    @dispatch(
        ast.Assign,
        ast.Discard,
        ast.BinaryOp,
        ast.Call,
        ast.Phi,
    )
    def visitOK(self, node):
        return self.record_clone(node, node.rewriteChildren(self))

    @defaultdispatch
    def visitDefault(self, node):
        return self.record_clone(node, node.rewriteChildren(self))


class CFGClonerPre(TypeDispatcher):
    def __init__(self, astcloner):
        self.astcloner = astcloner
        self.cache = {}

    @dispatch(cfg.Entry, cfg.Exit, cfg.Yield)
    def visitEntry(self, node):
        return type(node)(node.region)

    @dispatch(cfg.Merge)
    def visitMerge(self, node):
        merge = cfg.Merge(node.region)

        merge.phi = [self.astcloner(phi) for phi in node.phi]

        return merge

    @dispatch(cfg.Switch)
    def visitSwitch(self, node):
        return cfg.Switch(node.region, self.astcloner(node.condition))

    @dispatch(cfg.TypeSwitch)
    def visitTypeSwitch(self, node):
        return cfg.TypeSwitch(node.region, self.astcloner(node.original))

    @dispatch(cfg.ForIter)
    def visitForIter(self, node):
        return cfg.ForIter(
            node.region,
            self.astcloner(node.iterator),
            self.astcloner(node.index),
        )

    @dispatch(cfg.State)
    def visitState(self, node):
        return cfg.State(node.region, node.name)

    @dispatch(cfg.Suite)
    def visitSuite(self, node):
        origin_ast = (
            self.astcloner(node.origin_ast) if node.origin_ast is not None else None
        )
        suite = cfg.Suite(node.region, origin_ast=origin_ast)
        for op in node.ops:
            suite.ops.append(self.astcloner(op))
        return suite

    def __call__(self, node):
        self.cache[node] = TypeDispatcher.__call__(self, node)


class CFGClonerPost(TypeDispatcher):

    @defaultdispatch
    def visitEntry(self, node):
        replace = self.cache[node]

        for name, next in node.next.items():
            replace.clonedExit(name, self.cache[next])

        for prev, name in node.iterprev():
            replace.clonedPrev(self.cache[prev], name)


class CFGCloner(object):
    def __init__(self):
        self.cloner = CFGDFS(CFGClonerPre(ASTCloner()), CFGClonerPost())
        self.cloner.post.cache = self.cloner.pre.cache
        self.cfgCache = self.cloner.pre.cache

        self.lcl = self.cloner.pre.astcloner

    @property
    def generated_from(self):
        return self.lcl.generated_from

    def process(self, g):
        self.cloner.process(g.entryTerminal)

        newG = cfg.Code()

        original = g.code.codeparameters
        source_return = getattr(g, "returnParam", None)
        if source_return is None:
            if original.returnparams:
                source_return = original.returnparams[0]
            else:
                source_return = ast.Local("ret0")

        codeparams = ast.CodeParameters(
            selfparam=self.lcl(original.selfparam),
            posonlyparams=[self.lcl(p) for p in original.posonlyparams],
            posonlynames=original.posonlynames,
            params=[self.lcl(p) for p in original.params],
            paramnames=original.paramnames,
            defaults=[self.lcl(d) for d in original.defaults],
            vparam=self.lcl(original.vparam),
            kparam=self.lcl(original.kparam),
            returnparams=[self.lcl(p) for p in (original.returnparams or [source_return])],
            type_params=self.lcl(original.type_params),
        )
        newG.code = ast.Code(g.code.name + "_clone", codeparams, ast.Suite([]))

        newG.returnParam = codeparams.returnparams[0]

        newG.entryTerminal = self.cfgCache[g.entryTerminal]
        newG.normalTerminal = self.cfgCache.get(g.normalTerminal, newG.normalTerminal)
        newG.failTerminal = self.cfgCache.get(g.failTerminal, newG.failTerminal)
        newG.errorTerminal = self.cfgCache.get(g.errorTerminal, newG.errorTerminal)

        return newG


class InlineTransform(TypeDispatcher):
    def __init__(self, compiler, g, lut):
        self.compiler = compiler
        self.g = g
        self.lut = lut
        self.generated_from = {}

    @dispatch(cfg.Entry, cfg.Exit, cfg.Merge, cfg.Yield)
    def visitOK(self, node):
        pass

    @dispatch(cfg.Switch)
    def visitSwitch(self, node):
        pass

    @dispatch(cfg.TypeSwitch, cfg.ForIter, cfg.State)
    def visitControl(self, node):
        pass

    def bind_call(self, codeparameters, call):
        """Return ordered parameter initializers for a statically bindable call.

        CFG inlining is only valid after Python's argument binding succeeds.
        Handle positional, named, default, ``*args``-parameter and
        ``**kwargs``-parameter binding here; dynamic ``*expr``/``**expr`` calls
        remain ordinary calls because expanding them requires runtime checks.
        """
        if call.vargs is not None or call.kargs is not None:
            return None
        if codeparameters.selfparam is not None:
            return None

        formals = list(codeparameters.posonlyparams) + list(codeparameters.params)
        names = list(codeparameters.posonlynames) + list(codeparameters.paramnames)
        positional_only = len(codeparameters.posonlyparams)
        bound = {}

        if len(call.args) > len(formals) and codeparameters.vparam is None:
            return None
        for index, argument in enumerate(call.args[: len(formals)]):
            bound[index] = argument

        extra_keywords = []
        name_to_index = {
            name: index
            for index, name in enumerate(names)
            if index >= positional_only and name is not None
        }
        for name, argument in call.kwds:
            index = name_to_index.get(name)
            if index is None:
                if codeparameters.kparam is None:
                    return None
                extra_keywords.extend(
                    [ast.Existing(ast.program.Object(name)), argument]
                )
                continue
            if index in bound:
                return None
            bound[index] = argument

        defaults = list(codeparameters.defaults)
        default_start = len(formals) - len(defaults)
        for index in range(len(formals)):
            if index not in bound:
                if index < default_start:
                    return None
                bound[index] = defaults[index - default_start]

        initializers = [(formal, bound[index]) for index, formal in enumerate(formals)]
        if codeparameters.vparam is not None:
            initializers.append(
                (codeparameters.vparam, ast.BuildTuple(list(call.args[len(formals) :])))
            )
        if codeparameters.kparam is not None:
            initializers.append((codeparameters.kparam, ast.BuildMap(extra_keywords)))
        return initializers

    def materialize_returns(self, cloned):
        """Turn cloned Return operations into writes to formal return locals."""
        returnparams = list(cloned.code.codeparameters.returnparams)
        pending = [cloned.entryTerminal]
        seen = set()
        while pending:
            block = pending.pop()
            if block in seen:
                continue
            seen.add(block)
            pending.extend(block.forward())
            if not isinstance(block, cfg.Suite):
                continue

            rewritten = []
            for op in block.ops:
                if not isinstance(op, ast.Return):
                    rewritten.append(op)
                    continue
                expressions = list(op.exprs)
                if not expressions and len(returnparams) == 1:
                    expressions = [ast.Existing(ast.program.Object(None))]
                if len(expressions) != len(returnparams):
                    return False
                rewritten.extend(
                    ast.Assign(expression, [parameter])
                    for parameter, expression in zip(returnparams, expressions)
                )
            block.ops = rewritten
        return True

    @dispatch(cfg.Suite)
    def visitSuite(self, node):
        # Bug A fix: cfg.Merge() and cfg.Suite() require a region argument.
        # The original code passed no argument, causing TypeError at construction
        # time.  Pass node.region so the cloned blocks belong to the same region.
        region = node.region
        failTerminal = cfg.Merge(region) if node.getExit("fail") else None
        errorTerminal = cfg.Merge(region) if node.getExit("error") else None

        def makeSuite():
            suite = cfg.Suite(region)
            suite.setExit("fail", failTerminal)
            suite.setExit("error", errorTerminal)
            return suite

        head = makeSuite()
        current = head

        inlined = False

        for op in node.ops:
            invokes = self.getInline(op)
            if invokes is not None:
                call = op.expr

                cloner = CFGCloner()
                cloned = cloner.process(invokes)

                bindings = self.bind_call(cloned.code.codeparameters, call)
                if bindings is None or not self.materialize_returns(cloned):
                    current.ops.append(op)
                    continue
                inlined = True
                for generated, sources in cloner.generated_from.items():
                    self.generated_from[generated] = (call, *sources)

                # Bug A fix: stray debug print removed.
                # print("\t", invokes.code.name)

                # PREAMBLE, evaluate arguments
                for parameter, argument in bindings:
                    assignment = ast.Assign(argument, [parameter])
                    current.ops.append(assignment)
                    self.generated_from[assignment] = (call,)

                # Connect into the cloned code
                current.transferExit("normal", cloned.entryTerminal, "entry")

                cloned.failTerminal.redirectEntries(failTerminal)
                cloned.errorTerminal.redirectEntries(errorTerminal)

                # Connect the normal output
                if cloned.normalTerminal.prev:
                    current = makeSuite()
                    cloned.normalTerminal.redirectEntries(current)
                else:
                    current = None
                    break

                # POSTAMBLE transfer the return value
                # Bug 3 fix: ast.Assign stores targets in op.lcls (a list),
                # not op.target.  Also the argument order is (expr, lcls).
                if isinstance(op, ast.Assign):
                    assignment = ast.Assign(cloned.returnParam, op.lcls)
                    current.ops.append(assignment)
                    self.generated_from[assignment] = (call, op)
            else:
                current.ops.append(op)

        if inlined:
            # Inlining was performed, commit changes
            node.redirectEntries(head)

            # Redirect the outputs
            if current:
                if node.getExit("normal"):
                    current.transferExit("normal", node, "normal")
                current.simplify()

            if node.getExit("fail"):
                failTerminal.transferExit("normal", node, "fail")
                failTerminal.simplify()

            if node.getExit("error"):
                errorTerminal.transferExit("normal", node, "error")
                errorTerminal.simplify()

    def getInline(self, stmt):
        if isinstance(stmt, (ast.Assign, ast.Discard)):
            expr = stmt.expr
            if isinstance(expr, ast.Call):
                expr = expr.expr
                if isinstance(expr, ast.Existing):
                    return self.lut.get(expr.object)

        return None


def evaluate(compiler, g, lut):
    transaction = CFGTransformTransaction(g, "cfg-inline")
    inline_transform = InlineTransform(compiler, g, lut)
    transform = CFGDFS(post=inline_transform)
    transform.process(g.entryTerminal)
    simplify.evaluate(compiler, g, commit_revision=False)
    return transaction.commit(inline_transform.generated_from)
