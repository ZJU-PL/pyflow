"""CFG inlining functionality.

This module provides functionality to inline function calls in CFGs,
including AST cloning and inlining transformations.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.ir.cfg import graph as cfg
from pyflow.ir.cfg.dfs import CFGDFS

from . import simplify


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
    """Clones AST nodes with origin tracking.

    This class provides functionality to clone AST nodes while preserving
    and updating origin information for debugging and analysis purposes.

    Attributes:
        origin: Origin information for cloned nodes.
        cache: Cache for memoized cloning operations.
    """

    def __init__(self, origin):
        """Initialize the AST cloner.

        Args:
            origin: Origin information for cloned nodes.
        """
        self.origin = origin
        self.cache = {}

    def adjustOrigin(self, node):
        """Adjust the origin information of a node.

        Args:
            node: AST node to adjust origin for.

        Returns:
            AST node with adjusted origin.
        """
        if not hasattr(node, "annotation") or not hasattr(node.annotation, "origin"):
            return node

        origin = node.annotation.origin
        if origin is None:
            origin = [None]
        else:
            origin = list(origin)

        new_origin = list(self.origin) + origin
        node.rewriteAnnotation(origin=new_origin)
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
        result.annotation = node.annotation
        return self.adjustOrigin(result)

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
        return self.adjustOrigin(node.rewriteChildren(self))

    @defaultdispatch
    def visitDefault(self, node):
        return self.adjustOrigin(node.rewriteChildren(self))


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

    @dispatch(cfg.Suite)
    def visitSuite(self, node):
        suite = cfg.Suite(node.region)
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
    def __init__(self, origin):
        self.cloner = CFGDFS(CFGClonerPre(ASTCloner(origin)), CFGClonerPost())
        self.cloner.post.cache = self.cloner.pre.cache
        self.cfgCache = self.cloner.pre.cache

        self.lcl = self.cloner.pre.astcloner

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
            defaults=[self(d) for d in original.defaults],
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

    @dispatch(cfg.Entry, cfg.Exit, cfg.Merge, cfg.Yield)
    def visitOK(self, node):
        pass

    @dispatch(cfg.Switch)
    def visitSwitch(self, node):
        pass

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
                inlined = True

                call = op.expr

                cloner = CFGCloner(call.annotation.origin)
                cloned = cloner.process(invokes)

                # Bug A fix: stray debug print removed.
                # print("\t", invokes.code.name)

                # PREAMBLE, evaluate arguments
                for p, a in zip(cloned.code.params, call.arguments):
                    current.ops.append(ast.Assign(p, a))

                # Connect into the cloned code
                current.transferExit("normal", cloned.entryTerminal, "entry")
                current.simplify()

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
                    current.ops.append(ast.Assign(cloned.returnParam, op.lcls))
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
                    if expr.object.data in self.lut:
                        return self.lut[expr.object.data]

        return None


def evaluate(compiler, g, lut):
    transform = CFGDFS(post=InlineTransform(compiler, g, lut))
    transform.process(g.entryTerminal)
    simplify.evaluate(compiler, g)
