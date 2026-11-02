"""Program culling for dead code elimination.

This module provides functionality to identify and remove dead code from
programs by analyzing call graphs and function usage patterns.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.analysis.astcollector import getOps
from pyflow.ir.core import AnalysisFacts


class Finder(object):
    """Base class for finding and processing program elements.

    This class provides a framework for traversing program structures
    and identifying relevant elements based on specific criteria.

    Attributes:
        processed: Set of already processed nodes.
    """

    def __init__(self, catalog):
        """Initialize the finder."""
        self.processed = set()

    def process(self, node):
        """Process a node and its children.

        Args:
            node: Node to process.
        """
        if node not in self.processed:
            self.processed.add(node)
            for child in self.children(node):
                self.process(child)

    def children(self, node):
        """Get children of a node.

        Args:
            node: Node to get children for.

        Returns:
            List of child nodes.

        Note:
            This method should be implemented by subclasses.
        """
        raise NotImplementedError


class CallGraphFinder(Finder):
    """Finds call graph relationships in programs.

    This class analyzes programs to build call graphs, identifying
    which functions are called and in what contexts.

    Attributes:
        liveFunc: Set of live functions.
        liveFuncContext: Dictionary mapping functions to their contexts.
        invokes: Dictionary mapping functions to their call sites.
        invokesContext: Dictionary mapping call sites to contexts.
    """

    def __init__(self, catalog):
        """Initialize the call graph finder."""
        Finder.__init__(self, catalog)
        self.facts = AnalysisFacts(catalog)
        self.liveFunc = set()
        self.liveFuncContext = {}
        self.invokes = {}
        self.invokesContext = {}

    def children(self, node):
        """Get children of a call graph node.

        Args:
            node: Call graph node (code, context tuple).

        Returns:
            List of child nodes.
        """
        code, context = node

        self.liveFunc.add(code)

        if code not in self.liveFuncContext:
            self.liveFuncContext[code] = set()
        self.liveFuncContext[code].add(context)

        if code not in self.invokes:
            self.invokes[code] = set()

        if node not in self.invokesContext:
            self.invokesContext[node] = set()

        children = []

        ops, _lcls = getOps(code)
        resolved_targets = set()
        for op in ops:
            for dstf, dstc in self.facts.call_targets(code, op, context):
                child = (dstf, dstc)
                resolved_targets.add(dstf)
                self.invokes[code].add(dstf)
                self.invokesContext[node].add(child)
                children.append(child)

        # Some frontends publish a nested function's MakeFunction value but
        # omit the local-variable invocation from CALL_TARGETS. Recover the
        # unambiguous lexical case (``inner = MakeFunction(code); inner()``)
        # directly from this code object's AST. The mapping is local to this
        # enclosing code, so same-named callbacks in other functions cannot
        # be conflated.
        local_functions = {}

        def collect_local_functions(current):
            if current is None or isinstance(current, ast.Code):
                return
            if isinstance(current, ast.Assign) and isinstance(current.expr, ast.MakeFunction):
                nested_code = getattr(current.expr, "code", None)
                if nested_code is not None:
                    for target in getattr(current, "lcls", ()) or ():
                        local_name = getattr(target, "name", None)
                        if isinstance(local_name, str):
                            local_functions[local_name.lstrip("%")] = nested_code
            if isinstance(current, (list, tuple)):
                for item in current:
                    collect_local_functions(item)
            elif isinstance(current, ast.PythonASTNode):
                for child in current.children():
                    collect_local_functions(child)

        collect_local_functions(getattr(code, "ast", None))
        for operation in ops:
            if not isinstance(operation, (ast.Call, ast.MethodCall)):
                continue
            callee = getattr(operation, "expr", None)
            local_name = getattr(callee, "name", None) if isinstance(callee, ast.Local) else None
            nested_code = local_functions.get(str(local_name).lstrip("%")) if local_name else None
            if nested_code is None or nested_code in resolved_targets:
                continue
            try:
                contexts = self.facts.contexts(nested_code)
            except Exception:
                contexts = ()
            nested_context = (
                context if context in contexts else (next(iter(contexts)) if contexts else None)
            )
            self.invokes[code].add(nested_code)
            if nested_context is None:
                # No analysis context was published for this nested body. It
                # is still live; do not enqueue it for context-sensitive
                # traversal because that would query facts under a fabricated
                # context and can turn a conservative recovery into a crash.
                self.liveFunc.add(nested_code)
                continue
            child = (nested_code, nested_context)
            self.invokesContext[node].add(child)
            children.append(child)
        return children


def makeCGF(prgm):
    """Build a CallGraphFinder from the program interface.

    Bug fix: the original code silently swallowed *all* exceptions (both
    ``AssertionError`` and bare ``Exception``) with empty ``except`` blocks.
    This meant that bugs in annotation processing or context lookup were
    silently ignored, producing an incomplete call graph with no diagnostic.

    Missing published entry contexts and unexpected failures are reported
    explicitly instead of being recovered from legacy annotations.
    """
    import logging

    _LOG = logging.getLogger(__name__)

    cgf = CallGraphFinder(prgm.ir)
    entry_code_contexts = prgm.interface.entryCodeContexts()
    unexpected = []
    for code, context in entry_code_contexts:
        try:
            if context not in cgf.facts.contexts(code):
                raise ValueError(
                    "Entry-point context missing from published analysis contexts: "
                    f"{code!r} / {context!r}"
                )
            cgf.process((code, context))
        except Exception as e:
            unexpected.append((code, context, e))

    if unexpected:
        code, context, exc = unexpected[0]
        _LOG.error(
            "makeCGF: failed processing (%r, %r): %s",
            code,
            context,
            exc,
            exc_info=True,
        )
        raise RuntimeError(
            f"Failed to build a complete call graph for {code!r} / {context!r}: {exc}"
        ) from exc

    return cgf


def findLiveCode(prgm):
    cgf = makeCGF(prgm)

    entry = set()
    for code in prgm.interface.entryCode():
        entry.add(code)

    G = cgf.invokes
    head = None
    G[head] = entry

    prgm.liveCode = cgf.liveFunc

    return cgf.liveFunc, G


def findLiveContexts(prgm):
    cgf = makeCGF(prgm)
    prgm.liveCode = cgf.liveFunc
    return cgf.liveFuncContext


class LiveHeapFinder(TypeDispatcher):
    def __init__(self, catalog):
        TypeDispatcher.__init__(self)
        self.facts = AnalysisFacts(catalog)
        self.code = None
        self.live = set()

    def addReferences(self, refs):
        self.live.update(refs)

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        pass

    @dispatch(list, tuple)
    def visitContainer(self, node):
        for child in node:
            self(child)

    @dispatch(ast.Existing)
    def visitExisting(self, node):
        self.addReferences(self.facts.merged_references(self.code, node))

    @dispatch(ast.Local)
    def visitReference(self, node):
        self.addReferences(self.facts.merged_references(self.code, node))

    @defaultdispatch
    def visitDefault(self, node):
        node.visitChildren(self)

    def process(self, code):
        self.code = code
        code.visitChildrenForced(self)
        self.code = None


# HACK this may not be 100% sound, as it only considers references
# directly embedded in the code.
def findLiveHeap(prgm):
    finder = LiveHeapFinder(prgm.ir)
    for code in prgm.liveCode:
        finder.process(code)

    index = {}
    for obj in finder.live:
        group = obj.xtype.group()
        if not group in index:
            index[group] = []
        index[group].append(obj)

    return finder.live, index
