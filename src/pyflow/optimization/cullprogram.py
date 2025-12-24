"""
Program culling optimization.

This module eliminates unreferenced code contexts from programs, reducing
the size of the analyzed program by removing code that is never executed
or referenced. This is a whole-program optimization that requires
inter-procedural analysis to determine which contexts are live.

The optimization:
- Finds all live execution contexts using program culler
- Removes unused contexts from code annotations
- Updates local variable annotations to reflect remaining contexts
- Preserves only the contexts that are actually reachable

This is typically run after cloning and inlining to clean up unused
specializations.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

from pyflow.language.python.program import Object
from pyflow.analysis import programculler


class CodeContextCuller(TypeDispatcher):
    """
    Eliminates unreferenced code contexts from a program.
    
    This class processes code nodes and removes contexts that are not
    in the live set. It updates annotations to reflect only the live
    contexts, reducing memory usage and analysis complexity.
    
    The culler:
    - Remaps context indices to reflect only live contexts
    - Updates node annotations with context subsets
    - Tracks local variables that need annotation updates
    
    Attributes:
        locals: Set of local variables that need annotation updates
        remap: List mapping old context indices to new indices
    """
    # Critical: code references in direct calls must NOT have their annotations rewritten.
    @dispatch(ast.leafTypes, ast.Code)
    def visitLeaf(self, node):
        pass

    @dispatch(ast.Local)
    def visitLocal(self, node):
        if node not in self.locals:
            self.locals.add(node)
            node.annotation = node.annotation.contextSubset(self.remap)

    @defaultdispatch
    def default(self, node):
        assert not node.__shared__, type(node)
        node.visitChildren(self)
        if node.annotation is not None:
            node.annotation = node.annotation.contextSubset(self.remap)

    def process(self, code, contexts):
        """
        Process a code node and remove unused contexts.
        
        Creates a remapping from old context indices to new indices,
        keeping only the contexts that are in the live set. Updates
        the code's annotation and all child nodes.
        
        Args:
            code: Code node to process
            contexts: Set of live contexts to preserve
        """
        self.locals = set()
        self.remap = []

        # Build remapping: old index -> new index for live contexts
        for cindex, context in enumerate(code.annotation.contexts):
            if context in contexts:
                self.remap.append(cindex)

        # Update code annotation to only include live contexts
        code.annotation = code.annotation.contextSubset(self.remap)

        # Update all child nodes
        code.visitChildrenForced(self)


def evaluateCode(code, contexts, ccc):
    """
    Evaluate and cull contexts from a code node.
    
    Removes unused contexts from a code node if the number of contexts
    differs from the live set. Verifies invariants before and after.
    
    Args:
        code: Code node to process
        contexts: Set of live contexts
        ccc: CodeContextCuller instance
        
    Raises:
        AssertionError: If contexts are not in code.annotation.contexts
    """
    # Check invariant: all contexts must be in code's annotation
    for context in contexts:
        assert context in code.annotation.contexts, (code, id(context))

    # Only process if there are unused contexts to remove
    if len(code.annotation.contexts) != len(contexts):
        ccc.process(code, contexts)

    # Verify invariant after processing
    for context in contexts:
        assert context in code.annotation.contexts, (code, id(context))


def evaluate(compiler, prgm):
    """
    Main entry point for program culling.
    
    Finds all live contexts in the program and removes unused contexts
    from code annotations. This reduces memory usage and analysis
    complexity by eliminating unreachable code specializations.
    
    Args:
        compiler: Compiler instance
        prgm: Program to cull
    """
    with compiler.console.scope("cull"):
        # Find all live execution contexts
        liveContexts = programculler.findLiveContexts(prgm)

        # Cull unused contexts from each code node
        ccc = CodeContextCuller()
        for code, contexts in liveContexts.items():
            evaluateCode(code, contexts, ccc)

        prgm.liveCode = set(liveContexts.keys())
