"""Forward dataflow graph construction for numbering analysis.

This module provides ForwardDataflow, which constructs forward dataflow
graphs from Python AST. These graphs represent control flow relationships
and are used for dominance analysis and numbering.

The graph distinguishes between:
- Symbolic nodes: (node, "entry") and (node, "exit") for control structures
- Concrete nodes: Direct AST nodes for simple statements
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

import collections


class ForwardDataflow(TypeDispatcher):
    """Constructs forward dataflow graphs from AST.
    
    ForwardDataflow traverses Python AST and builds a forward dataflow
    graph representing control flow. The graph uses:
    - Symbolic nodes: For control structures (loops, conditionals)
    - Concrete nodes: For simple statements (assignments, etc.)
    
    Attributes:
        next: Dictionary mapping nodes to list of successor nodes
        entry: Dictionary mapping AST nodes to entry graph nodes
        exit: Dictionary mapping AST nodes to exit graph nodes
        returnExit: Exit node for return statements
    """
    def makeSymbolic(self, node):
        """Create symbolic entry/exit nodes for a control structure.
        
        Symbolic nodes are tuples (node, "entry") or (node, "exit")
        that represent control flow boundaries for complex structures.
        
        Args:
            node: AST node to create symbolic nodes for
            
        Returns:
            tuple: (entry node, exit node)
        """
        entry = (node, "entry")
        exit = (node, "exit")

        self.entry[node] = entry
        self.exit[node] = exit

        return entry, exit

    def makeConcrete(self, node):
        """Create concrete entry/exit nodes (same as node itself).
        
        Concrete nodes use the AST node directly as both entry and exit.
        Used for simple statements that don't need symbolic boundaries.
        
        Args:
            node: AST node to create concrete nodes for
            
        Returns:
            tuple: (entry node, exit node) - both are the same node
        """
        entry = node
        exit = node
        self.entry[node] = entry
        self.exit[node] = exit
        return entry, exit

    def link(self, prev, next):
        """Link two AST nodes in the dataflow graph.
        
        Creates an edge from prev's exit to next's entry.
        
        Args:
            prev: Previous AST node
            next: Next AST node
        """
        self._link(self.exit[prev], self.entry[next])

    def _link(self, prev, next):
        """Internal method to link graph nodes.
        
        Args:
            prev: Previous graph node
            next: Next graph node
        """
        if prev is not None:
            self.next[prev].append(next)

    @dispatch(ast.Assign, ast.Discard, ast.Store, ast.OutputBlock)
    def visitStatement(self, node):
        entry, exit = self.makeConcrete(node)

    @dispatch(ast.Return)
    def visitReturn(self, node):
        self.entry[node] = node
        self.exit[node] = None

        self._link(node, self.returnExit)

    @dispatch(ast.Condition)
    def visitCondition(self, node):
        # HACKISH?
        entry, exit = self.makeSymbolic(node)

        self(node.preamble)

        self._link(entry, self.entry[node.preamble])
        self._link(self.exit[node.preamble], exit)

    @dispatch(ast.Switch)
    def visitSwitch(self, node):
        entry, exit = self.makeSymbolic(node)

        self(node.condition)
        self(node.t)
        self(node.f)

        self._link(entry, self.entry[node.condition])

        self.link(node.condition, node.t)
        self.link(node.condition, node.f)

        self._link(self.exit[node.t], exit)
        self._link(self.exit[node.f], exit)

    @dispatch(ast.TypeSwitch)
    def visitTypeSwitch(self, node):
        entry, exit = self.makeSymbolic(node)

        # TODO conditional?

        for case in node.cases:
            self(case.body)
            self._link(entry, self.entry[case.body])
            self._link(self.exit[case.body], exit)

    @dispatch(ast.For)
    def visitFor(self, node):
        # HACKISH?

        entry, exit = self.makeSymbolic(node)

        self(node.loopPreamble)
        self(node.bodyPreamble)
        self(node.body)
        self(node.else_)

        self._link(entry, self.entry[node.loopPreamble])
        self.link(node.loopPreamble, node.bodyPreamble)
        self.link(node.bodyPreamble, node.body)
        self.link(node.body, node.bodyPreamble)
        self.link(node.body, node.else_)
        self._link(self.exit[node.else_], exit)

        # Nothing to iterate?
        self.link(node.loopPreamble, node.else_)

    @dispatch(ast.While)
    def visitWhile(self, node):
        # HACKISH?

        entry, exit = self.makeSymbolic(node)

        self(node.condition)
        self(node.body)
        self(node.else_)

        self._link(entry, self.entry[node.condition])
        self.link(node.condition, node.body)
        self.link(node.body, node.condition)
        self.link(node.condition, node.else_)
        self._link(self.exit[node.else_], exit)

    @dispatch(ast.Suite)
    def visitSuite(self, node):
        entry, exit = self.makeSymbolic(node)

        prev = entry
        for child in node.blocks:
            self(child)
            self._link(prev, self.entry[child])
            prev = self.exit[child]

        self._link(prev, exit)

    def processCode(self, code):
        """Process a code object and build its dataflow graph.
        
        Traverses the AST of a code object and builds a forward dataflow
        graph representing control flow relationships.
        
        Args:
            code: Code object to process
            
        Returns:
            dict: Dictionary mapping nodes to list of successor nodes
        """
        self.next = collections.defaultdict(list)
        self.entry = {}
        self.exit = {}

        entry, exit = self.makeSymbolic(code)

        self.returnExit = exit

        self(code.ast)

        self._link(entry, self.entry[code.ast])
        self._link(self.exit[code.ast], exit)

        return self.next
