"""
Null dereference detector.

Detects potential null pointer dereferences (NPD) where variables assigned None
are later accessed without null checks.

These heuristics are intentionally light-weight but leverage PyFlow's semantic
context (function names, call graph reachability, etc.) to reduce noise.
"""

from __future__ import annotations

import ast
import textwrap
from typing import List, Set

from ..core.context import AnalysisSession
from ..core.issue import Issue
from ..core.base import Detector


class NullDereferenceDetector(Detector):
    name = "null_dereference"
    description = "Detect null dereference hazards."

    def run(self, session: AnalysisSession) -> List[Issue]:
        reports: List[Issue] = []

        # Get call graph for reachability analysis
        # Handle case where IPA analysis is not available
        try:
            callgraph = session.queries.get_callgraph().get()
            reachable = set(callgraph.keys())
        except Exception:
            # If callgraph is not available, analyze all files
            reachable = set()

        for fname, src in session.sources_by_name.items():
            if reachable and fname not in reachable:
                # Skip unreachable code to stay context-aware
                continue
            tree = ast.parse(textwrap.dedent(src))
            reports.extend(self._null_deref_reports(fname, tree))
        return reports

    def _null_deref_reports(self, fname: str, tree: ast.AST) -> List[Issue]:
        reports: List[Issue] = []
        visitor = _NullDerefVisitor()
        visitor.visit(tree)
        for line, var in visitor.suspects:
            issue = Issue(
                severity="LOW",
                confidence="MEDIUM",
                cwe=476,  # CWE-476: NULL Pointer Dereference
                text=f"Variable '{var}' may be None before dereference.",
                ident=var,
                lineno=line,
                test_id="S001",  # Semantic checker rule ID
            )
            issue.fname = fname
            issue.test = "null_dereference"
            reports.append(issue)
        return reports


class _NullDerefVisitor(ast.NodeVisitor):
    """Find names set to None and later dereferenced without a guard.

    Bug #17 fix: the original implementation used module-level (instance-level)
    sets ``none_assigned`` and ``guarded`` that accumulated state across the
    entire module AST.  A variable assigned ``None`` in one function would be
    flagged as a null-dereference hazard in a completely unrelated function
    later in the same file, producing false positives.

    The fix resets per-function state when entering a function definition so
    that each function is analysed independently.
    """

    def __init__(self):
        self.none_assigned: Set[str] = set()
        self.guarded: Set[str] = set()
        self.suspects: List[tuple] = []

    def _reset_function_state(self):
        """Reset per-function tracking sets when entering a new function scope."""
        self.none_assigned = set()
        self.guarded = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Save outer-scope state, analyse the function body with fresh sets,
        # then restore the outer-scope state.
        saved_assigned = self.none_assigned
        saved_guarded = self.guarded
        self._reset_function_state()
        self.generic_visit(node)
        self.none_assigned = saved_assigned
        self.guarded = saved_guarded

    # Async functions have the same scoping rules.
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Constant) and node.value.value is None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.none_assigned.add(target.id)
        # A non-None assignment clears the "may be None" flag for that name.
        elif not (isinstance(node.value, ast.Constant) and node.value.value is None):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.none_assigned.discard(target.id)
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        # If we guard against None, remember it
        if isinstance(node.test, ast.Compare):
            for comparator in node.test.comparators:
                if isinstance(comparator, ast.Constant) and comparator.value is None:
                    if isinstance(node.test.left, ast.Name):
                        self.guarded.add(node.test.left.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if isinstance(node.value, ast.Name):
            name = node.value.id
            if name in self.none_assigned and name not in self.guarded:
                self.suspects.append((node.lineno, name))
        self.generic_visit(node)

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            self.visit(child)
