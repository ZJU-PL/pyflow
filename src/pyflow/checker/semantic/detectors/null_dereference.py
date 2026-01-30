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
        callgraph = session.queries.get_callgraph().get()
        reachable = set(callgraph.keys())
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
    """Find names set to None and later dereferenced without a guard."""

    def __init__(self):
        self.none_assigned: Set[str] = set()
        self.guarded: Set[str] = set()
        self.suspects: List[tuple[int, str]] = []

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Constant) and node.value.value is None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.none_assigned.add(target.id)
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
        # Note: This detector doesn't use parent tracking, so we don't need
        # to set parent attributes. Standard traversal is sufficient.
        for child in ast.iter_child_nodes(node):
            self.visit(child)
