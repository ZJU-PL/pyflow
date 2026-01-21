"""
Semantic misuse detectors (resource leaks, null-deref patterns, type hazards).

These heuristics are intentionally light-weight but leverage PyFlow's semantic context (function names, call graph reachability, lifetime, etc.) to reduce noise.
"""

from __future__ import annotations

import ast
import textwrap
from typing import List, Set

from ..context import AnalysisSession
from ..issue import BugInstance, IssueTrace, Severity
from .base import Detector


class MisuseDetector(Detector):
    name = "misuse"
    description = "Detect resource handling and null/typing hazards."

    def run(self, session: AnalysisSession) -> List[BugInstance]:
        reports: List[BugInstance] = []
        callgraph = session.queries.get_callgraph().get()
        reachable = set(callgraph.keys())
        for fname, src in session.sources_by_name.items():
            if reachable and fname not in reachable:
                # Skip unreachable code to stay context-aware
                continue
            tree = ast.parse(textwrap.dedent(src))
            reports.extend(self._resource_leak_reports(fname, tree))
            reports.extend(self._null_deref_reports(fname, tree))
        return reports

    # ----------------------------------------------------------- resource leaks
    def _resource_leak_reports(self, fname: str, tree: ast.AST) -> List[BugInstance]:
        reports: List[BugInstance] = []
        visitor = _ResourceUseVisitor()
        visitor.visit(tree)
        for leak in visitor.leaks:
            reports.append(
                BugInstance(
                    rule="resource-leak",
                    message=f"File handle opened without context manager/close() in '{fname}'.",
                    severity=Severity.MEDIUM,
                    function=fname,
                    line=leak,
                )
            )
        return reports

    # ----------------------------------------------------------- null deref
    def _null_deref_reports(self, fname: str, tree: ast.AST) -> List[BugInstance]:
        reports: List[BugInstance] = []
        visitor = _NullDerefVisitor()
        visitor.visit(tree)
        for line, var in visitor.suspects:
            reports.append(
                BugInstance(
                    rule="possible-null-deref",
                    message=f"Variable '{var}' may be None before dereference in '{fname}'.",
                    severity=Severity.LOW,
                    function=fname,
                    line=line,
                    traces=[
                        IssueTrace(
                            summary="Heuristic: variable assigned None and used without guarding check."
                        )
                    ],
                )
            )
        return reports


class _ResourceUseVisitor(ast.NodeVisitor):
    """Detect open() usage outside of a context manager."""

    def __init__(self):
        self.leaks: Set[int] = set()

    def visit_With(self, node: ast.With):
        # With statements safely manage context
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if not self._inside_with(node):
                self.leaks.add(node.lineno)
        self.generic_visit(node)

    def _inside_with(self, node: ast.AST) -> bool:
        parent = getattr(node, "parent", None)
        while parent:
            if isinstance(parent, ast.With):
                return True
            parent = getattr(parent, "parent", None)
        return False

    def generic_visit(self, node):
        for child in ast.iter_child_nodes(node):
            child.parent = node
            self.visit(child)


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
        for child in ast.iter_child_nodes(node):
            child.parent = node
            self.visit(child)
