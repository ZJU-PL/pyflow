"""Leak detectors leveraging PyFlow lifetime analysis and AST patterns."""

from __future__ import annotations

import ast
import textwrap
from typing import List, Optional, Set

from ..context import AnalysisSession
from ..issue import Issue
from .base import Detector


class LeakDetector(Detector):
    name = "leak"
    description = "Detect resource leaks (file handles) and scope leaks (escaping objects)."

    def run(self, session: AnalysisSession) -> List[Issue]:
        reports: List[Issue] = []
        
        # Resource leak detection (file handles)
        callgraph = session.queries.get_callgraph().get()
        reachable = set(callgraph.keys())
        for fname, src in session.sources_by_name.items():
            if reachable and fname not in reachable:
                # Skip unreachable code to stay context-aware
                continue
            tree = ast.parse(textwrap.dedent(src))
            reports.extend(self._resource_leak_reports(fname, tree))
        
        # Scope leak detection (escaping objects) using lifetime analysis
        reports.extend(self._scope_leak_reports(session))
        
        return reports

    # ----------------------------------------------------------- resource leaks
    def _resource_leak_reports(self, fname: str, tree: ast.AST) -> List[Issue]:
        reports: List[Issue] = []
        visitor = _ResourceUseVisitor()
        visitor.visit(tree)
        for leak in visitor.leaks:
            issue = Issue(
                severity="MEDIUM",
                confidence="HIGH",
                cwe=400,  # CWE-400: Uncontrolled Resource Consumption
                text=f"File handle opened without context manager/close().",
                ident=None,
                lineno=leak,
                test_id="S002",  # Semantic checker rule ID
            )
            issue.fname = fname
            issue.test = "leak"
            reports.append(issue)
        return reports

    # ----------------------------------------------------------- scope leaks
    def _scope_leak_reports(self, session: AnalysisSession) -> List[Issue]:
        """Flags locally-allocated objects that escape their defining scope."""
        la = session.lifetime
        if la is None:
            return []

        reports: List[Issue] = []

        escapes = getattr(la, "escapes", None)
        objects = getattr(la, "objects", None)
        if not escapes or not objects:
            return []

        for obj, info in objects.items():
            if obj not in escapes:
                continue
            # Skip externally visible / existing objects
            if getattr(info, "globallyVisible", False) or getattr(info, "externallyVisible", False):
                continue

            # Try to tie back to defining code object
            code_owner: Optional[str] = None
            for code in getattr(info, "localReference", []):
                if hasattr(code, "codeName"):
                    code_owner = code.codeName()
                    break

            issue = Issue(
                severity="MEDIUM",
                confidence="MEDIUM",
                cwe=0,  # No specific CWE for scope leaks
                text="Locally allocated object escapes its defining scope; review for leaks or unintended aliasing.",
                ident=code_owner,
                lineno=None,
                test_id="S003",  # Semantic checker rule ID
            )
            issue.test = "leak"
            reports.append(issue)
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
