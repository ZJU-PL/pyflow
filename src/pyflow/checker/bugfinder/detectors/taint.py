"""
Interprocedural taint-style vulnerability detection.

This detector combines light-weight local summaries with the IPA-derived
call graph to flag flows from user-controlled sources into dangerous sinks.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Set

from ..context import AnalysisSession
from ..issue import BugInstance, IssueTrace, Severity
from .base import Detector


DEFAULT_SOURCES = {"input", "sys.argv", "os.environ", "flask.request", "django.http.request"}
DEFAULT_SINKS = {
    "eval",
    "exec",
    "os.system",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "cursor.execute",
    "cursor.executemany",
    "pickle.loads",
}


@dataclass
class FunctionSummary:
    name: str
    has_source: bool = False
    returns_tainted: bool = False
    params_to_sink: Set[str] = field(default_factory=set)
    sinks: Set[str] = field(default_factory=set)


class TaintDetector(Detector):
    name = "taint"
    description = "Detect flows from untrusted sources to dangerous sinks."

    def __init__(self, sources=None, sinks=None):
        self.sources = set(sources or DEFAULT_SOURCES)
        self.sinks = set(sinks or DEFAULT_SINKS)

    def run(self, session: AnalysisSession) -> List[BugInstance]:
        summaries = self._build_summaries(session)
        callgraph = session.queries.get_callgraph().get()
        tainted: Set[str] = set()
        worklist: List[str] = []

        # Seed with functions that directly consume sources
        for name, summary in summaries.items():
            if summary.has_source:
                tainted.add(name)
                worklist.append(name)

        # Propagate taint through call graph using summaries
        while worklist:
            current = worklist.pop()
            for caller, callees in callgraph.items():
                if current in callees and caller not in tainted:
                    # If callee returns tainted or has source, caller becomes tainted
                    if summaries.get(current, FunctionSummary(current)).returns_tainted:
                        tainted.add(caller)
                        worklist.append(caller)

        reports: List[BugInstance] = []
        for caller, callees in callgraph.items():
            for callee in callees:
                if callee not in tainted:
                    continue
                summary = summaries.get(caller)
                if not summary:
                    continue
                for sink in summary.sinks:
                    reports.append(
                        BugInstance(
                            rule="taint-source-to-sink",
                            message=f"Untrusted data can reach sink '{sink}' in '{caller}' via call to '{callee}'.",
                            severity=Severity.HIGH,
                            function=caller,
                            traces=[
                                IssueTrace(
                                    summary=f"Call graph path: {caller} -> {callee}",
                                    detail="Derived from IPA call graph.",
                                )
                            ],
                        )
                    )
        return reports

    # ------------------------------------------------------------------ helpers
    def _build_summaries(self, session: AnalysisSession) -> Dict[str, FunctionSummary]:
        summaries: Dict[str, FunctionSummary] = {}
        for fname, src in session.sources_by_name.items():
            summaries[fname] = self._summarize_function(fname, src)
        return summaries

    def _summarize_function(self, name: str, src: str) -> FunctionSummary:
        tree = ast.parse(src)
        analyzer = _LocalTaintAnalyzer(self.sources, self.sinks)
        analyzer.visit(tree)
        return FunctionSummary(
            name=name,
            has_source=analyzer.has_source,
            returns_tainted=analyzer.returns_tainted,
            params_to_sink=analyzer.params_to_sink,
            sinks=analyzer.sinks_found,
        )


class _LocalTaintAnalyzer(ast.NodeVisitor):
    """Flow-sensitive intra-procedural taint tracking."""

    def __init__(self, sources: Set[str], sinks: Set[str]):
        self.sources = sources
        self.sinks = sinks
        self.tainted: Set[str] = set()
        self.has_source = False
        self.returns_tainted = False
        self.params_to_sink: Set[str] = set()
        self.sinks_found: Set[str] = set()
        self.current_params: Set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.current_params = {arg.arg for arg in node.args.args}
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if self._expr_is_source(node.value):
            self.has_source = True
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        elif self._expr_is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.add(target.id)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if self._expr_is_tainted(node.value):
            self.returns_tainted = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        fullname = self._call_fullname(node.func)
        if fullname in self.sinks:
            self.sinks_found.add(fullname)
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self.params_to_sink.add(arg.id)
        if self._expr_is_source(node):
            self.has_source = True
        self.generic_visit(node)

    # -------------------------------------------------------------- predicates
    def _expr_is_source(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.Call):
            fullname = self._call_fullname(expr.func)
            if fullname in self.sources:
                return True
        if isinstance(expr, ast.Attribute):
            dotted = self._attribute_name(expr)
            return dotted in self.sources
        if isinstance(expr, ast.Subscript) and isinstance(expr.value, ast.Name):
            if expr.value.id in {"os", "sys"}:
                return True
        return False

    def _expr_is_tainted(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name) and expr.id in self.tainted:
            return True
        if isinstance(expr, ast.Call):
            return any(self._expr_is_tainted(arg) for arg in expr.args)
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            return expr.value.id in self.tainted
        return False

    def _call_fullname(self, func: ast.AST) -> str:
        if isinstance(func, ast.Attribute):
            return self._attribute_name(func)
        if isinstance(func, ast.Name):
            return func.id
        return ""

    def _attribute_name(self, node: ast.Attribute) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
