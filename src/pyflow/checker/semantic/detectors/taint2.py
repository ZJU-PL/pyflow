"""
Advanced taint detection using PyFlow's analysis infrastructure.

This detector combines PyFlow's pre-computed analyses (IPA summaries, StoreGraph)
with local AST-based taint tracking for precise and complete taint flow detection.

Unlike the original TaintDetector, this version:
- Uses IPA return-param dependencies from PyFlow's infrastructure
- Uses StoreGraph for alias analysis when available
- Builds local taint analysis state via AST visiting
- Iterates to fixed point for interprocedural propagation
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Union, Tuple

from ..context import AnalysisSession
from ..issue import Issue
from .base import Detector

# Standard taint sources
DEFAULT_SOURCES = {
    "input",
    "sys.argv",
    "os.environ",
    "flask.request",
    "django.http.request",
    "taint_src",
}

# Standard taint sinks
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
    "taint_sink",
}


@dataclass
class FunctionSummary:
    """Summary of taint analysis for a function."""
    name: str
    has_source: bool = False
    returns_tainted: bool = False
    returns_tainted_unconditional: bool = False
    params_to_sink: Set[str] = field(default_factory=set)
    param_taint_outputs: Set[str] = field(default_factory=set)
    param_key_writes: Dict[str, Set[str]] = field(default_factory=dict)
    param_key_taint_writes: Dict[str, Set[str]] = field(default_factory=dict)
    sinks: Set[str] = field(default_factory=set)
    tainted_sinks: Set[str] = field(default_factory=set)
    tainted_sink: bool = False
    returns_value: bool = True
    return_param_deps: Set[str] = field(default_factory=set)


class TaintDetector2(Detector):
    """
    Advanced taint detector leveraging PyFlow's analysis infrastructure.

    This detector uses:
    - IPA function summaries for interprocedural return-param dependencies
    - StoreGraph for alias analysis (when available)
    - Local AST-based taint tracking with full state
    - Fixed-point iteration for interprocedural propagation
    """

    name = "taint2"
    description = "Advanced taint detection using PyFlow's analysis infrastructure."

    def __init__(
        self,
        sources: Optional[Set[str]] = None,
        sinks: Optional[Set[str]] = None,
    ):
        self.sources = set(sources or DEFAULT_SOURCES)
        self.sinks = set(sinks or DEFAULT_SINKS)

    def run(self, session: AnalysisSession) -> List[BugInstance]:
        """
        Run taint analysis using PyFlow's infrastructure.

        Args:
            session: Analysis session with queries and program

        Returns:
            List of BugInstance objects for each detected taint flow
        """
        # Build function summaries using hybrid approach
        summaries = self._build_summaries(session)

        reports: List[Issue] = []
        for name, summary in summaries.items():
            for sink in summary.tainted_sinks:
                issue = Issue(
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=79,  # CWE-79: XSS / Injection
                    text=f"Untrusted data can reach sink '{sink}'.",
                    ident=sink,
                    lineno=None,
                    test_id="S005",  # Semantic checker rule ID (IPA variant)
                )
                issue.fname = name  # Function name as file identifier
                issue.test = "taint2"
                reports.append(issue)

        return reports

    def _build_summaries(self, session: AnalysisSession) -> Dict[str, FunctionSummary]:
        """Build function summaries using PyFlow infrastructure and local analysis."""
        # Get IPA return-param dependencies from PyFlow
        return_param_deps, returns_value = self._collect_ipa_return_metadata(session)

        # Parse source code into ASTs
        function_trees: Dict[str, ast.AST] = {}
        param_names: Dict[str, List[str]] = {}
        for fname, src in session.sources_by_name.items():
            try:
                tree = ast.parse(textwrap.dedent(src))
                function_trees[fname] = tree
                param_names[fname] = self._extract_param_names(tree, fname)
            except SyntaxError:
                continue

        known_callees = set(function_trees.keys()) | set(return_param_deps.keys())
        summaries: Dict[str, FunctionSummary] = {}
        tainted_params: Dict[str, Set[str]] = {name: set() for name in known_callees}
        returns_unconditional: Dict[str, bool] = {name: False for name in known_callees}

        # Fixed-point iteration
        max_iters = max(3, len(function_trees) * 2)
        for _ in range(max_iters):
            changed = False
            callee_returns_tainted = {
                callee: summary.returns_tainted for callee, summary in summaries.items()
            }
            callee_has_source = {
                callee: summary.has_source for callee, summary in summaries.items()
            }
            callee_param_taint_outputs = {
                callee: summary.param_taint_outputs for callee, summary in summaries.items()
            }
            callee_param_key_writes = {
                callee: summary.param_key_writes for callee, summary in summaries.items()
            }
            callee_param_key_taint_writes = {
                callee: summary.param_key_taint_writes for callee, summary in summaries.items()
            }
            next_summaries: Dict[str, FunctionSummary] = {}
            next_unconditional: Dict[str, bool] = {}
            call_param_taints: Dict[str, Dict[str, Set[str]]] = {}

            for name, tree in function_trees.items():
                summary, call_taints = self._analyze_function(
                    name,
                    tree,
                    tainted_params.get(name, set()),
                    callee_returns_tainted,
                    callee_has_source,
                    callee_param_taint_outputs,
                    callee_param_key_writes,
                    callee_param_key_taint_writes,
                    returns_unconditional,
                    return_param_deps,
                    returns_value,
                    param_names,
                    known_callees,
                )
                unconditional_summary, _ = self._analyze_function(
                    name,
                    tree,
                    set(),
                    returns_unconditional,
                    callee_has_source,
                    callee_param_taint_outputs,
                    callee_param_key_writes,
                    callee_param_key_taint_writes,
                    returns_unconditional,
                    return_param_deps,
                    returns_value,
                    param_names,
                    known_callees,
                )
                summary.returns_tainted_unconditional = (
                    unconditional_summary.returns_tainted
                )
                summary.tainted_sink = bool(summary.tainted_sinks)
                next_summaries[name] = summary
                next_unconditional[name] = summary.returns_tainted_unconditional
                call_param_taints[name] = call_taints

            for name, summary in next_summaries.items():
                if self._summary_changed(summaries.get(name), summary):
                    changed = True

            summaries = next_summaries
            returns_unconditional = next_unconditional

            for callee_map in call_param_taints.values():
                for callee, params in callee_map.items():
                    if not params:
                        continue
                    if callee not in tainted_params:
                        tainted_params[callee] = set()
                    new_params = params - tainted_params[callee]
                    if new_params:
                        tainted_params[callee].update(new_params)
                        changed = True

            if not changed:
                break

        return summaries

    def _analyze_function(
        self,
        name: str,
        tree: ast.AST,
        entry_tainted_params: Set[str],
        callee_returns_tainted: Dict[str, bool],
        callee_has_source: Dict[str, bool],
        callee_param_taint_outputs: Dict[str, Set[str]],
        callee_param_key_writes: Dict[str, Dict[str, Set[str]]],
        callee_param_key_taint_writes: Dict[str, Dict[str, Set[str]]],
        callee_returns_unconditional: Dict[str, bool],
        return_param_deps: Dict[str, Set[str]],
        returns_value: Dict[str, bool],
        param_names: Dict[str, List[str]],
        known_callees: Set[str],
    ) -> Tuple[FunctionSummary, Dict[str, Set[str]]]:
        """Analyze a single function for taint flows."""
        analyzer = _LocalTaintAnalyzer2(
            sources=self.sources,
            sinks=self.sinks,
            entry_tainted_params=entry_tainted_params,
            callee_returns_tainted=callee_returns_tainted,
            callee_returns_unconditional=callee_returns_unconditional,
            callee_has_source=callee_has_source,
            callee_param_taint_outputs=callee_param_taint_outputs,
            callee_param_key_writes=callee_param_key_writes,
            callee_param_key_taint_writes=callee_param_key_taint_writes,
            callee_return_param_deps=return_param_deps,
            callee_param_names=param_names,
            callee_returns_value=returns_value,
            known_callees=known_callees,
        )
        analyzer.visit(tree)
        summary = FunctionSummary(
            name=name,
            has_source=analyzer.has_source,
            returns_tainted=analyzer.returns_tainted,
            params_to_sink=analyzer.params_to_sink,
            param_taint_outputs=analyzer.param_taint_outputs,
            param_key_writes=analyzer.param_key_writes,
            param_key_taint_writes=analyzer.param_key_taint_writes,
            sinks=analyzer.sinks_found,
            tainted_sinks=analyzer.tainted_sinks,
            tainted_sink=bool(analyzer.tainted_sinks),
            returns_value=returns_value.get(name, True),
            return_param_deps=return_param_deps.get(name, set()),
        )
        return summary, analyzer.call_param_taints

    def _summary_changed(self, old: Optional[FunctionSummary], new: FunctionSummary) -> bool:
        if old is None:
            return True
        return (
            old.has_source != new.has_source
            or old.returns_tainted != new.returns_tainted
            or old.returns_tainted_unconditional != new.returns_tainted_unconditional
            or old.params_to_sink != new.params_to_sink
            or old.param_taint_outputs != new.param_taint_outputs
            or old.param_key_writes != new.param_key_writes
            or old.param_key_taint_writes != new.param_key_taint_writes
            or old.sinks != new.sinks
            or old.tainted_sinks != new.tainted_sinks
        )

    def _extract_param_names(self, tree: ast.AST, name: str) -> List[str]:
        """Extract parameter names from function AST."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return self._collect_param_names(node.args)
        return []

    @staticmethod
    def _collect_param_names(args: ast.arguments) -> List[str]:
        names: List[str] = []
        for arg in getattr(args, "posonlyargs", []):
            names.append(arg.arg)
        for arg in args.args:
            names.append(arg.arg)
        for arg in args.kwonlyargs:
            names.append(arg.arg)
        return names

    def _collect_ipa_return_metadata(
        self, session: AnalysisSession
    ) -> Tuple[Dict[str, Set[str]], Dict[str, bool]]:
        """Collect return-param dependencies from IPA analysis."""
        return_param_deps: Dict[str, Set[str]] = {}
        returns_value: Dict[str, bool] = {}
        try:
            ipa = session.queries.get_ipa_analysis()
        except Exception:
            return return_param_deps, returns_value

        context_helper = getattr(session.queries, "context", None)
        if context_helper is None:
            return return_param_deps, returns_value

        for context in ipa.contexts.values():
            name = context_helper.context_name(context)
            if not name:
                continue
            params = self._extract_ipa_param_names(context.params)
            if params:
                deps = self._extract_ipa_return_deps(context.returns, params)
                if deps:
                    return_param_deps.setdefault(name, set()).update(deps)
            returns_value[name] = returns_value.get(name, False) or bool(context.returns)

        return return_param_deps, returns_value

    @staticmethod
    def _extract_ipa_param_names(params: Any) -> Set[str]:
        """Extract parameter names from IPA context."""
        names: Set[str] = set()
        for param in params:
            raw = getattr(param, "name", None)
            name = getattr(raw, "name", None)
            if isinstance(name, str):
                names.add(name)
            elif isinstance(raw, str):
                names.add(raw)
        return names

    @staticmethod
    def _extract_ipa_return_deps(returns: Any, params: Set[str]) -> Set[str]:
        """Extract which parameters affect return values."""
        deps: Set[str] = set()
        for ret in returns:
            critical = getattr(ret, "critical", None)
            values = getattr(critical, "values", ())
            for value in values:
                name = getattr(value, "name", None)
                if isinstance(name, str) and name in params:
                    deps.add(name)
                elif isinstance(value, str) and value in params:
                    deps.add(value)
        return deps


class _LocalTaintAnalyzer2(ast.NodeVisitor):
    """Flow-sensitive intra-procedural taint tracking (TaintDetector2 version)."""

    def __init__(
        self,
        *,
        sources: Set[str],
        sinks: Set[str],
        entry_tainted_params: Set[str],
        callee_returns_tainted: Dict[str, bool],
        callee_returns_unconditional: Dict[str, bool],
        callee_has_source: Dict[str, bool],
        callee_param_taint_outputs: Dict[str, Set[str]],
        callee_param_key_writes: Dict[str, Dict[str, Set[str]]],
        callee_param_key_taint_writes: Dict[str, Dict[str, Set[str]]],
        callee_return_param_deps: Dict[str, Set[str]],
        callee_param_names: Dict[str, List[str]],
        callee_returns_value: Dict[str, bool],
        known_callees: Set[str],
    ):
        self.sources = sources
        self.sinks = sinks
        self.entry_tainted_params = entry_tainted_params
        self.callee_returns_tainted = callee_returns_tainted
        self.callee_returns_unconditional = callee_returns_unconditional
        self.callee_has_source = callee_has_source
        self.callee_param_taint_outputs = callee_param_taint_outputs
        self.callee_param_key_writes = callee_param_key_writes
        self.callee_param_key_taint_writes = callee_param_key_taint_writes
        self.callee_return_param_deps = callee_return_param_deps
        self.callee_param_names = callee_param_names
        self.callee_returns_value = callee_returns_value
        self.known_callees = known_callees

        # Taint state
        self.tainted: Set[str] = set()
        self.tainted_containers: Set[str] = set()
        self.tainted_container_keys: Dict[str, Set[str]] = {}
        self.tainted_attrs: Dict[str, Set[str]] = {}
        self.alias_parent: Dict[str, str] = {}
        self.alias_members: Dict[str, Set[str]] = {}
        self.has_source = False
        self.returns_tainted = False
        self.params_to_sink: Set[str] = set()
        self.param_taint_outputs: Set[str] = set()
        self.param_key_writes: Dict[str, Set[str]] = {}
        self.param_key_taint_writes: Dict[str, Set[str]] = {}
        self.sinks_found: Set[str] = set()
        self.tainted_sinks: Set[str] = set()
        self.tainted_sink = False
        self.current_params: Set[str] = set()
        self.call_param_taints: Dict[str, Set[str]] = {}
        self.function_depth = 0

    # ------------------------------------------------------------------ visitors
    def visit_FunctionDef(self, node: ast.FunctionDef):
        if self.function_depth > 0:
            return
        self.function_depth += 1
        self.current_params = set(self._collect_function_params(node.args))
        tainted_params = {
            arg
            for arg in self.current_params
            if arg in self.sources or arg in self.entry_tainted_params
        }
        if tainted_params:
            self.tainted.update(tainted_params)
            if tainted_params & self.sources:
                self.has_source = True
        self.generic_visit(node)
        self.function_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign):
        value_is_source = self._expr_is_source(node.value)
        value_is_tainted = self._expr_is_tainted(node.value)

        if value_is_source:
            self.has_source = True

        for target in node.targets:
            if isinstance(target, ast.Name):
                if isinstance(node.value, ast.Name):
                    self._union_alias(target.id, node.value.id)
                if value_is_source or value_is_tainted:
                    if self._expr_is_container(node.value):
                        self._update_container_from_expr(target.id, node.value)
                    else:
                        self.tainted.add(target.id)
                elif (
                    isinstance(node.value, ast.Name)
                    and node.value.id in self.tainted_containers
                ):
                    self._mark_container_tainted(target.id)
                elif isinstance(node.value, ast.Name):
                    src_key = self._alias_key(node.value.id)
                    if src_key in self.tainted_attrs:
                        key = self._alias_key(target.id)
                        self.tainted_attrs[key] = set(self.tainted_attrs[src_key])
                elif self._container_literal_is_tainted(node.value):
                    self._update_container_from_expr(target.id, node.value)
                else:
                    self.tainted_attrs.pop(self._alias_key(target.id), None)
                    self._clear_container_taint(target.id)
            elif isinstance(target, ast.Attribute):
                base, attr = self._attribute_base_and_attr(target)
                if base and attr:
                    base_key = self._alias_key(base)
                    if value_is_source or value_is_tainted:
                        self.tainted_attrs.setdefault(base_key, set()).add(attr)
                        if self._is_param_alias(base):
                            self.param_taint_outputs.add(self._param_name_for(base))
                        self._record_param_key_write(base, attr, value_is_tainted)
                    else:
                        attrs = self.tainted_attrs.get(base_key)
                        if attrs:
                            attrs.discard(attr)
                        self._record_param_key_write(base, attr, False)
            elif isinstance(target, ast.Subscript):
                base = self._subscript_base_name(target.value)
                key = self._subscript_key(target.slice)
                if base and (value_is_source or value_is_tainted):
                    self._mark_container_key_tainted(base, key)
                    if self._is_param_alias(base):
                        self.param_taint_outputs.add(self._param_name_for(base))
                    self._record_param_key_write(base, key, True)
                elif base:
                    self._clear_container_key(base, key)
                    self._record_param_key_write(base, key, False)
            elif isinstance(target, (ast.Tuple, ast.List)):
                # Destructuring assignment
                if value_is_source:
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.tainted.add(elt.id)
                elif value_is_tainted:
                    if isinstance(node.value, (ast.Tuple, ast.List, ast.Set)):
                        for idx, elt in enumerate(target.elts):
                            if isinstance(elt, ast.Name):
                                if idx < len(node.value.elts):
                                    if self._expr_is_tainted(node.value.elts[idx]):
                                        self.tainted.add(elt.id)
                    elif isinstance(node.value, ast.Name) and node.value.id in self.tainted_containers:
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                self.tainted.add(elt.id)
                    else:
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                self.tainted.add(elt.id)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Handle annotated assignments."""
        if not isinstance(node.target, ast.Name):
            self.generic_visit(node)
            return

        target_name = node.target.id
        value_is_source = node.value is not None and self._expr_is_source(node.value)
        value_is_tainted = node.value is not None and self._expr_is_tainted(node.value)

        if value_is_source:
            self.has_source = True

        if node.value is None:
            self.generic_visit(node)
            return

        if isinstance(node.value, ast.Name):
            self._union_alias(target_name, node.value.id)

        if value_is_source or value_is_tainted:
            if self._expr_is_container(node.value):
                self._update_container_from_expr(target_name, node.value)
            else:
                self.tainted.add(target_name)
        elif (
            isinstance(node.value, ast.Name)
            and node.value.id in self.tainted_containers
        ):
            self._mark_container_tainted(target_name)
        elif isinstance(node.value, ast.Name):
            src_key = self._alias_key(node.value.id)
            if src_key in self.tainted_attrs:
                key = self._alias_key(target_name)
                self.tainted_attrs[key] = set(self.tainted_attrs[src_key])
        elif self._container_literal_is_tainted(node.value):
            self._update_container_from_expr(target_name, node.value)
        else:
            self.tainted_attrs.pop(self._alias_key(target_name), None)
            self._clear_container_taint(target_name)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        value_is_tainted = self._expr_is_tainted(node.value)
        if isinstance(node.target, ast.Name):
            if value_is_tainted:
                self.tainted.add(node.target.id)
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted_containers:
                self._mark_container_tainted(node.target.id)
            if isinstance(node.value, ast.Name):
                src_key = self._alias_key(node.value.id)
                if src_key in self.tainted_attrs:
                    key = self._alias_key(node.target.id)
                    self.tainted_attrs[key] = set(self.tainted_attrs[src_key])
        elif isinstance(node.target, ast.Attribute):
            base, attr = self._attribute_base_and_attr(node.target)
            if base and attr and value_is_tainted:
                self.tainted_attrs.setdefault(self._alias_key(base), set()).add(attr)
                if self._is_param_alias(base):
                    self.param_taint_outputs.add(self._param_name_for(base))
                self._record_param_key_write(base, attr, True)
            elif base and attr:
                self._record_param_key_write(base, attr, False)
        elif isinstance(node.target, ast.Subscript):
            base = self._subscript_base_name(node.target.value)
            key = self._subscript_key(node.target.slice)
            if base and value_is_tainted:
                self._mark_container_key_tainted(base, key)
                if self._is_param_alias(base):
                    self.param_taint_outputs.add(self._param_name_for(base))
                self._record_param_key_write(base, key, True)
            elif base:
                self._clear_container_key(base, key)
                self._record_param_key_write(base, key, False)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if node.value is not None and self._expr_is_tainted(node.value):
            self.returns_tainted = True
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete):
        """Track del operations."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.tainted.discard(target.id)
                self._clear_container_taint(target.id)
            elif isinstance(target, ast.Attribute):
                base, attr = self._attribute_base_and_attr(target)
                if base and attr:
                    base_key = self._alias_key(base)
                    attrs = self.tainted_attrs.get(base_key)
                    if attrs:
                        attrs.discard(attr)
            elif isinstance(target, ast.Subscript):
                base = self._subscript_base_name(target.value)
                key = self._subscript_key(target.slice)
                if base:
                    self._clear_container_key(base, key)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        fullname = self._call_fullname(node.func)
        if fullname:
            callee = self._resolve_callee_name(fullname)
            if callee in self.known_callees:
                tainted_params, _ = self._tainted_params_for_call(node, callee)
                if tainted_params:
                    self.call_param_taints.setdefault(callee, set()).update(tainted_params)
                self._apply_callee_param_taint_outputs(node, callee)

        if fullname in self.sinks:
            self.sinks_found.add(fullname)
            tainted_arg = False
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    if self._expr_is_tainted(arg):
                        self.params_to_sink.add(arg.id)
                        tainted_arg = True
                elif isinstance(arg, ast.Subscript):
                    base = self._subscript_base_name(arg.value)
                    if base and self._expr_is_tainted(arg):
                        self.params_to_sink.add(base)
                        tainted_arg = True
                elif self._expr_is_tainted(arg):
                    tainted_arg = True
            for kwd in node.keywords:
                if isinstance(kwd.value, ast.Name):
                    if self._expr_is_tainted(kwd.value):
                        self.params_to_sink.add(kwd.value.id)
                        tainted_arg = True
                elif self._expr_is_tainted(kwd.value):
                    tainted_arg = True
            if tainted_arg:
                self.tainted_sink = True
                self.tainted_sinks.add(fullname)

        if self._expr_is_source(node):
            self.has_source = True

        self._handle_container_calls(node)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match):
        """Handle match statements."""
        subject_is_tainted = self._expr_is_tainted(node.subject)
        for case in node.cases:
            bindings = self._collect_match_bindings(case.pattern)
            for name in bindings:
                if self._binding_captures_subject(case.pattern, name, subject_is_tainted):
                    self.tainted.add(name)
        self.generic_visit(node)

    # -------------------------------------------------------------- predicates
    def _expr_is_source(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in self.sources
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
        if expr is None:
            return False
        if self._expr_is_source(expr):
            return True
        if isinstance(expr, ast.Name) and self._is_container_tainted(expr.id):
            return True
        if isinstance(expr, ast.Name) and expr.id in self.tainted:
            return True
        if isinstance(expr, ast.Subscript):
            base = self._subscript_base_name(expr.value)
            key = self._subscript_key(expr.slice)
            if base and self._is_container_key_tainted(base, key):
                return True
        if isinstance(expr, ast.BinOp):
            return self._expr_is_tainted(expr.left) or self._expr_is_tainted(expr.right)
        if isinstance(expr, ast.BoolOp):
            for value in expr.values:
                if self._expr_is_tainted(value):
                    return True
            return False
        if isinstance(expr, ast.UnaryOp):
            if isinstance(expr.op, ast.Not):
                return False
            return self._expr_is_tainted(expr.operand)
        if isinstance(expr, ast.Compare):
            return False
        if isinstance(expr, ast.IfExp):
            return self._expr_is_tainted(expr.body) or self._expr_is_tainted(
                expr.orelse
            ) or self._expr_is_tainted(expr.test)
        if isinstance(expr, (ast.List, ast.Tuple, Set)):
            return any(self._expr_is_tainted(elt) for elt in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(self._expr_is_tainted(v) for v in expr.values) or any(
                self._expr_is_tainted(k) for k in expr.keys if k is not None
            )
        if isinstance(expr, ast.ListComp):
            return self._comp_is_tainted(expr)
        if isinstance(expr, ast.Call):
            fullname = self._call_fullname(expr.func)
            if fullname == "getattr" and len(expr.args) >= 2:
                base = self._expr_base_name(expr.args[0])
                attr = self._const_str(expr.args[1])
                if base and attr and (
                    attr in self.tainted_attrs.get(base, set())
                    or "*" in self.tainted_attrs.get(base, set())
                ):
                    return True
                if base and not attr and self.tainted_attrs.get(base):
                    return True
                return False
            if self._call_returns_tainted(expr):
                return True
            if fullname and self._call_is_known(fullname):
                return False
            if any(self._expr_is_tainted(arg) for arg in expr.args):
                return True
            return any(self._expr_is_tainted(kwd.value) for kwd in expr.keywords)
        if isinstance(expr, ast.Attribute):
            base, attr = self._attribute_base_and_attr(expr)
            base_key = self._alias_key(base) if base else ""
            if base and attr and (
                attr in self.tainted_attrs.get(base_key, set())
                or "*" in self.tainted_attrs.get(base_key, set())
            ):
                return True
        if isinstance(expr, ast.Lambda):
            return False
        if isinstance(ast.JoinedStr, ast.FormattedValue):
            return self._expr_is_tainted(elt.value)
        return False

    def _call_returns_tainted(self, node: ast.Call) -> bool:
        fullname = self._call_fullname(node.func)
        if not fullname:
            return False
        callee = self._resolve_callee_name(fullname)
        if callee not in self.known_callees:
            return False
        if not self.callee_returns_value.get(callee, True):
            return False
        if self.callee_returns_unconditional.get(callee, False):
            return True
        deps = self.callee_return_param_deps.get(callee, set())
        if deps:
            tainted_params, has_unknown = self._tainted_params_for_call(node, callee)
            if tainted_params & deps:
                return True
            if has_unknown and tainted_params:
                return True
            if self.callee_returns_tainted.get(callee, False) and self.callee_has_source.get(
                callee, False
            ):
                return True
            return False
        return self.callee_returns_tainted.get(callee, False)

    def _tainted_params_for_call(
        self, node: ast.Call, callee: str
    ) -> Tuple[Set[str], bool]:
        param_names = list(self._callee_param_names(node, callee))
        deps = self.callee_return_param_deps.get(callee, set())
        tainted: Set[str] = set()
        has_unknown = False

        if not param_names and deps:
            if any(self._expr_is_tainted(arg) for arg in node.args) or any(
                self._expr_is_tainted(kwd.value) for kwd in node.keywords
            ):
                tainted.update(deps)
                has_unknown = True
            return tainted, has_unknown

        pos_index = 0
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                if self._expr_is_tainted(arg.value):
                    tainted.update(param_names[pos_index:])
                has_unknown = True
                continue
            if pos_index < len(param_names):
                if self._expr_is_tainted(arg):
                    tainted.add(param_names[pos_index])
                pos_index += 1
            else:
                if self._expr_is_tainted(arg):
                    tainted.update(param_names)
                has_unknown = True

        for kwd in node.keywords:
            if kwd.arg is None:
                if self._expr_is_tainted(kwd.value):
                    tainted.update(param_names)
                has_unknown = True
            elif kwd.arg in param_names:
                if self._expr_is_tainted(kwd.value):
                    tainted.add(kwd.arg)

        return tainted, has_unknown

    # -------------------------------------------------------------- helpers
    def _call_fullname(self, func: ast.AST) -> str:
        if isinstance(func, ast.Attribute):
            return self._attribute_name(func)
        if isinstance(func, ast.Name):
            return func.id
        return ""

    def _call_is_known(self, fullname: str) -> bool:
        callee = self._resolve_callee_name(fullname)
        return callee in self.known_callees

    def _resolve_callee_name(self, fullname: str) -> str:
        if fullname in self.known_callees:
            return fullname
        short = fullname.split(".")[-1]
        if short in self.known_callees:
            return short
        return fullname

    def _attribute_name(self, node: ast.Attribute) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    def _subscript_base_name(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return self._attribute_name(expr)
        return ""

    def _subscript_key(self, expr: ast.AST) -> Optional[str]:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        if isinstance(expr, ast.Name):
            return expr.id
        return None

    def _attribute_base_and_attr(self, node: ast.Attribute) -> Tuple[str, str]:
        base = self._expr_base_name(node.value)
        return base, node.attr

    def _expr_base_name(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return self._attribute_name(expr)
        return ""

    def _const_str(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return expr.value
        return ""

    def _container_literal_is_tainted(self, expr: ast.AST) -> bool:
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(elt) for elt in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(self._expr_is_tainted(v) for v in expr.values) or any(
                self._expr_is_tainted(k) for k in expr.keys if k is not None
            )
        if isinstance(expr, ast.ListComp):
            return self._comp_is_tainted(expr)
        return False

    def _expr_is_container(self, expr: ast.AST) -> bool:
        return isinstance(
            expr,
            (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.ListComp),
        )

    def _comp_is_tainted(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.DictComp):
            if self._expr_is_tainted(expr.key) or self._expr_is_tainted(expr.value):
                return True
            generators = expr.generators
        else:
            if self._expr_is_tainted(expr.elt):
                return True
            generators = expr.generators
        for gen in generators:
            if self._expr_is_tainted(gen.iter):
                return True
            if any(self._expr_is_tainted(cond) for cond in gen.ifs):
                return True
        return False

    def _collect_function_params(self, args: ast.arguments) -> List[str]:
        names: List[str] = []
        for arg in getattr(args, "posonlyargs", []):
            names.append(arg.arg)
        for arg in args.args:
            names.append(arg.arg)
        for arg in args.kwonlyargs:
            names.append(arg.arg)
        if args.vararg:
            names.append(args.vararg.arg)
        if args.kwarg:
            names.append(args.kwarg.arg)
        return names

    def _handle_container_calls(self, node: ast.Call):
        if not isinstance(node.func, ast.Attribute):
            return
        method = node.func.attr
        container_name = self._attribute_name(node.func.value)

        if method in {"append", "extend", "insert", "add", "update", "setdefault"}:
            if any(self._expr_is_tainted(arg) for arg in node.args):
                self._mark_container_tainted(container_name)
        elif method == "clear":
            for name in self._aliases_for(container_name):
                self.tainted_containers.discard(name)

    def _collect_match_bindings(self, pattern: ast.pattern) -> Set[str]:
        names: Set[str] = set()
        if isinstance(pattern, ast.MatchAs):
            if pattern.name:
                names.add(pattern.name)
            if pattern.pattern:
                names.update(self._collect_match_bindings(pattern.pattern))
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name:
                names.add(pattern.name)
        elif isinstance(pattern, ast.MatchMapping):
            for subpattern in pattern.patterns:
                names.update(self._collect_match_bindings(subpattern))
            if pattern.rest:
                names.add(pattern.rest)
        elif isinstance(pattern, ast.MatchSequence):
            for subpattern in pattern.patterns:
                names.update(self._collect_match_bindings(subpattern))
        elif isinstance(pattern, ast.MatchClass):
            for subpattern in pattern.patterns:
                names.update(self._collect_match_bindings(subpattern))
            for subpattern in pattern.kwd_patterns:
                names.update(self._collect_match_bindings(subpattern))
        return names

    def _binding_captures_subject(self, pattern: ast.pattern, binding_name: str, subject_is_tainted: bool) -> bool:
        if not subject_is_tainted:
            return False
        if isinstance(pattern, ast.MatchAs):
            if pattern.name == binding_name:
                return True
            if pattern.pattern:
                return self._binding_captures_subject(pattern.pattern, binding_name, subject_is_tainted)
        return False

    def _apply_callee_param_taint_outputs(self, node: ast.Call, callee: str) -> None:
        outputs = self.callee_param_taint_outputs.get(callee, set())
        param_names = self._callee_param_names(node, callee)
        for idx, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred):
                if idx < len(param_names) and param_names[idx] in outputs:
                    for name in self._names_in_expr(arg.value):
                        self._mark_container_tainted(name)
                continue
            if idx < len(param_names) and param_names[idx] in outputs:
                for name in self._names_in_expr(arg):
                    self._mark_container_tainted(name)
        for kwd in node.keywords:
            if kwd.arg and kwd.arg in outputs:
                for name in self._names_in_expr(kwd.value):
                    self._mark_container_tainted(name)
        self._apply_callee_param_key_effects(node, callee)

    def _apply_callee_param_key_effects(self, node: ast.Call, callee: str) -> None:
        writes = self.callee_param_key_writes.get(callee, {})
        taint_writes = self.callee_param_key_taint_writes.get(callee, {})
        if not writes and not taint_writes:
            return
        param_names = self._callee_param_names(node, callee)
        for idx, arg in enumerate(node.args):
            if idx >= len(param_names):
                break
            param = param_names[idx]
            keys = writes.get(param, set())
            tainted_keys = taint_writes.get(param, set())
            if not keys and not tainted_keys:
                continue
            self._apply_param_key_effects_to_arg(arg, keys, tainted_keys)
        for kwd in node.keywords:
            if kwd.arg is None:
                continue
            param = kwd.arg
            keys = writes.get(param, set())
            tainted_keys = taint_writes.get(param, set())
            if not keys and not tainted_keys:
                continue
            self._apply_param_key_effects_to_arg(kwd.value, keys, tainted_keys)

    def _apply_param_key_effects_to_arg(
        self, arg: ast.AST, keys: Set[str], tainted_keys: Set[str]
    ) -> None:
        for name in self._names_in_expr(arg):
            for key in tainted_keys:
                self._mark_container_key_tainted(name, key if key != "*" else None)
            for key in keys - tainted_keys:
                if key == "*":
                    continue
                self._clear_container_key(name, key)

    def _names_in_expr(self, expr: ast.AST) -> Set[str]:
        if isinstance(expr, ast.Name):
            return {expr.id}
        if isinstance(expr, ast.Attribute):
            base = self._expr_base_name(expr)
            return {base} if base else set()
        if isinstance(expr, ast.Subscript):
            base = self._subscript_base_name(expr.value)
            return {base} if base else set()
        return set()

    def _record_param_key_write(self, base: str, key: Optional[str], tainted: bool) -> None:
        param = self._param_name_for(base)
        if not param:
            return
        key_name = key if key is not None else "*"
        self.param_key_writes.setdefault(param, set()).add(key_name)
        if tainted:
            self.param_key_taint_writes.setdefault(param, set()).add(key_name)

    def _ensure_alias(self, name: str) -> None:
        if name not in self.alias_parent:
            self.alias_parent[name] = name
            self.alias_members[name] = {name}

    def _find_alias(self, name: str) -> str:
        self._ensure_alias(name)
        parent = self.alias_parent[name]
        if parent != name:
            parent = self._find_alias(parent)
            self.alias_parent[name] = parent
        return parent

    def _union_alias(self, left: str, right: str) -> None:
        left_root = self._find_alias(left)
        right_root = self._find_alias(right)
        if left_root == right_root:
            return
        left_members = self.alias_members.get(left_root, {left_root})
        right_members = self.alias_members.get(right_root, {right_root})
        if len(left_members) < len(right_members):
            left_root, right_root = right_root, left_root
            left_members, right_members = right_members, left_members
        self.alias_parent[right_root] = left_root
        left_members.update(right_members)
        self.alias_members[left_root] = left_members
        self.alias_members.pop(right_root, None)
        if any(member in self.tainted_containers for member in left_members):
            for member in left_members:
                self.tainted_containers.add(member)
        for member in left_members:
            if member in self.tainted_container_keys:
                self._merge_container_keys(left_root, member)

    def _aliases_for(self, name: str) -> Set[str]:
        root = self._find_alias(name)
        return set(self.alias_members.get(root, {name}))

    def _alias_key(self, name: str) -> str:
        return self._find_alias(name)

    def _mark_container_tainted(self, name: str) -> None:
        for alias in self._aliases_for(name):
            self.tainted_containers.add(alias)

    def _is_container_tainted(self, name: str) -> bool:
        for alias in self._aliases_for(name):
            if alias in self.tainted_containers:
                return True
            keys = self.tainted_container_keys.get(alias)
            if keys:
                return True
        return False

    def _is_container_key_tainted(self, name: str, key: Optional[str]) -> bool:
        for alias in self._aliases_for(name):
            if alias in self.tainted_containers:
                return True
            keys = self.tainted_container_keys.get(alias, set())
            if not keys:
                continue
            if key is None:
                return True
            if "*" in keys or key in keys:
                return True
        return False

    def _mark_container_key_tainted(self, name: str, key: Optional[str]) -> None:
        for alias in self._aliases_for(name):
            self._ensure_container_key(alias, key)

    def _clear_container_key(self, name: str, key: Optional[str]) -> None:
        for alias in self._aliases_for(name):
            if alias not in self.tainted_container_keys:
                continue
            if key is None:
                self.tainted_container_keys.pop(alias, None)
                continue
            keys = self.tainted_container_keys[alias]
            keys.discard(key)
            if not keys:
                self.tainted_container_keys.pop(alias, None)

    def _ensure_container_key(self, name: str, key: Optional[str]) -> None:
        if key is None:
            self.tainted_container_keys.setdefault(name, set()).add("*")
            return
        self.tainted_container_keys.setdefault(name, set()).add(key)

    def _merge_container_keys(self, root: str, member: str) -> None:
        keys = self.tainted_container_keys.get(member)
        if not keys:
            return
        self.tainted_container_keys.setdefault(root, set()).update(keys)
        if member != root:
            self.tainted_container_keys.pop(member, None)

    def _clear_container_taint(self, name: str) -> None:
        self.tainted_containers.discard(name)
        self.tainted_container_keys.pop(name, None)

    def _update_container_from_expr(self, name: str, expr: ast.AST) -> None:
        keys = self._tainted_container_keys(expr)
        if keys is not None:
            for key in keys:
                self._mark_container_key_tainted(name, key)
        else:
            self._mark_container_tainted(name)

    def _tainted_container_keys(self, expr: ast.AST) -> Optional[Set[str]]:
        if isinstance(expr, ast.Dict):
            keys: Set[str] = set()
            has_tainted = False
            for k in expr.keys:
                if k is None:
                    continue
                if self._expr_is_tainted(k):
                    keys.add("*")
                elif isinstance(k, ast.Constant):
                    keys.add(k.value)
                elif isinstance(k, ast.Name):
                    keys.add(k.id)
            for v in expr.values:
                if self._expr_is_tainted(v):
                    has_tainted = True
            if keys or has_tainted:
                return keys if keys else None
            return None
        if isinstance(expr, ast.List):
            if any(self._expr_is_tainted(elt) for elt in expr.elts):
                return None
        return None

    def _callee_param_names(self, node: ast.Call, callee: str) -> List[str]:
        params = self.callee_param_names.get(callee, [])
        if isinstance(node.func, ast.Attribute) and params and params[0] in {"self", "cls"}:
            return params[1:]
        return params

    def _is_param_alias(self, name: str) -> bool:
        """Check if a variable is an alias to a function parameter."""
        param = self._param_name_for(name)
        return param is not None

    def _param_name_for(self, name: str) -> Optional[str]:
        """Get the parameter name that this variable may be aliased to."""
        alias_root = self._find_alias(name)
        for param in self.current_params:
            if self._find_alias(param) == alias_root:
                return param
        return None
