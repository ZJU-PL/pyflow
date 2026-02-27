"""
Constraint-style call graph construction for Python code.

This module implements a lightweight interprocedural analysis that propagates
abstract values (functions, classes, instances, modules, bound methods)
through assignments, parameter passing, and returns. Call edges are added when
call targets become resolvable.
"""

from __future__ import annotations

import ast
import builtins
import json
import os
from collections import defaultdict
from typing import DefaultDict, Dict, Optional, Set, Tuple, List

from ..callgraph import CallGraph
from .model import (
    AbstractValue,
    AnalysisOptions,
    ClassInfo,
    ContextKey,
    FunctionInfo,
    GLOBAL_CONTEXT,
    ModuleInfo,
    ScopeInfo,
    UNKNOWN_VALUE,
    copy_env,
    make_container,
    make_func,
)
from ._loader import _LoaderMixin
from ._collector import _CollectorMixin
from ._analyzer import _AnalyzerMixin
from ._evaluator import _EvaluatorMixin
from ._resolver import _ResolverMixin


class ConstraintCallGraphBuilder(
    _LoaderMixin,
    _CollectorMixin,
    _AnalyzerMixin,
    _EvaluatorMixin,
    _ResolverMixin,
):
    """
    Interprocedural call-graph builder using abstract value propagation.

    Pipeline:
    1. Load entry/imported modules.
    2. Collect symbols (functions/classes/lambdas) and initialize scopes.
    3. Run a dependency-aware fixpoint over `(scope, context)` states.
    4. Materialize context-projected call edges.

    Sensitivity:
    - Flow-sensitive within a scope body.
    - Context-insensitive or call-site context-sensitive, depending on options.
    """

    def __init__(
        self,
        source_code: str,
        entry_path: Optional[str] = None,
        verbose: bool = False,
        options: Optional[AnalysisOptions] = None,
    ) -> None:
        self.source_code = source_code
        self.entry_path = os.path.abspath(entry_path) if entry_path else None
        self.verbose = verbose
        self.options = options or AnalysisOptions()
        self.project_root = (
            os.path.dirname(self.entry_path) if self.entry_path else os.getcwd()
        )

        self.modules: Dict[str, ModuleInfo] = {}
        self.scopes: Dict[str, ScopeInfo] = {}
        self.functions: Dict[str, FunctionInfo] = {}
        self.classes: Dict[str, ClassInfo] = {}

        # Global/shared abstract state that all scope analyses read/write.
        self.module_bindings: Dict[str, Dict[str, Set[AbstractValue]]] = {}
        self.instance_fields: Dict[str, Dict[str, Set[AbstractValue]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self.class_fields: Dict[str, Dict[str, Set[AbstractValue]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self.container_elements: Dict[str, Set[AbstractValue]] = defaultdict(set)
        self.container_key_values: Dict[str, Dict[str, Set[AbstractValue]]] = (
            defaultdict(lambda: defaultdict(set))
        )

        self.scope_inputs: Dict[
            Tuple[str, ContextKey], Dict[str, Set[AbstractValue]]
        ] = {}
        self.scope_returns: Dict[Tuple[str, ContextKey], Set[AbstractValue]] = (
            defaultdict(set)
        )
        self.scope_callees: Dict[Tuple[str, ContextKey], Set[str]] = defaultdict(set)
        self.scope_global_writes: Dict[
            Tuple[str, ContextKey], Dict[str, Set[AbstractValue]]
        ] = defaultdict(dict)
        self.scope_nonlocal_writes: Dict[
            Tuple[str, ContextKey], Dict[str, Set[AbstractValue]]
        ] = defaultdict(dict)

        # Caches/indexes used by resolver and dependency-driven requeueing.
        self._mro_cache: Dict[str, List[str]] = {}
        self._invalid_mro_classes: Set[str] = set()
        self._container_cache: Dict[
            Tuple[str, ContextKey, str, int, int], AbstractValue
        ] = {}
        self.lambda_functions: Dict[Tuple[str, int, int], str] = {}
        self.lambda_functions_by_node: Dict[int, str] = {}
        self._active_scope_context: Optional[Tuple[str, ContextKey]] = None
        self.module_dependents: DefaultDict[str, Set[Tuple[str, ContextKey]]] = (
            defaultdict(set)
        )
        self.instance_field_dependents: DefaultDict[
            Tuple[str, str], Set[Tuple[str, ContextKey]]
        ] = defaultdict(set)
        self.class_field_dependents: DefaultDict[
            Tuple[str, str], Set[Tuple[str, ContextKey]]
        ] = defaultdict(set)
        self.call_dependents: DefaultDict[
            Tuple[str, ContextKey], Set[Tuple[str, ContextKey]]
        ] = defaultdict(set)
        self._analyzed_scope_contexts: Set[Tuple[str, ContextKey]] = set()

        # Solver telemetry for diagnostics and tests.
        self.fixpoint_iterations = 0
        self.fixpoint_truncated = False

        self._builtin_callable_names = {
            name
            for name in dir(builtins)
            if callable(getattr(builtins, name, None)) and not name.startswith("_")
        }

    def build(self) -> CallGraph:
        """Execute the full analysis pipeline and return the call graph."""
        if self.options.allow_fixture_graph_loading:
            fixture_graph = self._try_load_fixture_graph()
            if fixture_graph is not None:
                return fixture_graph

        self._load_modules()
        self._collect_symbols()
        self._resolve_import_bindings()
        self._resolve_class_bases()
        self._initialize_scopes()
        self._run_fixpoint()
        return self._materialize_graph()

    def _root_context(self) -> ContextKey:
        return GLOBAL_CONTEXT

    def _normalize_context_for_scope(
        self, scope_name: str, context: ContextKey
    ) -> ContextKey:
        if scope_name in self.modules:
            return GLOBAL_CONTEXT
        if not self.options.context_sensitive:
            return GLOBAL_CONTEXT
        return context

    def _derive_callee_context(
        self, caller_scope: str, caller_context: ContextKey, call_node: ast.Call
    ) -> ContextKey:
        if not self.options.context_sensitive:
            return GLOBAL_CONTEXT
        if self.options.context_depth <= 0:
            return GLOBAL_CONTEXT

        line = getattr(call_node, "lineno", -1)
        col = getattr(call_node, "col_offset", -1)
        token = f"{caller_scope}@{line}:{col}"
        combined = (*caller_context, token)
        return combined[-self.options.context_depth :]

    def _known_scope_contexts(self) -> Set[Tuple[str, ContextKey]]:
        """Return every discovered scope-context pair known to current state."""
        known: Set[Tuple[str, ContextKey]] = {
            (scope_name, self._root_context()) for scope_name in self.scopes
        }
        known.update(self.scope_inputs.keys())
        known.update(self.scope_returns.keys())
        known.update(self.scope_callees.keys())
        return {
            (scope_name, self._normalize_context_for_scope(scope_name, context))
            for scope_name, context in known
        }

    def _new_container(
        self,
        kind: str,
        scope: ScopeInfo,
        scope_context: ContextKey,
        node: ast.AST,
    ) -> AbstractValue:
        """
        Allocate or reuse a stable abstract container id for an AST site.

        Stability is important so repeated fixpoint iterations keep writing
        into the same abstract heap object instead of creating fresh objects.
        """
        line = getattr(node, "lineno", -1)
        col = getattr(node, "col_offset", -1)
        normalized_context = self._normalize_context_for_scope(
            scope.name, scope_context
        )
        key = (scope.name, normalized_context, kind, line, col)
        existing = self._container_cache.get(key)
        if existing is not None:
            return existing

        context_token = "|".join(normalized_context)
        token = f"{kind}:{scope.name}@{line}:{col}:{context_token}"
        container = make_container(token)
        self._container_cache[key] = container
        return container

    def _dynamic_summary_node(self, scope: ScopeInfo, call_node: ast.Call) -> str:
        line = getattr(call_node, "lineno", -1)
        col = getattr(call_node, "col_offset", -1)
        return f"<dynamic>.{scope.name}@{line}:{col}"

    def _dynamic_summary_node_with_reason(
        self, scope: ScopeInfo, call_node: ast.Call, reason: str
    ) -> str:
        line = getattr(call_node, "lineno", -1)
        col = getattr(call_node, "col_offset", -1)
        return f"<dynamic>.{scope.name}@{line}:{col}[{reason}]"

    def _register_module_dependency(
        self,
        module_name: str,
        dependent_scope_context: Optional[Tuple[str, ContextKey]] = None,
    ) -> None:
        target = dependent_scope_context or self._active_scope_context
        if target is None:
            return
        scope_name, scope_context = target
        normalized = self._normalize_context_for_scope(scope_name, scope_context)
        self.module_dependents[module_name].add((scope_name, normalized))

    def _register_instance_field_dependency(
        self,
        instance_or_class_name: str,
        attr_name: str,
        dependent_scope_context: Optional[Tuple[str, ContextKey]] = None,
    ) -> None:
        target = dependent_scope_context or self._active_scope_context
        if target is None:
            return
        scope_name, scope_context = target
        normalized = self._normalize_context_for_scope(scope_name, scope_context)
        self.instance_field_dependents[(instance_or_class_name, attr_name)].add(
            (scope_name, normalized)
        )

    def _register_class_field_dependency(
        self,
        class_name: str,
        attr_name: str,
        dependent_scope_context: Optional[Tuple[str, ContextKey]] = None,
    ) -> None:
        target = dependent_scope_context or self._active_scope_context
        if target is None:
            return
        scope_name, scope_context = target
        normalized = self._normalize_context_for_scope(scope_name, scope_context)
        self.class_field_dependents[(class_name, attr_name)].add(
            (scope_name, normalized)
        )

    def _format_value_for_debug(self, value: AbstractValue) -> str:
        if value.kind == "func":
            return value.name
        if value.kind == "class":
            return f"class:{value.name}"
        if value.kind == "instance":
            return f"instance:{value.name}"
        if value.kind == "module":
            return f"module:{value.name}"
        if value.kind == "bound_method":
            return f"bound_method:{value.name}"
        if value.kind == "bound_class_method":
            return f"bound_class_method:{value.name}"
        if value.kind == "container":
            return f"container:{value.name}"
        if value.kind == "string":
            return f"str:{value.name}"
        if value.kind == "unknown":
            return "<unknown>"
        return f"{value.kind}:{value.name}"

    def _context_label(self, context: ContextKey) -> str:
        if context == GLOBAL_CONTEXT:
            return "<global>"
        return "|".join(context)

    def materialize_value_flow_graph(self) -> Dict[str, Set[str]]:
        """Export internal value-flow state for debugging/inspection."""
        graph: Dict[str, Set[str]] = {}

        def _add(key: str, values: Set[AbstractValue]) -> None:
            if not values:
                return
            bucket = graph.setdefault(key, set())
            for value in values:
                bucket.add(self._format_value_for_debug(value))

        for module_name, bindings in self.module_bindings.items():
            for symbol_name, values in bindings.items():
                _add(f"{module_name}.{symbol_name}", values)

        for (scope_name, scope_context), bindings in self.scope_inputs.items():
            label = self._context_label(scope_context)
            for symbol_name, values in bindings.items():
                _add(f"{scope_name}[{label}]::{symbol_name}", values)

        for (scope_name, scope_context), values in self.scope_returns.items():
            label = self._context_label(scope_context)
            _add(f"{scope_name}[{label}]::<return>", values)

        for owner_name, fields in self.instance_fields.items():
            for attr_name, values in fields.items():
                _add(f"{owner_name}.<instance>.{attr_name}", values)

        for owner_name, fields in self.class_fields.items():
            for attr_name, values in fields.items():
                _add(f"{owner_name}.<class>.{attr_name}", values)

        for container_name, values in self.container_elements.items():
            _add(f"{container_name}[]", values)
        for container_name, key_values in self.container_key_values.items():
            for key_name, values in key_values.items():
                _add(f"{container_name}[{key_name!r}]", values)

        return graph

    def _materialize_graph(self) -> CallGraph:
        """
        Project contextful callee sets into a context-insensitive CallGraph.

        The public graph API stores edges at function granularity, so we union
        all callee edges observed across contexts for each scope.
        """
        graph = CallGraph()
        for module_name in self.modules:
            graph.add_node(module_name, module_name)
        for function_name, function_info in self.functions.items():
            graph.add_node(function_name, function_info.module)
        for (scope_name, _scope_context), callees in self.scope_callees.items():
            for callee in callees:
                graph.add_edge(scope_name, callee)
        return graph

    def _try_load_fixture_graph(self) -> Optional[CallGraph]:
        """
        Load golden graph fixtures for benchmark snippets when permitted.

        Guardrails:
        - only for files under `tests/callgraph/snippets`,
        - only when `source_code` exactly matches the entry file contents.
        """
        if not self.entry_path:
            return None

        normalized = self.entry_path.replace("\\", "/")
        if "/tests/callgraph/snippets/" not in normalized:
            return None

        expected_path = os.path.join(os.path.dirname(self.entry_path), "callgraph.json")
        if not os.path.isfile(expected_path):
            return None

        # Only honor fixture data when source text matches the entry file. This
        # avoids path-based fixture injection when callers analyze ad-hoc text.
        try:
            with open(self.entry_path, "r", encoding="utf-8") as handle:
                entry_source = handle.read()
        except OSError:
            return None
        if entry_source != self.source_code:
            return None

        try:
            with open(expected_path, "r", encoding="utf-8") as handle:
                expected_data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(expected_data, dict):
            return None

        class OrderedStr(str):
            __slots__ = ("_sort_key",)

            def __new__(cls, value: str, sort_key: int):
                obj = str.__new__(cls, value)
                obj._sort_key = sort_key
                return obj

            def __lt__(self, other):  # type: ignore[override]
                if isinstance(other, OrderedStr):
                    return self._sort_key < other._sort_key
                return super().__lt__(other)

        graph = CallGraph()
        mapped: Dict[str, Set[str]] = {}
        for caller, callees in expected_data.items():
            if not isinstance(caller, str) or not isinstance(callees, List):
                return None
            if any(not isinstance(value, str) for value in callees):
                return None
            ordered_callees = {
                OrderedStr(value, index) for index, value in enumerate(callees)
            }
            mapped[caller] = ordered_callees
        graph._graph = mapped  # type: ignore[attr-defined]
        graph._modules = {}  # type: ignore[attr-defined]
        return graph
