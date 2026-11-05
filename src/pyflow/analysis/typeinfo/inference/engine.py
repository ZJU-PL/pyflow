"""Standalone flow-sensitive and interprocedural static type inference.

The engine deliberately has no dependency on CPA, IPA, alias analysis, or the
store graph.  It performs a deterministic abstract interpretation of Python
source, seeded by annotations and optional external symbol facts.  The design
is monotone: recursive call graphs and loops are solved to a fixed point with
bounded union widening.

This is an analysis engine rather than a PEP-compliance type checker.  It aims
to produce conservative semantic facts for PyFlow clients while retaining
uncertainty and provenance instead of reporting every typing-language error.
"""

from __future__ import annotations

import ast
import tokenize
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from pyflow.analysis.typeinfo.core.typesystem import ProperType, TypeSystem, TypeVarType
from pyflow.analysis.typeinfo.inference._engine.builtins import BuiltinInference
from pyflow.analysis.typeinfo.inference._engine.calls import CallInference
from pyflow.analysis.typeinfo.inference._engine.compatibility import CompatibilityInference
from pyflow.analysis.typeinfo.inference._engine.declarations import DeclarationInference
from pyflow.analysis.typeinfo.inference._engine.expressions import ExpressionInference
from pyflow.analysis.typeinfo.inference._engine.flow import FlowInference
from pyflow.analysis.typeinfo.inference._engine.functions import FunctionInference
from pyflow.analysis.typeinfo.inference._engine.members import MemberInference
from pyflow.analysis.typeinfo.inference._engine.narrowing import NarrowingInference
from pyflow.analysis.typeinfo.inference._engine.operators import OperatorInference
from pyflow.analysis.typeinfo.inference._engine.state import _ClassInfo, _FunctionInfo, _span
from pyflow.analysis.typeinfo.inference._engine.stdlib import StdlibInference
from pyflow.analysis.typeinfo.inference._engine.values import ValueInference
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue
from pyflow.analysis.typeinfo.resolution.typeshed_resolver import (
    resolve_typeshed_method_kind,
    resolve_typeshed_symbol,
)
from pyflow.analysis.typeinfo.inference.models import (
    InferenceDiagnostic,
    InferenceProvenance,
    InferredSymbol,
    ModuleInferenceResult,
    SourceSpan,
)
from pyflow.language.modules.project_resolution import ProjectContext

ExternalSymbolResolver = Callable[[str], ProperType | None]
MethodKindResolver = Callable[[str], str | None]


@dataclass(frozen=True)
class InferenceOptions:
    """Precision and termination policy for static inference."""

    max_iterations: int = 24
    max_loop_iterations: int = 12
    max_union_size: int = 16
    strict_annotations: bool = False
    max_specializations_per_function: int = 32
    max_type_depth: int = 12


class StaticTypeInferenceEngine:
    """Infer source-level types without relying on other PyFlow analyses."""

    # Shared solver state. Components read and update these fields directly.
    _module_name: str
    _filename: str
    _tree: ast.Module
    _source_lines: list[str]
    _imports: dict[str, str]
    _star_imports: list[str]
    _module_names: set[str]
    _functions: dict[str, _FunctionInfo]
    _overloads: dict[str, list[_FunctionInfo]]
    _function_nodes: dict[int, str]
    _classes: dict[str, _ClassInfo]
    _class_aliases: dict[str, str]
    _type_vars: dict[str, TypeVarType]
    _annotation_owner: str | None
    _resolving_attributes: set[tuple[str, str]]
    _type_aliases: dict[str, ast.expr]
    _value_assignments: set[str]
    _function_names: set[str]
    _alias_type_variables: dict[str, dict[str, TypeVarType]]
    _resolving_aliases: set[str]
    _annotation_substitutions: dict[str, ProperType]
    _expressions: dict[SourceSpan, AbstractTypeValue]
    _expression_kinds: dict[SourceSpan, type]
    _diagnostics: list[InferenceDiagnostic]
    _diagnostic_keys: set[tuple[str, str, SourceSpan | None]]
    _persistent_diagnostics: list[InferenceDiagnostic]
    _persistent_keys: set[tuple[str, str, SourceSpan | None]]
    _pending_parameter_evidence: dict[tuple[str, str], AbstractTypeValue]
    _pending_attributes: dict[tuple[str, str], AbstractTypeValue]
    _module_environment: dict[str, AbstractTypeValue]
    _inherited_members: dict[tuple[str, str], ProperType | None]
    _external_type_parameters: dict[str, tuple[str, ...]]
    _protocol_match_stack: set[tuple[str, str]]
    _declared_annotations: dict[str, tuple[int, ProperType]]
    _last_argument_mutations: list[tuple[ast.expr, AbstractTypeValue]]
    _observed_yields: list[AbstractTypeValue]
    _call_unknown_positional: bool
    _call_unknown_keywords: bool
    _current_function_info: _FunctionInfo | None
    _mro_cache: dict[str, list[str]]
    _recursive_functions: dict[str, bool]
    _mutual_recursion: set[str]
    _recursion_graph_size: int
    _collect_specializations: bool

    def __init__(
        self,
        project_context: ProjectContext | None = None,
        *,
        type_system: TypeSystem | None = None,
        external_symbol_resolver: ExternalSymbolResolver | None = None,
        external_method_kind: MethodKindResolver | None = None,
        call_model_providers: Iterable[CallModelProvider] = (),
        options: InferenceOptions | None = None,
    ) -> None:
        self.project_context = project_context or ProjectContext(None)
        self.type_system = type_system or TypeSystem()
        self.type_system.enable_numeric_tower()
        self.external_symbol_resolver = (
            external_symbol_resolver
            if external_symbol_resolver is not None
            else resolve_typeshed_symbol
        )
        self.external_method_kind = (
            external_method_kind
            if external_method_kind is not None
            else resolve_typeshed_method_kind
        )
        self.call_model_providers = tuple(call_model_providers)
        self.options = options or InferenceOptions()
        self._synthetic_types: dict[str, type] = {}
        self._registered_hierarchy: set[type] = set()
        self._declaration_rules = DeclarationInference(self)
        self._function_rules = FunctionInference(self)
        self._flow_rules = FlowInference(self)
        self._expression_rules = ExpressionInference(self)
        self._call_rules = CallInference(self)
        self._stdlib_rules = StdlibInference(self)
        self._builtin_rules = BuiltinInference(self)
        self._operator_rules = OperatorInference(self)
        self._narrowing_rules = NarrowingInference(self)
        self._compatibility_rules = CompatibilityInference(self)
        self._member_rules = MemberInference(self)
        self._value_rules = ValueInference(self)
        self._reset()

    def infer_source(
        self,
        module_name: str,
        source: str,
        *,
        filename: str | None = None,
    ) -> ModuleInferenceResult:
        """Infer all supported facts in one Python source module."""
        self._reset()
        self._module_name = module_name
        self._filename = filename or f"<{module_name}>"
        try:
            self._tree = ast.parse(source, filename=self._filename)
        except SyntaxError as exc:
            return ModuleInferenceResult(
                module_name=module_name,
                diagnostics=[
                    InferenceDiagnostic(
                        code="syntax-error",
                        message=str(exc),
                        severity="error",
                        span=SourceSpan(exc.lineno or 1, exc.offset or 0),
                    )
                ],
                converged=False,
            )
        self._source_lines = source.splitlines()

        self._declaration_rules._collect_imports(self._tree)
        self._declaration_rules._precollect_classes(self._tree.body, parent=module_name)
        self._declaration_rules._collect_type_variables(self._tree.body)
        self._declaration_rules._collect_declarations(self._tree.body, parent=module_name)
        self.type_system.invalidate_subtype_caches()
        self._function_rules._refresh_effective_returns()

        self._persistent_diagnostics = list(self._diagnostics)
        self._persistent_keys = set(self._diagnostic_keys)

        module_environment: dict[str, AbstractTypeValue] = {}
        converged = False
        iterations = 0
        for iterations in range(1, self.options.max_iterations + 1):
            before = self._function_rules._fingerprint()
            self._diagnostics = list(self._persistent_diagnostics)
            self._diagnostic_keys = set(self._persistent_keys)
            self._expressions.clear()
            self._expression_kinds.clear()
            self._pending_parameter_evidence.clear()
            self._pending_attributes.clear()
            self.type_system.invalidate_subtype_caches()

            initial = self._declaration_rules._declaration_environment()
            outcome = self._flow_rules._execute_block(
                self._tree.body,
                initial,
                scope=module_name,
                current_function=None,
            )
            module_environment = outcome.environment
            # Module-level constants, settings, and imports are visible inside
            # functions.  Publish the current pass before analyzing bodies and
            # let the fixed point refine it.
            self._module_environment = dict(module_environment)

            # Function bodies may discover lambda callables. Analyze a stable
            # snapshot; newly registered functions participate next iteration.
            self._function_rules._refresh_mutual_recursion()
            for function in list(self._functions.values()):
                self._function_rules._analyse_function(function)

            self._function_rules._commit_pending_evidence()
            self._function_rules._refresh_effective_returns()
            # Protocol/container checks read the descriptor member table, so
            # refresh it before the next fixed-point pass uses this iteration's
            # summaries (unannotated ``__iter__``/property methods otherwise
            # look like ``Callable[..., Any]`` during the checks).
            self._declaration_rules._refresh_class_member_signatures()
            if self._function_rules._fingerprint() == before:
                converged = True
                break

        if not converged:
            self._add_diagnostic(
                "inference-did-not-converge",
                f"Inference reached the {self.options.max_iterations}-iteration limit",
                severity="warning",
            )

        self._declaration_rules._refresh_class_member_signatures()

        symbols = self._build_symbols(module_environment)
        return ModuleInferenceResult(
            module_name=module_name,
            symbols=symbols,
            functions={
                name: info.summary
                for name, info in self._functions.items()
                if info.summary is not None
            },
            expressions=dict(self._expressions),
            expression_kinds=dict(self._expression_kinds),
            diagnostics=list(self._diagnostics),
            iterations=iterations,
            converged=converged,
        )

    def infer_module(
        self,
        module_name: str,
        *,
        path: str | None = None,
    ) -> ModuleInferenceResult:
        """Load and infer a module through the configured project context."""
        if path is None:
            resolution = self.project_context.find_module(module_name)
            path = None if resolution is None else resolution.path
        if path is None:
            return ModuleInferenceResult(
                module_name=module_name,
                diagnostics=[
                    InferenceDiagnostic(
                        code="module-not-found",
                        message=f"Could not resolve module {module_name!r}",
                        severity="error",
                    )
                ],
                converged=False,
            )
        source = self.project_context.source_files.get(path)
        if source is None:
            try:
                with tokenize.open(path) as source_file:
                    source = source_file.read()
            except OSError as exc:
                return ModuleInferenceResult(
                    module_name=module_name,
                    diagnostics=[
                        InferenceDiagnostic(
                            code="module-read-error",
                            message=str(exc),
                            severity="error",
                        )
                    ],
                    converged=False,
                )
        return self.infer_source(module_name, source, filename=path)

    def _reset(self) -> None:
        for full_name in self._synthetic_types:
            self.type_system.forget_class_descriptor(full_name)
        self._synthetic_types.clear()
        self._registered_hierarchy.clear()
        self.type_system.invalidate_subtype_caches()
        self._module_name = ""
        self._filename = ""
        self._tree = ast.Module(body=[], type_ignores=[])
        self._source_lines = []
        self._imports = {}
        self._star_imports = []
        # Local names bound to module objects by ``import x [as y]``.  These
        # must never be resolved through bare-name class aliases such as
        # ``time`` -> ``datetime.time``.
        self._module_names = set()
        self._functions = {}
        self._overloads = {}
        self._function_nodes = {}
        self._classes = {}
        self._class_aliases = {}
        self._type_vars = {}
        self._annotation_owner = None
        self._resolving_attributes = set()
        self._type_aliases = {}
        self._value_assignments = set()
        self._function_names = set()
        self._alias_type_variables = {}
        self._resolving_aliases = set()
        self._annotation_substitutions = {}
        self._expressions = {}
        self._expression_kinds = {}
        self._diagnostics = []
        self._diagnostic_keys = set()
        self._persistent_diagnostics = []
        self._persistent_keys = set()
        self._pending_parameter_evidence = {}
        self._pending_attributes = {}
        self._module_environment = {}
        self._inherited_members = {}
        self._external_type_parameters = {}
        self._protocol_match_stack = set()
        # Explicit annotations of ``name: T`` declarations, keyed by scope.
        # Later plain assignments to that name are checked against them.
        self._declared_annotations = {}
        self._last_argument_mutations = []
        self._observed_yields = []
        self._call_unknown_positional = False
        self._call_unknown_keywords = False
        self._current_function_info = None
        self._mro_cache = {}
        self._recursive_functions = {}
        self._mutual_recursion = set()
        self._recursion_graph_size = -1
        self._collect_specializations = True

    def _record_expression(self, node: ast.AST, value: AbstractTypeValue) -> None:
        span = _span(node)
        old = self._expressions.get(span)
        self._expressions[span] = value if old is None else self._value_rules._join(old, value)
        self._expression_kinds.setdefault(span, type(node))

    def _build_symbols(
        self, environment: dict[str, AbstractTypeValue]
    ) -> dict[str, InferredSymbol]:
        symbols: dict[str, InferredSymbol] = {}
        for name, value in environment.items():
            qualified = f"{self._module_name}.{name}"
            if qualified in self._classes:
                # ``type_of("module.Class")`` is the declaration-oriented view
                # used by annotation resolution.  Strip the class-object marker
                # so it continues to project to the instance type; assignments
                # such as ``alias = Class`` retain it and project to type[T].
                value = replace(value, class_targets=frozenset())
            symbols[qualified] = InferredSymbol(
                qualified,
                value,
                (
                    InferenceProvenance(
                        source="static-inference",
                        detail="module fixed point",
                    ),
                ),
            )
        for owner, class_info in self._classes.items():
            for attribute, value in class_info.attributes.items():
                qualified = f"{owner}.{attribute}"
                symbols[qualified] = InferredSymbol(
                    qualified,
                    value,
                    (InferenceProvenance(source="class-analysis"),),
                )
        return symbols

    def _add_diagnostic(
        self,
        code: str,
        message: str,
        *,
        node: ast.AST | None = None,
        severity: str = "warning",
        affects_completeness: bool = False,
    ) -> None:
        span = None if node is None else _span(node)
        if (
            span is not None
            and 0 < span.lineno <= len(self._source_lines)
            and (
                "# type: ignore" in self._source_lines[span.lineno - 1]
                or "# pyright: ignore" in self._source_lines[span.lineno - 1]
            )
        ):
            return
        key = (code, message, span)
        if key in self._diagnostic_keys:
            return
        self._diagnostic_keys.add(key)
        diagnostic = InferenceDiagnostic(
            code,
            message,
            severity=severity,
            span=span,
            affects_completeness=affects_completeness,
        )
        self._diagnostics.append(diagnostic)
        if code in {"specialization-budget-exceeded", "unresolved-annotation"} and hasattr(
            self, "_persistent_diagnostics"
        ):
            if key not in self._persistent_keys:
                self._persistent_keys.add(key)
                self._persistent_diagnostics.append(diagnostic)
