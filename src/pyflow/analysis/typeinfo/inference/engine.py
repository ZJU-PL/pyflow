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
from dataclasses import dataclass, field, replace
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
from pyflow.analysis.typeinfo.inference._engine.state import (
    _ClassInfo,
    _FunctionInfo,
    _expression_name,
    _span,
)
from pyflow.analysis.typeinfo.inference._engine.stdlib import StdlibInference
from pyflow.analysis.typeinfo.inference._engine.values import ValueInference
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue
from pyflow.analysis.typeinfo.resolution.typeshed_resolver import (
    resolve_typeshed_declared_return,
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
DeclaredReturnResolver = Callable[[str], bool | None]


@dataclass(frozen=True)
class InferenceOptions:
    """Precision and termination policy for static inference."""

    max_iterations: int = 24
    max_loop_iterations: int = 12
    max_union_size: int = 16
    strict_annotations: bool = False
    # Checked on receivers whose type is declared (parameters, ``self``,
    # ``x: T``); inferred receivers are skipped because an over-specific
    # inferred type would flag code that mypy accepts.
    check_member_access: bool = True
    check_overrides: bool = True
    # mypy-style ``--disable-error-code``: diagnostic codes that are never
    # emitted, and per-code severity overrides ("error" marks the module
    # partial, "warning"/"info" do not).
    disabled_diagnostics: frozenset[str] = frozenset()
    diagnostic_severity: dict[str, str] = field(default_factory=dict)
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
        external_declared_return: DeclaredReturnResolver | None = None,
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
        self.external_declared_return = (
            external_declared_return
            if external_declared_return is not None
            else resolve_typeshed_declared_return
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
        if self.options.check_overrides:
            self._member_rules.check_overrides()
        if self.options.check_member_access:
            # Checking must happen after the fixed point: during the first pass
            # ``self.attr`` assignments from ``__init__`` are not committed yet
            # and every receiver would look incomplete.  mypy also types first
            # and checks the final symbol table.
            self._check_member_access()

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

    def _check_member_access(self) -> None:
        """Post-convergence union-attr/attr-defined pass.

        Only receivers whose type was *declared* are checked: parameters with
        annotations, ``self``, ``x: T`` declarations, annotated instance
        attributes, and variables bound to a call whose callee declares its
        return type.  Types inferred from expressions can be over-specific, and
        reporting them would flag code that mypy accepts.
        """
        module_names = {
            statement.target.id
            for statement in self._tree.body
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)
        }
        module_names.add("self")
        module_names |= self._call_declared_names(self._tree.body, self._module_name)

        def class_attributes(node: ast.ClassDef) -> set[str]:
            names: set[str] = set()
            for statement in node.body:
                if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    names.add(statement.target.id)
            # Annotated instance attributes are usually declared inside
            # ``__init__`` (``self.tags: Tags | None = None``); unannotated
            # assignments stay inferred and are not checkable receivers.
            for statement in ast.walk(node):
                if (
                    isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Attribute)
                    and isinstance(statement.target.value, ast.Name)
                    and statement.target.value.id == "self"
                ):
                    names.add(statement.target.attr)
            return names

        def walk(node: ast.AST, annotated: set[str], attributes: set[str], path: str) -> None:
            if isinstance(node, ast.ClassDef):
                class_scope = attributes | class_attributes(node)
                class_path = f"{path}.{node.name}"
                for child in node.body:
                    walk(child, annotated | {"self"}, class_scope, class_path)
                return
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_path = f"{path}.{node.name}"
                parameters = {
                    argument.arg
                    for argument in (
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    )
                    if argument.annotation is not None
                }
                declared = {
                    statement.target.id
                    for statement in node.body
                    if isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                }
                names = (
                    annotated
                    | parameters
                    | declared
                    | {"self"}
                    | self._call_declared_names(node.body, function_path)
                )
                for child in node.body:
                    walk(child, names, attributes, function_path)
                return
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                receiver_is_declared = isinstance(node.value, ast.Name) and (
                    node.value.id in annotated
                )
                if (
                    not receiver_is_declared
                    and isinstance(node.value, ast.Attribute)
                    and isinstance(node.value.value, ast.Name)
                ):
                    root = node.value.value.id
                    if root == "self" and node.value.attr in attributes:
                        receiver_is_declared = True
                    elif root in annotated:
                        # ``tags.classifier_tags.multi_label``: the chain
                        # starts at a declared variable, so the member type of
                        # each link comes from a known class.
                        receiver_is_declared = True
                if (
                    not receiver_is_declared
                    and isinstance(node.value, ast.Attribute)
                    and isinstance(node.value.value, ast.Call)
                    and self._call_has_declared_return(node.value.value, path)
                ):
                    # ``get_tags(x).classifier_tags.multi_class``: the chain
                    # starts at a call with a declared return type.
                    receiver_is_declared = True
                if receiver_is_declared:
                    base = self._expressions.get(_span(node.value))
                    if base is not None:
                        self._member_rules.report_missing_member(base, node.attr, node)
            for child in ast.iter_child_nodes(node):
                walk(child, annotated, attributes, path)

        for statement in self._tree.body:
            walk(statement, module_names, set(), self._module_name)

    def _call_declared_names(self, statements, scope: str) -> set[str]:
        """Names bound to a call whose return type is declared by the callee."""
        names: set[str] = set()
        for statement in statements:
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            target = statement.targets[0]
            value = statement.value
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Call)
                and self._call_has_declared_return(value, scope)
            ):
                names.add(target.id)
        return names

    def _call_has_declared_return(self, call: ast.Call, scope: str) -> bool:
        callee = _expression_name(call.func)
        if callee is None:
            return False
        qualified = self._value_rules._resolve_lexical_function(callee, scope)
        if qualified is not None:
            info = self._functions.get(qualified)
            if info is not None and info.explicit_return is not None:
                return True
        imported = self._value_rules._resolve_import_name(callee)
        if imported is not None and self.external_declared_return is not None:
            try:
                return bool(self.external_declared_return(imported))
            except (ImportError, LookupError, OSError, RuntimeError):
                return False
        return False

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
        if code in self.options.disabled_diagnostics:
            return
        severity = self.options.diagnostic_severity.get(code, severity)
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
