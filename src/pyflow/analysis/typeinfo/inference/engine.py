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
import builtins
import collections.abc as cabc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, cast

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    NEVER,
    NONE_TYPE,
    CallableType,
    Instance,
    NoneType,
    ProperType,
    TupleType,
    TypeType,
    TypeSystem,
    TypeVarType,
    Variance,
)
from pyflow.analysis.typeinfo.inference.domain import (
    AbstractTypeValue,
    join_all,
)
from pyflow.analysis.typeinfo.inference.call_models import CallModelProvider
from pyflow.analysis.typeinfo.inference.models import (
    FunctionSpecialization,
    FunctionSummary,
    InferenceDiagnostic,
    InferenceProvenance,
    InferredSymbol,
    ModuleInferenceResult,
    SourceSpan,
)
from pyflow.analysis.typeinfo.resolution.annotations import (
    BuiltinTypeLookup,
    TypeLookup,
    resolve_annotation,
)
from pyflow.analysis.typeinfo.resolution.typing_syntax import substitute_type_vars
from pyflow.language.modules.project_resolution import ProjectContext

ExternalSymbolResolver = Callable[[str], ProperType | None]


@dataclass(frozen=True)
class InferenceOptions:
    """Precision and termination policy for static inference."""

    max_iterations: int = 24
    max_loop_iterations: int = 12
    max_union_size: int = 16
    strict_annotations: bool = False
    max_specializations_per_function: int = 32


@dataclass(frozen=True)
class _SpecializationKey:
    """Hashable identity for one normalized callable input context."""

    parameters: tuple[tuple[str, AbstractTypeValue], ...] = ()
    widened: bool = False


@dataclass
class _FunctionInfo:
    qualified_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
    parameter_names: list[str]
    owner: str | None = None
    explicit_parameters: dict[str, AbstractTypeValue] = field(default_factory=dict)
    explicit_return: AbstractTypeValue | None = None
    parameter_evidence: dict[str, AbstractTypeValue] = field(default_factory=dict)
    closure_evidence: dict[str, AbstractTypeValue] = field(default_factory=dict)
    specializations: dict[_SpecializationKey, FunctionSpecialization] = field(
        default_factory=dict
    )
    widened_parameters: dict[str, AbstractTypeValue] = field(default_factory=dict)
    summary: FunctionSummary | None = None


@dataclass
class _ClassInfo:
    qualified_name: str
    instance: Instance
    methods: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, AbstractTypeValue] = field(default_factory=dict)
    bases: tuple[str, ...] = ()


@dataclass
class _Outcome:
    environment: dict[str, AbstractTypeValue]
    returns: list[AbstractTypeValue] = field(default_factory=list)
    yields: list[AbstractTypeValue] = field(default_factory=list)
    terminated: bool = False


class StaticTypeInferenceEngine:
    """Infer source-level types without relying on other PyFlow analyses."""

    def __init__(
        self,
        project_context: ProjectContext | None = None,
        *,
        type_system: TypeSystem | None = None,
        external_symbol_resolver: ExternalSymbolResolver | None = None,
        call_model_providers: Iterable[CallModelProvider] = (),
        options: InferenceOptions | None = None,
    ) -> None:
        self.project_context = project_context or ProjectContext(None)
        self.type_system = type_system or TypeSystem()
        self.type_system.enable_numeric_tower()
        self.external_symbol_resolver = external_symbol_resolver
        self.call_model_providers = tuple(call_model_providers)
        self.options = options or InferenceOptions()
        self._synthetic_types: dict[str, type] = {}
        self._registered_hierarchy: set[type] = set()
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

        self._collect_imports(self._tree)
        self._precollect_classes(self._tree.body, parent=module_name)
        self._collect_type_variables(self._tree.body)
        self._collect_declarations(self._tree.body, parent=module_name)

        module_environment: dict[str, AbstractTypeValue] = {}
        converged = False
        iterations = 0
        for iterations in range(1, self.options.max_iterations + 1):
            before = self._fingerprint()
            self._expressions.clear()
            self._pending_parameter_evidence.clear()
            self._pending_attributes.clear()

            initial = self._declaration_environment()
            outcome = self._execute_block(
                self._tree.body,
                initial,
                scope=module_name,
                current_function=None,
            )
            module_environment = outcome.environment

            for function in self._functions.values():
                self._analyse_function(function)

            self._commit_pending_evidence()
            if self._fingerprint() == before:
                converged = True
                break

        if not converged:
            self._add_diagnostic(
                "inference-did-not-converge",
                f"Inference reached the {self.options.max_iterations}-iteration limit",
                severity="warning",
            )

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
                source = Path(path).read_text(encoding="utf-8")
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
        self._module_name = ""
        self._filename = ""
        self._tree = ast.Module(body=[], type_ignores=[])
        self._imports: dict[str, str] = {}
        self._functions: dict[str, _FunctionInfo] = {}
        self._function_nodes: dict[int, str] = {}
        self._classes: dict[str, _ClassInfo] = {}
        self._class_aliases: dict[str, str] = {}
        self._type_vars: dict[str, TypeVarType] = {}
        self._expressions: dict[SourceSpan, AbstractTypeValue] = {}
        self._diagnostics: list[InferenceDiagnostic] = []
        self._diagnostic_keys: set[tuple[str, str, SourceSpan | None]] = set()
        self._pending_parameter_evidence: dict[
            tuple[str, str], AbstractTypeValue
        ] = {}
        self._pending_attributes: dict[tuple[str, str], AbstractTypeValue] = {}
        self._collect_specializations = True

    # ------------------------------------------------------------------
    # Declaration and annotation discovery
    # ------------------------------------------------------------------

    def _collect_imports(self, tree: ast.Module) -> None:
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self._imports[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    module = self.project_context.resolve_import_name(
                        self._module_name,
                        module or None,
                        node.level,
                        current_path=self._filename,
                    ) or module
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self._imports[local] = (
                        f"{module}.{alias.name}" if module else alias.name
                    )

    def _collect_declarations(
        self,
        statements: Iterable[ast.stmt],
        *,
        parent: str,
        owner: str | None = None,
    ) -> None:
        for node in statements:
            if isinstance(node, ast.ClassDef):
                qualified = f"{parent}.{node.name}"
                class_info = self._classes[qualified]
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(
                        item.target, ast.Name
                    ):
                        class_info.attributes[item.target.id] = (
                            self._annotation_value(item.annotation)
                        )
                self._collect_declarations(
                    node.body,
                    parent=qualified,
                    owner=qualified,
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{parent}.{node.name}"
                parameters = [arg.arg for arg in _all_arguments(node.args)]
                info = _FunctionInfo(
                    qualified_name=qualified,
                    node=node,
                    parameter_names=parameters,
                    owner=owner,
                )
                for arg in _all_arguments(node.args):
                    if arg.annotation is not None:
                        info.explicit_parameters[arg.arg] = self._annotation_value(
                            arg.annotation
                        )
                if node.returns is not None:
                    info.explicit_return = self._annotation_value(node.returns)
                self._functions[qualified] = info
                self._function_nodes[id(node)] = qualified
                if owner is not None:
                    self._classes[owner].methods[node.name] = qualified
                self._collect_declarations(
                    node.body,
                    parent=qualified,
                    owner=None,
                )

    def _precollect_classes(
        self,
        statements: Iterable[ast.stmt],
        *,
        parent: str,
    ) -> None:
        for node in statements:
            if not isinstance(node, ast.ClassDef):
                continue
            qualified = f"{parent}.{node.name}"
            bases = tuple(
                base_name
                for base in node.bases
                if (base_name := self._resolve_class_expression(base)) is not None
            )
            self._classes[qualified] = _ClassInfo(
                qualified,
                self._synthetic_instance(qualified),
                bases=bases,
            )
            self._class_aliases[node.name] = qualified
            for base in bases:
                base_type = self._lookup_annotation_type(base)
                if isinstance(base_type, Instance):
                    self.type_system.add_subclass_edge(
                        super_class=base_type.type,
                        sub_class=self._classes[qualified].instance.type,
                    )
            self._precollect_classes(node.body, parent=qualified)

    def _collect_type_variables(self, statements: Iterable[ast.stmt]) -> None:
        for node in statements:
            if isinstance(node, ast.ClassDef):
                self._collect_type_variables(node.body)
                continue
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            value = node.value
            if not (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Call)
                and isinstance(value.func, (ast.Name, ast.Attribute))
                and _expression_name(value.func) in {"TypeVar", "typing.TypeVar"}
            ):
                continue
            constraints = tuple(
                resolved
                for argument in value.args[1:]
                if (resolved := self._evaluate_type_expression(argument).public_type())
                is not None
            )
            bound = None
            variance = Variance.INVARIANT
            for keyword in value.keywords:
                if keyword.arg == "bound":
                    bound = self._evaluate_type_expression(
                        keyword.value
                    ).public_type()
                elif keyword.arg == "covariant" and isinstance(
                    keyword.value, ast.Constant
                ) and keyword.value.value:
                    variance = Variance.COVARIANT
                elif keyword.arg == "contravariant" and isinstance(
                    keyword.value, ast.Constant
                ) and keyword.value.value:
                    variance = Variance.CONTRAVARIANT
            self._type_vars[target.id] = TypeVarType(
                target.id,
                constraints=constraints,
                bound=bound,
                variance=variance,
            )

    def _annotation_value(self, node: ast.expr) -> AbstractTypeValue:
        try:
            text = ast.unparse(node)
        except Exception:
            return AbstractTypeValue.unresolved()
        resolved = resolve_annotation(
            text,
            cast(TypeLookup, self._lookup_annotation_type),
        )
        return AbstractTypeValue.from_type(resolved)

    def _lookup_annotation_type(self, name: str) -> ProperType | None:
        normalized = name.rsplit(".", 1)[-1]
        type_var = self._type_vars.get(name) or self._type_vars.get(normalized)
        if type_var is not None:
            return type_var
        local = self._class_aliases.get(name) or self._class_aliases.get(normalized)
        if local is not None:
            return self._classes[local].instance

        imported = self._resolve_import_name(name)
        if imported is not None:
            external = self._external_type(imported)
            if external is not None:
                return external
            return self._synthetic_instance(imported)

        builtin = BuiltinTypeLookup()(name)
        if builtin is not None:
            return builtin
        external = self._external_type(name)
        if external is not None:
            return external
        qualified = f"{self._module_name}.{name}"
        if qualified in self._classes:
            return self._classes[qualified].instance
        return None

    # ------------------------------------------------------------------
    # Fixed-point orchestration
    # ------------------------------------------------------------------

    def _declaration_environment(self) -> dict[str, AbstractTypeValue]:
        environment: dict[str, AbstractTypeValue] = {}
        module_prefix = f"{self._module_name}."
        for name, class_info in self._classes.items():
            remainder = name.removeprefix(module_prefix)
            if "." not in remainder:
                environment[remainder] = AbstractTypeValue.from_type(
                    class_info.instance,
                    class_target=name,
                )
        for name, function in self._functions.items():
            remainder = name.removeprefix(module_prefix)
            if "." not in remainder:
                environment[remainder] = self._function_value(function)
        return environment

    def _analyse_function(self, function: _FunctionInfo) -> None:
        for key in sorted(
            function.specializations,
            key=self._specialization_key_fingerprint,
        ):
            previous = function.specializations[key]
            function.specializations[key] = self._analyse_function_context(
                function,
                dict(previous.parameters),
                widened=key.widened,
                collect_specializations=True,
            )

        fallback_parameters = self._fallback_parameters(function)
        fallback = self._analyse_function_context(
            function,
            fallback_parameters,
            collect_specializations=False,
        )
        ordered_specializations = tuple(
            function.specializations[key]
            for key in sorted(
                function.specializations,
                key=self._specialization_key_fingerprint,
            )
        )
        function.summary = FunctionSummary(
            qualified_name=function.qualified_name,
            parameters=fallback.parameter_map,
            return_value=fallback.return_value,
            yield_value=fallback.yield_value,
            return_dependencies=self._return_dependencies(function),
            is_async=isinstance(function.node, ast.AsyncFunctionDef),
            is_generator=not fallback.yield_value.is_bottom,
            specializations=ordered_specializations,
        )

    def _fallback_parameters(
        self, function: _FunctionInfo
    ) -> dict[str, AbstractTypeValue]:
        parameters: dict[str, AbstractTypeValue] = {}
        for index, name in enumerate(function.parameter_names):
            explicit = function.explicit_parameters.get(name)
            if explicit is not None and not explicit.unknown:
                parameters[name] = explicit
                continue
            evidence = function.parameter_evidence.get(
                name, AbstractTypeValue.bottom()
            )
            pending = self._pending_parameter_evidence.get(
                (function.qualified_name, name), AbstractTypeValue.bottom()
            )
            combined = self._join(evidence, pending)
            if not combined.is_bottom:
                parameters[name] = combined
            elif function.owner is not None and index == 0:
                parameters[name] = AbstractTypeValue.from_type(
                    self._classes[function.owner].instance
                )
            else:
                parameters[name] = AbstractTypeValue.unresolved()
        return parameters

    def _analyse_function_context(
        self,
        function: _FunctionInfo,
        parameters: dict[str, AbstractTypeValue],
        *,
        widened: bool = False,
        collect_specializations: bool,
    ) -> FunctionSpecialization:
        environment = self._declaration_environment()
        environment.update(function.closure_evidence)
        substitutions = self._generic_substitutions(function, parameters)
        input_parameters: dict[str, AbstractTypeValue] = {}
        for name in function.parameter_names:
            actual = parameters.get(name, AbstractTypeValue.unresolved())
            explicit = function.explicit_parameters.get(name)
            if explicit is not None and not explicit.unknown:
                explicit_type = explicit.public_type()
                if explicit_type is not None and substitutions:
                    explicit_type = substitute_type_vars(
                        explicit_type, substitutions
                    )
                value = AbstractTypeValue(
                    types=frozenset(
                        () if explicit_type is None else (explicit_type,)
                    ),
                    unknown=explicit.unknown,
                    callable_targets=actual.callable_targets,
                    class_targets=actual.class_targets,
                )
            else:
                value = actual
            environment[name] = value
            input_parameters[name] = value

        node = function.node
        previous_mode = self._collect_specializations
        self._collect_specializations = collect_specializations
        try:
            if isinstance(node, ast.Lambda):
                return_value = self._evaluate_expression(
                    node.body,
                    environment,
                    scope=function.qualified_name,
                    current_function=function,
                )
                yields = AbstractTypeValue.bottom()
            else:
                outcome = self._execute_block(
                    node.body,
                    environment,
                    scope=function.qualified_name,
                    current_function=function,
                )
                returns = list(outcome.returns)
                if not returns:
                    returns.append(
                        AbstractTypeValue.from_type(
                            NEVER if outcome.terminated else NONE_TYPE
                        )
                    )
                return_value = join_all(
                    returns,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
                yields = join_all(
                    outcome.yields,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
        finally:
            self._collect_specializations = previous_mode

        if function.explicit_return is not None:
            explicit_return = function.explicit_return
            returned_type = explicit_return.public_type()
            if returned_type is not None and substitutions:
                explicit_return = AbstractTypeValue.from_type(
                    substitute_type_vars(returned_type, substitutions)
                )
            self._check_annotation_compatibility(
                return_value,
                explicit_return,
                function.node,
                context=f"return of {function.qualified_name}",
            )
            return_value = explicit_return

        return FunctionSpecialization(
            parameters=tuple(
                (name, input_parameters[name])
                for name in function.parameter_names
            ),
            return_value=return_value,
            yield_value=yields,
            widened=widened,
        )

    def _commit_pending_evidence(self) -> None:
        for (target, parameter), value in self._pending_parameter_evidence.items():
            function = self._functions.get(target)
            if function is None or parameter in function.explicit_parameters:
                continue
            old = function.parameter_evidence.get(
                parameter, AbstractTypeValue.bottom()
            )
            function.parameter_evidence[parameter] = old.join(
                value,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
        for (owner, attribute), value in self._pending_attributes.items():
            if (
                not value.types
                and not value.callable_targets
                and not value.class_targets
            ):
                continue
            class_info = self._classes[owner]
            old = class_info.attributes.get(attribute, AbstractTypeValue.bottom())
            class_info.attributes[attribute] = old.join(
                value,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )

    def _fingerprint(self) -> tuple[object, ...]:
        functions = tuple(
            (
                name,
                self._environment_fingerprint(info.parameter_evidence),
                self._environment_fingerprint(info.closure_evidence),
                tuple(
                    (
                        key.widened,
                        tuple(
                            (parameter, self._value_fingerprint(value))
                            for parameter, value in key.parameters
                        ),
                        tuple(
                            (parameter, self._value_fingerprint(value))
                            for parameter, value in specialization.parameters
                        ),
                        self._value_fingerprint(
                            specialization.return_value
                        ),
                        self._value_fingerprint(specialization.yield_value),
                    )
                    for key, specialization in sorted(
                        info.specializations.items(),
                        key=lambda item: self._specialization_key_fingerprint(
                            item[0]
                        ),
                    )
                ),
                self._environment_fingerprint(info.widened_parameters),
                self._summary_fingerprint(info.summary),
            )
            for name, info in sorted(self._functions.items())
        )
        classes = tuple(
            (name, self._environment_fingerprint(info.attributes))
            for name, info in sorted(self._classes.items())
        )
        return functions, classes

    @staticmethod
    def _value_fingerprint(value: AbstractTypeValue) -> tuple[object, ...]:
        return (
            tuple(sorted(str(typ) for typ in value.types)),
            value.unknown,
            tuple(sorted(value.callable_targets)),
            tuple(sorted(value.class_targets)),
        )

    def _environment_fingerprint(
        self, environment: dict[str, AbstractTypeValue]
    ) -> tuple[object, ...]:
        return tuple(
            (name, self._value_fingerprint(value))
            for name, value in sorted(environment.items())
        )

    def _specialization_key_fingerprint(
        self, key: _SpecializationKey
    ) -> tuple[object, ...]:
        return (
            key.widened,
            tuple(
                (name, self._value_fingerprint(value))
                for name, value in key.parameters
            ),
        )

    def _summary_fingerprint(
        self, summary: FunctionSummary | None
    ) -> tuple[object, ...] | None:
        if summary is None:
            return None
        return (
            self._environment_fingerprint(summary.parameters),
            self._value_fingerprint(summary.return_value),
            self._value_fingerprint(summary.yield_value),
            tuple(sorted(summary.return_dependencies)),
            summary.is_async,
            summary.is_generator,
        )

    # ------------------------------------------------------------------
    # Statements and control flow
    # ------------------------------------------------------------------

    def _execute_block(
        self,
        statements: Iterable[ast.stmt],
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> _Outcome:
        current = dict(environment)
        returns: list[AbstractTypeValue] = []
        yields: list[AbstractTypeValue] = []
        terminated = False
        for statement in statements:
            outcome = self._execute_statement(
                statement,
                current,
                scope=scope,
                current_function=current_function,
            )
            current = outcome.environment
            returns.extend(outcome.returns)
            yields.extend(outcome.yields)
            if outcome.terminated:
                terminated = True
                break
        return _Outcome(current, returns, yields, terminated)

    def _execute_statement(
        self,
        node: ast.stmt,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> _Outcome:
        result = dict(environment)
        if isinstance(node, ast.Assign):
            value = self._evaluate_expression(
                node.value, result, scope=scope, current_function=current_function
            )
            if self._is_never_value(value):
                return _Outcome(result, terminated=True)
            for target in node.targets:
                self._assign_target(target, value, result, current_function)
            return _Outcome(result)

        if isinstance(node, ast.AnnAssign):
            annotated = self._annotation_value(node.annotation)
            if node.value is not None:
                inferred = self._evaluate_expression(
                    node.value,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
                if self._is_never_value(inferred):
                    return _Outcome(result, terminated=True)
                self._check_annotation_compatibility(
                    inferred, annotated, node, context="annotated assignment"
                )
            self._assign_target(node.target, annotated, result, current_function)
            return _Outcome(result)

        if isinstance(node, ast.AugAssign):
            left = self._evaluate_expression(
                node.target, result, scope=scope, current_function=current_function
            )
            right = self._evaluate_expression(
                node.value, result, scope=scope, current_function=current_function
            )
            if self._is_never_value(left) or self._is_never_value(right):
                return _Outcome(result, terminated=True)
            value = self._binary_result(left, right, node.op)
            self._assign_target(node.target, value, result, current_function)
            return _Outcome(result)

        if isinstance(node, ast.Expr):
            value = self._evaluate_expression(
                node.value, result, scope=scope, current_function=current_function
            )
            yields = (
                [value]
                if isinstance(node.value, (ast.Yield, ast.YieldFrom))
                else []
            )
            return _Outcome(
                result,
                yields=yields,
                terminated=self._is_never_value(value),
            )

        if isinstance(node, ast.Return):
            value = (
                AbstractTypeValue.from_type(NONE_TYPE)
                if node.value is None
                else self._evaluate_expression(
                    node.value,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
            )
            return _Outcome(result, returns=[value], terminated=True)

        if isinstance(node, ast.If):
            test = self._evaluate_expression(
                node.test, result, scope=scope, current_function=current_function
            )
            if self._is_never_value(test):
                return _Outcome(result, terminated=True)
            true_env = self._narrow_environment(node.test, result, truthy=True)
            false_env = self._narrow_environment(node.test, result, truthy=False)
            true_outcome = self._execute_block(
                node.body,
                true_env,
                scope=scope,
                current_function=current_function,
            )
            false_outcome = self._execute_block(
                node.orelse,
                false_env,
                scope=scope,
                current_function=current_function,
            )
            merged = self._join_environments(
                true_outcome.environment, false_outcome.environment
            )
            return _Outcome(
                merged,
                true_outcome.returns + false_outcome.returns,
                true_outcome.yields + false_outcome.yields,
                true_outcome.terminated and false_outcome.terminated,
            )

        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            return self._execute_loop(
                node,
                result,
                scope=scope,
                current_function=current_function,
            )

        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                context = self._evaluate_expression(
                    item.context_expr,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
                if self._is_never_value(context):
                    return _Outcome(result, terminated=True)
                if item.optional_vars is not None:
                    self._assign_target(
                        item.optional_vars,
                        context,
                        result,
                        current_function,
                    )
            return self._execute_block(
                node.body,
                result,
                scope=scope,
                current_function=current_function,
            )

        if isinstance(node, ast.Try):
            outcomes = [
                self._execute_block(
                    node.body,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
            ]
            for handler in node.handlers:
                handler_env = dict(result)
                if handler.name:
                    exception_type = (
                        self._evaluate_type_expression(handler.type)
                        if handler.type is not None
                        else self._instance(BaseException)
                    )
                    handler_env[handler.name] = exception_type
                outcomes.append(
                    self._execute_block(
                        handler.body,
                        handler_env,
                        scope=scope,
                        current_function=current_function,
                    )
                )
            if node.orelse:
                outcomes.append(
                    self._execute_block(
                        node.orelse,
                        outcomes[0].environment,
                        scope=scope,
                        current_function=current_function,
                    )
                )
            merged = self._join_many_environments(
                outcome.environment for outcome in outcomes
            )
            returns = [value for outcome in outcomes for value in outcome.returns]
            yields = [value for outcome in outcomes for value in outcome.yields]
            if node.finalbody:
                final = self._execute_block(
                    node.finalbody,
                    merged,
                    scope=scope,
                    current_function=current_function,
                )
                merged = final.environment
                returns.extend(final.returns)
                yields.extend(final.yields)
            return _Outcome(merged, returns, yields)

        if isinstance(node, ast.Assert):
            test = self._evaluate_expression(
                node.test, result, scope=scope, current_function=current_function
            )
            if self._is_never_value(test):
                return _Outcome(result, terminated=True)
            return _Outcome(
                self._narrow_environment(node.test, result, truthy=True)
            )

        if isinstance(node, ast.Match):
            subject = self._evaluate_expression(
                node.subject,
                result,
                scope=scope,
                current_function=current_function,
            )
            if self._is_never_value(subject):
                return _Outcome(result, terminated=True)
            match_outcomes: list[_Outcome] = []
            for case in node.cases:
                case_environment = self._narrow_pattern(
                    case.pattern,
                    node.subject,
                    subject,
                    result,
                    current_function,
                )
                if case.guard is not None:
                    self._evaluate_expression(
                        case.guard,
                        case_environment,
                        scope=scope,
                        current_function=current_function,
                    )
                    case_environment = self._narrow_environment(
                        case.guard, case_environment, truthy=True
                    )
                match_outcomes.append(
                    self._execute_block(
                        case.body,
                        case_environment,
                        scope=scope,
                        current_function=current_function,
                    )
                )
            if not match_outcomes:
                return _Outcome(result)
            return _Outcome(
                self._join_many_environments(
                    outcome.environment for outcome in match_outcomes
                ),
                [
                    value
                    for outcome in match_outcomes
                    for value in outcome.returns
                ],
                [
                    value
                    for outcome in match_outcomes
                    for value in outcome.yields
                ],
                all(outcome.terminated for outcome in match_outcomes),
            )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_target = self._function_nodes.get(id(node))
            if function_target is not None:
                nested = self._functions[function_target]
                if function_target.rpartition(".")[0] != self._module_name:
                    for name, value in result.items():
                        old = nested.closure_evidence.get(
                            name, AbstractTypeValue.bottom()
                        )
                        nested.closure_evidence[name] = self._join(old, value)
                result[node.name] = self._function_value(nested)
            return _Outcome(result)

        if isinstance(node, ast.ClassDef):
            qualified = f"{scope}.{node.name}"
            class_info = self._classes.get(qualified)
            if class_info is not None:
                result[node.name] = AbstractTypeValue.from_type(
                    class_info.instance, class_target=qualified
                )
            return _Outcome(result)

        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result.pop(target.id, None)
            return _Outcome(result)

        if isinstance(node, (ast.Raise, ast.Break, ast.Continue)):
            return _Outcome(result, terminated=True)

        # Imports, pass, global/nonlocal, and unsupported statements do not
        # invalidate the complete environment.  Their expressions are still
        # conservatively unknown when referenced later.
        return _Outcome(result)

    def _execute_loop(
        self,
        node: ast.While | ast.For | ast.AsyncFor,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> _Outcome:
        entry = dict(environment)
        head = dict(environment)
        returns: list[AbstractTypeValue] = []
        yields: list[AbstractTypeValue] = []
        for _ in range(self.options.max_loop_iterations):
            body_env = dict(head)
            if isinstance(node, ast.While):
                test = self._evaluate_expression(
                    node.test,
                    body_env,
                    scope=scope,
                    current_function=current_function,
                )
                if self._is_never_value(test):
                    return _Outcome(body_env, returns, yields, terminated=True)
                body_env = self._narrow_environment(
                    node.test, body_env, truthy=True
                )
            else:
                iterable = self._evaluate_expression(
                    node.iter,
                    body_env,
                    scope=scope,
                    current_function=current_function,
                )
                if self._is_never_value(iterable):
                    return _Outcome(body_env, returns, yields, terminated=True)
                self._assign_target(
                    node.target,
                    self._iterable_element(iterable),
                    body_env,
                    current_function,
                )
            outcome = self._execute_block(
                node.body,
                body_env,
                scope=scope,
                current_function=current_function,
            )
            returns.extend(outcome.returns)
            yields.extend(outcome.yields)
            next_head = self._join_environments(entry, outcome.environment)
            if next_head == head:
                head = next_head
                break
            head = next_head
        else:
            self._add_diagnostic(
                "loop-widened",
                "Loop inference reached its local iteration limit",
                node=node,
                severity="information",
            )

        orelse = self._execute_block(
            node.orelse,
            head,
            scope=scope,
            current_function=current_function,
        )
        returns.extend(orelse.returns)
        yields.extend(orelse.yields)
        return _Outcome(orelse.environment, returns, yields)

    # ------------------------------------------------------------------
    # Expression semantics
    # ------------------------------------------------------------------

    def _evaluate_expression(
        self,
        node: ast.expr,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        value: AbstractTypeValue
        if isinstance(node, ast.Constant):
            value = AbstractTypeValue.from_type(
                NONE_TYPE
                if node.value is None
                else self._proper_instance(type(node.value))
            )
        elif isinstance(node, ast.Name):
            value = self._name_value(node.id, environment, scope)
        elif isinstance(node, ast.List):
            element = self._evaluate_many(
                node.elts, environment, scope, current_function
            )
            value = (
                element
                if self._is_never_value(element)
                else self._instance(list, element.public_type() or ANY)
            )
        elif isinstance(node, ast.Set):
            element = self._evaluate_many(
                node.elts, environment, scope, current_function
            )
            value = (
                element
                if self._is_never_value(element)
                else self._instance(set, element.public_type() or ANY)
            )
        elif isinstance(node, ast.Tuple):
            evaluated = [
                self._evaluate_expression(
                    item,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                for item in node.elts
            ]
            if any(self._is_never_value(item) for item in evaluated):
                value = AbstractTypeValue.from_type(NEVER)
            else:
                value = AbstractTypeValue.from_type(
                    TupleType(tuple(item.public_type() or ANY for item in evaluated))
                )
        elif isinstance(node, ast.Dict):
            keys = self._evaluate_many(
                (item for item in node.keys if item is not None),
                environment,
                scope,
                current_function,
            )
            values = self._evaluate_many(
                node.values, environment, scope, current_function
            )
            if self._is_never_value(keys) or self._is_never_value(values):
                value = AbstractTypeValue.from_type(NEVER)
            else:
                value = self._instance(
                    dict,
                    keys.public_type() or ANY,
                    values.public_type() or ANY,
                )
        elif isinstance(node, ast.BinOp):
            left = self._evaluate_expression(
                node.left, environment, scope=scope, current_function=current_function
            )
            right = self._evaluate_expression(
                node.right, environment, scope=scope, current_function=current_function
            )
            value = (
                AbstractTypeValue.from_type(NEVER)
                if self._is_never_value(left) or self._is_never_value(right)
                else self._binary_result(left, right, node.op)
            )
        elif isinstance(node, ast.UnaryOp):
            operand = self._evaluate_expression(
                node.operand,
                environment,
                scope=scope,
                current_function=current_function,
            )
            value = (
                operand
                if self._is_never_value(operand)
                else self._instance(bool) if isinstance(node.op, ast.Not) else operand
            )
        elif isinstance(node, ast.Compare):
            operands = [
                self._evaluate_expression(
                    child,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                for child in (node.left, *node.comparators)
            ]
            value = (
                AbstractTypeValue.from_type(NEVER)
                if any(self._is_never_value(item) for item in operands)
                else self._instance(bool)
            )
        elif isinstance(node, ast.BoolOp):
            first = self._evaluate_expression(
                node.values[0],
                environment,
                scope=scope,
                current_function=current_function,
            )
            if self._is_never_value(first):
                value = first
            else:
                rest = [
                    self._evaluate_expression(
                        item,
                        environment,
                        scope=scope,
                        current_function=current_function,
                    )
                    for item in node.values[1:]
                ]
                value = self._join_normal_results((first, *rest))
        elif isinstance(node, ast.IfExp):
            test = self._evaluate_expression(
                node.test, environment, scope=scope, current_function=current_function
            )
            if self._is_never_value(test):
                value = test
            else:
                left = self._evaluate_expression(
                    node.body,
                    self._narrow_environment(node.test, environment, truthy=True),
                    scope=scope,
                    current_function=current_function,
                )
                right = self._evaluate_expression(
                    node.orelse,
                    self._narrow_environment(node.test, environment, truthy=False),
                    scope=scope,
                    current_function=current_function,
                )
                value = self._join_normal_results((left, right))
        elif isinstance(node, ast.Call):
            value = self._evaluate_call(node, environment, scope, current_function)
        elif isinstance(node, ast.Attribute):
            base = self._evaluate_expression(
                node.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            value = (
                base
                if self._is_never_value(base)
                else self._attribute_value(base, node.attr)
            )
        elif isinstance(node, ast.Subscript):
            base = self._evaluate_expression(
                node.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            index = self._evaluate_expression(
                node.slice,
                environment,
                scope=scope,
                current_function=current_function,
            )
            value = (
                AbstractTypeValue.from_type(NEVER)
                if self._is_never_value(base) or self._is_never_value(index)
                else self._subscript_value(base, node.slice)
            )
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            local_env = self._comprehension_environment(
                node.generators, environment, scope, current_function
            )
            element = self._evaluate_expression(
                node.elt,
                local_env,
                scope=scope,
                current_function=current_function,
            )
            raw = set if isinstance(node, ast.SetComp) else list
            value = self._instance(raw, element.public_type() or ANY)
        elif isinstance(node, ast.DictComp):
            local_env = self._comprehension_environment(
                node.generators, environment, scope, current_function
            )
            key = self._evaluate_expression(
                node.key, local_env, scope=scope, current_function=current_function
            )
            item = self._evaluate_expression(
                node.value, local_env, scope=scope, current_function=current_function
            )
            value = self._instance(
                dict, key.public_type() or ANY, item.public_type() or ANY
            )
        elif isinstance(node, ast.Lambda):
            qualified = f"{scope}.<lambda@{node.lineno}:{node.col_offset}>"
            info = self._functions.get(qualified)
            if info is None:
                parameters = [arg.arg for arg in _all_arguments(node.args)]
                info = _FunctionInfo(qualified, node, parameters)
                self._functions[qualified] = info
            value = self._function_value(info)
        elif isinstance(node, ast.NamedExpr):
            value = self._evaluate_expression(
                node.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            self._assign_target(node.target, value, environment, current_function)
        elif isinstance(node, ast.Await):
            awaited = self._evaluate_expression(
                node.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            value = (
                awaited
                if self._is_never_value(awaited)
                else self._unwrap_single_generic(awaited)
            )
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            value = (
                AbstractTypeValue.from_type(NONE_TYPE)
                if node.value is None
                else self._evaluate_expression(
                    node.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
            )
            if isinstance(node, ast.YieldFrom):
                value = self._iterable_element(value)
        elif isinstance(node, ast.JoinedStr):
            value = self._instance(str)
        else:
            value = AbstractTypeValue.unresolved()

        self._record_expression(node, value)
        return value

    def _evaluate_call(
        self,
        node: ast.Call,
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        arguments = [
            self._evaluate_expression(
                arg, environment, scope=scope, current_function=current_function
            )
            for arg in node.args
        ]
        keywords = {
            keyword.arg: self._evaluate_expression(
                keyword.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            for keyword in node.keywords
            if keyword.arg is not None
        }
        if any(self._is_never_value(value) for value in arguments) or any(
            self._is_never_value(value) for value in keywords.values()
        ):
            return AbstractTypeValue.from_type(NEVER)

        qualified_callee = self._qualified_callee_name(node.func)
        if qualified_callee is not None:
            modelled = self._model_external_call(
                qualified_callee, arguments, keywords, node
            )
            if modelled is not None:
                return modelled

        if isinstance(node.func, ast.Name):
            builtin_result = self._call_builtin(node.func.id, arguments, keywords)
            if builtin_result is not None:
                return builtin_result

        if isinstance(node.func, ast.Attribute):
            base = self._evaluate_expression(
                node.func.value,
                environment,
                scope=scope,
                current_function=current_function,
            )
            if self._is_never_value(base):
                return base
            method_result = self._call_attribute(
                node.func,
                base,
                arguments,
                keywords,
                environment,
            )
            if method_result is not None:
                return method_result

        callee = self._evaluate_expression(
            node.func,
            environment,
            scope=scope,
            current_function=current_function,
        )
        if self._is_never_value(callee):
            return callee
        results: list[AbstractTypeValue] = []
        for class_target in callee.class_targets:
            class_info = self._classes.get(class_target)
            if class_info is not None:
                instance = AbstractTypeValue.from_type(class_info.instance)
                initializer = self._class_method(class_target, "__init__")
                if initializer is not None:
                    self._apply_function(
                        initializer,
                        [instance, *arguments],
                        keywords,
                    )
                results.append(instance)
            else:
                external_instances = [
                    typ
                    for typ in callee.types
                    if isinstance(typ, Instance)
                    and typ.type.full_name == class_target
                ]
                results.append(
                    AbstractTypeValue.from_type(
                        external_instances[0]
                        if external_instances
                        else self._synthetic_instance(class_target)
                    )
                )
        for target in callee.callable_targets:
            results.append(self._apply_function(target, arguments, keywords))
        if not callee.callable_targets and not callee.class_targets:
            for typ in callee.types:
                if isinstance(typ, CallableType):
                    results.append(AbstractTypeValue.from_type(typ.return_type))
        return (
            join_all(
                results,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            if results
            else AbstractTypeValue.unresolved()
        )

    def _model_external_call(
        self,
        qualified_name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.Call,
    ) -> AbstractTypeValue | None:
        for provider in self.call_model_providers:
            try:
                result = provider.infer_call(
                    qualified_name, arguments, keywords
                )
            except Exception as exc:  # noqa: BLE001 - provider isolation boundary
                self._add_diagnostic(
                    "call-model-error",
                    f"Call model for {qualified_name} failed: {exc}",
                    node=node,
                )
                continue
            if result is not None:
                return result
        return None

    def _call_builtin(
        self,
        name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        constructors: dict[str, type] = {
            "bool": bool,
            "bytes": bytes,
            "complex": complex,
            "dict": dict,
            "float": float,
            "frozenset": frozenset,
            "int": int,
            "list": list,
            "object": object,
            "set": set,
            "str": str,
            "tuple": tuple,
        }
        if name in constructors:
            raw = constructors[name]
            if raw in {list, set, frozenset, tuple} and arguments:
                element = self._iterable_element(arguments[0]).public_type() or ANY
                if raw is tuple:
                    return AbstractTypeValue.from_type(
                        TupleType((element,), unknown_size=True)
                    )
                return self._instance(raw, element)
            if raw is dict and arguments:
                for typ in arguments[0].types:
                    if isinstance(typ, Instance) and typ.type.raw_type is dict:
                        return AbstractTypeValue.from_type(typ)
            return self._instance(raw)
        if name in {"len", "hash", "id", "ord"}:
            return self._instance(int)
        if name in {"all", "any", "callable", "hasattr", "isinstance", "issubclass"}:
            return self._instance(bool)
        if name in {"repr", "ascii", "format", "chr", "input"}:
            return self._instance(str)
        if name == "range":
            return self._instance(range)
        if name == "iter":
            if len(arguments) > 1:
                callable_return = self._callable_return_type(arguments[0])
                return self._instance(
                    cabc.Iterator, callable_return.public_type() or ANY
                )
            iterator_element = (
                self._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            return self._instance(
                cabc.Iterator, iterator_element.public_type() or ANY
            )
        if name == "reversed":
            reversed_element = (
                self._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            return self._instance(
                cabc.Iterator, reversed_element.public_type() or ANY
            )
        if name == "filter":
            filtered_element = (
                self._iterable_element(arguments[1])
                if len(arguments) > 1
                else AbstractTypeValue.unresolved()
            )
            return self._instance(
                cabc.Iterator, filtered_element.public_type() or ANY
            )
        if name == "enumerate":
            enumerated_element = (
                self._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            pair = TupleType(
                (self._proper_instance(int), enumerated_element.public_type() or ANY)
            )
            return self._instance(cabc.Iterator, pair)
        if name == "zip":
            elements = tuple(
                self._iterable_element(argument).public_type() or ANY
                for argument in arguments
            )
            return self._instance(cabc.Iterator, TupleType(elements))
        if name == "map":
            mapped_element = (
                self._callable_return_type(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            return self._instance(
                cabc.Iterator, mapped_element.public_type() or ANY
            )
        if name in {"min", "max"} and arguments:
            if len(arguments) == 1:
                return self._iterable_element(arguments[0])
            return join_all(
                arguments,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
        if name == "next" and arguments:
            return self._iterable_element(arguments[0])
        if name == "sum":
            if not arguments:
                return self._instance(int)
            element = self._iterable_element(arguments[0])
            start = arguments[1] if len(arguments) > 1 else self._instance(int)
            return self._binary_result(start, element, ast.Add())
        if name == "sorted" and arguments:
            sorted_element = self._iterable_element(arguments[0])
            return self._instance(list, sorted_element.public_type() or ANY)
        if name == "type":
            if len(arguments) == 1:
                return AbstractTypeValue.from_type(
                    TypeType(arguments[0].public_type() or ANY)
                )
            return self._instance(type)
        return None

    def _call_attribute(
        self,
        node: ast.Attribute,
        base: AbstractTypeValue,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        environment: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        for target in base.callable_targets:
            if node.attr == "__call__":
                return self._apply_function(target, arguments, keywords)

        method_targets: list[str] = []
        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            class_info = self._classes.get(typ.type.full_name)
            if class_info is not None:
                method = self._class_method(class_info.qualified_name, node.attr)
                if method is not None:
                    method_targets.append(method)
        if method_targets:
            return join_all(
                [
                    self._apply_function(target, [base, *arguments], keywords)
                    for target in method_targets
                ],
                self.type_system,
                max_union_size=self.options.max_union_size,
            )

        text_results = [
            result
            for typ in base.types
            if isinstance(typ, Instance) and typ.type.raw_type in {str, bytes}
            if (
                result := self._model_text_method(
                    cast(type, typ.type.raw_type), node.attr
                )
            )
            is not None
        ]
        if text_results:
            return join_all(
                text_results,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )

        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            raw = typ.type.raw_type
            args = typ.args
            if raw is list or raw is set:
                collection_element = AbstractTypeValue.from_type(
                    args[0] if args else ANY
                )
                if node.attr in {"append", "add", "insert"}:
                    if arguments and isinstance(node.value, ast.Name):
                        widened = self._join(
                            collection_element, arguments[-1]
                        )
                        environment[node.value.id] = self._instance(
                            cast(type, raw), widened.public_type() or ANY
                        )
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"pop"}:
                    return collection_element
                if node.attr in {"copy"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"count", "index"}:
                    return self._instance(int)
            if raw is dict:
                key = args[0] if len(args) > 0 else ANY
                item = args[1] if len(args) > 1 else ANY
                if node.attr == "get":
                    result = AbstractTypeValue.from_type(item)
                    default = (
                        arguments[1]
                        if len(arguments) > 1
                        else AbstractTypeValue.from_type(NONE_TYPE)
                    )
                    return self._join(result, default)
                if node.attr in {"setdefault", "pop"}:
                    return AbstractTypeValue.from_type(item)
                if node.attr == "keys":
                    return self._instance(cabc.KeysView, key)
                if node.attr == "values":
                    return self._instance(cabc.ValuesView, item)
                if node.attr == "items":
                    return self._instance(cabc.ItemsView, key, item)
                if node.attr in {"update", "clear"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
        return None

    def _model_text_method(
        self, receiver: type, attribute: str
    ) -> AbstractTypeValue | None:
        """Model one ``str`` or ``bytes`` receiver alternative."""
        preserving: dict[type, set[str]] = {
            str: {
                "capitalize", "casefold", "center", "expandtabs", "format",
                "format_map", "join", "ljust", "lower", "lstrip",
                "removeprefix", "removesuffix", "replace", "rjust", "rstrip",
                "strip", "swapcase", "title", "translate", "upper", "zfill",
            },
            bytes: {
                "capitalize", "center", "expandtabs", "join", "ljust", "lower",
                "lstrip", "removeprefix", "removesuffix", "replace", "rjust",
                "rstrip", "strip", "swapcase", "title", "translate", "upper",
                "zfill",
            },
        }
        predicates: dict[type, set[str]] = {
            str: {
                "endswith", "isalnum", "isalpha", "isascii", "isdecimal",
                "isdigit", "isidentifier", "islower", "isnumeric", "isprintable",
                "isspace", "istitle", "isupper", "startswith",
            },
            bytes: {
                "endswith", "isalnum", "isalpha", "isascii", "isdigit", "islower",
                "isspace", "istitle", "isupper", "startswith",
            },
        }
        if attribute == "encode" and receiver is str:
            return self._instance(bytes)
        if attribute == "decode" and receiver is bytes:
            return self._instance(str)
        if attribute in preserving[receiver]:
            return self._instance(receiver)
        if attribute in predicates[receiver]:
            return self._instance(bool)
        if attribute in {"count", "find", "index", "rfind", "rindex"}:
            return self._instance(int)
        element = self._proper_instance(receiver)
        if attribute in {"partition", "rpartition"}:
            return AbstractTypeValue.from_type(
                TupleType((element, element, element))
            )
        if attribute in {"split", "rsplit", "splitlines"}:
            return self._instance(list, element)
        return None

    # ------------------------------------------------------------------
    # Type operations and narrowing
    # ------------------------------------------------------------------

    def _binary_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
        operator: ast.operator,
    ) -> AbstractTypeValue:
        if isinstance(operator, ast.Div):
            return self._instance(float)
        if isinstance(operator, ast.FloorDiv):
            if self._contains_raw(left, int) and self._contains_raw(right, int):
                return self._instance(int)
        if isinstance(operator, ast.MatMult):
            return AbstractTypeValue.unresolved()
        if isinstance(operator, ast.Add):
            for raw in (str, bytes, list, tuple):
                if self._contains_raw(left, raw) and self._contains_raw(right, raw):
                    if raw is tuple:
                        return self._join(left, right)
                    if raw is list:
                        element = self._join(
                            self._iterable_element(left), self._iterable_element(right)
                        )
                        return self._instance(list, element.public_type() or ANY)
                    return self._instance(raw)
        if isinstance(operator, ast.Mult):
            for raw in (str, bytes, list, tuple):
                if self._contains_raw(left, raw) or self._contains_raw(right, raw):
                    return left if self._contains_raw(left, raw) else right
        numeric = self._numeric_join((left, right))
        if numeric.public_type() is not None:
            return numeric
        return self._join(left, right).join(
            AbstractTypeValue.unresolved(),
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    def _numeric_join(
        self, values: Iterable[AbstractTypeValue]
    ) -> AbstractTypeValue:
        ranks = {bool: 0, int: 1, float: 2, complex: 3}
        best: type | None = None
        for value in values:
            for typ in value.types:
                if isinstance(typ, Instance) and typ.type.raw_type in ranks:
                    numeric_raw = cast(type, typ.type.raw_type)
                    if best is None or ranks[numeric_raw] > ranks[best]:
                        best = numeric_raw
        return AbstractTypeValue.bottom() if best is None else self._instance(best)

    def _narrow_environment(
        self,
        condition: ast.expr,
        environment: dict[str, AbstractTypeValue],
        *,
        truthy: bool,
    ) -> dict[str, AbstractTypeValue]:
        result = dict(environment)
        if isinstance(condition, ast.UnaryOp) and isinstance(condition.op, ast.Not):
            return self._narrow_environment(
                condition.operand, environment, truthy=not truthy
            )
        if isinstance(condition, ast.Name) and truthy:
            value = result.get(condition.id)
            if value is not None:
                result[condition.id] = self._remove_none(value)
            return result
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "isinstance"
            and len(condition.args) >= 2
            and isinstance(condition.args[0], ast.Name)
        ):
            name = condition.args[0].id
            narrowed = self._evaluate_type_expression(condition.args[1])
            if truthy and not narrowed.unknown:
                result[name] = narrowed
            return result
        if isinstance(condition, ast.Compare) and len(condition.ops) == 1:
            left, right = condition.left, condition.comparators[0]
            name_node: ast.Name | None = None
            none_side = False
            if isinstance(left, ast.Name) and self._is_none_literal(right):
                name_node, none_side = left, True
            elif isinstance(right, ast.Name) and self._is_none_literal(left):
                name_node, none_side = right, True
            if name_node is not None and none_side:
                equality = isinstance(condition.ops[0], (ast.Is, ast.Eq))
                keep_none = truthy == equality
                old = result.get(name_node.id, AbstractTypeValue.unresolved())
                result[name_node.id] = (
                    AbstractTypeValue.from_type(NONE_TYPE)
                    if keep_none
                    else self._remove_none(old)
                )
        return result

    def _narrow_pattern(
        self,
        pattern: ast.pattern,
        subject_node: ast.expr,
        subject: AbstractTypeValue,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> dict[str, AbstractTypeValue]:
        result = dict(environment)
        if isinstance(pattern, ast.MatchSingleton):
            if pattern.value is None and isinstance(subject_node, ast.Name):
                result[subject_node.id] = AbstractTypeValue.from_type(NONE_TYPE)
        elif isinstance(pattern, ast.MatchClass):
            narrowed = self._evaluate_type_expression(pattern.cls)
            if isinstance(subject_node, ast.Name) and not narrowed.unknown:
                result[subject_node.id] = narrowed
            for child in pattern.patterns:
                result = self._narrow_pattern(
                    child,
                    subject_node,
                    subject,
                    result,
                    current_function,
                )
        elif isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None:
                result = self._narrow_pattern(
                    pattern.pattern,
                    subject_node,
                    subject,
                    result,
                    current_function,
                )
            if pattern.name is not None:
                result[pattern.name] = subject
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name is not None:
                element = self._iterable_element(subject)
                result[pattern.name] = self._instance(
                    list, element.public_type() or ANY
                )
        elif isinstance(pattern, ast.MatchSequence):
            unpacked = self._unpack_value(subject, len(pattern.patterns))
            for child, child_value in zip(pattern.patterns, unpacked):
                result = self._narrow_pattern(
                    child,
                    subject_node,
                    child_value,
                    result,
                    current_function,
                )
        elif isinstance(pattern, ast.MatchMapping):
            item = self._subscript_value(subject, ast.Constant(value=""))
            for child in pattern.patterns:
                result = self._narrow_pattern(
                    child,
                    subject_node,
                    item,
                    result,
                    current_function,
                )
            if pattern.rest is not None:
                result[pattern.rest] = subject
        elif isinstance(pattern, ast.MatchOr):
            alternatives = [
                self._narrow_pattern(
                    child,
                    subject_node,
                    subject,
                    result,
                    current_function,
                )
                for child in pattern.patterns
            ]
            result = self._join_many_environments(alternatives)
        return result

    def _check_annotation_compatibility(
        self,
        inferred: AbstractTypeValue,
        annotated: AbstractTypeValue,
        node: ast.AST,
        *,
        context: str,
    ) -> None:
        expected = annotated.public_type()
        if expected is None or not inferred.types:
            return
        incompatible = []
        for candidate in inferred.types:
            try:
                compatible = self.type_system.is_subtype(candidate, expected)
            except (AssertionError, KeyError, TypeError):
                compatible = candidate == expected
            if not compatible:
                incompatible.append(candidate)
        if incompatible:
            self._add_diagnostic(
                "annotation-mismatch",
                f"Inferred {', '.join(map(str, incompatible))} is incompatible "
                f"with annotated {expected} for {context}",
                node=node,
                severity="error" if self.options.strict_annotations else "warning",
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _name_value(
        self,
        name: str,
        environment: dict[str, AbstractTypeValue],
        scope: str,
    ) -> AbstractTypeValue:
        if name in environment:
            return environment[name]
        qualified = self._resolve_lexical_function(name, scope)
        if qualified is not None:
            return self._function_value(self._functions[qualified])
        class_name = self._class_aliases.get(name)
        if class_name is not None:
            return AbstractTypeValue.from_type(
                self._classes[class_name].instance,
                class_target=class_name,
            )
        imported = self._resolve_import_name(name)
        if imported is not None:
            external = self._external_type(imported)
            return AbstractTypeValue.from_type(
                external,
                unknown=external is None,
                class_target=imported if self._looks_like_class(name) else None,
            )
        builtin = getattr(builtins, name, None)
        if isinstance(builtin, type):
            return AbstractTypeValue.from_type(
                self._proper_instance(builtin), class_target=f"builtins.{name}"
            )
        return AbstractTypeValue.unresolved()

    def _function_value(self, function: _FunctionInfo) -> AbstractTypeValue:
        parameters: list[ProperType] = []
        for name in function.parameter_names:
            explicit = function.explicit_parameters.get(name)
            evidence = function.parameter_evidence.get(name)
            parameter = explicit or evidence
            parameter_type = None if parameter is None else parameter.public_type()
            parameters.append(parameter_type or ANY)
        if function.explicit_return is not None:
            returns = function.explicit_return.public_type() or ANY
        elif function.summary is not None:
            returns = function.summary.return_type or ANY
        else:
            returns = ANY
        return AbstractTypeValue.from_type(
            CallableType(tuple(parameters), returns),
            callable_target=function.qualified_name,
        )

    def _apply_function(
        self,
        target: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue:
        function = self._functions.get(target)
        if function is None:
            external = self._external_type(target)
            if isinstance(external, CallableType):
                return AbstractTypeValue.from_type(external.return_type)
            return AbstractTypeValue.unresolved()
        bound_arguments = self._bind_call_arguments(
            function, arguments, keywords
        )
        for name, value in bound_arguments.items():
            self._queue_parameter_evidence(target, name, value)
        specialization = (
            self._register_specialization(function, bound_arguments)
            if self._collect_specializations
            else None
        )
        if function.summary is not None and len(
            function.summary.return_dependencies
        ) == 1:
            dependency = next(iter(function.summary.return_dependencies))
            if dependency in bound_arguments:
                return self._wrap_call_result(
                    function, bound_arguments[dependency]
                )
        if function.explicit_return is not None:
            substitutions = self._generic_substitutions(
                function, bound_arguments
            )
            returned = function.explicit_return.public_type()
            if returned is not None and substitutions:
                returned = substitute_type_vars(returned, substitutions)
                return self._wrap_call_result(
                    function, AbstractTypeValue.from_type(returned)
                )
            return self._wrap_call_result(function, function.explicit_return)
        if specialization is not None:
            return self._wrap_call_result(
                function,
                specialization.return_value,
                yield_value=specialization.yield_value,
            )
        if function.summary is not None:
            return self._wrap_call_result(
                function, function.summary.return_value
            )
        return AbstractTypeValue.unresolved()

    def _wrap_call_result(
        self,
        function: _FunctionInfo,
        returned: AbstractTypeValue,
        *,
        yield_value: AbstractTypeValue | None = None,
    ) -> AbstractTypeValue:
        summary = function.summary
        effective_yield = yield_value
        if effective_yield is None and summary is not None and summary.is_generator:
            effective_yield = summary.yield_value
        if effective_yield is not None and not effective_yield.is_bottom:
            element = effective_yield.public_type() or ANY
            return self._instance(cabc.Iterator, element)
        if isinstance(function.node, ast.AsyncFunctionDef):
            result = returned.public_type() or ANY
            return self._instance(cabc.Coroutine, ANY, ANY, result)
        return returned

    def _register_specialization(
        self,
        function: _FunctionInfo,
        bound_arguments: dict[str, AbstractTypeValue],
    ) -> FunctionSpecialization:
        parameters = self._call_context_parameters(function, bound_arguments)
        key = _SpecializationKey(
            tuple((name, parameters[name]) for name in function.parameter_names)
        )
        existing = function.specializations.get(key)
        if existing is not None:
            return existing

        normal_count = sum(
            not candidate.widened for candidate in function.specializations
        )
        if normal_count < self.options.max_specializations_per_function:
            specialization = FunctionSpecialization(
                parameters=key.parameters,
                return_value=AbstractTypeValue.bottom(),
            )
            function.specializations[key] = specialization
            return specialization

        widened_key = _SpecializationKey(widened=True)
        for name, value in parameters.items():
            previous_value = function.widened_parameters.get(
                name, AbstractTypeValue.bottom()
            )
            function.widened_parameters[name] = self._join(
                previous_value, value
            )
        widened_parameters = tuple(
            (name, function.widened_parameters[name])
            for name in function.parameter_names
        )
        previous_specialization = function.specializations.get(widened_key)
        specialization = FunctionSpecialization(
            parameters=widened_parameters,
            return_value=(
                AbstractTypeValue.bottom()
                if previous_specialization is None
                else previous_specialization.return_value
            ),
            yield_value=(
                AbstractTypeValue.bottom()
                if previous_specialization is None
                else previous_specialization.yield_value
            ),
            widened=True,
        )
        function.specializations[widened_key] = specialization
        self._add_diagnostic(
            "specialization-budget-exceeded",
            f"{function.qualified_name} exceeded its "
            f"{self.options.max_specializations_per_function}-context budget; "
            "additional calls are analyzed in a widened context",
            node=function.node,
        )
        return specialization

    def _call_context_parameters(
        self,
        function: _FunctionInfo,
        bound_arguments: dict[str, AbstractTypeValue],
    ) -> dict[str, AbstractTypeValue]:
        parameters: dict[str, AbstractTypeValue] = {}
        for index, name in enumerate(function.parameter_names):
            actual = bound_arguments.get(name)
            if actual is not None:
                parameters[name] = self._normalize_context_value(actual)
            elif function.owner is not None and index == 0:
                parameters[name] = AbstractTypeValue.from_type(
                    self._classes[function.owner].instance
                )
            else:
                explicit = function.explicit_parameters.get(name)
                parameters[name] = (
                    explicit
                    if explicit is not None
                    else AbstractTypeValue.unresolved()
                )
        return parameters

    @staticmethod
    def _normalize_context_value(
        value: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Remove evolving display-only callable signatures from context keys.

        User-defined callable identity is carried by ``callable_targets``.  Its
        synthesized ``CallableType`` return annotation changes as inference
        converges and must not manufacture a fresh specialization each round.
        """
        if not value.callable_targets:
            return value
        return AbstractTypeValue(
            types=frozenset(
                typ for typ in value.types if not isinstance(typ, CallableType)
            ),
            unknown=value.unknown,
            callable_targets=value.callable_targets,
            class_targets=value.class_targets,
        )

    def _bind_call_arguments(
        self,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> dict[str, AbstractTypeValue]:
        node_arguments = function.node.args
        positional_names = [
            arg.arg for arg in (*node_arguments.posonlyargs, *node_arguments.args)
        ]
        positional_only = {arg.arg for arg in node_arguments.posonlyargs}
        keyword_only = {arg.arg for arg in node_arguments.kwonlyargs}
        bound: dict[str, AbstractTypeValue] = {}

        for index, value in enumerate(arguments[: len(positional_names)]):
            bound[positional_names[index]] = value

        extra_positional = arguments[len(positional_names) :]
        if node_arguments.vararg is not None and extra_positional:
            element = join_all(
                extra_positional,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            bound[node_arguments.vararg.arg] = AbstractTypeValue.from_type(
                TupleType((element.public_type() or ANY,), unknown_size=True)
            )

        unmatched_keywords: list[AbstractTypeValue] = []
        for name, value in keywords.items():
            if name in positional_names and name not in positional_only:
                bound[name] = value
            elif name in keyword_only:
                bound[name] = value
            else:
                unmatched_keywords.append(value)

        if node_arguments.kwarg is not None and unmatched_keywords:
            values = join_all(
                unmatched_keywords,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            bound[node_arguments.kwarg.arg] = self._instance(
                dict,
                self._proper_instance(str),
                values.public_type() or ANY,
            )
        return bound

    def _return_dependencies(self, function: _FunctionInfo) -> frozenset[str]:
        """Find direct parameter-to-return relations for context precision."""
        if isinstance(function.node, ast.Lambda):
            if isinstance(function.node.body, ast.Name):
                name = function.node.body.id
                if name in function.parameter_names:
                    return frozenset((name,))
            return frozenset()
        dependencies: set[str] = set()
        saw_return = False
        invalid = False

        def visit(node: ast.AST, *, root: bool = False) -> None:
            nonlocal saw_return, invalid
            if invalid:
                return
            if not root and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                return
            if isinstance(node, ast.Return):
                saw_return = True
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id in function.parameter_names
                ):
                    dependencies.add(node.value.id)
                else:
                    invalid = True
                return
            for child in ast.iter_child_nodes(node):
                visit(child)

        visit(function.node, root=True)
        return (
            frozenset(dependencies)
            if saw_return and not invalid
            else frozenset()
        )

    def _generic_substitutions(
        self,
        function: _FunctionInfo,
        actuals: dict[str, AbstractTypeValue],
    ) -> dict[str, ProperType]:
        substitutions: dict[str, ProperType] = {}
        for name, formal_value in function.explicit_parameters.items():
            formal = formal_value.public_type()
            actual = actuals.get(name)
            if formal is None or actual is None:
                continue
            actual_type = actual.public_type()
            if actual_type is not None:
                self._match_type_variables(formal, actual_type, substitutions)
        return substitutions

    def _match_type_variables(
        self,
        formal: ProperType,
        actual: ProperType,
        substitutions: dict[str, ProperType],
    ) -> None:
        if isinstance(formal, TypeVarType):
            existing = substitutions.get(formal.name)
            if existing is None:
                substitutions[formal.name] = actual
            else:
                joined = self._join(
                    AbstractTypeValue.from_type(existing),
                    AbstractTypeValue.from_type(actual),
                ).public_type()
                if joined is not None:
                    substitutions[formal.name] = joined
            return
        if isinstance(formal, Instance) and isinstance(actual, Instance):
            if formal.type.raw_type is actual.type.raw_type:
                for formal_arg, actual_arg in zip(formal.args, actual.args):
                    self._match_type_variables(
                        formal_arg, actual_arg, substitutions
                    )
        elif isinstance(formal, TupleType) and isinstance(actual, TupleType):
            for formal_arg, actual_arg in zip(formal.args, actual.args):
                self._match_type_variables(formal_arg, actual_arg, substitutions)

    def _queue_parameter_evidence(
        self, target: str, parameter: str, value: AbstractTypeValue
    ) -> None:
        if not value.types and not value.callable_targets and not value.class_targets:
            return
        key = (target, parameter)
        old = self._pending_parameter_evidence.get(
            key, AbstractTypeValue.bottom()
        )
        self._pending_parameter_evidence[key] = self._join(old, value)

    def _attribute_value(
        self, base: AbstractTypeValue, attribute: str
    ) -> AbstractTypeValue:
        values: list[AbstractTypeValue] = []
        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            class_info = self._classes.get(typ.type.full_name)
            if class_info is not None:
                member = self._class_attribute(
                    class_info.qualified_name, attribute
                )
                if member is not None:
                    values.append(member)
                method = self._class_method(
                    class_info.qualified_name, attribute
                )
                if method is not None:
                    values.append(
                        self._function_value(
                            self._functions[method]
                        )
                    )
            raw = typ.type.raw_type
            member = getattr(raw, attribute, None) if isinstance(raw, type) else None
            if callable(member):
                try:
                    annotation = getattr(member, "__annotations__", {}).get("return")
                    returned = self.type_system.convert_type_hint(annotation)
                except (AttributeError, TypeError, ValueError):
                    returned = ANY
                values.append(AbstractTypeValue.from_type(CallableType(None, returned)))
        return (
            join_all(
                values,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            if values
            else AbstractTypeValue.unresolved()
        )

    def _subscript_value(
        self, base: AbstractTypeValue, slice_node: ast.expr
    ) -> AbstractTypeValue:
        values: list[AbstractTypeValue] = []
        for typ in base.types:
            if isinstance(typ, TupleType):
                if isinstance(slice_node, ast.Constant) and isinstance(
                    slice_node.value, int
                ):
                    index = slice_node.value
                    if -len(typ.args) <= index < len(typ.args):
                        values.append(AbstractTypeValue.from_type(typ.args[index]))
                        continue
                values.extend(AbstractTypeValue.from_type(item) for item in typ.args)
            elif isinstance(typ, Instance):
                raw = typ.type.raw_type
                if raw in {list, set, frozenset} and typ.args:
                    values.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw is dict and len(typ.args) > 1:
                    values.append(AbstractTypeValue.from_type(typ.args[1]))
                elif raw in {str, bytes}:
                    values.append(AbstractTypeValue.from_type(typ))
        return (
            join_all(
                values,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            if values
            else AbstractTypeValue.unresolved()
        )

    def _iterable_element(self, value: AbstractTypeValue) -> AbstractTypeValue:
        elements: list[AbstractTypeValue] = []
        for typ in value.types:
            if isinstance(typ, TupleType):
                elements.extend(AbstractTypeValue.from_type(item) for item in typ.args)
            elif isinstance(typ, Instance):
                raw = typ.type.raw_type
                if raw is dict and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw in {list, set, frozenset} and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw in {cabc.Iterable, cabc.Iterator, cabc.Generator} and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw in {cabc.KeysView, cabc.ValuesView} and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw is cabc.ItemsView and len(typ.args) >= 2:
                    elements.append(
                        AbstractTypeValue.from_type(
                            TupleType((typ.args[0], typ.args[1]))
                        )
                    )
                elif raw is str:
                    elements.append(self._instance(str))
                elif raw is bytes:
                    elements.append(self._instance(int))
                elif raw is range:
                    elements.append(self._instance(int))
        return (
            join_all(
                elements,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            if elements
            else AbstractTypeValue.unresolved()
        )

    def _callable_return_type(
        self, value: AbstractTypeValue
    ) -> AbstractTypeValue:
        returns = [
            AbstractTypeValue.from_type(typ.return_type)
            for typ in value.types
            if isinstance(typ, CallableType)
        ]
        return (
            join_all(
                returns,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            if returns
            else AbstractTypeValue.unresolved()
        )

    def _assign_target(
        self,
        target: ast.expr,
        value: AbstractTypeValue,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> None:
        if isinstance(target, ast.Name):
            environment[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            unpacked = self._unpack_value(value, len(target.elts))
            for child, child_value in zip(target.elts, unpacked):
                self._assign_target(child, child_value, environment, current_function)
            return
        if isinstance(target, ast.Attribute):
            if (
                current_function is not None
                and current_function.owner is not None
                and isinstance(target.value, ast.Name)
                and current_function.parameter_names
                and target.value.id == current_function.parameter_names[0]
            ):
                key = (current_function.owner, target.attr)
                old = self._pending_attributes.get(
                    key, AbstractTypeValue.bottom()
                )
                self._pending_attributes[key] = self._join(old, value)
            return
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            name = target.value.id
            base = environment.get(name, AbstractTypeValue.unresolved())
            updated: list[AbstractTypeValue] = []
            for typ in base.types:
                if isinstance(typ, Instance) and typ.type.raw_type is dict:
                    key_type = typ.args[0] if typ.args else ANY
                    old_value = typ.args[1] if len(typ.args) > 1 else ANY
                    joined = self._join(
                        AbstractTypeValue.from_type(old_value), value
                    )
                    updated.append(
                        self._instance(dict, key_type, joined.public_type() or ANY)
                    )
                elif isinstance(typ, Instance) and typ.type.raw_type is list:
                    old_value = typ.args[0] if typ.args else ANY
                    joined = self._join(
                        AbstractTypeValue.from_type(old_value), value
                    )
                    updated.append(
                        self._instance(list, joined.public_type() or ANY)
                    )
            if updated:
                environment[name] = join_all(
                    updated,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )

    def _unpack_value(
        self, value: AbstractTypeValue, count: int
    ) -> list[AbstractTypeValue]:
        tuples = [typ for typ in value.types if isinstance(typ, TupleType)]
        if len(tuples) == 1 and len(tuples[0].args) == count:
            return [AbstractTypeValue.from_type(item) for item in tuples[0].args]
        element = self._iterable_element(value)
        return [element] * count

    def _comprehension_environment(
        self,
        generators: list[ast.comprehension],
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> dict[str, AbstractTypeValue]:
        result = dict(environment)
        for generator in generators:
            iterable = self._evaluate_expression(
                generator.iter,
                result,
                scope=scope,
                current_function=current_function,
            )
            self._assign_target(
                generator.target,
                self._iterable_element(iterable),
                result,
                current_function,
            )
            for condition in generator.ifs:
                result = self._narrow_environment(condition, result, truthy=True)
        return result

    def _evaluate_many(
        self,
        nodes: Iterable[ast.expr],
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        values = [
            self._evaluate_expression(
                node,
                environment,
                scope=scope,
                current_function=current_function,
            )
            for node in nodes
        ]
        if any(self._is_never_value(value) for value in values):
            return AbstractTypeValue.from_type(NEVER)
        return join_all(
            values,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    def _evaluate_type_expression(self, node: ast.expr) -> AbstractTypeValue:
        if isinstance(node, ast.Tuple):
            return join_all(
                (self._evaluate_type_expression(item) for item in node.elts),
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
        try:
            annotation = ast.unparse(node)
        except Exception:
            return AbstractTypeValue.unresolved()
        return AbstractTypeValue.from_type(
            resolve_annotation(
                annotation,
                cast(TypeLookup, self._lookup_annotation_type),
            )
        )

    def _join(
        self, left: AbstractTypeValue, right: AbstractTypeValue
    ) -> AbstractTypeValue:
        return left.join(
            right,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    def _join_normal_results(
        self, values: Iterable[AbstractTypeValue]
    ) -> AbstractTypeValue:
        """Join values from branches that can complete normally."""
        candidates = list(values)
        normal = [
            value for value in candidates if not self._is_never_value(value)
        ]
        return join_all(
            normal or candidates,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    def _join_environments(
        self,
        left: dict[str, AbstractTypeValue],
        right: dict[str, AbstractTypeValue],
    ) -> dict[str, AbstractTypeValue]:
        result: dict[str, AbstractTypeValue] = {}
        for name in left.keys() | right.keys():
            left_value = left.get(name, AbstractTypeValue.unresolved())
            right_value = right.get(name, AbstractTypeValue.unresolved())
            result[name] = self._join(left_value, right_value)
        return result

    def _join_many_environments(
        self, environments: Iterable[dict[str, AbstractTypeValue]]
    ) -> dict[str, AbstractTypeValue]:
        iterator = iter(environments)
        try:
            result = dict(next(iterator))
        except StopIteration:
            return {}
        for environment in iterator:
            result = self._join_environments(result, environment)
        return result

    def _instance(self, raw_type: type, *args: ProperType) -> AbstractTypeValue:
        return AbstractTypeValue.from_type(self._proper_instance(raw_type, *args))

    def _proper_instance(self, raw_type: type, *args: ProperType) -> Instance:
        self._register_type_hierarchy(raw_type)
        return Instance(self.type_system.to_class_descriptor(raw_type), tuple(args))

    def _register_type_hierarchy(self, raw_type: type) -> None:
        if raw_type in self._registered_hierarchy:
            return
        self._registered_hierarchy.add(raw_type)
        descriptor = self.type_system.to_class_descriptor(raw_type)
        for base in getattr(raw_type, "__bases__", ()):
            self._register_type_hierarchy(base)
            self.type_system.add_subclass_edge(
                super_class=self.type_system.to_class_descriptor(base),
                sub_class=descriptor,
            )

    def _synthetic_instance(self, full_name: str) -> Instance:
        raw = self._synthetic_types.get(full_name)
        if raw is None:
            module, _, name = full_name.rpartition(".")
            raw = type(name, (), {"__module__": module})
            self._synthetic_types[full_name] = raw
        return self._proper_instance(raw)

    def _contains_raw(self, value: AbstractTypeValue, raw_type: type) -> bool:
        return any(
            isinstance(typ, Instance) and typ.type.raw_type is raw_type
            for typ in value.types
        )

    @staticmethod
    def _is_never_value(value: AbstractTypeValue) -> bool:
        """Whether evaluating a value cannot complete normally."""
        return not value.unknown and value.types == frozenset((NEVER,))

    def _remove_none(self, value: AbstractTypeValue) -> AbstractTypeValue:
        return value.without_type(NoneType)

    @staticmethod
    def _is_none_literal(node: ast.expr) -> bool:
        return isinstance(node, ast.Constant) and node.value is None

    def _unwrap_single_generic(
        self, value: AbstractTypeValue
    ) -> AbstractTypeValue:
        values = []
        for typ in value.types:
            if isinstance(typ, Instance) and typ.args:
                values.append(AbstractTypeValue.from_type(typ.args[-1]))
        return (
            join_all(values, self.type_system)
            if values
            else AbstractTypeValue.unresolved()
        )

    def _resolve_lexical_function(self, name: str, scope: str) -> str | None:
        current = scope
        while current:
            candidate = f"{current}.{name}"
            if candidate in self._functions:
                return candidate
            if "." not in current:
                break
            current = current.rpartition(".")[0]
        candidate = f"{self._module_name}.{name}"
        return candidate if candidate in self._functions else None

    def _resolve_import_name(self, name: str) -> str | None:
        direct = self._imports.get(name)
        if direct is not None:
            return direct
        prefix, separator, remainder = name.partition(".")
        if not separator or prefix not in self._imports:
            return None
        return f"{self._imports[prefix]}.{remainder}"

    def _qualified_callee_name(self, node: ast.expr) -> str | None:
        name = _expression_name(node)
        if name is None:
            return None
        return self._resolve_import_name(name) or name

    def _resolve_class_expression(self, node: ast.expr) -> str | None:
        name = _expression_name(node)
        if name is None:
            return None
        local = self._class_aliases.get(name)
        if local is not None:
            return local
        imported = self._resolve_import_name(name)
        if imported is not None:
            return imported
        qualified = f"{self._module_name}.{name}"
        if qualified in self._classes:
            return qualified
        if hasattr(builtins, name) and isinstance(getattr(builtins, name), type):
            return f"builtins.{name}"
        return name

    def _class_method(
        self,
        class_name: str,
        method: str,
        seen: set[str] | None = None,
    ) -> str | None:
        seen = set() if seen is None else seen
        if class_name in seen:
            return None
        seen.add(class_name)
        class_info = self._classes.get(class_name)
        if class_info is None:
            return None
        if method in class_info.methods:
            return class_info.methods[method]
        for base in class_info.bases:
            found = self._class_method(base, method, seen)
            if found is not None:
                return found
        return None

    def _class_attribute(
        self,
        class_name: str,
        attribute: str,
        seen: set[str] | None = None,
    ) -> AbstractTypeValue | None:
        seen = set() if seen is None else seen
        if class_name in seen:
            return None
        seen.add(class_name)
        class_info = self._classes.get(class_name)
        if class_info is None:
            return None
        if attribute in class_info.attributes:
            return class_info.attributes[attribute]
        for base in class_info.bases:
            found = self._class_attribute(base, attribute, seen)
            if found is not None:
                return found
        return None

    def _external_type(self, qualified_name: str) -> ProperType | None:
        if self.external_symbol_resolver is None:
            return None
        try:
            return self.external_symbol_resolver(qualified_name)
        except (ImportError, LookupError, OSError, RuntimeError):
            return None

    @staticmethod
    def _looks_like_class(name: str) -> bool:
        final = name.rsplit(".", 1)[-1]
        return bool(final) and final[0].isupper()

    def _record_expression(
        self, node: ast.AST, value: AbstractTypeValue
    ) -> None:
        span = _span(node)
        old = self._expressions.get(span)
        self._expressions[span] = value if old is None else self._join(old, value)

    def _build_symbols(
        self, environment: dict[str, AbstractTypeValue]
    ) -> dict[str, InferredSymbol]:
        symbols: dict[str, InferredSymbol] = {}
        for name, value in environment.items():
            qualified = f"{self._module_name}.{name}"
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
    ) -> None:
        span = None if node is None else _span(node)
        key = (code, message, span)
        if key in self._diagnostic_keys:
            return
        self._diagnostic_keys.add(key)
        self._diagnostics.append(
            InferenceDiagnostic(code, message, severity=severity, span=span)
        )


def _all_arguments(arguments: ast.arguments) -> list[ast.arg]:
    result = [*arguments.posonlyargs, *arguments.args]
    if arguments.vararg is not None:
        result.append(arguments.vararg)
    result.extend(arguments.kwonlyargs)
    if arguments.kwarg is not None:
        result.append(arguments.kwarg)
    return result


def _expression_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expression_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _span(node: ast.AST) -> SourceSpan:
    return SourceSpan(
        lineno=getattr(node, "lineno", 1),
        col_offset=getattr(node, "col_offset", 0),
        end_lineno=getattr(node, "end_lineno", None),
        end_col_offset=getattr(node, "end_col_offset", None),
    )
