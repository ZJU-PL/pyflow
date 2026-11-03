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
import collections
import collections.abc as cabc
import contextvars
import contextlib
import enum
import functools
import io
import itertools
import operator
import os
import queue
import concurrent.futures
import asyncio
import shutil
import subprocess
import logging
import tempfile
import re
import threading
import datetime
import tokenize
import types
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, cast

from pyflow.analysis.typeinfo.core.typesystem import (
    ANY,
    AnyType,
    NEVER,
    NONE_TYPE,
    CallableType,
    Instance,
    LiteralType,
    NeverType,
    NoneType,
    ProperType,
    TupleType,
    TypeType,
    TypeSystem,
    TypeVarType,
    UnionType,
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
from pyflow.analysis.typeinfo.resolution.typing_syntax import (
    collect_type_vars,
    substitute_type_vars,
)
from pyflow.analysis.typeinfo.resolution.docstrings import (
    search_param_in_docstr,
    search_return_in_docstr,
)
from pyflow.analysis.typeinfo.resolution.docstring_types import resolve_documented_type
from pyflow.analysis.typeinfo.resolution.imports import iter_module_imports
from pyflow.language.modules.project_resolution import ProjectContext

# Runtime names such as ``types.MappingProxyType`` are aliases for classes
# whose ``__name__`` differs (``mappingproxy``).  Class-object detection must
# compare against the actual runtime class name, not the imported alias.
_UNION_JOIN_METHODS = frozenset(
    {
        "copy",
        "count",
        "index",
        "get",
        "keys",
        "values",
        "items",
        "union",
        "intersection",
        "difference",
        "symmetric_difference",
        "issubset",
        "issuperset",
        "isdisjoint",
        "decode",
        "encode",
        "hex",
        "upper",
        "lower",
        "strip",
        "lstrip",
        "rstrip",
        "split",
        "rsplit",
        "splitlines",
        "replace",
        "startswith",
        "endswith",
        "find",
        "rfind",
        "join",
        "format",
        "title",
        "capitalize",
        "casefold",
        "center",
        "ljust",
        "rjust",
        "zfill",
        "removeprefix",
        "removesuffix",
        "partition",
        "rpartition",
        "swapcase",
        "translate",
        "expandtabs",
        "isalnum",
        "isalpha",
        "isdecimal",
        "isdigit",
        "isidentifier",
        "islower",
        "isnumeric",
        "isprintable",
        "isspace",
        "istitle",
        "isupper",
    }
)

_STDLIB_CLASS_ALIASES = {
    name: f"{value.__module__}.{value.__name__}"
    for name, value in vars(types).items()
    if isinstance(value, type) and value.__name__ != name
}

ExternalSymbolResolver = Callable[[str], ProperType | None]


@dataclass(frozen=True)
class InferenceOptions:
    """Precision and termination policy for static inference."""

    max_iterations: int = 24
    max_loop_iterations: int = 12
    max_union_size: int = 16
    strict_annotations: bool = False
    max_specializations_per_function: int = 32
    max_type_depth: int = 12


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
    default_parameters: dict[str, ast.expr] = field(default_factory=dict)
    explicit_return: AbstractTypeValue | None = None
    documented_parameters: dict[str, AbstractTypeValue] = field(default_factory=dict)
    documented_return: AbstractTypeValue | None = None
    parameter_evidence: dict[str, AbstractTypeValue] = field(default_factory=dict)
    closure_evidence: dict[str, AbstractTypeValue] = field(default_factory=dict)
    mutated_closure_names: set[str] = field(default_factory=set)
    extra_keywords: dict[str, AbstractTypeValue] = field(default_factory=dict)
    specializations: dict[_SpecializationKey, FunctionSpecialization] = field(default_factory=dict)
    widened_parameters: dict[str, AbstractTypeValue] = field(default_factory=dict)
    summary: FunctionSummary | None = None
    type_variables: dict[str, TypeVarType] = field(default_factory=dict)
    method_kind: str = "instance"
    global_names: set[str] = field(default_factory=set)
    nonlocal_names: set[str] = field(default_factory=set)
    is_generator_source: bool = False
    effective_return: AbstractTypeValue | None = None
    type_guard_target: tuple[str, AbstractTypeValue, bool] | None = None
    overloads: list["_FunctionInfo"] = field(default_factory=list)


@dataclass
class _ClassInfo:
    qualified_name: str
    instance: Instance
    methods: dict[str, str] = field(default_factory=dict)
    properties: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, AbstractTypeValue] = field(default_factory=dict)
    bases: tuple[str, ...] = ()
    type_variables: dict[str, TypeVarType] = field(default_factory=dict)
    type_var_bindings: dict[str, ProperType] = field(default_factory=dict)
    builtin_base: tuple[type, tuple[ProperType, ...]] | None = None
    attribute_templates: dict[str, AbstractTypeValue] = field(default_factory=dict)
    enum_values: dict[str, AbstractTypeValue] = field(default_factory=dict)


@dataclass
class _Outcome:
    environment: dict[str, AbstractTypeValue]
    returns: list[AbstractTypeValue] = field(default_factory=list)
    yields: list[AbstractTypeValue] = field(default_factory=list)
    terminated: bool = False
    breaks: bool = False
    continues: bool = False
    break_envs: list[dict[str, AbstractTypeValue]] = field(default_factory=list)
    continue_envs: list[dict[str, AbstractTypeValue]] = field(default_factory=list)


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
        self._source_lines = source.splitlines()

        self._collect_imports(self._tree)
        self._precollect_classes(self._tree.body, parent=module_name)
        self._collect_type_variables(self._tree.body)
        self._collect_declarations(self._tree.body, parent=module_name)
        self.type_system.invalidate_subtype_caches()
        self._refresh_effective_returns()

        self._persistent_diagnostics = list(self._diagnostics)
        self._persistent_keys = set(self._diagnostic_keys)

        module_environment: dict[str, AbstractTypeValue] = {}
        converged = False
        iterations = 0
        for iterations in range(1, self.options.max_iterations + 1):
            before = self._fingerprint()
            self._diagnostics = list(self._persistent_diagnostics)
            self._diagnostic_keys = set(self._persistent_keys)
            self._expressions.clear()
            self._expression_kinds.clear()
            self._pending_parameter_evidence.clear()
            self._pending_attributes.clear()
            self.type_system.invalidate_subtype_caches()

            initial = self._declaration_environment()
            outcome = self._execute_block(
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
            for function in list(self._functions.values()):
                self._analyse_function(function)

            self._commit_pending_evidence()
            self._refresh_effective_returns()
            if self._fingerprint() == before:
                converged = True
                break

        if not converged:
            self._add_diagnostic(
                "inference-did-not-converge",
                f"Inference reached the {self.options.max_iterations}-iteration limit",
                severity="warning",
            )

        self._refresh_class_member_signatures()

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
        self._source_lines: list[str] = []
        self._imports: dict[str, str] = {}
        self._star_imports: list[str] = []
        self._functions: dict[str, _FunctionInfo] = {}
        self._overloads: dict[str, list[_FunctionInfo]] = {}
        self._function_nodes: dict[int, str] = {}
        self._classes: dict[str, _ClassInfo] = {}
        self._class_aliases: dict[str, str] = {}
        self._type_vars: dict[str, TypeVarType] = {}
        self._annotation_owner: str | None = None
        self._resolving_attributes: set[tuple[str, str]] = set()
        self._type_aliases: dict[str, ast.expr] = {}
        self._value_assignments: set[str] = set()
        self._function_names: set[str] = set()
        self._alias_type_variables: dict[str, dict[str, TypeVarType]] = {}
        self._resolving_aliases: set[str] = set()
        self._annotation_substitutions: dict[str, ProperType] = {}
        self._expressions: dict[SourceSpan, AbstractTypeValue] = {}
        self._expression_kinds: dict[SourceSpan, type] = {}
        self._diagnostics: list[InferenceDiagnostic] = []
        self._diagnostic_keys: set[tuple[str, str, SourceSpan | None]] = set()
        self._persistent_diagnostics: list[InferenceDiagnostic] = []
        self._persistent_keys: set[tuple[str, str, SourceSpan | None]] = set()
        self._pending_parameter_evidence: dict[tuple[str, str], AbstractTypeValue] = {}
        self._pending_attributes: dict[tuple[str, str], AbstractTypeValue] = {}
        self._module_environment: dict[str, AbstractTypeValue] = {}
        self._last_argument_mutations: list[tuple[ast.expr, AbstractTypeValue]] = []
        self._observed_yields: list[AbstractTypeValue] = []
        self._call_unknown_positional = False
        self._call_unknown_keywords = False
        self._current_function_info: _FunctionInfo | None = None
        self._mro_cache: dict[str, list[str]] = {}
        self._collect_specializations = True

    # ------------------------------------------------------------------
    # Declaration and annotation discovery
    # ------------------------------------------------------------------

    def _collect_imports(self, tree: ast.Module) -> None:
        for node in iter_module_imports(tree.body):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self._imports[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    module = (
                        self.project_context.resolve_import_name(
                            self._module_name,
                            module or None,
                            node.level,
                            current_path=self._filename,
                        )
                        or module
                    )
                for alias in node.names:
                    if alias.name == "*":
                        if module:
                            self._star_imports.append(module)
                        continue
                    local = alias.asname or alias.name
                    self._imports[local] = f"{module}.{alias.name}" if module else alias.name

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
                previous_owner = self._annotation_owner
                previous_vars = dict(self._type_vars)
                self._annotation_owner = qualified
                for base_node in node.bases:
                    if isinstance(base_node, ast.Subscript):
                        for parameter in ast.walk(base_node.slice):
                            if isinstance(parameter, ast.Name) and parameter.id in self._type_vars:
                                class_info.type_variables[parameter.id] = self._type_vars[
                                    parameter.id
                                ]
                        if not class_info.type_variables:
                            resolved = self._annotation_value(base_node).public_type()
                            if isinstance(resolved, Instance) and resolved.args:
                                base_info = self._classes.get(resolved.type.full_name)
                                if base_info is not None and base_info.type_variables:
                                    class_info.type_variables = dict(base_info.type_variables)
                class_info.instance.type.type_parameters = tuple(class_info.type_variables.values())
                self._type_vars.update(class_info.type_variables)
                for base_node in node.bases:
                    if not isinstance(base_node, ast.Subscript):
                        continue
                    resolved_base = self._annotation_value(base_node).public_type()
                    if not isinstance(resolved_base, Instance):
                        continue
                    if isinstance(
                        resolved_base.type.raw_type, type
                    ) and resolved_base.type.raw_type in {
                        list,
                        set,
                        frozenset,
                        dict,
                        tuple,
                    }:
                        class_info.builtin_base = (
                            resolved_base.type.raw_type,
                            resolved_base.args,
                        )
                    base_info = self._classes.get(resolved_base.type.full_name)
                    if base_info is None:
                        continue
                    bindings = dict(base_info.type_var_bindings)
                    template = list(base_info.type_variables)
                    if template and resolved_base.args:
                        bindings.update(zip(template, resolved_base.args))
                    class_info.type_var_bindings.update(bindings)
                for base in class_info.bases:
                    base_info = self._classes.get(base)
                    if base_info and base_info.instance.type.typed_dict_fields is not None:
                        class_info.instance.type.typed_dict_fields = dict(
                            base_info.instance.type.typed_dict_fields
                        )
                        class_info.instance.type.required_keys = (
                            base_info.instance.type.required_keys
                        )
                        class_info.attributes.update(base_info.attributes)
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        if self._is_dataclass_pseudo_annotation(item.annotation):
                            continue
                        val_annotation = self._annotation_value(item.annotation)
                        is_bare = (
                            isinstance(item.annotation, ast.Name)
                            and item.annotation.id in {"Final", "ClassVar"}
                        ) or (
                            isinstance(item.annotation, ast.Attribute)
                            and item.annotation.attr in {"Final", "ClassVar"}
                        )
                        if is_bare and item.value is not None:
                            val_annotation = self._evaluate_expression(
                                item.value, {}, scope=qualified, current_function=None
                            )
                        class_info.attributes[item.target.id] = val_annotation
                self._collect_declarations(
                    node.body,
                    parent=qualified,
                    owner=qualified,
                )
                descriptor = class_info.instance.type
                descriptor.members.update(
                    {
                        name: value.public_type() or ANY
                        for name, value in class_info.attributes.items()
                    }
                )
                if descriptor.typed_dict_fields is not None:
                    descriptor.typed_dict_fields.update(descriptor.members)
                    required = set(descriptor.required_keys)
                    total = not any(
                        keyword.arg == "total"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                        for keyword in node.keywords
                    )
                    for item in node.body:
                        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            wrapper = (
                                self._qualified_callee_name(item.annotation.value)
                                if isinstance(item.annotation, ast.Subscript)
                                else ""
                            ) or ""
                            if wrapper.endswith("Required") and not wrapper.endswith("NotRequired"):
                                required.add(item.target.id)
                            elif wrapper.endswith("NotRequired"):
                                required.discard(item.target.id)
                            elif total:
                                required.add(item.target.id)
                    descriptor.required_keys = frozenset(required)
                if descriptor.tuple_fields is not None:
                    descriptor.tuple_fields = tuple(class_info.attributes)
                for name, target in class_info.methods.items():
                    signature = self._function_value(self._functions[target]).public_type()
                    if isinstance(signature, CallableType):
                        descriptor.members[name] = (
                            signature.return_type
                            if name in class_info.properties
                            else CallableType(
                                (
                                    signature.arg_types
                                    if self._functions[target].method_kind == "static"
                                    else signature.arg_types[1:] if signature.arg_types else ()
                                ),
                                signature.return_type,
                            )
                        )
                self._annotation_owner = previous_owner
                self._type_vars = previous_vars
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                previous_vars = dict(self._type_vars)
                self._type_vars.update(self._pep695_type_variables(node))
                qualified = f"{parent}.{node.name}"
                accessor = next(
                    (
                        decorator.attr
                        for decorator in node.decorator_list
                        if isinstance(decorator, ast.Attribute)
                        and decorator.attr in {"setter", "deleter"}
                        and isinstance(decorator.value, ast.Name)
                        and decorator.value.id == node.name
                    ),
                    "",
                )
                getter = any(
                    (self._qualified_callee_name(decorator) or "").rsplit(".", 1)[-1]
                    in {"property", "cached_property"}
                    for decorator in node.decorator_list
                    if not isinstance(decorator, ast.Call)
                )
                if owner and accessor:
                    qualified += f".<{accessor}>"
                parameters = [arg.arg for arg in _all_arguments(node.args)]
                info = _FunctionInfo(
                    qualified_name=qualified,
                    node=node,
                    parameter_names=parameters,
                    owner=owner,
                    type_variables=dict(self._type_vars),
                )
                decorators = {self._qualified_callee_name(item) for item in node.decorator_list}
                if decorators & {"staticmethod", "builtins.staticmethod"}:
                    info.method_kind = "static"
                elif decorators & {"classmethod", "builtins.classmethod"}:
                    info.method_kind = "class"
                for arg in _all_arguments(node.args):
                    if arg.annotation is not None:
                        info.explicit_parameters[arg.arg] = self._annotation_value(arg.annotation)
                positional = [*node.args.posonlyargs, *node.args.args]
                if node.args.defaults:
                    for arg, default in zip(
                        positional[-len(node.args.defaults) :], node.args.defaults
                    ):
                        info.default_parameters[arg.arg] = default
                for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                    if default is not None:
                        info.default_parameters[arg.arg] = default
                if node.returns is not None:
                    info.explicit_return = self._annotation_value(node.returns)
                docstring = ast.get_docstring(node)
                if docstring:

                    def resolve_hint(text: str) -> ProperType | None:
                        return self._annotation_value(ast.Constant(value=text)).public_type()

                    for arg in _all_arguments(node.args):
                        if arg.annotation is None:
                            hint = resolve_documented_type(
                                search_param_in_docstr(docstring, arg.arg), resolve_hint
                            )
                            if hint is not None:
                                info.documented_parameters[arg.arg] = AbstractTypeValue.from_type(
                                    hint
                                )
                    if node.returns is None:
                        hint = resolve_documented_type(
                            search_return_in_docstr(docstring), resolve_hint
                        )
                        if hint is not None:
                            info.documented_return = AbstractTypeValue.from_type(hint)
                info.global_names = {
                    name
                    for statement in node.body
                    if isinstance(statement, ast.Global)
                    for name in statement.names
                }
                info.nonlocal_names = {
                    name
                    for statement in node.body
                    if isinstance(statement, ast.Nonlocal)
                    for name in statement.names
                }
                info.is_generator_source = self._contains_yield(node)
                if node.returns is not None and isinstance(node.returns, ast.Subscript):
                    guard_callee = self._qualified_callee_name(node.returns.value) or (
                        node.returns.value.id if isinstance(node.returns.value, ast.Name) else ""
                    )
                    guard_short = guard_callee.rsplit(".", 1)[-1]
                    if guard_short in {"TypeGuard", "TypeIs"}:
                        guard_target = self._evaluate_type_expression(node.returns.slice)
                        first_param = info.parameter_names[0] if info.parameter_names else None
                        if first_param and not guard_target.unknown:
                            info.type_guard_target = (
                                first_param,
                                guard_target,
                                guard_short == "TypeIs",
                            )
                is_overload = bool(
                    decorators & {"overload", "typing.overload", "typing_extensions.overload"}
                )
                if is_overload:
                    self._overloads.setdefault(qualified, []).append(info)
                    if qualified not in self._functions:
                        self._functions[qualified] = info
                else:
                    info.overloads = list(self._overloads.get(qualified, ()))
                    self._functions[qualified] = info
                for decorator in node.decorator_list:
                    target = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if not (
                        isinstance(target, ast.Attribute)
                        and target.attr in {"register", "dispatch"}
                    ):
                        continue
                    base_name = _expression_name(target.value)
                    if base_name is None:
                        continue
                    base = self._resolve_lexical_function(base_name, parent)
                    if base is not None and base != qualified:
                        self._functions[base].overloads.append(info)
                info.effective_return = self._decorator_effective_return(node, parent)
                self._function_names.add(node.name)
                self._function_nodes[id(node)] = qualified
                if owner is not None and not accessor:
                    self._classes[owner].methods[node.name] = qualified
                    if getter:
                        self._classes[owner].properties[node.name] = qualified
                    if node.name == "__init__" and parameters:
                        templates = self._classes[owner].attribute_templates
                        for statement in ast.walk(node):
                            if isinstance(statement, ast.AnnAssign):
                                targets = [statement.target]
                                template = self._annotation_value(statement.annotation)
                            elif isinstance(statement, ast.Assign) and isinstance(
                                statement.value, ast.Name
                            ):
                                targets = statement.targets
                                template = info.explicit_parameters.get(statement.value.id)
                                if template is not None:
                                    template = self._body_parameter_value(
                                        info, statement.value.id, template
                                    )
                            else:
                                continue
                            for target in targets:
                                if (
                                    template is not None
                                    and isinstance(target, ast.Attribute)
                                    and isinstance(target.value, ast.Name)
                                    and target.value.id == parameters[0]
                                ):
                                    templates[target.attr] = template
                self._collect_declarations(
                    node.body,
                    parent=qualified,
                    owner=None,
                )
                self._type_vars = previous_vars

    @staticmethod
    def _is_dataclass_pseudo_annotation(node: ast.expr) -> bool:
        base = node.value if isinstance(node, ast.Subscript) else node
        name = _expression_name(base) or ""
        return name.rsplit(".", 1)[-1] in {"KW_ONLY", "InitVar"}

    def _precollect_classes(
        self,
        statements: Iterable[ast.stmt],
        *,
        parent: str,
    ) -> None:
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._precollect_classes(node.body, parent=f"{parent}.{node.name}")
                continue
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
            descriptor = self._classes[qualified].instance.type
            # Source classes rebuild their structure on every analysis pass.
            # Clear fields left by a previous revision of this module (for
            # example a NamedTuple or TypedDict that is now a plain class).
            # Stub descriptors are refreshed separately and keep their
            # incrementally populated members.
            descriptor.members.clear()
            descriptor.instance_attributes.clear()
            descriptor.attributes.clear()
            descriptor.typed_dict_fields = None
            descriptor.required_keys = frozenset()
            descriptor.tuple_fields = None
            descriptor.type_parameters = ()
            descriptor.is_protocol = any(base.rsplit(".", 1)[-1] == "Protocol" for base in bases)
            if any(base.rsplit(".", 1)[-1] == "TypedDict" for base in bases):
                descriptor.typed_dict_fields = {}
            if any(base.rsplit(".", 1)[-1] == "NamedTuple" for base in bases):
                descriptor.tuple_fields = ()
            variables = self._pep695_type_variables(node)
            for base_node in node.bases:
                if isinstance(base_node, ast.Subscript):
                    resolved_base = self._annotation_value(base_node).public_type()
                    if isinstance(resolved_base, Instance):
                        base_info = self._classes.get(resolved_base.type.full_name)
                        if base_info is not None:
                            bindings = dict(base_info.type_var_bindings)
                            template = list(base_info.type_variables)
                            if template and resolved_base.args:
                                bindings.update(zip(template, resolved_base.args))
                            self._classes[qualified].type_var_bindings.update(bindings)
                    for parameter in ast.walk(base_node.slice):
                        if isinstance(parameter, ast.Name) and parameter.id in self._type_vars:
                            variables[parameter.id] = self._type_vars[parameter.id]
                    if not variables:
                        # ``class IntBox(Box[int])`` inherits Box's type
                        # parameters; constructor inference below binds them
                        # from the inherited __init__ arguments.
                        resolved = self._annotation_value(base_node).public_type()
                        if isinstance(resolved, Instance) and resolved.args:
                            base_info = self._classes.get(resolved.type.full_name)
                            if base_info is not None and base_info.type_variables:
                                variables = dict(base_info.type_variables)
            self._classes[qualified].type_variables = variables
            descriptor.type_parameters = tuple(variables.values())
            for base in bases:
                base_type = self._lookup_annotation_type(base)
                if isinstance(base_type, Instance):
                    self.type_system.add_subclass_edge(
                        super_class=base_type.type,
                        sub_class=self._classes[qualified].instance.type,
                    )
                    if base_type.type.typed_dict_fields is not None:
                        descriptor.typed_dict_fields = dict(base_type.type.typed_dict_fields)
                        descriptor.required_keys = base_type.type.required_keys
            enum_kind = next(
                (kind for base in bases if (kind := self._enum_base_kind(base)) is not None),
                None,
            )
            if enum_kind in {"IntEnum", "IntFlag"}:
                self.type_system.add_subclass_edge(
                    super_class=self.type_system.to_class_descriptor(int),
                    sub_class=self._classes[qualified].instance.type,
                )
            elif enum_kind == "StrEnum":
                self.type_system.add_subclass_edge(
                    super_class=self.type_system.to_class_descriptor(str),
                    sub_class=self._classes[qualified].instance.type,
                )
            if enum_kind is not None:
                self._classes[qualified].instance.type.enum_kind = enum_kind
                for item in node.body:
                    targets: list[ast.expr] = []
                    if isinstance(item, ast.Assign):
                        targets = list(item.targets)
                    elif isinstance(item, ast.AnnAssign):
                        targets = [item.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and not target.id.startswith("_"):
                            self._classes[qualified].enum_values.setdefault(
                                target.id, AbstractTypeValue.from_type(ANY)
                            )
            self._precollect_classes(node.body, parent=qualified)

    def _collect_type_variables(self, statements: Iterable[ast.stmt]) -> None:
        for node in statements:
            if isinstance(node, getattr(ast, "TypeAlias", ())):
                self._type_aliases[node.name.id] = node.value
                self._alias_type_variables[node.name.id] = self._pep695_type_variables(node)
                continue
            if isinstance(node, ast.ClassDef):
                self._collect_type_variables(node.body)
                continue
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.value is not None
                and self._qualified_callee_name(node.annotation)
                in {"typing.TypeAlias", "typing_extensions.TypeAlias"}
            ):
                self._type_aliases[node.target.id] = node.value
                continue
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            value = node.value
            if isinstance(target, ast.Name) and self._is_type_alias_expression(value):
                self._type_aliases[target.id] = value
                continue
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Call)
                and self._qualified_callee_name(value.func)
                in {"typing.NewType", "typing_extensions.NewType"}
                and len(value.args) >= 2
            ):
                self._type_aliases[target.id] = value.args[1]
                continue
            if not (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Call)
                and isinstance(value.func, (ast.Name, ast.Attribute))
                and self._qualified_callee_name(value.func)
                in {"TypeVar", "typing.TypeVar", "typing_extensions.TypeVar"}
            ):
                if isinstance(target, ast.Name):
                    self._value_assignments.add(target.id)
                continue
            constraints = tuple(
                resolved
                for argument in value.args[1:]
                if (resolved := self._evaluate_type_expression(argument).public_type()) is not None
            )
            bound = None
            variance = Variance.INVARIANT
            for keyword in value.keywords:
                if keyword.arg == "bound":
                    bound = self._evaluate_type_expression(keyword.value).public_type()
                elif (
                    keyword.arg == "covariant"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value
                ):
                    variance = Variance.COVARIANT
                elif (
                    keyword.arg == "contravariant"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value
                ):
                    variance = Variance.CONTRAVARIANT
            self._type_vars[target.id] = TypeVarType(
                target.id,
                constraints=constraints,
                bound=bound,
                variance=variance,
            )

    def _is_type_alias_expression(self, node: ast.expr) -> bool:
        """Recognize type syntax without treating ordinary indexing as an alias."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self._is_type_alias_expression(node.left) and self._is_type_alias_expression(
                node.right
            )
        if isinstance(node, ast.Constant):
            # ``X = None`` is a common sentinel value, not a type alias.
            # Treating it as one makes every later ``Y = X`` resolve to NoneType.
            return False
        base = node.value if isinstance(node, ast.Subscript) else node
        name = _expression_name(base)
        if name is None:
            return False
        if name in self._value_assignments or name in self._function_names:
            # A local value/function shadows a builtin type name.
            return False
        if name in self._class_aliases:
            class_info = self._classes.get(self._class_aliases[name])
            if self._is_enum_class_info(class_info):
                return False
            return True
        if name in self._type_aliases or name in self._type_vars:
            return True
        qualified = self._qualified_callee_name(base) or name
        if qualified.startswith(("typing.", "typing_extensions.", "collections.abc.")):
            return True
        return BuiltinTypeLookup()(qualified) is not None

    def _pep695_type_variables(self, node: ast.AST) -> dict[str, TypeVarType]:
        variables = {}
        for parameter in getattr(node, "type_params", ()):
            bound_node = getattr(parameter, "bound", None)
            constraints = ()
            bound = None
            if isinstance(bound_node, ast.Tuple):
                constraints = tuple(
                    self._annotation_value(item).public_type() or ANY for item in bound_node.elts
                )
            elif bound_node is not None:
                bound = self._annotation_value(bound_node).public_type()
            variables[parameter.name] = TypeVarType(
                parameter.name, bound=bound, constraints=constraints
            )
        return variables

    def _annotation_value(self, node: ast.expr) -> AbstractTypeValue:
        if isinstance(node, ast.Starred) or (
            isinstance(node, ast.Subscript)
            and self._qualified_callee_name(node.value)
            in {
                "Unpack",
                "typing.Unpack",
                "typing_extensions.Unpack",
            }
        ):
            # Variadic parameter annotations are not fully modelled yet.
            # Treat them as gradual evidence instead of re-specializing the
            # same call until project inference hits its iteration limit.
            return AbstractTypeValue.from_type(ANY)
        try:
            text = ast.unparse(node)
        except Exception:
            return AbstractTypeValue.unresolved()
        resolved = resolve_annotation(
            text,
            cast(TypeLookup, self._lookup_annotation_type),
            aliases=self._annotation_aliases(),
            type_parameters={
                name: tuple(parameters) for name, parameters in self._alias_type_variables.items()
            },
        )
        uncertain = self._has_unresolved_annotation(resolved)
        if uncertain:
            self._add_diagnostic(
                "unresolved-annotation",
                f"No external type facts for annotation {text}",
                node=node,
                affects_completeness=True,
            )
        return AbstractTypeValue.from_type(resolved, unknown=uncertain)

    def _annotation_aliases(self):
        return {
            name: target
            for name, target in self._imports.items()
            if name not in self._class_aliases
            and f"{self._module_name}.{name}" not in self._functions
        }

    @staticmethod
    def _has_unresolved_annotation(typ):
        if isinstance(typ, Instance):
            return bool(getattr(typ.type.raw_type, "__pyflow_unresolved_external__", False)) or any(
                StaticTypeInferenceEngine._has_unresolved_annotation(item) for item in typ.args
            )
        if isinstance(typ, (UnionType, TupleType)):
            return any(
                StaticTypeInferenceEngine._has_unresolved_annotation(item)
                for item in (typ.items if isinstance(typ, UnionType) else typ.args)
            )
        if isinstance(typ, TypeType):
            return StaticTypeInferenceEngine._has_unresolved_annotation(typ.item)
        if isinstance(typ, CallableType):
            return StaticTypeInferenceEngine._has_unresolved_annotation(typ.return_type) or any(
                StaticTypeInferenceEngine._has_unresolved_annotation(item)
                for item in typ.arg_types or ()
            )
        return False

    @staticmethod
    def _contains_type_var(typ) -> bool:
        if isinstance(typ, TypeVarType):
            return True
        if isinstance(typ, Instance):
            return any(StaticTypeInferenceEngine._contains_type_var(item) for item in typ.args)
        if isinstance(typ, (UnionType, TupleType)):
            return any(
                StaticTypeInferenceEngine._contains_type_var(item)
                for item in (typ.items if isinstance(typ, UnionType) else typ.args)
            )
        if isinstance(typ, TypeType):
            return StaticTypeInferenceEngine._contains_type_var(typ.item)
        if isinstance(typ, CallableType):
            return StaticTypeInferenceEngine._contains_type_var(typ.return_type) or any(
                StaticTypeInferenceEngine._contains_type_var(item) for item in typ.arg_types or ()
            )
        return False

    def _lookup_annotation_type(self, name: str) -> ProperType | None:
        normalized = name.rsplit(".", 1)[-1]
        if normalized in self._annotation_substitutions:
            return self._annotation_substitutions[normalized]
        if normalized == "Self" and self._annotation_owner:
            return TypeVarType("Self", bound=self._classes[self._annotation_owner].instance)
        if name in self._type_aliases and name not in self._resolving_aliases:
            self._resolving_aliases.add(name)
            previous_vars = self._type_vars
            self._type_vars = {**previous_vars, **self._alias_type_variables.get(name, {})}
            try:
                return self._annotation_value(self._type_aliases[name]).public_type()
            finally:
                self._type_vars = previous_vars
                self._resolving_aliases.remove(name)
        type_var = self._type_vars.get(name) or self._type_vars.get(normalized)
        if type_var is not None:
            return type_var
        local = self._class_aliases.get(name) or self._class_aliases.get(normalized)
        if local is not None:
            return self._classes[local].instance

        class_name, separator, member_name = name.rpartition(".")
        if separator:
            resolved_class_name = class_name
            if resolved_class_name not in self._classes:
                resolved_class_name = self._class_aliases.get(class_name, class_name)
            class_info = self._classes.get(resolved_class_name)
            if (
                class_info is not None
                and class_info.enum_values
                and member_name in class_info.enum_values
            ):
                return LiteralType(
                    ("enum", class_info.qualified_name, member_name),
                    class_info.instance,
                )

        imported = self._resolve_import_name(name)
        if imported is not None:
            external = self._external_type(imported)
            if external is not None:
                if isinstance(external, TypeType):
                    external = external.item
                if (
                    isinstance(external, CallableType)
                    and external.arg_types
                    and len(external.arg_types) == 1
                    and external.return_type == external.arg_types[0]
                ):
                    # Cross-module ``NewType`` aliases are exposed as their
                    # identity constructor; annotations should use the wrapped
                    # type.
                    external = external.arg_types[0]
                return external
            builtin = BuiltinTypeLookup()(imported)
            if builtin is not None:
                external = self._external_type(imported)
                if external is not None:
                    if isinstance(external, TypeType):
                        external = external.item
                    if (
                        isinstance(external, CallableType)
                        and external.arg_types
                        and len(external.arg_types) == 1
                        and external.return_type == external.arg_types[0]
                    ):
                        external = external.arg_types[0]
                    return external
                return builtin
            return self._synthetic_instance(imported, unresolved=True)

        external = self._external_type(name)
        if external is not None:
            if isinstance(external, TypeType):
                external = external.item
            return external
        builtin = BuiltinTypeLookup()(name)
        if builtin is not None:
            return builtin
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

    def _refresh_class_member_signatures(self) -> None:
        """Refresh descriptor members after unannotated methods are summarized."""
        for class_info in self._classes.values():
            for name, target in class_info.methods.items():
                function = self._functions.get(target)
                if function is None:
                    continue
                signature = self._function_value(function).public_type()
                if not isinstance(signature, CallableType):
                    continue
                if name in class_info.properties:
                    class_info.instance.type.members[name] = signature.return_type
                elif function.method_kind == "static":
                    class_info.instance.type.members[name] = signature
                else:
                    class_info.instance.type.members[name] = CallableType(
                        signature.arg_types[1:] if signature.arg_types else (),
                        signature.return_type,
                    )
        self.type_system.invalidate_subtype_caches()

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
        summary_return = (
            function.effective_return
            if function.effective_return is not None
            else fallback.return_value
        )
        function.summary = FunctionSummary(
            qualified_name=function.qualified_name,
            parameters=fallback.parameter_map,
            return_value=summary_return,
            yield_value=fallback.yield_value,
            return_dependencies=self._return_dependencies(function),
            is_async=isinstance(function.node, ast.AsyncFunctionDef),
            is_generator=function.is_generator_source or not fallback.yield_value.is_bottom,
            specializations=ordered_specializations,
        )

    def _fallback_parameters(self, function: _FunctionInfo) -> dict[str, AbstractTypeValue]:
        parameters: dict[str, AbstractTypeValue] = {}
        for index, name in enumerate(function.parameter_names):
            explicit = function.explicit_parameters.get(name)
            if explicit is not None and not explicit.unknown:
                parameters[name] = self._body_parameter_value(function, name, explicit)
                continue
            evidence = function.parameter_evidence.get(name, AbstractTypeValue.bottom())
            pending = self._pending_parameter_evidence.get(
                (function.qualified_name, name), AbstractTypeValue.bottom()
            )
            combined = self._join(evidence, pending)
            if not combined.is_bottom:
                parameters[name] = combined
            elif function.owner is not None and function.method_kind != "static" and index == 0:
                parameters[name] = AbstractTypeValue.from_type(
                    self._classes[function.owner].instance,
                    class_target=function.owner if function.method_kind == "class" else None,
                )
            else:
                default = function.default_parameters.get(name)
                if default is not None:
                    parameters[name] = self._evaluate_expression(
                        default,
                        self._module_environment,
                        scope=function.qualified_name,
                        current_function=None,
                    )
                else:
                    parameters[name] = function.documented_parameters.get(
                        name, AbstractTypeValue.unresolved()
                    )
        return parameters

    def _body_parameter_value(
        self,
        function: _FunctionInfo,
        name: str,
        value: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Project a parameter annotation to the object visible in the body.

        ``*args: T`` binds a tuple of ``T`` and ``**kwargs: T`` binds a
        ``dict[str, T]``.  Call signatures keep the element type, but body
        analysis must see the container.
        """
        arguments = function.node.args
        if arguments.vararg is not None and arguments.vararg.arg == name:
            annotation = arguments.vararg.annotation
            if isinstance(annotation, ast.Attribute) and annotation.attr == "args":
                # ParamSpec.args already describes the whole positional
                # argument tuple; wrapping it again produces
                # tuple[tuple[...], ...] and corrupts forwarded calls.
                return AbstractTypeValue.from_type(TupleType((ANY,), unknown_size=True))
            if any(
                isinstance(typ, TupleType)
                or (isinstance(typ, Instance) and typ.type.raw_type is tuple)
                for typ in value.types
            ):
                return value
            return AbstractTypeValue.from_type(
                TupleType((value.public_type() or ANY,), unknown_size=True)
            )
        if arguments.kwarg is not None and arguments.kwarg.arg == name:
            annotation = arguments.kwarg.annotation
            if isinstance(annotation, ast.Attribute) and annotation.attr == "kwargs":
                return self._instance(dict, self._proper_instance(str), ANY)
            if any(isinstance(typ, Instance) and typ.type.raw_type is dict for typ in value.types):
                return value
            return self._instance(dict, self._proper_instance(str), value.public_type() or ANY)
        return value

    @staticmethod
    def _contains_yield(node: ast.AST) -> bool:
        stack: list[tuple[ast.AST, bool]] = [(node, True)]
        while stack:
            child, root = stack.pop()
            if not root and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                continue
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
            stack.extend((item, False) for item in ast.iter_child_nodes(child))
        return False

    def _interface_stub(self, function):
        node = function.node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        marked = any(
            (self._qualified_callee_name(item.func if isinstance(item, ast.Call) else item) or "")
            in {
                "abc.abstractmethod",
                "abstractmethod",
                "typing.overload",
                "typing_extensions.overload",
                "overload",
            }
            for item in node.decorator_list
        )
        owner = self._classes.get(function.owner)
        marked = marked or bool(
            owner
            and any(
                base in {"typing.Protocol", "typing_extensions.Protocol", "Protocol"}
                for base in owner.bases
            )
        )

        def empty(statement):
            if isinstance(statement, ast.Pass):
                return True
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                return statement.value.value is Ellipsis or isinstance(statement.value.value, str)
            if isinstance(statement, ast.Raise):
                value = statement.exc.func if isinstance(statement.exc, ast.Call) else statement.exc
                return isinstance(value, ast.Name) and value.id == "NotImplementedError"
            return False

        has_ellipsis = any(
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is Ellipsis
            for statement in node.body
        )
        is_stub_file = bool(getattr(self, "_filename", "").endswith(".pyi"))
        has_docstring_only = bool(
            node.body
            and all(
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
                for statement in node.body
            )
        )
        # An ellipsis body is the conventional in-source stub form.  It is
        # common outside protocols and overloads (generic classes, interfaces
        # awaiting implementation), and must not be treated as ``return None``.
        return all(empty(statement) for statement in node.body) and (
            marked or has_ellipsis or is_stub_file or has_docstring_only
        )

    def _class_is_metaclass(self, class_info: _ClassInfo) -> bool:
        return any(
            base.rsplit(".", 1)[-1] in {"type", "ABCMeta"} for base in class_info.bases
        ) or any(
            method in class_info.methods for method in {"__subclasscheck__", "__instancecheck__"}
        )

    def _analyse_function_context(
        self,
        function: _FunctionInfo,
        parameters: dict[str, AbstractTypeValue],
        *,
        widened: bool = False,
        collect_specializations: bool,
    ) -> FunctionSpecialization:
        environment: dict[str, AbstractTypeValue] = {}
        environment.update(function.closure_evidence)
        substitutions = self._generic_substitutions(function, parameters)
        input_parameters: dict[str, AbstractTypeValue] = {}
        for name in function.parameter_names:
            actual = parameters.get(name)
            if actual is None:
                default = function.default_parameters.get(name)
                if default is not None:
                    actual = self._evaluate_expression(
                        default,
                        self._module_environment,
                        scope=function.qualified_name,
                        current_function=None,
                    )
                else:
                    actual = AbstractTypeValue.unresolved()
            explicit = function.explicit_parameters.get(name)
            if explicit is not None:
                explicit_type = explicit.public_type()
                if explicit_type is not None and substitutions:
                    explicit_type = substitute_type_vars(explicit_type, substitutions)
                types = frozenset(() if explicit_type is None else (explicit_type,))
                unknown = explicit.unknown
                if unknown:
                    # A partially unresolved annotation is still useful evidence.
                    # Keep its known alternatives and the default/call-site
                    # evidence, but never let the default replace the annotation.
                    is_vararg = bool(
                        function.node.args.vararg and function.node.args.vararg.arg == name
                    )
                    is_kwarg = bool(
                        function.node.args.kwarg and function.node.args.kwarg.arg == name
                    )
                    if is_vararg:
                        elem_types = self._iterable_element(actual).types
                        types = frozenset(set(types) | set(elem_types))
                    elif is_kwarg:
                        kw_val_types = set()
                        for typ in actual.types:
                            if isinstance(typ, Instance) and len(typ.args) > 1:
                                kw_val_types.add(typ.args[1])
                        types = frozenset(set(types) | kw_val_types)
                    else:
                        types = frozenset(set(types) | set(actual.types))
                    unknown = True
                value = AbstractTypeValue(
                    types=types,
                    unknown=unknown,
                    callable_targets=actual.callable_targets,
                    class_targets=actual.class_targets,
                )
                value = self._body_parameter_value(function, name, value)
            else:
                # Call-site evidence already binds *args/**kwargs to their
                # container shape; wrapping it again would double the element.
                value = actual
            if (
                function.parameter_names.index(name) == 0
                and function.owner is not None
                and function.method_kind != "static"
                and self._class_is_metaclass(self._classes[function.owner])
            ):
                value = AbstractTypeValue.from_type(TypeType(self._proper_instance(object)))
            environment[name] = value
            input_parameters[name] = value
            for argument in (
                *function.node.args.posonlyargs,
                *function.node.args.args,
                *function.node.args.kwonlyargs,
            ):
                if argument.arg == name:
                    self._record_expression(argument, value)
                    break

        node = function.node
        previous_mode = self._collect_specializations
        previous_vars = self._type_vars
        previous_owner = self._annotation_owner
        previous_substitutions = self._annotation_substitutions
        previous_current_function = self._current_function_info
        self._annotation_substitutions = substitutions
        self._current_function_info = function
        self._type_vars = {**previous_vars, **function.type_variables}
        self._annotation_owner = function.owner
        self._collect_specializations = collect_specializations
        self._observed_yields = []
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
                body_environment = outcome.environment
                returns = list(outcome.returns)
                if not outcome.terminated:
                    returns.append(AbstractTypeValue.from_type(NONE_TYPE))
                elif not returns:
                    returns.append(AbstractTypeValue.from_type(NEVER))
                return_value = join_all(
                    returns,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
                yields = join_all(
                    [*outcome.yields, *self._observed_yields],
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
        finally:
            self._collect_specializations = previous_mode
            self._type_vars = previous_vars
            self._annotation_owner = previous_owner
            self._annotation_substitutions = previous_substitutions
            self._current_function_info = previous_current_function

        if function.explicit_return is not None:
            explicit_return = function.explicit_return
            returned_type = explicit_return.public_type()
            if returned_type is not None and substitutions:
                explicit_return = AbstractTypeValue.from_type(
                    substitute_type_vars(returned_type, substitutions)
                )
            if self._interface_stub(function):
                return_value = explicit_return
            elif function.is_generator_source and yields.is_bottom:
                # A path-insensitive pass may miss a yield inside a branch or
                # loop.  The syntax still makes the function a generator.
                return_value = explicit_return
            elif not yields.is_bottom:
                self._check_generator_annotation(function, explicit_return, yields, return_value)
                # Callers receive the generator object described by the
                # annotation; the element type lives in ``yield_value``.
                return_value = explicit_return
            else:
                if not self._is_substituted_type_variable_annotation(
                    function.node.returns, explicit_return, function.type_variables
                ):
                    # A bare type variable is a placeholder.  Checking it
                    # against one concrete specialization reports spurious
                    # mismatches in generic base-class methods.
                    self._check_annotation_compatibility(
                        return_value,
                        explicit_return,
                        self._return_check_node(function.node),
                        context=f"return of {function.qualified_name}",
                    )
                return_value = explicit_return
        elif (
            return_value.unknown
            and not return_value.types
            and function.documented_return is not None
        ):
            # Documentation supplies a fallback; concrete body/call evidence
            # and explicit annotations take precedence over it.
            return_value = function.documented_return

        mutated_parameters: list[tuple[str, AbstractTypeValue]] = []
        if not isinstance(node, ast.Lambda):
            for name in function.parameter_names:
                original = input_parameters[name]
                final = body_environment.get(name, original)
                if self._is_widened_container(original, final):
                    mutated_parameters.append((name, final))
        return FunctionSpecialization(
            parameters=tuple((name, input_parameters[name]) for name in function.parameter_names),
            return_value=self._bound_type_depth(return_value),
            yield_value=self._bound_type_depth(yields),
            widened=widened,
            mutated_parameters=tuple(mutated_parameters),
        )

    @staticmethod
    def _return_check_node(node: ast.AST) -> ast.AST:
        returns: list[ast.Return] = []

        def walk(statements: Iterable[ast.stmt]) -> None:
            for statement in statements:
                if isinstance(
                    statement,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
                ):
                    continue
                if isinstance(statement, ast.Return):
                    returns.append(statement)
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.stmt):
                        walk((child,))

        walk(getattr(node, "body", ()))
        return returns[0] if len(returns) == 1 else node

    def _check_generator_annotation(self, function, annotation, yields, returned):
        expected = annotation.public_type()
        asynchronous = isinstance(function.node, ast.AsyncFunctionDef)
        allowed = (
            {cabc.AsyncIterator, cabc.AsyncIterable, cabc.AsyncGenerator}
            if asynchronous
            else {cabc.Iterator, cabc.Iterable, cabc.Generator}
        )
        if isinstance(expected, Instance) and expected.type.raw_type in allowed:
            if expected.args:
                self._check_annotation_compatibility(
                    yields,
                    AbstractTypeValue.from_type(expected.args[0]),
                    function.node,
                    context=f"yield of {function.qualified_name}",
                )
            if expected.type.raw_type is cabc.Generator and len(expected.args) == 3:
                self._check_annotation_compatibility(
                    returned,
                    AbstractTypeValue.from_type(expected.args[2]),
                    function.node,
                    context=f"generator return of {function.qualified_name}",
                )
        else:
            wrapper = self._instance(
                cabc.AsyncIterator if asynchronous else cabc.Iterator, yields.public_type() or ANY
            )
            self._check_annotation_compatibility(
                wrapper, annotation, function.node, context=f"return of {function.qualified_name}"
            )

    def _commit_pending_evidence(self) -> None:
        for (target, parameter), value in self._pending_parameter_evidence.items():
            function = self._functions.get(target)
            if function is None or parameter in function.explicit_parameters:
                continue
            old = function.parameter_evidence.get(parameter, AbstractTypeValue.bottom())
            function.parameter_evidence[parameter] = old.join(
                value,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
        for (owner, attribute), value in self._pending_attributes.items():
            if not value.types and not value.callable_targets and not value.class_targets:
                continue
            class_info = self._classes[owner]
            old = class_info.attributes.get(attribute, AbstractTypeValue.bottom())
            class_info.attributes[attribute] = old.join(
                value,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            class_info.instance.type.members[attribute] = (
                class_info.attributes[attribute].public_type() or ANY
            )
            self.type_system.invalidate_subtype_caches()

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
                        self._value_fingerprint(specialization.return_value),
                        self._value_fingerprint(specialization.yield_value),
                        tuple(
                            (name, self._value_fingerprint(value))
                            for name, value in specialization.mutated_parameters
                        ),
                    )
                    for key, specialization in sorted(
                        info.specializations.items(),
                        key=lambda item: self._specialization_key_fingerprint(item[0]),
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
            (
                value.dict_shapes is not None,
                tuple(
                    sorted(
                        tuple((name, str(typ)) for name, typ in shape)
                        for shape in (value.dict_shapes or ())
                    )
                ),
            ),
        )

    def _environment_fingerprint(
        self, environment: dict[str, AbstractTypeValue]
    ) -> tuple[object, ...]:
        return tuple(
            (name, self._value_fingerprint(value)) for name, value in sorted(environment.items())
        )

    def _specialization_key_fingerprint(self, key: _SpecializationKey) -> tuple[object, ...]:
        return (
            key.widened,
            tuple((name, self._value_fingerprint(value)) for name, value in key.parameters),
        )

    def _summary_fingerprint(self, summary: FunctionSummary | None) -> tuple[object, ...] | None:
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
        breaks = False
        continues = False
        break_envs: list[dict[str, AbstractTypeValue]] = []
        continue_envs: list[dict[str, AbstractTypeValue]] = []
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
            breaks = breaks or outcome.breaks
            continues = continues or outcome.continues
            break_envs.extend(outcome.break_envs)
            continue_envs.extend(outcome.continue_envs)
            if outcome.terminated:
                terminated = True
                break
        return _Outcome(
            current,
            returns,
            yields,
            terminated,
            breaks=breaks,
            continues=continues,
            break_envs=break_envs,
            continue_envs=continue_envs,
        )

    def _execute_statement(
        self,
        node: ast.stmt,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> _Outcome:
        result = dict(environment)
        if isinstance(node, getattr(ast, "TypeAlias", ())):
            previous_vars = dict(self._type_vars)
            self._type_vars.update(self._pep695_type_variables(node))
            result[node.name.id] = self._annotation_value(node.value)
            self._type_vars = previous_vars
            return _Outcome(result)
        if isinstance(node, ast.Assign):
            target = node.targets[0] if len(node.targets) == 1 else None
            if (
                isinstance(target, ast.Name)
                and target.id in self._type_aliases
                and self._is_type_alias_expression(node.value)
            ):
                alias_val = self._annotation_value(node.value)
                if not alias_val.is_bottom and alias_val.types:
                    if isinstance(node.value, (ast.Name, ast.Attribute)):
                        # ``Alias = SomeClass`` is both a typing alias and a
                        # runtime class-object assignment.
                        runtime = self._evaluate_expression(
                            node.value,
                            result,
                            scope=scope,
                            current_function=current_function,
                        )
                        class_targets = runtime.class_targets
                        proxy = alias_val.public_type()
                        if (
                            not class_targets
                            and isinstance(proxy, Instance)
                            and isinstance(proxy.type.raw_type, type)
                        ):
                            class_targets = frozenset((proxy.type.full_name,))
                        alias_val = replace(
                            alias_val,
                            class_targets=class_targets,
                        )
                    self._assign_target(target, alias_val, result, current_function)
                    return _Outcome(result)
            value = self._evaluate_expression(
                node.value, result, scope=scope, current_function=current_function
            )
            if self._is_never_value(value):
                return _Outcome(result, terminated=True)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id in self._type_vars:
                        tv_val = AbstractTypeValue.from_type(self._type_vars[target.id])
                        self._assign_target(target, tv_val, result, current_function)
                        continue
                self._assign_target(target, value, result, current_function)
            return _Outcome(result)

        if isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id in self._type_aliases
                and self._qualified_callee_name(node.annotation)
                in {"typing.TypeAlias", "typing_extensions.TypeAlias"}
            ):
                result[node.target.id] = self._annotation_value(node.value)
                return _Outcome(result)
            annotated = self._annotation_value(node.annotation)
            inferred: AbstractTypeValue | None = None
            if node.value is not None:
                inferred = self._evaluate_expression(
                    node.value,
                    result,
                    scope=scope,
                    current_function=current_function,
                )
                if self._is_never_value(inferred):
                    return _Outcome(result, terminated=True)
                if not self._is_substituted_type_variable_annotation(node.annotation, annotated):
                    self._check_annotation_compatibility(
                        inferred, annotated, node, context="annotated assignment"
                    )
            is_bare_qualifier = (
                isinstance(node.annotation, ast.Name)
                and node.annotation.id in {"Final", "ClassVar"}
            ) or (
                isinstance(node.annotation, ast.Attribute)
                and node.annotation.attr in {"Final", "ClassVar"}
            )
            if inferred is not None and (
                annotated.unknown or not annotated.types or is_bare_qualifier
            ):
                # An unresolved annotation or bare qualifier is not evidence that the value has
                # no type.  Keep the value evidence instead of propagating a
                # synthetic placeholder for the missing annotation.
                self._assign_target(node.target, inferred, result, current_function)
            else:
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
            return _Outcome(
                result,
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

        if isinstance(node, ast.Assert):
            test = self._evaluate_expression(
                node.test, result, scope=scope, current_function=current_function
            )
            if (
                self._is_never_value(test)
                or isinstance(node.test, ast.Constant)
                and not node.test.value
            ):
                return _Outcome(result, terminated=True)
            narrowed = self._narrow_environment(node.test, result, truthy=True)
            return _Outcome(
                narrowed, terminated=any(value.is_bottom for value in narrowed.values())
            )

        if isinstance(node, ast.If):
            test = self._evaluate_expression(
                node.test, result, scope=scope, current_function=current_function
            )
            if self._is_never_value(test):
                return _Outcome(result, terminated=True)
            true_env = self._narrow_environment(node.test, result, truthy=True)
            false_env = self._narrow_environment(node.test, result, truthy=False)
            true_outcome = (
                _Outcome(true_env, terminated=True)
                if any(value.is_bottom for value in true_env.values())
                else self._execute_block(
                    node.body,
                    true_env,
                    scope=scope,
                    current_function=current_function,
                )
            )
            false_outcome = (
                _Outcome(false_env, terminated=True)
                if any(value.is_bottom for value in false_env.values())
                else self._execute_block(
                    node.orelse,
                    false_env,
                    scope=scope,
                    current_function=current_function,
                )
            )
            self._fill_missing_attribute_joins(
                result, true_outcome.environment, false_outcome.environment
            )
            if true_outcome.terminated and not false_outcome.terminated:
                merged = false_outcome.environment
            elif false_outcome.terminated and not true_outcome.terminated:
                merged = true_outcome.environment
            else:
                merged = self._join_environments(
                    true_outcome.environment, false_outcome.environment
                )
            return _Outcome(
                merged,
                true_outcome.returns + false_outcome.returns,
                true_outcome.yields + false_outcome.yields,
                true_outcome.terminated and false_outcome.terminated,
                breaks=true_outcome.breaks or false_outcome.breaks,
                continues=true_outcome.continues or false_outcome.continues,
                break_envs=true_outcome.break_envs + false_outcome.break_envs,
                continue_envs=true_outcome.continue_envs + false_outcome.continue_envs,
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
                method = "__aenter__" if isinstance(node, ast.AsyncWith) else "__enter__"
                attribute = ast.copy_location(
                    ast.Attribute(value=item.context_expr, attr=method, ctx=ast.Load()),
                    item.context_expr,
                )
                alternatives = []
                for typ in context.types:
                    expected_context = (
                        contextlib.AbstractAsyncContextManager
                        if isinstance(node, ast.AsyncWith)
                        else contextlib.AbstractContextManager
                    )
                    if (
                        isinstance(typ, Instance)
                        and typ.type.raw_type is expected_context
                        and typ.args
                    ):
                        alternatives.append(AbstractTypeValue.from_type(typ.args[0]))
                        continue
                    base = AbstractTypeValue.from_type(typ)
                    value = self._call_attribute(attribute, base, [], {}, result)
                    if value is None:
                        value = self._callable_return_type(self._attribute_value(base, method))
                    if isinstance(node, ast.AsyncWith) and not self._is_never_value(value):
                        value = self._unwrap_single_generic(value)
                    alternatives.append(value)
                if context.unknown or not alternatives:
                    alternatives.append(AbstractTypeValue.unresolved())
                entered = join_all(
                    alternatives, self.type_system, max_union_size=self.options.max_union_size
                )
                if entered.unknown:
                    self._add_diagnostic(
                        "unmodeled-context-manager",
                        f"Cannot resolve context manager {method}; bound value remains unknown",
                        node=item.context_expr,
                        affects_completeness=item.optional_vars is not None,
                    )
                if self._is_never_value(entered):
                    return _Outcome(result, terminated=True)
                if item.optional_vars is not None:
                    self._assign_target(
                        item.optional_vars,
                        entered,
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
            if node.orelse and not outcomes[0].terminated:
                body = outcomes[0]
                otherwise = self._execute_block(
                    node.orelse, body.environment, scope=scope, current_function=current_function
                )
                outcomes[0] = _Outcome(
                    otherwise.environment,
                    body.returns + otherwise.returns,
                    body.yields + otherwise.yields,
                    otherwise.terminated,
                    breaks=body.breaks or otherwise.breaks,
                    continues=body.continues or otherwise.continues,
                    break_envs=body.break_envs + otherwise.break_envs,
                    continue_envs=body.continue_envs + otherwise.continue_envs,
                )
            break_envs = [env for outcome in outcomes for env in outcome.break_envs]
            continue_envs = [env for outcome in outcomes for env in outcome.continue_envs]
            active = [outcome.environment for outcome in outcomes if not outcome.terminated]
            merged = self._join_many_environments(
                active if active else [outcome.environment for outcome in outcomes]
            )
            returns = [value for outcome in outcomes for value in outcome.returns]
            yields = [value for outcome in outcomes for value in outcome.yields]
            terminated = all(outcome.terminated for outcome in outcomes)
            breaks = any(outcome.breaks for outcome in outcomes)
            continues = any(outcome.continues for outcome in outcomes)
            if node.finalbody:
                final = self._execute_block(
                    node.finalbody, merged, scope=scope, current_function=current_function
                )
                merged = final.environment
                returns = final.returns if final.terminated else returns + final.returns
                yields.extend(final.yields)
                terminated = terminated or final.terminated
                breaks = breaks or final.breaks
                continues = continues or final.continues
                break_envs.extend(final.break_envs)
                continue_envs.extend(final.continue_envs)
            return _Outcome(
                merged,
                returns,
                yields,
                terminated,
                breaks=breaks,
                continues=continues,
                break_envs=break_envs,
                continue_envs=continue_envs,
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
                self._join_many_environments(outcome.environment for outcome in match_outcomes),
                [value for outcome in match_outcomes for value in outcome.returns],
                [value for outcome in match_outcomes for value in outcome.yields],
                all(outcome.terminated for outcome in match_outcomes),
            )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_target = self._function_nodes.get(id(node))
            if function_target is not None:
                nested = self._functions[function_target]
                if function_target.rpartition(".")[0] != self._module_name:
                    for name, value in result.items():
                        old = nested.closure_evidence.get(name, AbstractTypeValue.bottom())
                        nested.closure_evidence[name] = self._join(old, value)
                result[node.name] = self._function_value(nested)
            return _Outcome(result)

        if isinstance(node, ast.ClassDef):
            qualified = f"{scope}.{node.name}"
            class_info = self._classes.get(qualified)
            if class_info is not None:
                class_environment = dict(result)
                class_environment.update(class_info.attributes)
                enum_class = self._is_enum_class_info(class_info)
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        value = self._evaluate_expression(
                            item.value,
                            class_environment,
                            scope=qualified,
                            current_function=current_function,
                        )
                        for target in item.targets:
                            self._assign_target(target, value, class_environment, current_function)
                            for name in ast.walk(target):
                                if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                                    if enum_class and not name.id.startswith("_"):
                                        class_info.enum_values[name.id] = value
                                        member = AbstractTypeValue.from_type(class_info.instance)
                                    else:
                                        member = class_environment[name.id]
                                    class_info.attributes[name.id] = member
                                    class_info.instance.type.members[name.id] = (
                                        member.public_type() or ANY
                                    )
                    elif (
                        isinstance(item, ast.AnnAssign)
                        and isinstance(item.target, ast.Name)
                        and item.value is not None
                        and not self._is_dataclass_pseudo_annotation(item.annotation)
                    ):
                        value = self._evaluate_expression(
                            item.value,
                            class_environment,
                            scope=qualified,
                            current_function=current_function,
                        )
                        annotated = self._annotation_value(item.annotation)
                        self._check_annotation_compatibility(
                            value,
                            annotated,
                            item,
                            context="annotated assignment",
                        )
                        member = annotated if not annotated.unknown and annotated.types else value
                        self._assign_target(
                            item.target,
                            member,
                            class_environment,
                            current_function,
                        )
                        class_info.attributes[item.target.id] = member
                        class_info.instance.type.members[item.target.id] = (
                            member.public_type() or ANY
                        )
                result[node.name] = AbstractTypeValue.from_type(
                    class_info.instance, class_target=qualified
                )
            return _Outcome(result)

        if isinstance(node, ast.Delete):
            for target in node.targets:
                self._invalidate_refinements(result, target)
                if isinstance(target, ast.Name):
                    result.pop(target.id, None)
                else:
                    result.pop(ast.unparse(target), None)
            return _Outcome(result)

        if isinstance(node, (ast.Raise, ast.Break, ast.Continue)):
            return _Outcome(
                result,
                terminated=True,
                breaks=isinstance(node, ast.Break),
                continues=isinstance(node, ast.Continue),
                break_envs=[dict(result)] if isinstance(node, ast.Break) else [],
                continue_envs=[dict(result)] if isinstance(node, ast.Continue) else [],
            )

        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                qualified = self._imports.get(local)
                if qualified is None:
                    module = node.module or ""
                    if node.level:
                        module = (
                            self.project_context.resolve_import_name(
                                self._module_name,
                                module or None,
                                node.level,
                                current_path=self._filename,
                            )
                            or module
                        )
                    qualified = f"{module}.{alias.name}" if module else alias.name
                # Typing constructs are handled by their dedicated syntax
                # paths (cast/NewType/TypeVar/overload/aliases).  Binding them
                # as ordinary values would shadow those models.
                if qualified.split(".", 1)[0] in {"typing", "typing_extensions", "__future__"}:
                    continue
                if qualified in {
                    "sys.exit",
                    "os._exit",
                    "pytest.fail",
                    "pytest.skip",
                    "pytest.xfail",
                    "werkzeug.exceptions.abort",
                    "flask.abort",
                    "flask.helpers.abort",
                }:
                    # These are modelled as non-returning calls.  Binding the
                    # import would make the abort path look shadowed.
                    continue
                external = self._external_type(qualified)
                builtin_class = False
                if external is None:
                    external = BuiltinTypeLookup()(qualified)
                    builtin_class = external is not None
                if external is None:
                    if self.project_context.find_module(qualified) is not None:
                        # from . import submodule keeps the module itself
                        # unresolved; attribute access resolves through imports.
                        continue
                    result[local] = AbstractTypeValue.unresolved()
                    continue
                if isinstance(external, TypeType):
                    external = external.item
                result[local] = AbstractTypeValue.from_type(
                    external,
                    class_target=self._external_class_target(
                        external, alias.name, builtin_class=builtin_class
                    ),
                )
            return _Outcome(result)

        if not isinstance(node, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global, ast.Nonlocal)):
            self._add_diagnostic(
                "unsupported-statement",
                f"No type model for {type(node).__name__}",
                node=node,
                affects_completeness=True,
            )
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    result[child.id] = AbstractTypeValue.unresolved()
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
        break_envs: list[dict[str, AbstractTypeValue]] = []
        continue_envs: list[dict[str, AbstractTypeValue]] = []
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
                body_env = self._narrow_environment(node.test, body_env, truthy=True)
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
            break_envs.extend(outcome.break_envs)
            continue_envs.extend(outcome.continue_envs)
            next_head = self._join_environments(entry, outcome.environment)
            for continue_env in outcome.continue_envs:
                next_head = self._join_environments(next_head, continue_env)
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
        exit_env = orelse.environment
        for break_env in [*break_envs, *continue_envs]:
            exit_env = self._join_environments(exit_env, break_env)

        class BreakFinder(ast.NodeVisitor):
            found = False

            def visit_Break(self, child):
                self.found = True

            def visit_For(self, child):
                pass

            def visit_AsyncFor(self, child):
                pass

            def visit_While(self, child):
                pass

            def visit_FunctionDef(self, child):
                pass

            def visit_AsyncFunctionDef(self, child):
                pass

            def visit_ClassDef(self, child):
                pass

        finder = BreakFinder()
        for statement in node.body:
            finder.visit(statement)
        infinite = (
            isinstance(node, ast.While)
            and isinstance(node.test, ast.Constant)
            and bool(node.test.value)
            and not finder.found
        )
        return _Outcome(exit_env, returns, yields, terminated=infinite)

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
            base = NONE_TYPE if node.value is None else self._proper_instance(type(node.value))
            value = AbstractTypeValue.from_type(base, literal_values=frozenset((node.value,)))
        elif isinstance(node, ast.Name):
            value = self._name_value(node.id, environment, scope)
        elif isinstance(node, ast.List):
            evaluated = [
                self._evaluate_expression(
                    item, environment, scope=scope, current_function=current_function
                )
                for item in node.elts
            ]
            element = self._join_many_values(evaluated)
            value = (
                element
                if self._is_never_value(element)
                else self._instance(
                    list,
                    NEVER if not node.elts else (element.runtime_type() or ANY),
                )
            )
            shapes = {shape for item in evaluated for shape in (item.dict_shapes or ())}
            if shapes:
                value = replace(value, element_dict_shapes=frozenset(shapes))
        elif isinstance(node, ast.Set):
            element = self._evaluate_many(node.elts, environment, scope, current_function)
            value = (
                element
                if self._is_never_value(element)
                else self._instance(set, element.runtime_type() or ANY)
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
                    TupleType(tuple(item.runtime_type() or ANY for item in evaluated))
                )
        elif isinstance(node, ast.Dict):
            evaluated_keys = [
                (
                    None
                    if item is None
                    else self._evaluate_expression(
                        item, environment, scope=scope, current_function=current_function
                    )
                )
                for item in node.keys
            ]
            evaluated_values = [
                self._evaluate_expression(
                    item, environment, scope=scope, current_function=current_function
                )
                for item in node.values
            ]
            key_parts: list[AbstractTypeValue] = []
            value_parts: list[AbstractTypeValue] = []
            for key_node, key_value, item_value in zip(node.keys, evaluated_keys, evaluated_values):
                if key_node is None:
                    mapping_key, mapping_value = self._mapping_key_value(item_value)
                    key_parts.append(mapping_key)
                    value_parts.append(mapping_value)
                else:
                    assert key_value is not None
                    key_parts.append(self._dict_key_value(key_value))
                    value_parts.append(item_value)
            keys = join_all(key_parts, self.type_system)
            values = join_all(value_parts, self.type_system)
            if not node.keys:
                value = self._instance(dict, NEVER, NEVER)
            elif self._is_never_value(keys) or self._is_never_value(values):
                value = AbstractTypeValue.from_type(NEVER)
            else:
                value = self._instance(
                    dict,
                    keys.runtime_type() or ANY,
                    values.runtime_type() or ANY,
                )
                if all(
                    isinstance(key, ast.Constant) and isinstance(key.value, str)
                    for key in node.keys
                ):
                    fields = {
                        key.value: item.runtime_type() or ANY
                        for key, item in zip(node.keys, evaluated_values)
                    }
                    value = replace(
                        value,
                        dict_shapes=frozenset((tuple(sorted(fields.items())),)),
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
                else self._operator_result(
                    node,
                    left,
                    right,
                    self._binary_protocol_names(node.op),
                    environment,
                )
                or self._binary_result(left, right, node.op)
            )
        elif isinstance(node, ast.UnaryOp):
            operand = self._evaluate_expression(
                node.operand,
                environment,
                scope=scope,
                current_function=current_function,
            )
            if self._is_never_value(operand):
                value = operand
            elif isinstance(node.op, ast.Not):
                value = self._instance(bool)
            else:
                unary_methods = {
                    ast.UAdd: "__pos__",
                    ast.USub: "__neg__",
                    ast.Invert: "__invert__",
                }
                method = next(
                    (name for kind, name in unary_methods.items() if isinstance(node.op, kind)),
                    None,
                )
                value = (
                    self._operator_result(
                        node,
                        operand,
                        None,
                        (method, None),
                        environment,
                    )
                    if method is not None
                    else None
                )
                if isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)) and self._all_bool_values(
                    operand
                ):
                    value = self._instance(int)
                elif value is None:
                    value = operand
                if isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)) and operand.literal_values:
                    transformed: set[object] = set()
                    for literal in operand.literal_values:
                        try:
                            if isinstance(node.op, ast.UAdd):
                                transformed.add(+literal)  # type: ignore[operator]
                            elif isinstance(node.op, ast.USub):
                                transformed.add(-literal)  # type: ignore[operator]
                            else:
                                transformed.add(~literal)  # type: ignore[operator]
                        except TypeError:
                            transformed.clear()
                            break
                    if transformed:
                        base = value.public_type() or operand.public_type() or ANY
                        value = AbstractTypeValue.from_type(
                            base, literal_values=frozenset(transformed)
                        )
        elif isinstance(node, ast.Compare):
            value = self._comparison_result(
                node,
                environment,
                scope,
                current_function,
            )
        elif isinstance(node, ast.BoolOp):
            contributions = []
            branch = environment
            for position, item in enumerate(node.values):
                before_keys = set(branch)
                operand = self._evaluate_expression(
                    item, branch, scope=scope, current_function=current_function
                )
                for k in list(branch.keys()):
                    if k not in before_keys or branch[k] != environment.get(k):
                        environment[k] = branch[k]
                if self._is_never_value(operand):
                    contributions.append(operand)
                    break
                # A non-final operand of ``or`` contributes only when truthy.
                # In particular, Optional[T] or [] cannot return None.
                contribution = (
                    self._remove_none(operand)
                    if isinstance(node.op, ast.Or) and position < len(node.values) - 1
                    else operand
                )
                if not contribution.is_bottom:
                    contributions.append(contribution)
                branch = self._narrow_environment(item, branch, truthy=isinstance(node.op, ast.And))
            value = self._join_normal_results(contributions)
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
            qualified = _expression_name(node)
            root = qualified.split(".", 1)[0] if qualified is not None else None
            external_value: AbstractTypeValue | None = None
            if qualified is not None and root is not None and root not in environment:
                imported = self._resolve_import_name(qualified)
                if imported is not None and root in self._imports:
                    external = self._external_type(imported)
                    if external is not None:
                        if isinstance(external, TypeType):
                            external = external.item
                        external_value = AbstractTypeValue.from_type(
                            external,
                            class_target=self._external_class_target(
                                external, imported.rsplit(".", 1)[-1]
                            ),
                        )
            if external_value is not None:
                value = external_value
            else:
                base = self._evaluate_expression(
                    node.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                value = environment.get(ast.unparse(node))
                if value is None:
                    value = (
                        base
                        if self._is_never_value(base)
                        else self._attribute_value(base, node.attr)
                    )
        elif isinstance(node, ast.Slice):
            self._evaluate_many(
                [value for value in (node.lower, node.upper, node.step) if value is not None],
                environment,
                scope,
                current_function,
            )
            value = self._instance(slice)
        elif isinstance(node, ast.Starred):
            inner = self._evaluate_expression(
                node.value, environment, scope=scope, current_function=current_function
            )
            value = self._iterable_element(inner)
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
                else environment.get(
                    ast.unparse(node),
                    self._subscript_value(base, node.slice, index_value=index),
                )
            )
            if (
                not base.types
                and base.unknown
                and value.unknown
                and isinstance(node.slice, (ast.Slice, ast.Tuple))
            ):
                self._add_diagnostic(
                    "unsupported-expression",
                    f"No type model for {type(node).__name__} of an unknown value",
                    node=node,
                    affects_completeness=True,
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
            self._propagate_comprehension_walrus(node, local_env, environment, current_function)
            if isinstance(node, ast.GeneratorExp):
                value = self._instance(
                    cabc.Generator,
                    element.public_type() or ANY,
                    NONE_TYPE,
                    NONE_TYPE,
                )
            else:
                raw = set if isinstance(node, ast.SetComp) else list
                value = self._instance(raw, element.public_type() or ANY)
                if element.dict_shapes:
                    value = replace(value, element_dict_shapes=frozenset(element.dict_shapes))
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
            self._propagate_comprehension_walrus(node, local_env, environment, current_function)
            value = self._instance(dict, key.public_type() or ANY, item.public_type() or ANY)
        elif isinstance(node, ast.Lambda):
            qualified = f"{scope}.<lambda@{node.lineno}:{node.col_offset}>"
            info = self._functions.get(qualified)
            if info is None:
                parameters = [arg.arg for arg in _all_arguments(node.args)]
                info = _FunctionInfo(qualified, node, parameters)
                positional = [*node.args.posonlyargs, *node.args.args]
                for argument, default in zip(
                    positional[-len(node.args.defaults) :], node.args.defaults
                ):
                    info.default_parameters[argument.arg] = default
                for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                    if default is not None:
                        info.default_parameters[argument.arg] = default
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
                awaited if self._is_never_value(awaited) else self._unwrap_single_generic(awaited)
            )
        elif isinstance(node, (ast.Yield, ast.YieldFrom)):
            yielded = (
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
                yielded = self._iterable_element(yielded)
            self._observed_yields.append(yielded)
            # The value of a yield expression is the value sent by the caller,
            # not the yielded object.
            value = AbstractTypeValue.unresolved()
        elif isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    self._evaluate_expression(
                        part.value, environment, scope=scope, current_function=current_function
                    )
                    if part.format_spec is not None:
                        self._evaluate_expression(
                            part.format_spec,
                            environment,
                            scope=scope,
                            current_function=current_function,
                        )
                else:
                    self._evaluate_expression(
                        part, environment, scope=scope, current_function=current_function
                    )
            value = self._instance(str)
        else:
            value = AbstractTypeValue.unresolved()
            self._add_diagnostic(
                "unsupported-expression",
                f"No type model for {type(node).__name__}",
                node=node,
                affects_completeness=True,
            )

        self._record_expression(node, value)
        return value

    def _star_expansion(
        self,
        node: ast.Starred,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> list[AbstractTypeValue] | None:
        """Expand a starred call argument when its arity is statically known."""
        if isinstance(node.value, (ast.List, ast.Tuple)):
            return [
                self._evaluate_expression(
                    item,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                for item in node.value.elts
                if not isinstance(item, ast.Starred)
            ]
        value = self._evaluate_expression(
            node.value,
            environment,
            scope=scope,
            current_function=current_function,
        )
        parts = self._flatten_union_parts(value)
        if len(parts) == 1 and isinstance(parts[0], TupleType) and not parts[0].unknown_size:
            return [AbstractTypeValue.from_type(item) for item in parts[0].args]
        return None

    def _keyword_expansion(
        self,
        mapping: AbstractTypeValue,
    ) -> dict[str, AbstractTypeValue] | None:
        """Expand a ``**mapping`` when its string-key layout is known."""
        shapes = mapping.dict_shapes
        if not shapes or len(shapes) != 1:
            return None
        expanded: dict[str, AbstractTypeValue] = {}
        for key, value in next(iter(shapes)):
            if not isinstance(key, str):
                return None
            expanded[key] = AbstractTypeValue.from_type(value)
        return expanded

    def _evaluate_call(
        self,
        node: ast.Call,
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        previous_positional = self._call_unknown_positional
        previous_keywords = self._call_unknown_keywords
        self._call_unknown_positional = False
        self._call_unknown_keywords = False
        try:
            return self._evaluate_call_impl(
                node, environment, scope=scope, current_function=current_function
            )
        finally:
            self._call_unknown_positional = previous_positional
            self._call_unknown_keywords = previous_keywords

    def _evaluate_call_impl(
        self,
        node: ast.Call,
        environment: dict[str, AbstractTypeValue],
        *,
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        arguments: list[AbstractTypeValue] = []
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                expanded = self._star_expansion(
                    argument, environment, scope=scope, current_function=current_function
                )
                if expanded is None:
                    # ``_star_expansion`` already evaluated the operand.
                    # Its length is unknown, so do not bind the iterable
                    # itself as one positional argument.
                    self._call_unknown_positional = True
                else:
                    arguments.extend(expanded)
            else:
                arguments.append(
                    self._evaluate_expression(
                        argument,
                        environment,
                        scope=scope,
                        current_function=current_function,
                    )
                )
        keywords: dict[str, AbstractTypeValue] = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                mapping = self._evaluate_expression(
                    keyword.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
                expanded_keywords = self._keyword_expansion(mapping)
                if expanded_keywords is None:
                    self._call_unknown_keywords = True
                else:
                    keywords.update(expanded_keywords)
            else:
                keywords[keyword.arg] = self._evaluate_expression(
                    keyword.value,
                    environment,
                    scope=scope,
                    current_function=current_function,
                )
        if any(self._is_never_value(value) for value in arguments) or any(
            self._is_never_value(value) for value in keywords.values()
        ):
            return AbstractTypeValue.from_type(NEVER)

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "super"
            and not self._name_is_shadowed(node.func.id, environment, scope)
        ):
            super_value = self._super_value(node, environment, current_function)
            if super_value is not None:
                return super_value

        qualified_callee = self._qualified_callee_name(node.func)
        root = (_expression_name(node.func) or "").split(".", 1)[0]
        if root not in environment:
            if (
                qualified_callee in {"typing.cast", "typing_extensions.cast"}
                and len(node.args) >= 2
            ):
                return self._annotation_value(node.args[0])
            if (
                qualified_callee in {"typing.NewType", "typing_extensions.NewType"}
                and len(node.args) >= 2
            ):
                wrapped = self._annotation_value(node.args[1]).public_type() or ANY
                return AbstractTypeValue.from_type(CallableType((wrapped,), wrapped))
        if (
            qualified_callee
            in {
                "sys.exit",
                "os._exit",
                "pytest.fail",
                "pytest.skip",
                "pytest.xfail",
                "werkzeug.exceptions.abort",
                "flask.abort",
                "flask.helpers.abort",
            }
            and (callee_name := _expression_name(node.func)) is not None
            and self._resolve_import_name(callee_name) is not None
        ):
            root = callee_name.split(".", 1)[0]
            # Imports do not occupy the local value environment; parameters
            # and assignments do, and must shadow these external call models.
            if root not in environment:
                return AbstractTypeValue.from_type(NEVER)
        # A dynamic unpack supplies an unknown number of iterables to zip.
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "zip"
            and any(isinstance(arg, ast.Starred) for arg in node.args)
        ):
            elements = [self._iterable_element(argument) for argument in arguments]
            element = join_all(elements, self.type_system).public_type() or ANY
            return self._instance(zip, TupleType((element,), unknown_size=True))
        if qualified_callee is not None:
            modelled = self._model_external_call(qualified_callee, arguments, keywords, node)
            if modelled is not None:
                return modelled
        if isinstance(node.func, ast.Attribute) and qualified_callee is not None:
            # Attribute-style module access (import pathlib;
            # pathlib.Path(...)) or imported names (from pathlib import Path; Path(...))
            # are common and should construct the class when a builtin annotation lookup
            # or an external fact knows it.
            external_class = self._external_type(qualified_callee)
            if external_class is None:
                external_class = BuiltinTypeLookup()(qualified_callee)
            if isinstance(external_class, TypeType):
                external_class = external_class.item
            if isinstance(external_class, Instance):
                return AbstractTypeValue.from_type(external_class)
            if isinstance(external_class, CallableType):
                selected = self._select_callable_overload(external_class, arguments)
                return AbstractTypeValue.from_type(
                    selected.return_type if selected is not None else external_class.return_type
                )
        if isinstance(node.func, ast.Name) and not self._name_is_shadowed(
            node.func.id, environment, scope
        ):
            builtin_result = self._call_builtin(node.func.id, arguments, keywords, call_node=node)
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
                call_node=node,
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
                specialized = next(
                    (
                        typ
                        for typ in callee.types
                        if isinstance(typ, Instance) and typ.type == class_info.instance.type
                    ),
                    class_info.instance,
                )
                instance = AbstractTypeValue.from_type(specialized)
                initializer = self._class_method(class_target, "__init__")
                if class_info.type_variables and not (
                    isinstance(specialized, Instance) and specialized.args
                ):
                    if initializer is not None:
                        initializer_info = self._functions[initializer]
                        bound = self._bind_call_arguments(
                            initializer_info, [instance, *arguments], keywords
                        )
                        substitutions = self._generic_substitutions(initializer_info, bound)
                        inferred_args = tuple(
                            substitutions.get(name, ANY) for name in class_info.type_variables
                        )
                    else:
                        inferred_args = self._generic_constructor_args(
                            class_info, arguments, keywords
                        )
                    if inferred_args is not None:
                        specialized = Instance(class_info.instance.type, inferred_args)
                        instance = AbstractTypeValue.from_type(specialized)
                if class_info.instance.type.typed_dict_fields is not None:
                    for name, expected in class_info.instance.type.typed_dict_fields.items():
                        if name in keywords:
                            self._check_annotation_compatibility(
                                keywords[name],
                                AbstractTypeValue.from_type(expected),
                                node,
                                context=f"TypedDict key {name}",
                            )
                if initializer is not None:
                    self._apply_function(
                        initializer,
                        [instance, *arguments],
                        keywords,
                        node=node,
                    )
                if self._class_is_metaclass(class_info):
                    # Calling a metaclass creates a class object, not an
                    # instance of the metaclass.
                    results.append(
                        AbstractTypeValue.from_type(TypeType(self._proper_instance(object)))
                    )
                else:
                    results.append(instance)
            else:
                external_instances = [
                    typ
                    for typ in callee.types
                    if isinstance(typ, Instance) and typ.type.full_name == class_target
                ]
                results.append(
                    AbstractTypeValue.from_type(
                        external_instances[0]
                        if external_instances
                        else self._synthetic_instance(class_target, unresolved=True)
                    )
                )
        self._last_argument_mutations = []
        for target in callee.callable_targets:
            results.append(self._apply_function(target, arguments, keywords, node=node))
            called = self._functions.get(target)
            if called is not None:
                for name in called.mutated_closure_names:
                    closure_value = called.closure_evidence.get(name)
                    if closure_value is not None:
                        environment[name] = closure_value
                if called.nonlocal_names:
                    parent = self._enclosing_function(called)
                    if parent is current_function:
                        for name in called.nonlocal_names:
                            closure_value = parent.closure_evidence.get(name)
                            if closure_value is not None:
                                environment[name] = closure_value
                for name in called.global_names:
                    global_value = self._module_environment.get(name)
                    if global_value is not None and (
                        current_function is None or name in current_function.global_names
                    ):
                        environment[name] = global_value
        for argument_node, final in self._last_argument_mutations:
            self._update_environment_receiver(environment, argument_node, final)
        self._last_argument_mutations = []
        if not callee.class_targets:
            for typ in callee.types:
                if not isinstance(typ, Instance):
                    continue
                class_info = self._classes.get(typ.type.full_name)
                if class_info is None:
                    continue
                call_method = self._class_method(class_info.qualified_name, "__call__")
                if call_method is not None:
                    results.append(
                        self._apply_function(
                            call_method,
                            [AbstractTypeValue.from_type(typ), *arguments],
                            keywords,
                            node=node,
                        )
                    )
        if not callee.callable_targets and not callee.class_targets:
            for typ in callee.types:
                if isinstance(typ, CallableType):
                    selected = self._select_callable_overload(typ, arguments)
                    results.append(
                        AbstractTypeValue.from_type(
                            selected.return_type if selected is not None else typ.return_type
                        )
                    )
        if results:
            return join_all(
                results,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
        if self._contains_any(callee):
            return AbstractTypeValue.from_type(ANY)
        return AbstractTypeValue.unresolved()

    def _model_external_call(
        self,
        qualified_name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.Call,
    ) -> AbstractTypeValue | None:
        for provider in self.call_model_providers:
            try:
                result = provider.infer_call(qualified_name, arguments, keywords)
            except Exception as exc:  # noqa: BLE001 - provider isolation boundary
                self._add_diagnostic(
                    "call-model-error",
                    f"Call model for {qualified_name} failed: {exc}",
                    node=node,
                    affects_completeness=True,
                )
                continue
            if result is not None:
                return result
        modelled = self._model_stdlib_call(qualified_name, arguments, keywords, node=node)
        if modelled is not None:
            return modelled
        return None

    def _model_stdlib_call(
        self,
        qualified_name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        *,
        node: ast.Call | None = None,
    ) -> AbstractTypeValue | None:
        """Model common stdlib calls when no stub or call provider is available."""

        def element(value: AbstractTypeValue) -> ProperType:
            return self._iterable_element(value).public_type() or ANY

        if qualified_name == "collections.deque":
            return self._instance(collections.deque, element(arguments[0]) if arguments else ANY)
        if qualified_name in {"datetime.datetime", "datetime.date", "datetime.timedelta"}:
            raw = {
                "datetime.datetime": datetime.datetime,
                "datetime.date": datetime.date,
                "datetime.timedelta": datetime.timedelta,
            }[qualified_name]
            return self._instance(raw)
        if qualified_name in {"dict.fromkeys", "collections.OrderedDict.fromkeys"} and arguments:
            key_type = element(arguments[0])
            value = arguments[1] if len(arguments) > 1 else keywords.get("value")
            value_type = (value.public_type() or ANY) if value is not None else NONE_TYPE
            return self._instance(dict, key_type, value_type)
        if qualified_name == "dataclasses.replace" and arguments:
            return AbstractTypeValue.from_type(arguments[0].public_type() or ANY)
        if qualified_name == "dataclasses.asdict":
            return self._instance(dict, self._proper_instance(str), ANY)
        if qualified_name == "dataclasses.astuple":
            return AbstractTypeValue.from_type(TupleType((ANY,), unknown_size=True))
        if qualified_name == "dataclasses.fields":
            return AbstractTypeValue.from_type(TupleType((ANY,), unknown_size=True))
        if qualified_name == "dataclasses.is_dataclass":
            return self._instance(bool)
        if qualified_name in {"bytes.fromhex", "bytearray.fromhex"}:
            return self._instance(bytearray if qualified_name.startswith("bytearray") else bytes)
        if qualified_name == "int.from_bytes":
            return self._instance(int)
        if qualified_name == "float.fromhex":
            return self._instance(float)
        if qualified_name in {
            "datetime.datetime.now",
            "datetime.datetime.utcnow",
            "datetime.datetime.today",
            "datetime.datetime.fromtimestamp",
            "datetime.datetime.utcfromtimestamp",
            "datetime.datetime.strptime",
            "datetime.datetime.combine",
            "datetime.datetime.fromisoformat",
        }:
            return self._instance(datetime.datetime)
        if qualified_name in {
            "datetime.date.today",
            "datetime.date.fromtimestamp",
            "datetime.date.fromisoformat",
            "datetime.date.fromordinal",
        }:
            return self._instance(datetime.date)
        if qualified_name.startswith("re."):
            text_raw: type = str
            candidates = (arguments[1].types if len(arguments) > 1 else ()) if arguments else ()
            if not candidates and arguments:
                candidates = arguments[0].types
            for typ in candidates:
                if isinstance(typ, Instance) and typ.type.raw_type is bytes:
                    text_raw = bytes
                    break
                if isinstance(typ, Instance) and typ.type.raw_type is str:
                    text_raw = str
                    break
            text_type = self._proper_instance(text_raw)
            match_type = self._proper_instance(re.Match, text_type)
            pattern_type = self._proper_instance(re.Pattern, text_type)
            if qualified_name == "re.compile":
                return AbstractTypeValue.from_type(pattern_type)
            if qualified_name in {"re.match", "re.search", "re.fullmatch"}:
                return self._join(
                    AbstractTypeValue.from_type(match_type),
                    AbstractTypeValue.from_type(NONE_TYPE),
                )
            if qualified_name == "re.findall":
                return self._instance(list, text_type)
            if qualified_name == "re.finditer":
                return self._instance(cabc.Iterator, match_type)
            if qualified_name == "re.sub":
                return self._instance(text_raw)
            if qualified_name == "re.subn":
                return AbstractTypeValue.from_type(
                    TupleType((text_type, self._proper_instance(int)))
                )
            if qualified_name == "re.split":
                return self._instance(list, text_type)
            if qualified_name == "re.escape":
                return self._instance(str)
        if qualified_name == "collections.Counter":
            return self._instance(collections.Counter, element(arguments[0]) if arguments else ANY)
        if qualified_name == "collections.namedtuple" and node is not None:
            if len(node.args) < 2 or not isinstance(node.args[0], ast.Constant):
                return AbstractTypeValue.unresolved()
            name = node.args[0].value
            try:
                fields_node = ast.literal_eval(node.args[1])
            except (ValueError, TypeError, SyntaxError):
                return AbstractTypeValue.unresolved()
            if not isinstance(name, str):
                return AbstractTypeValue.unresolved()
            if isinstance(fields_node, str):
                fields = tuple(part for part in fields_node.replace(",", " ").split() if part)
            elif isinstance(fields_node, (list, tuple)) and all(
                isinstance(part, str) for part in fields_node
            ):
                fields = tuple(fields_node)
            else:
                return AbstractTypeValue.unresolved()
            qualified = f"{self._module_name}.{name}"
            raw = type(
                name,
                (tuple,),
                {"__module__": self._module_name, "_fields": fields},
            )
            instance = self._proper_instance(raw)
            descriptor = instance.type
            descriptor.tuple_fields = fields
            for field in fields:
                descriptor.members[field] = ANY
            fields_type = AbstractTypeValue.from_type(
                TupleType((self._proper_instance(str),), unknown_size=True)
            )
            self._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                attributes={
                    **{field: AbstractTypeValue.from_type(ANY) for field in fields},
                    "_fields": fields_type,
                },
            )
            self._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if qualified_name in {"enum.Enum", "enum.IntEnum"} and node is not None:
            if not node.args or not isinstance(node.args[0], ast.Constant):
                return AbstractTypeValue.unresolved()
            name = node.args[0].value
            if not isinstance(name, str):
                return AbstractTypeValue.unresolved()
            names: tuple[str, ...] = ()
            if len(node.args) > 1:
                try:
                    raw_names = ast.literal_eval(node.args[1])
                except (ValueError, TypeError, SyntaxError):
                    raw_names = None
                if isinstance(raw_names, str):
                    names = tuple(part for part in raw_names.replace(",", " ").split() if part)
                elif isinstance(raw_names, (list, tuple)) and all(
                    isinstance(part, str) for part in raw_names
                ):
                    names = tuple(raw_names)
            qualified = f"{self._module_name}.{name}"
            raw = type(name, (), {"__module__": self._module_name})
            instance = self._proper_instance(raw)
            attributes: dict[str, AbstractTypeValue] = {}
            enum_values: dict[str, AbstractTypeValue] = {}
            for index, member in enumerate(names, start=1):
                attributes[member] = AbstractTypeValue.from_type(instance)
                enum_values[member] = self._instance(int)
            self._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                bases=(qualified_name,),
                attributes=attributes,
                enum_values=enum_values,
            )
            self._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if (
            qualified_name in {"typing.TypedDict", "typing_extensions.TypedDict"}
            and node is not None
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and isinstance(node.args[1], ast.Dict)
        ):
            name = node.args[0].value
            fields: dict[str, ProperType] = {}
            for key_node, value_node in zip(node.args[1].keys, node.args[1].values):
                if not (isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)):
                    continue
                fields[key_node.value] = self._annotation_value(value_node).public_type() or ANY
            total = not any(
                isinstance(keyword, ast.keyword)
                and keyword.arg == "total"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            )
            qualified = f"{self._module_name}.{name}"
            raw = type(name, (dict,), {"__module__": self._module_name})
            instance = self._proper_instance(raw)
            descriptor = instance.type
            descriptor.typed_dict_fields = fields
            descriptor.required_keys = frozenset(fields) if total else frozenset()
            self._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                attributes={
                    field: AbstractTypeValue.from_type(field_type)
                    for field, field_type in fields.items()
                },
            )
            self._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if (
            qualified_name in {"typing.NamedTuple", "typing_extensions.NamedTuple"}
            and node is not None
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and isinstance(node.args[1], (ast.List, ast.Tuple))
        ):
            name = node.args[0].value
            fields: dict[str, ProperType] = {}
            for item in node.args[1].elts:
                if not (
                    isinstance(item, ast.Tuple)
                    and len(item.elts) >= 2
                    and isinstance(item.elts[0], ast.Constant)
                    and isinstance(item.elts[0].value, str)
                ):
                    continue
                fields[item.elts[0].value] = (
                    self._annotation_value(item.elts[1]).public_type() or ANY
                )
            qualified = f"{self._module_name}.{name}"
            raw = type(name, (tuple,), {"__module__": self._module_name})
            instance = self._proper_instance(raw)
            descriptor = instance.type
            descriptor.tuple_fields = tuple(fields)
            for field, field_type in fields.items():
                descriptor.members[field] = field_type
            self._classes[qualified] = _ClassInfo(
                qualified,
                instance,
                attributes={
                    field: AbstractTypeValue.from_type(field_type)
                    for field, field_type in fields.items()
                },
            )
            self._class_aliases[name] = qualified
            return AbstractTypeValue.from_type(instance, class_target=qualified)
        if qualified_name == "collections.defaultdict":
            value_type: ProperType = ANY
            if arguments:
                for target in arguments[0].class_targets:
                    if target.startswith("builtins."):
                        value_type = self._proper_instance(
                            getattr(builtins, target.removeprefix("builtins."), object)
                        )
                        break
                else:
                    value_type = self._callable_return_type(arguments[0]).public_type() or ANY
            return self._instance(collections.defaultdict, ANY, value_type)
        if qualified_name in {"collections.OrderedDict", "collections.ChainMap"}:
            if keywords:
                value = join_all(
                    keywords.values(),
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
                key_type = self._proper_instance(str)
                value_type = value.public_type() or ANY
            else:
                key_parts: list[ProperType] = []
                value_parts: list[ProperType] = []
                for argument in arguments:
                    for typ in argument.types:
                        if (
                            isinstance(typ, Instance)
                            and typ.type.raw_type is dict
                            and len(typ.args) >= 2
                        ):
                            # An empty dict contributes no key/value evidence;
                            # Never would otherwise make the result unusable
                            # as a Mapping[str, Any].
                            if not isinstance(typ.args[0], NeverType):
                                key_parts.append(typ.args[0])
                            if not isinstance(typ.args[1], NeverType):
                                value_parts.append(typ.args[1])
                key_type = (
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in key_parts),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    ).public_type()
                    or ANY
                )
                value_type = (
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in value_parts),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    ).public_type()
                    or ANY
                )
            raw = (
                collections.OrderedDict
                if qualified_name.endswith("OrderedDict")
                else collections.ChainMap
            )
            return self._instance(raw, key_type, value_type)
        if qualified_name == "functools.partial" and arguments:
            for typ in arguments[0].types:
                if not isinstance(typ, CallableType):
                    continue
                if typ.arg_types is None:
                    return AbstractTypeValue.from_type(typ)
                bound_positions = set(range(len(arguments) - 1))
                target_name = next(iter(arguments[0].callable_targets), None)
                target = self._functions.get(target_name) if target_name else None
                if target is not None:
                    names = target.parameter_names
                    bound_positions.update(
                        names.index(name)
                        for name in keywords
                        if name in names and names.index(name) < len(typ.arg_types)
                    )
                remaining = tuple(
                    item for index, item in enumerate(typ.arg_types) if index not in bound_positions
                )
                return AbstractTypeValue.from_type(CallableType(remaining, typ.return_type))
            return AbstractTypeValue.unresolved()
        if qualified_name == "functools.reduce" and len(arguments) >= 2:
            reduced = element(arguments[1])
            if len(arguments) >= 3:
                reduced = (
                    self._join(AbstractTypeValue.from_type(reduced), arguments[2]).public_type()
                    or ANY
                )
            return AbstractTypeValue.from_type(reduced)
        if qualified_name.startswith("itertools."):
            if qualified_name == "itertools.chain.from_iterable" and arguments:
                inner = element(arguments[0])
                joined = (
                    self._iterable_element(AbstractTypeValue.from_type(inner)).public_type() or ANY
                )
                return self._instance(cabc.Iterator, joined)
            if qualified_name == "itertools.chain":
                values = [element(argument) for argument in arguments]
                joined = (
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in values),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    ).public_type()
                    or ANY
                )
                return self._instance(cabc.Iterator, joined)
            if qualified_name == "itertools.islice" and arguments:
                return self._instance(cabc.Iterator, element(arguments[0]))
            if (
                qualified_name
                in {
                    "itertools.filterfalse",
                    "itertools.dropwhile",
                    "itertools.takewhile",
                }
                and len(arguments) >= 2
            ):
                return self._instance(cabc.Iterator, element(arguments[1]))
            if qualified_name == "itertools.starmap" and len(arguments) >= 2:
                tuple_element = element(arguments[1])
                callable_targets = arguments[0].callable_targets
                if callable_targets and isinstance(tuple_element, TupleType):
                    return self._instance(
                        cabc.Iterator,
                        join_all(
                            (
                                self._apply_function(
                                    target,
                                    [
                                        AbstractTypeValue.from_type(item)
                                        for item in tuple_element.args
                                    ],
                                    {},
                                )
                                for target in callable_targets
                            ),
                            self.type_system,
                            max_union_size=self.options.max_union_size,
                        ).public_type()
                        or ANY,
                    )
                return self._instance(cabc.Iterator, tuple_element)
            if qualified_name == "itertools.accumulate" and arguments:
                accumulated = element(arguments[0])
                if len(arguments) > 1 and arguments[1].callable_targets:
                    target = next(iter(arguments[1].callable_targets))
                    result = self._apply_function(
                        target,
                        [
                            AbstractTypeValue.from_type(accumulated),
                            AbstractTypeValue.from_type(accumulated),
                        ],
                        {},
                    ).public_type()
                    if result is not None:
                        accumulated = result
                return self._instance(cabc.Iterator, accumulated)
            if qualified_name == "itertools.count" and arguments:
                count_raw = (
                    float
                    if any(
                        isinstance(part, Instance) and part.type.raw_type is float
                        for argument in arguments
                        for part in argument.types
                    )
                    else int
                )
                return self._instance(cabc.Iterator, self._proper_instance(count_raw))
            if qualified_name == "itertools.cycle" and arguments:
                return self._instance(cabc.Iterator, element(arguments[0]))
            if qualified_name == "itertools.tee" and arguments:
                item = element(arguments[0])
                count = 2
                if len(arguments) > 1 or "n" in keywords:
                    try:
                        count_node = next(
                            (keyword.value for keyword in node.keywords if keyword.arg == "n"),
                            node.args[1] if len(node.args) > 1 else None,
                        )
                        count_value = ast.literal_eval(count_node)
                        if isinstance(count_value, int):
                            count = max(0, count_value)
                    except (ValueError, TypeError, SyntaxError):
                        count = 2
                return AbstractTypeValue.from_type(
                    TupleType(
                        tuple(self._proper_instance(cabc.Iterator, item) for _ in range(count))
                    )
                )
            if qualified_name in {"itertools.product", "itertools.zip_longest"}:
                return self._instance(
                    cabc.Iterator,
                    TupleType(tuple(element(argument) for argument in arguments)),
                )
            if qualified_name in {"itertools.combinations", "itertools.permutations"} and arguments:
                return self._instance(
                    cabc.Iterator,
                    TupleType((element(arguments[0]),), unknown_size=True),
                )
            if qualified_name == "itertools.repeat" and arguments:
                return self._instance(cabc.Iterator, arguments[0].public_type() or ANY)
            if qualified_name == "itertools.groupby" and arguments:
                item = element(arguments[0])
                return self._instance(
                    cabc.Iterator,
                    TupleType((item, self._proper_instance(cabc.Iterator, item))),
                )
        if qualified_name in {"os.getcwd", "os.getcwdb"}:
            return self._instance(bytes if qualified_name.endswith("b") else str)
        if qualified_name in {"os.getpid", "os.getppid"}:
            return self._instance(int)
        if qualified_name in {"os.getenv", "os.environ.get"}:
            default = arguments[1] if len(arguments) > 1 else keywords.get("default")
            string_value = AbstractTypeValue.from_type(self._proper_instance(str))
            if default is not None and default.public_type() is not None:
                return self._join(string_value, default)
            return self._join(string_value, AbstractTypeValue.from_type(NONE_TYPE))
        if qualified_name == "os.cpu_count":
            return self._join(
                AbstractTypeValue.from_type(self._proper_instance(int)),
                AbstractTypeValue.from_type(NONE_TYPE),
            )
        if qualified_name == "os.listdir":
            return self._instance(list, self._proper_instance(str))
        if qualified_name == "os.scandir":
            return self._instance(cabc.Iterator, ANY)
        if qualified_name in {"os.stat", "os.lstat"}:
            return self._instance(os.stat_result)
        if qualified_name == "os.urandom":
            return self._instance(bytes)
        if qualified_name in {
            "os.makedirs",
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "os.rename",
            "os.replace",
            "os.chmod",
            "os.chown",
            "os.chdir",
            "os.symlink",
            "os.link",
        }:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name in {"os.path.join", "posixpath.join", "ntpath.join"}:
            return self._instance(
                bytes if any(self._contains_raw(argument, bytes) for argument in arguments) else str
            )
        if qualified_name in {
            "os.fspath",
            "os.path.basename",
            "os.path.dirname",
            "os.path.abspath",
            "os.path.realpath",
            "os.path.normpath",
            "os.path.expanduser",
            "os.path.expandvars",
            "os.path.relpath",
            "posixpath.basename",
            "posixpath.dirname",
            "posixpath.abspath",
            "posixpath.realpath",
            "ntpath.basename",
            "ntpath.dirname",
            "ntpath.abspath",
            "ntpath.realpath",
        }:
            return self._instance(
                bytes if any(self._contains_raw(argument, bytes) for argument in arguments) else str
            )
        if qualified_name in {
            "os.path.exists",
            "os.path.isfile",
            "os.path.isdir",
            "os.path.islink",
            "os.path.isabs",
            "os.path.samefile",
            "posixpath.exists",
            "posixpath.isfile",
            "posixpath.isdir",
            "ntpath.exists",
            "ntpath.isfile",
            "ntpath.isdir",
        }:
            return self._instance(bool)
        if qualified_name in {"os.path.getsize", "os.path.getmtime"}:
            return self._instance(int if qualified_name.endswith("getsize") else float)
        if qualified_name in {
            "os.path.splitext",
            "os.path.split",
            "posixpath.splitext",
            "posixpath.split",
            "ntpath.splitext",
            "ntpath.split",
        }:
            raw = (
                bytes if any(self._contains_raw(argument, bytes) for argument in arguments) else str
            )
            return AbstractTypeValue.from_type(
                TupleType((self._proper_instance(raw), self._proper_instance(raw)))
            )
        if qualified_name == "contextlib.nullcontext":
            entered = (arguments[0].public_type() or ANY) if arguments else NONE_TYPE
            return self._instance(contextlib.AbstractContextManager, entered)
        if qualified_name == "contextlib.closing" and arguments:
            return self._instance(
                contextlib.AbstractContextManager,
                arguments[0].public_type() or ANY,
            )
        if qualified_name in {
            "contextlib.suppress",
            "contextlib.redirect_stdout",
            "contextlib.redirect_stderr",
        }:
            return self._instance(contextlib.AbstractContextManager, NONE_TYPE)
        if qualified_name.startswith("asyncio."):
            result_types = [
                (
                    self._await_result(argument)
                    if self._is_awaitable_value(argument)
                    else AbstractTypeValue.unresolved()
                )
                for argument in arguments
            ]
            if qualified_name == "asyncio.sleep":
                return self._instance(cabc.Coroutine, ANY, ANY, NONE_TYPE)
            if qualified_name in {"asyncio.create_task"} and result_types:
                return self._instance(asyncio.Task, result_types[0].public_type() or ANY)
            if qualified_name in {"asyncio.ensure_future", "asyncio.shield"} and result_types:
                return self._instance(asyncio.Future, result_types[0].public_type() or ANY)
            if qualified_name == "asyncio.run" and result_types:
                return result_types[0]
            if qualified_name == "asyncio.wait_for" and result_types:
                return self._instance(
                    cabc.Coroutine,
                    ANY,
                    ANY,
                    result_types[0].public_type() or ANY,
                )
            if qualified_name == "asyncio.gather" and result_types:
                gathered = (
                    join_all(
                        result_types,
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    ).public_type()
                    or ANY
                )
                return self._instance(asyncio.Future, self._proper_instance(list, gathered))
            if qualified_name == "asyncio.to_thread" and arguments:
                return self._instance(
                    cabc.Coroutine,
                    ANY,
                    ANY,
                    self._callable_return_type(arguments[0]).public_type() or ANY,
                )
            if qualified_name in {"asyncio.get_running_loop", "asyncio.get_event_loop"}:
                return self._instance(asyncio.AbstractEventLoop)
        if qualified_name in {"subprocess.run", "subprocess.Popen"}:
            text_mode = any(
                keyword.arg in {"text", "universal_newlines", "encoding", "errors"}
                and not (
                    isinstance(keyword.value, ast.Constant) and keyword.value.value in (False, None)
                )
                for keyword in node.keywords
            )
            raw = str if text_mode else bytes
            if qualified_name.endswith("run"):
                return self._instance(subprocess.CompletedProcess, self._proper_instance(raw))
            return self._instance(subprocess.Popen, self._proper_instance(raw))
        if qualified_name in {"subprocess.check_output", "subprocess.getoutput"}:
            text_mode = any(
                keyword.arg in {"text", "universal_newlines", "encoding", "errors"}
                and not (
                    isinstance(keyword.value, ast.Constant) and keyword.value.value in (False, None)
                )
                for keyword in node.keywords
            )
            return self._instance(
                str if text_mode or qualified_name.endswith("getoutput") else bytes
            )
        if qualified_name == "subprocess.getstatusoutput":
            return AbstractTypeValue.from_type(
                TupleType((self._proper_instance(int), self._proper_instance(str)))
            )
        if qualified_name in {"subprocess.call", "subprocess.check_call"}:
            return self._instance(int)
        if qualified_name == "shutil.which":
            return self._join(
                AbstractTypeValue.from_type(self._proper_instance(str)),
                AbstractTypeValue.from_type(NONE_TYPE),
            )
        if qualified_name in {
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.copytree",
            "shutil.move",
            "shutil.make_archive",
        }:
            return self._instance(str)
        if qualified_name in {
            "shutil.rmtree",
            "shutil.chown",
            "shutil.copymode",
            "shutil.copystat",
        }:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name == "shutil.disk_usage":
            return AbstractTypeValue.from_type(
                TupleType(
                    (
                        self._proper_instance(int),
                        self._proper_instance(int),
                        self._proper_instance(int),
                    )
                )
            )
        if qualified_name == "shutil.get_terminal_size":
            return AbstractTypeValue.from_type(
                TupleType((self._proper_instance(int), self._proper_instance(int)))
            )
        if qualified_name in {
            "logging.getLogger",
            "logging.getLoggerClass",
        }:
            return self._instance(logging.Logger)
        if qualified_name == "logging.basicConfig":
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name in {
            "logging.debug",
            "logging.info",
            "logging.warning",
            "logging.error",
            "logging.exception",
            "logging.critical",
            "logging.log",
        }:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name == "tempfile.mkdtemp":
            return self._instance(str)
        if qualified_name == "tempfile.mkstemp":
            return AbstractTypeValue.from_type(
                TupleType((self._proper_instance(int), self._proper_instance(str)))
            )
        if qualified_name == "tempfile.gettempdir":
            return self._instance(str)
        if qualified_name == "tempfile.NamedTemporaryFile":
            return self._instance(io.BufferedIOBase)
        if qualified_name == "tempfile.TemporaryDirectory":
            return self._instance(contextlib.AbstractContextManager, self._proper_instance(str))
        if qualified_name == "json.dumps":
            return self._instance(str)
        if qualified_name in {"json.dump"}:
            return AbstractTypeValue.from_type(NONE_TYPE)
        if qualified_name in {"json.loads", "json.load"}:
            return AbstractTypeValue.from_type(ANY)
        if qualified_name == "enum.auto":
            # ``auto()`` assigns increasing integers to enum members.
            return self._instance(int)
        return None

    def _call_builtin(
        self,
        name: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        *,
        call_node: ast.Call | None = None,
    ) -> AbstractTypeValue | None:
        if name == "open":
            mode = "r"
            if call_node is not None:
                mode_node: ast.expr | None = call_node.args[1] if len(call_node.args) > 1 else None
                if mode_node is None:
                    mode_node = next(
                        (kw.value for kw in call_node.keywords if kw.arg == "mode"),
                        None,
                    )
                if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                    mode = mode_node.value
            return self._instance(io.BufferedIOBase if "b" in mode else io.TextIOWrapper)

        if name in {"staticmethod", "classmethod"} and arguments:
            # An explicit ``x = staticmethod(f)`` class attribute is exposed
            # as the wrapped callable when accessed through the class.
            return arguments[0]
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
                    return AbstractTypeValue.from_type(TupleType((element,), unknown_size=True))
                result = self._instance(raw, element)
                if raw is list and arguments[0].element_dict_shapes:
                    result = replace(
                        result,
                        element_dict_shapes=arguments[0].element_dict_shapes,
                    )
                return result
            if raw is tuple:
                return AbstractTypeValue.from_type(TupleType(()))
            if raw in {list, set, frozenset}:
                return self._instance(raw, NEVER)
            if raw is dict:
                if keywords:
                    value = join_all(
                        (
                            AbstractTypeValue.from_type(self._runtime_value_type(keyword_value))
                            for keyword_value in keywords.values()
                        ),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    )
                    return self._instance(
                        dict, self._proper_instance(str), value.public_type() or ANY
                    )
                if arguments:
                    for typ in arguments[0].types:
                        if not isinstance(typ, Instance):
                            continue
                        raw_type = typ.type.raw_type
                        if (
                            isinstance(raw_type, type)
                            and issubclass(raw_type, dict)
                            and len(typ.args) >= 2
                        ):
                            return AbstractTypeValue.from_type(typ)
                        if (
                            typ.type.full_name
                            in {
                                "collections.abc.Mapping",
                                "collections.abc.MutableMapping",
                                "typing.Mapping",
                                "typing.MutableMapping",
                            }
                            and len(typ.args) >= 2
                        ):
                            return self._instance(dict, typ.args[0], typ.args[1])
                    element = self._iterable_element(arguments[0])
                    for typ in element.types:
                        if isinstance(typ, TupleType) and len(typ.args) >= 2:
                            return self._instance(dict, typ.args[0], typ.args[1])
                        if isinstance(typ, Instance) and typ.type.raw_type is dict:
                            return AbstractTypeValue.from_type(typ)
                    return self._instance(dict, ANY, ANY)
                return self._instance(dict, NEVER, NEVER)
            return self._instance(raw)
        if name in {"len", "hash", "id", "ord"}:
            return self._instance(int)
        if name in {"all", "any", "callable", "hasattr", "isinstance", "issubclass"}:
            return self._instance(bool)
        if name in {"repr", "ascii", "format", "chr", "input"}:
            return self._instance(str)
        if name == "abs" and arguments:
            if self._all_bool_values(arguments[0]):
                return self._instance(int)
            if self._contains_any(arguments[0]):
                return AbstractTypeValue.from_type(ANY)
            if any(
                isinstance(part, Instance) and part.type.raw_type is complex
                for part in arguments[0].types
            ):
                return self._instance(float)
            numeric = self._numeric_join((arguments[0],))
            return numeric if numeric.public_type() is not None else AbstractTypeValue.unresolved()
        if name == "round" and arguments:
            ndigits = arguments[1] if len(arguments) > 1 else keywords.get("ndigits")
            if ndigits is not None and not (
                ndigits.types and all(isinstance(part, NoneType) for part in ndigits.types)
            ):
                return self._instance(float)
            return self._instance(int)
        if name == "divmod" and len(arguments) >= 2:
            numeric = self._numeric_join(arguments[:2])
            if numeric.public_type() is None:
                return AbstractTypeValue.unresolved()
            return AbstractTypeValue.from_type(
                TupleType((numeric.public_type() or ANY, numeric.public_type() or ANY))
            )
        if name == "pow" and len(arguments) >= 2:
            if len(arguments) >= 3:
                numeric = self._numeric_join(arguments[:2])
                return (
                    numeric if numeric.public_type() is not None else AbstractTypeValue.unresolved()
                )
            return self._pow_result(arguments[0], arguments[1])
        if name == "getattr" and len(arguments) >= 2:
            if (
                call_node is not None
                and len(call_node.args) >= 2
                and isinstance(call_node.args[1], ast.Constant)
                and isinstance(call_node.args[1].value, str)
            ):
                result = self._attribute_value(arguments[0], call_node.args[1].value)
                if len(arguments) >= 3:
                    return self._join(result, arguments[2])
                return result
            return AbstractTypeValue.unresolved()
        if name == "vars" and arguments:
            return self._instance(dict, self._proper_instance(str), ANY)
        if name == "range":
            return self._instance(range)
        if name == "iter":
            if len(arguments) > 1:
                callable_return = self._callable_return_type(arguments[0])
                return self._instance(cabc.Iterator, callable_return.public_type() or ANY)
            iterator_element = (
                self._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            return self._instance(cabc.Iterator, iterator_element.public_type() or ANY)
        if name == "reversed":
            reversed_element = (
                self._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            return self._instance(cabc.Iterator, reversed_element.public_type() or ANY)
        if name == "filter":
            filtered_element = (
                self._iterable_element(arguments[1])
                if len(arguments) > 1
                else AbstractTypeValue.unresolved()
            )
            if (
                call_node is not None
                and len(call_node.args) > 1
                and isinstance(call_node.args[0], ast.Constant)
                and call_node.args[0].value is None
            ):
                filtered_element = filtered_element.without_type(NoneType)
            return self._instance(cabc.Iterator, filtered_element.public_type() or ANY)
        if name == "enumerate":
            enumerated_element = (
                self._iterable_element(arguments[0])
                if arguments
                else AbstractTypeValue.unresolved()
            )
            pair = TupleType((self._proper_instance(int), enumerated_element.public_type() or ANY))
            return self._instance(cabc.Iterator, pair)
        if name == "zip":
            elements = tuple(
                self._iterable_element(argument).public_type() or ANY for argument in arguments
            )
            return self._instance(zip, TupleType(elements))
        if name == "map":
            mapped_element = AbstractTypeValue.unresolved()
            if arguments:
                builtin_targets = [
                    target.removeprefix("builtins.")
                    for target in arguments[0].class_targets
                    if target.startswith("builtins.")
                ]
                builtin_target = next(
                    (
                        getattr(builtins, target)
                        for target in builtin_targets
                        if isinstance(getattr(builtins, target, None), type)
                    ),
                    None,
                )
                if builtin_target is not None:
                    mapped_element = self._instance(builtin_target)
                elif (
                    call_node is not None
                    and call_node.args
                    and isinstance(call_node.args[0], ast.Lambda)
                    and len(arguments) > 1
                    and arguments[0].callable_targets
                ):
                    element = self._iterable_element(arguments[1])
                    mapped_element = join_all(
                        (
                            self._apply_function(target, [element], {})
                            for target in arguments[0].callable_targets
                        ),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    )
                else:
                    mapped_element = self._callable_return_type(arguments[0])
            return self._instance(cabc.Iterator, mapped_element.public_type() or ANY)
        if name in {"min", "max"} and arguments:
            default = keywords.get("default")
            if len(arguments) == 1:
                result = self._iterable_element(arguments[0])
            else:
                result = join_all(
                    arguments,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
            if default is not None:
                if self._is_never_value(result) or result.is_bottom:
                    return default
                result = self._join(result, default)
            return result
        if name == "next" and arguments:
            if len(arguments) > 1:
                return self._join(self._iterable_element(arguments[0]), arguments[1])
            return self._iterable_element(arguments[0])
        if name == "sum":
            if not arguments:
                return self._instance(int)
            element = self._iterable_element(arguments[0])
            start = (
                arguments[1] if len(arguments) > 1 else keywords.get("start", self._instance(int))
            )
            if self._is_never_value(element):
                element = AbstractTypeValue.from_type(NONE_TYPE)
            return self._binary_result(start, element, ast.Add())
        if name == "sorted" and arguments:
            sorted_element = self._iterable_element(arguments[0])
            return self._instance(list, sorted_element.public_type() or ANY)
        if name == "type":
            if len(arguments) == 1:
                return AbstractTypeValue.from_type(TypeType(arguments[0].public_type() or ANY))
            return self._instance(type)
        if name == "open":
            import io as _io

            return self._instance(_io.TextIOWrapper)
        return None

    def _call_attribute(
        self,
        node: ast.Attribute,
        base: AbstractTypeValue,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        environment: dict[str, AbstractTypeValue],
        call_node: ast.Call | None = None,
    ) -> AbstractTypeValue | None:
        for target in base.callable_targets:
            if node.attr == "__call__":
                return self._apply_function(target, arguments, keywords, node=call_node or node)

        union_parts = self._flatten_union_parts(base)
        if len(union_parts) > 1 and node.attr in _UNION_JOIN_METHODS:
            results: list[AbstractTypeValue] = []
            for part in union_parts:
                result = self._call_attribute(
                    node,
                    AbstractTypeValue.from_type(part),
                    arguments,
                    keywords,
                    environment,
                    call_node=call_node,
                )
                if result is not None:
                    results.append(result)
            if results:
                joined = join_all(
                    results,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
                return replace(joined, unknown=joined.unknown or base.unknown)

        for typ in base.types:
            pathlib_class: Instance | None = None
            if isinstance(typ, TypeType) and isinstance(typ.item, Instance):
                pathlib_class = typ.item
            elif isinstance(typ, Instance) and base.class_targets:
                pathlib_class = typ
            if (
                pathlib_class is not None
                and self._is_pathlib_type(pathlib_class)
                and node.attr in {"home", "cwd"}
            ):
                return AbstractTypeValue.from_type(pathlib_class)

        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            class_info = self._classes.get(typ.type.full_name)
            if class_info is None or class_info.instance.type.tuple_fields is None:
                continue
            if node.attr in {"_replace", "_make"}:
                return AbstractTypeValue.from_type(typ)
            if node.attr == "_asdict":
                return self._instance(dict, self._proper_instance(str), ANY)
            if node.attr in {"_fields", "__match_args__"}:
                return AbstractTypeValue.from_type(
                    TupleType((self._proper_instance(str),), unknown_size=True)
                )
            if node.attr == "_field_defaults":
                return self._instance(dict, self._proper_instance(str), ANY)

        method_targets: list[str] = []
        for typ in base.types:
            if isinstance(typ, TupleType):
                if node.attr in {"count", "index"}:
                    return self._instance(int)
                if node.attr in {"sort", "reverse"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                continue
            if not isinstance(typ, Instance):
                continue
            class_info = self._classes.get(typ.type.full_name)
            if class_info is not None:
                getter = self._class_property(class_info.qualified_name, node.attr)
                if getter is not None:
                    # ``obj.prop(...)`` calls the property's value, not the
                    # getter function itself.
                    function = self._functions[getter]
                    value = function.explicit_return or (
                        function.summary.return_value
                        if function.summary
                        else AbstractTypeValue.unresolved()
                    )
                    return self._call_property_value(value, arguments, keywords, call_node or node)
                method = self._class_method(class_info.qualified_name, node.attr)
                if method is not None:
                    method_targets.append(method)
            else:
                member = typ.type.members.get(node.attr)
                if isinstance(member, CallableType):
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    if substitutions:
                        member = substitute_type_vars(member, substitutions)
                    selected = self._select_callable_overload(member, arguments)
                    return AbstractTypeValue.from_type(
                        selected.return_type if selected is not None else member.return_type
                    )
        if method_targets:
            return join_all(
                [
                    self._apply_function(
                        target,
                        self._method_arguments(self._functions[target], base, arguments),
                        keywords,
                        node=call_node or node,
                    )
                    for target in method_targets
                ],
                self.type_system,
                max_union_size=self.options.max_union_size,
            )

        text_results = [
            result
            for typ in base.types
            if isinstance(typ, Instance) and typ.type.raw_type in {str, bytes}
            if (result := self._model_text_method(cast(type, typ.type.raw_type), node.attr))
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
            original_type = typ.type
            if typ.type.typed_dict_fields is None:
                projected = self._builtin_projection(typ)
                if projected is not None:
                    typ = projected
            raw = typ.type.raw_type
            args = typ.args
            if raw is cabc.Generator:
                if node.attr == "send" and args:
                    # Generator[Y, S, R].send() returns the next yielded value.
                    return AbstractTypeValue.from_type(args[0])
                if node.attr == "throw" and args:
                    return AbstractTypeValue.from_type(args[0])
                if node.attr == "close":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is cabc.AsyncGenerator:
                if node.attr == "asend" and args:
                    return self._instance(cabc.Coroutine, ANY, ANY, args[0])
                if node.attr == "athrow" and args:
                    return self._instance(cabc.Coroutine, ANY, ANY, args[0])
                if node.attr == "aclose":
                    return self._instance(cabc.Coroutine, ANY, ANY, NONE_TYPE)
            if isinstance(raw, type) and issubclass(raw, io.IOBase):
                if node.attr == "__enter__":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__", "close", "flush", "writelines"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"seek", "tell", "fileno"}:
                    return self._instance(int)
                if node.attr == "name":
                    return self._instance(str)
                if node.attr == "mode":
                    return self._instance(str)
                if node.attr == "encoding":
                    return self._join(
                        AbstractTypeValue.from_type(self._instance(str)),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                binary = issubclass(raw, io.BufferedIOBase) or issubclass(raw, io.RawIOBase)
                if not issubclass(raw, io.TextIOBase) and not binary:
                    binary = False
                if node.attr in {"read", "readline"}:
                    return self._instance(bytes if binary else str)
                if node.attr == "readlines":
                    return self._instance(list, self._proper_instance(bytes if binary else str))
                if node.attr in {"readinto", "write"}:
                    return self._instance(int if node.attr == "write" else int)
            if self._is_pathlib_type(typ):
                if node.attr == "read_text":
                    return self._instance(str)
                if node.attr == "read_bytes":
                    return self._instance(bytes)
                if node.attr in {"write_text", "write_bytes"}:
                    return self._instance(int)
                if node.attr in {
                    "exists",
                    "is_file",
                    "is_dir",
                    "is_symlink",
                    "is_absolute",
                    "is_relative_to",
                    "match",
                    "samefile",
                    "is_mount",
                    "is_socket",
                    "is_fifo",
                    "is_block_device",
                    "is_char_device",
                }:
                    return self._instance(bool)
                if node.attr in {"stat", "lstat"}:
                    return self._instance(os.stat_result)
                if node.attr in {"owner", "group", "as_uri"}:
                    return self._instance(str)
                if node.attr == "readlink":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"iterdir", "glob", "rglob"}:
                    return self._instance(cabc.Iterator, typ)
                if node.attr == "walk":
                    return self._instance(
                        cabc.Iterator,
                        TupleType(
                            (
                                typ,
                                self._instance(list, self._proper_instance(str)),
                                self._instance(list, self._proper_instance(str)),
                            )
                        ),
                    )
                if node.attr in {
                    "resolve",
                    "absolute",
                    "expanduser",
                    "with_name",
                    "with_suffix",
                    "with_stem",
                    "joinpath",
                    "relative_to",
                    "rename",
                    "replace",
                }:
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "open":
                    mode = "r"
                    if call_node is not None:
                        mode_node = call_node.args[0] if call_node.args else None
                        if mode_node is None:
                            mode_node = next(
                                (
                                    keyword.value
                                    for keyword in call_node.keywords
                                    if keyword.arg == "mode"
                                ),
                                None,
                            )
                        if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                            mode = mode_node.value
                    return self._instance(io.BufferedIOBase if "b" in mode else io.TextIOWrapper)
                if node.attr in {
                    "mkdir",
                    "touch",
                    "unlink",
                    "rmdir",
                    "chmod",
                    "symlink_to",
                    "hardlink_to",
                    "write_text",
                }:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is datetime.datetime:
                if node.attr == "date":
                    return self._instance(datetime.date)
                if node.attr in {"time", "timetz"}:
                    return self._instance(datetime.time)
                if node.attr == "tzinfo":
                    return self._join(
                        self._instance(datetime.tzinfo),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "timestamp":
                    return self._instance(float)
                if node.attr in {"isoformat", "strftime", "ctime"}:
                    return self._instance(str)
                if node.attr == "utcoffset":
                    return self._join(
                        self._instance(datetime.timedelta),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr in {"weekday", "isoweekday"}:
                    return self._instance(int)
                if node.attr in {"replace", "astimezone", "fromisoformat"}:
                    return AbstractTypeValue.from_type(typ)
            if raw is datetime.date:
                if node.attr in {"isoformat", "strftime", "ctime"}:
                    return self._instance(str)
                if node.attr in {"weekday", "isoweekday"}:
                    return self._instance(int)
                if node.attr in {
                    "replace",
                    "today",
                    "fromtimestamp",
                    "fromisoformat",
                    "fromordinal",
                }:
                    return AbstractTypeValue.from_type(typ)
            if raw is datetime.timedelta:
                if node.attr == "total_seconds":
                    return self._instance(float)
            if raw is collections.deque:
                collection_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr in {"append", "appendleft", "extend", "extendleft"}:
                    if arguments:
                        added = (
                            arguments[-1]
                            if node.attr in {"append", "appendleft"}
                            else self._iterable_element(arguments[0])
                        )
                        widened = self._join(collection_element, added)
                        updated = AbstractTypeValue.from_type(
                            Instance(original_type, (widened.public_type() or ANY,))
                        )
                        self._update_environment_receiver(environment, node.value, updated)
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"pop", "popleft"}:
                    return collection_element
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"count", "index"}:
                    return self._instance(int)
                if node.attr in {"clear", "rotate", "reverse", "remove"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is list or raw is set:
                collection_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr in {"sort", "reverse"} and raw is list:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if (raw is list and node.attr in {"append", "insert"}) or (
                    raw is set and node.attr == "add"
                ):
                    if arguments:
                        widened = self._join(collection_element, arguments[-1])
                        updated = AbstractTypeValue.from_type(
                            Instance(original_type, (widened.public_type() or ANY,))
                        )
                        updated = self._augment_element_shapes(updated, arguments[-1])
                        self._update_environment_receiver(environment, node.value, updated)
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if (raw is list and node.attr == "extend") or (
                    raw is set and node.attr == "update"
                ):
                    if arguments:
                        added = self._iterable_element(arguments[0])
                        widened = self._join(collection_element, added)
                        updated = AbstractTypeValue.from_type(
                            Instance(original_type, (widened.public_type() or ANY,))
                        )
                        updated = self._augment_element_shapes(updated, arguments[0])
                        self._update_environment_receiver(environment, node.value, updated)
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"pop"}:
                    return collection_element
                if node.attr in {"copy"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"count", "index"}:
                    return self._instance(int)
                if node.attr in {
                    "union",
                    "intersection",
                    "difference",
                    "symmetric_difference",
                }:
                    element = collection_element
                    if node.attr == "union" and arguments:
                        element = self._join(element, self._iterable_element(arguments[0]))
                    return AbstractTypeValue.from_type(
                        Instance(original_type, (element.public_type() or ANY,))
                    )
                if node.attr in {"issubset", "issuperset", "isdisjoint"}:
                    return self._instance(bool)
                if node.attr in {"clear", "discard", "remove"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is frozenset:
                collection_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {
                    "union",
                    "intersection",
                    "difference",
                    "symmetric_difference",
                }:
                    element = collection_element
                    if node.attr == "union" and arguments:
                        element = self._join(element, self._iterable_element(arguments[0]))
                    return self._instance(frozenset, element.public_type() or ANY)
                if node.attr in {"issubset", "issuperset", "isdisjoint"}:
                    return self._instance(bool)
            if raw is bytearray:
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "decode":
                    return self._instance(str)
                if node.attr == "hex":
                    return self._instance(str)
                if node.attr in {"append", "extend"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is re.Pattern:
                text = args[0] if args else ANY
                match_type = self._proper_instance(re.Match, text)
                if node.attr in {"match", "search", "fullmatch"}:
                    return self._join(
                        AbstractTypeValue.from_type(match_type),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "findall":
                    return self._instance(list, text)
                if node.attr == "finditer":
                    return self._instance(cabc.Iterator, match_type)
                if node.attr == "sub":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "subn":
                    return AbstractTypeValue.from_type(
                        TupleType((text, self._proper_instance(int)))
                    )
                if node.attr == "split":
                    return self._instance(list, text)
            if raw is re.Match:
                text = args[0] if args else ANY
                match_or_none = self._join(
                    AbstractTypeValue.from_type(text),
                    AbstractTypeValue.from_type(NONE_TYPE),
                )
                if node.attr == "group":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "expand":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "__getitem__":
                    return AbstractTypeValue.from_type(text)
                if node.attr == "groups":
                    return AbstractTypeValue.from_type(
                        TupleType((match_or_none.public_type() or ANY,), unknown_size=True)
                    )
                if node.attr == "groupdict":
                    return self._instance(
                        dict, self._proper_instance(str), match_or_none.public_type() or ANY
                    )
                if node.attr in {"start", "end"}:
                    if arguments:
                        return self._join(
                            AbstractTypeValue.from_type(self._proper_instance(int)),
                            AbstractTypeValue.from_type(NONE_TYPE),
                        )
                    return self._instance(int)
                if node.attr == "span":
                    if arguments:
                        return AbstractTypeValue.from_type(
                            TupleType(
                                (
                                    self._join(
                                        AbstractTypeValue.from_type(self._proper_instance(int)),
                                        AbstractTypeValue.from_type(NONE_TYPE),
                                    ).public_type()
                                    or ANY,
                                    self._join(
                                        AbstractTypeValue.from_type(self._proper_instance(int)),
                                        AbstractTypeValue.from_type(NONE_TYPE),
                                    ).public_type()
                                    or ANY,
                                )
                            )
                        )
                    return AbstractTypeValue.from_type(
                        TupleType((self._proper_instance(int), self._proper_instance(int)))
                    )
            if raw in {threading.Lock, threading.RLock}:
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__", "release"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"acquire", "locked"}:
                    return self._instance(bool)
            if raw in {
                threading.Event,
                threading.Condition,
                threading.Semaphore,
                threading.BoundedSemaphore,
                threading.Barrier,
            }:
                if node.attr in {
                    "wait",
                    "wait_for",
                    "is_set",
                    "isSet",
                    "acquire",
                }:
                    return self._instance(bool)
                if node.attr in {
                    "set",
                    "clear",
                    "release",
                    "notify_all",
                    "notifyAll",
                    "abort",
                    "reset",
                }:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is threading.Thread:
                if node.attr in {"start", "join", "run"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"is_alive"}:
                    return self._instance(bool)
                if node.attr == "name":
                    return self._instance(str)
                if node.attr in {"daemon"}:
                    return self._instance(bool)
            if raw in {asyncio.Future, asyncio.Task}:
                item = args[0] if args else ANY
                if node.attr == "result":
                    return AbstractTypeValue.from_type(item)
                if node.attr == "exception":
                    return self._join(
                        AbstractTypeValue.from_type(self._proper_instance(BaseException)),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr in {"done", "cancelled", "cancel"}:
                    return self._instance(bool)
                if node.attr in {"add_done_callback", "remove_done_callback"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if raw is asyncio.Task and node.attr == "get_name":
                    return self._instance(str)
                if raw is asyncio.Task and node.attr == "set_name":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            async_bool = self._instance(cabc.Coroutine, ANY, ANY, self._proper_instance(bool))
            if raw in {asyncio.Lock}:
                if node.attr in {"__aenter__"}:
                    return self._instance(cabc.Coroutine, ANY, ANY, typ)
                if node.attr in {"__aexit__", "release"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "acquire":
                    return async_bool
                if node.attr == "locked":
                    return self._instance(bool)
            if raw in {asyncio.Event}:
                if node.attr == "wait":
                    return async_bool
                if node.attr in {"set", "clear"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "is_set":
                    return self._instance(bool)
            if raw in {asyncio.Semaphore, asyncio.BoundedSemaphore}:
                if node.attr in {"__aenter__"}:
                    return self._instance(cabc.Coroutine, ANY, ANY, typ)
                if node.attr in {"__aexit__", "release"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "acquire":
                    return async_bool
                if node.attr == "locked":
                    return self._instance(bool)
            if raw in {
                queue.Queue,
                queue.SimpleQueue,
                queue.LifoQueue,
                queue.PriorityQueue,
            }:
                item = args[0] if args else ANY
                if node.attr == "get":
                    return AbstractTypeValue.from_type(item)
                if node.attr in {"put", "put_nowait", "task_done", "join"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "qsize":
                    return self._instance(int)
                if node.attr in {"empty", "full"}:
                    return self._instance(bool)
            if raw is concurrent.futures.Future:
                item = args[0] if args else ANY
                if node.attr == "result":
                    return AbstractTypeValue.from_type(item)
                if node.attr == "exception":
                    return self._join(
                        AbstractTypeValue.from_type(self._proper_instance(BaseException)),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr in {"done", "cancelled", "running", "cancel"}:
                    return self._instance(bool)
                if node.attr in {
                    "set_result",
                    "set_exception",
                    "set_running_or_notify_cancel",
                    "add_done_callback",
                }:
                    return AbstractTypeValue.from_type(
                        self._proper_instance(bool)
                        if node.attr == "set_running_or_notify_cancel"
                        else NONE_TYPE
                    )
            if raw in {
                concurrent.futures.ThreadPoolExecutor,
                concurrent.futures.ProcessPoolExecutor,
            }:
                if node.attr == "submit" and arguments:
                    return self._instance(
                        concurrent.futures.Future,
                        self._callable_return_type(arguments[0]).public_type() or ANY,
                    )
                if node.attr == "map" and arguments:
                    return self._instance(
                        cabc.Iterator,
                        self._callable_return_type(arguments[0]).public_type() or ANY,
                    )
                if node.attr in {"shutdown"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw in {cabc.Iterator, cabc.AsyncIterator}:
                item = args[0] if args else ANY
                if node.attr in {"__iter__", "__aiter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__next__", "__anext__"}:
                    return AbstractTypeValue.from_type(item)
            if raw in {cabc.Mapping, cabc.MutableMapping}:
                key = args[0] if args else ANY
                item = args[1] if len(args) > 1 else ANY
                key_value = AbstractTypeValue.from_type(key)
                item_value = AbstractTypeValue.from_type(item)
                if node.attr == "get":
                    default = (
                        arguments[1]
                        if len(arguments) > 1
                        else AbstractTypeValue.from_type(NONE_TYPE)
                    )
                    return self._join(item_value, default)
                if node.attr in {"__getitem__", "pop"}:
                    if node.attr == "pop" and len(arguments) > 1:
                        return self._join(item_value, arguments[1])
                    return item_value
                if node.attr == "keys":
                    return self._instance(cabc.KeysView, key)
                if node.attr == "values":
                    return self._instance(cabc.ValuesView, item)
                if node.attr == "items":
                    return self._instance(cabc.ItemsView, key, item)
                if node.attr in {"copy", "__iter__"}:
                    return (
                        AbstractTypeValue.from_type(typ)
                        if node.attr == "copy"
                        else self._instance(cabc.Iterator, key)
                    )
                if node.attr in {"__len__", "count"}:
                    return self._instance(int)
                if node.attr in {"clear", "update", "setdefault"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw in {cabc.Sequence, cabc.MutableSequence}:
                item = args[0] if args else ANY
                item_value = AbstractTypeValue.from_type(item)
                if node.attr == "__getitem__":
                    return item_value
                if node.attr in {"count", "index", "__len__"}:
                    return self._instance(int)
                if node.attr in {"pop"}:
                    return item_value
                if node.attr in {"copy", "reverse"}:
                    return (
                        AbstractTypeValue.from_type(typ)
                        if node.attr == "copy"
                        else AbstractTypeValue.from_type(NONE_TYPE)
                    )
                if node.attr in {"append", "extend", "insert", "remove", "sort", "clear"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "__iter__":
                    return self._instance(cabc.Iterator, item)
            if raw is subprocess.CompletedProcess:
                text = args[0] if args else ANY
                if node.attr == "stdout" or node.attr == "stderr":
                    return self._join(
                        AbstractTypeValue.from_type(text),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "returncode":
                    return self._instance(int)
                if node.attr == "check_returncode":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is subprocess.Popen:
                text = args[0] if args else ANY
                if node.attr == "wait":
                    return self._instance(int)
                if node.attr == "poll":
                    return self._join(
                        AbstractTypeValue.from_type(self._proper_instance(int)),
                        AbstractTypeValue.from_type(NONE_TYPE),
                    )
                if node.attr == "communicate":
                    return AbstractTypeValue.from_type(
                        TupleType(
                            (
                                self._join(
                                    AbstractTypeValue.from_type(text),
                                    AbstractTypeValue.from_type(NONE_TYPE),
                                ).public_type()
                                or ANY,
                                self._join(
                                    AbstractTypeValue.from_type(text),
                                    AbstractTypeValue.from_type(NONE_TYPE),
                                ).public_type()
                                or ANY,
                            )
                        )
                    )
                if node.attr in {"kill", "terminate", "send_signal"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr in {"__exit__"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr in {"__enter__"}:
                    return AbstractTypeValue.from_type(typ)
            if raw is logging.Logger:
                if node.attr in {
                    "debug",
                    "info",
                    "warning",
                    "error",
                    "exception",
                    "critical",
                    "log",
                    "setLevel",
                    "addHandler",
                }:
                    return AbstractTypeValue.from_type(NONE_TYPE)
                if node.attr == "isEnabledFor":
                    return self._instance(bool)
            if raw is contextlib.ExitStack:
                if node.attr in {"__enter__", "pop_all"}:
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "enter_context" and arguments:
                    entered: ProperType = ANY
                    for item in arguments[0].types:
                        if (
                            isinstance(item, Instance)
                            and item.type.raw_type
                            in {
                                contextlib.AbstractContextManager,
                                contextlib.AbstractAsyncContextManager,
                            }
                            and item.args
                        ):
                            entered = item.args[0]
                            break
                    return AbstractTypeValue.from_type(entered)
                if node.attr in {"__exit__", "close", "callback", "push", "push_async"}:
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is contextvars.ContextVar:
                item = args[0] if args else ANY
                if node.attr == "get":
                    return AbstractTypeValue.from_type(item)
                if node.attr == "set":
                    return self._instance(contextvars.Token, item)
                if node.attr == "reset":
                    return AbstractTypeValue.from_type(NONE_TYPE)
            if raw is collections.Counter:
                counter_element = AbstractTypeValue.from_type(args[0] if args else ANY)
                if node.attr == "most_common":
                    pair = TupleType(
                        (counter_element.public_type() or ANY, self._proper_instance(int))
                    )
                    return self._instance(list, pair)
                if node.attr == "elements":
                    return self._instance(cabc.Iterator, counter_element.public_type() or ANY)
                if node.attr == "total":
                    return self._instance(int)
                args = (args[0] if args else ANY, self._proper_instance(int))
            if (
                raw
                in {
                    dict,
                    collections.defaultdict,
                    collections.OrderedDict,
                    collections.ChainMap,
                    collections.Counter,
                }
                or typ.type.typed_dict_fields is not None
            ):
                if node.attr == "copy":
                    return AbstractTypeValue.from_type(typ)
                if node.attr == "fromkeys" and arguments:
                    key_value = self._iterable_element(arguments[0]).public_type() or ANY
                    value = arguments[1] if len(arguments) > 1 else keywords.get("value")
                    value_type = (value.public_type() or ANY) if value is not None else NONE_TYPE
                    return self._instance(dict, key_value, value_type)
                if typ.type.typed_dict_fields is not None:
                    fields = typ.type.typed_dict_fields
                    key = self._proper_instance(str)
                    field_values = list(fields.values())
                    if not field_values:
                        item = ANY
                    elif len(field_values) == 1:
                        item = field_values[0]
                    else:
                        item = UnionType(tuple(sorted(field_values)))
                    key_name = (
                        call_node.args[0].value
                        if call_node
                        and call_node.args
                        and isinstance(call_node.args[0], ast.Constant)
                        and isinstance(call_node.args[0].value, str)
                        else None
                    )
                    if node.attr == "get":
                        if key_name in fields:
                            result = AbstractTypeValue.from_type(fields[key_name])
                            if key_name in typ.type.required_keys:
                                return result
                            default = (
                                arguments[1]
                                if len(arguments) > 1
                                else AbstractTypeValue.from_type(NONE_TYPE)
                            )
                            return self._join(result, default)
                        result = AbstractTypeValue.from_type(item)
                        default = (
                            arguments[1]
                            if len(arguments) > 1
                            else AbstractTypeValue.from_type(NONE_TYPE)
                        )
                        return self._join(result, default)
                    if node.attr == "setdefault":
                        default = (
                            arguments[1]
                            if len(arguments) > 1
                            else AbstractTypeValue.from_type(NONE_TYPE)
                        )
                        field = fields.get(key_name) if key_name is not None else None
                        if key_name in typ.type.required_keys and field is not None:
                            return AbstractTypeValue.from_type(field)
                        if field is not None:
                            return self._join(AbstractTypeValue.from_type(field), default)
                        return self._join(AbstractTypeValue.from_type(item), default)
                    if node.attr == "pop":
                        field = fields.get(key_name) if key_name is not None else None
                        result = AbstractTypeValue.from_type(field if field is not None else item)
                        if key_name in typ.type.required_keys:
                            return result
                        if len(arguments) > 1:
                            return self._join(result, arguments[1])
                        return result
                    if node.attr == "popitem":
                        return AbstractTypeValue.from_type(TupleType((key, item)))
                    if node.attr == "keys":
                        return self._instance(cabc.KeysView, key)
                    if node.attr == "values":
                        return self._instance(cabc.ValuesView, item)
                    if node.attr == "items":
                        return self._instance(cabc.ItemsView, key, item)
                    if node.attr in {"update", "clear"}:
                        # TypedDict keys and their types are fixed by the
                        # declaration; mutating methods must not project the
                        # receiver to an anonymous dict.
                        return AbstractTypeValue.from_type(NONE_TYPE)
                else:
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
                    if node.attr == "setdefault":
                        default = (
                            arguments[1]
                            if len(arguments) > 1
                            else AbstractTypeValue.from_type(NONE_TYPE)
                        )
                        result = self._join(AbstractTypeValue.from_type(item), default)
                        key_type = (
                            arguments[0].public_type()
                            if arguments and arguments[0].public_type() is not None
                            else key
                        )
                        widened_key = self._join(
                            AbstractTypeValue.from_type(key), AbstractTypeValue.from_type(key_type)
                        )
                        widened_item = self._join(AbstractTypeValue.from_type(item), default)
                        self._update_environment_receiver(
                            environment,
                            node.value,
                            self._instance(
                                dict,
                                widened_key.public_type() or ANY,
                                widened_item.public_type() or ANY,
                            ),
                        )
                        return result
                    if node.attr == "pop":
                        result = AbstractTypeValue.from_type(item)
                        if len(arguments) > 1:
                            return self._join(result, arguments[1])
                        return result
                    if node.attr == "popitem":
                        return AbstractTypeValue.from_type(TupleType((key, item)))
                    if node.attr == "keys":
                        return self._instance(cabc.KeysView, key)
                    if node.attr == "values":
                        return self._instance(cabc.ValuesView, item)
                    if node.attr == "items":
                        return self._instance(cabc.ItemsView, key, item)
                    if node.attr in {"update", "clear"}:
                        if node.attr == "update":
                            mapping_key: AbstractTypeValue | None = None
                            mapping_item: AbstractTypeValue | None = None
                            if arguments:
                                mapping_key, mapping_item = self._mapping_key_value(arguments[0])
                            elif keywords:
                                mapping_key = self._instance(str)
                                mapping_item = join_all(
                                    keywords.values(),
                                    self.type_system,
                                    max_union_size=self.options.max_union_size,
                                )
                            if mapping_key is not None and mapping_item is not None:
                                widened_key = self._join(
                                    AbstractTypeValue.from_type(key), mapping_key
                                )
                                widened_item = self._join(
                                    AbstractTypeValue.from_type(item), mapping_item
                                )
                                self._update_environment_receiver(
                                    environment,
                                    node.value,
                                    self._instance(
                                        dict,
                                        widened_key.public_type() or ANY,
                                        widened_item.public_type() or ANY,
                                    ),
                                )
                        return AbstractTypeValue.from_type(NONE_TYPE)
        return None

    def _method_arguments(self, function, base, arguments):
        if function.method_kind == "static":
            return arguments
        if function.method_kind == "class":
            receiver = replace(
                base,
                class_targets=frozenset(
                    typ.type.full_name for typ in base.types if isinstance(typ, Instance)
                ),
            )
            return [receiver, *arguments]
        return arguments if base.class_targets else [base, *arguments]

    def _model_text_method(self, receiver: type, attribute: str) -> AbstractTypeValue | None:
        """Model one ``str`` or ``bytes`` receiver alternative."""
        preserving: dict[type, set[str]] = {
            str: {
                "capitalize",
                "casefold",
                "center",
                "expandtabs",
                "format",
                "format_map",
                "join",
                "ljust",
                "lower",
                "lstrip",
                "removeprefix",
                "removesuffix",
                "replace",
                "rjust",
                "rstrip",
                "strip",
                "swapcase",
                "title",
                "translate",
                "upper",
                "zfill",
            },
            bytes: {
                "capitalize",
                "center",
                "expandtabs",
                "join",
                "ljust",
                "lower",
                "lstrip",
                "removeprefix",
                "removesuffix",
                "replace",
                "rjust",
                "rstrip",
                "strip",
                "swapcase",
                "title",
                "translate",
                "upper",
                "zfill",
            },
        }
        predicates: dict[type, set[str]] = {
            str: {
                "endswith",
                "isalnum",
                "isalpha",
                "isascii",
                "isdecimal",
                "isdigit",
                "isidentifier",
                "islower",
                "isnumeric",
                "isprintable",
                "isspace",
                "istitle",
                "isupper",
                "startswith",
            },
            bytes: {
                "endswith",
                "isalnum",
                "isalpha",
                "isascii",
                "isdigit",
                "islower",
                "isspace",
                "istitle",
                "isupper",
                "startswith",
            },
        }
        if attribute == "encode" and receiver is str:
            return self._instance(bytes)
        if attribute == "decode" and receiver is bytes:
            return self._instance(str)
        if attribute == "hex" and receiver is bytes:
            return self._instance(str)
        if attribute in preserving[receiver]:
            return self._instance(receiver)
        if attribute in predicates[receiver]:
            return self._instance(bool)
        if attribute in {"count", "find", "index", "rfind", "rindex"}:
            return self._instance(int)
        element = self._proper_instance(receiver)
        if attribute in {"partition", "rpartition"}:
            return AbstractTypeValue.from_type(TupleType((element, element, element)))
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
        if any(isinstance(part, UnionType) for part in left.types):
            left = left.join(AbstractTypeValue.bottom(), self.type_system)
        if any(isinstance(part, UnionType) for part in right.types):
            right = right.join(AbstractTypeValue.bottom(), self.type_system)
        if isinstance(operator, ast.Mod):
            if self._contains_raw(left, str) or self._contains_raw(left, bytes):
                values = [
                    (
                        self._instance(part.type.raw_type)
                        if isinstance(part, Instance) and part.type.raw_type in {str, bytes}
                        else self._binary_result(AbstractTypeValue.from_type(part), right, operator)
                    )
                    for part in left.types
                ]
                if left.unknown:
                    values.append(AbstractTypeValue.unresolved())
                return join_all(values, self.type_system)
            numeric = {bool, int, float, complex}
            if (
                not left.unknown
                and not right.unknown
                and left.types
                and right.types
                and all(
                    isinstance(part, Instance) and part.type.raw_type in numeric
                    for part in (*left.types, *right.types)
                )
            ):
                if self._all_bool_values(left, right):
                    return self._instance(int)
                return self._numeric_join((left, right))
            if self._contains_any(left) or self._contains_any(right):
                return AbstractTypeValue.from_type(ANY)
            # An unresolved format string does not make the formatting
            # arguments a possible result of the operation.
            return AbstractTypeValue.unresolved()
        if isinstance(operator, ast.BitOr):
            return self._bit_or_result(left, right)
        if isinstance(operator, ast.Div):
            if len(left.types) == 1:
                left_part = next(iter(left.types))
                if isinstance(left_part, Instance) and self._is_pathlib_type(left_part):
                    return AbstractTypeValue.from_type(left_part)
            numeric = {bool, int, float, complex}
            if (
                not left.unknown
                and not right.unknown
                and left.types
                and right.types
                and all(
                    isinstance(part, Instance) and part.type.raw_type in numeric
                    for part in (*left.types, *right.types)
                )
            ):
                if any(
                    isinstance(part, Instance) and part.type.raw_type in {float, complex}
                    for part in (*left.types, *right.types)
                ):
                    return self._numeric_join((left, right))
                return self._instance(float)
            if self._contains_any(left) or self._contains_any(right):
                return AbstractTypeValue.from_type(ANY)
            # Division is not defined for every object.  When no local or
            # external ``__truediv__`` model produced a result, coercing to
            # float would be unsound (``Path / str``, ``Decimal / int``, ...).
            return AbstractTypeValue.unresolved()
        if isinstance(operator, ast.FloorDiv):
            if (
                not left.unknown
                and not right.unknown
                and self._contains_raw(left, int)
                and self._contains_raw(right, int)
            ):
                return self._instance(int)
        if isinstance(operator, ast.MatMult):
            return AbstractTypeValue.unresolved()
        if isinstance(operator, ast.Add):
            return self._add_result(left, right)
        if isinstance(operator, ast.Sub):
            set_result = self._set_difference_result(left, right)
            if set_result is not None:
                return set_result
            raw_pairs = {
                (datetime.datetime, datetime.datetime): datetime.timedelta,
                (datetime.date, datetime.date): datetime.timedelta,
                (datetime.timedelta, datetime.timedelta): datetime.timedelta,
                (datetime.datetime, datetime.timedelta): datetime.datetime,
                (datetime.date, datetime.timedelta): datetime.date,
            }
            if len(left.types) == 1 and len(right.types) == 1:
                left_part = next(iter(left.types))
                right_part = next(iter(right.types))
                if isinstance(left_part, Instance) and isinstance(right_part, Instance):
                    result = raw_pairs.get((left_part.type.raw_type, right_part.type.raw_type))
                    if result is not None:
                        return self._instance(result)
        if isinstance(operator, ast.Mult):
            return self._mult_result(left, right)
        if isinstance(operator, (ast.BitAnd, ast.BitXor)):
            return self._set_bitwise_result(left, right)
        if isinstance(operator, ast.Pow):
            return self._pow_result(left, right)
        if self._contains_any(left) or self._contains_any(right):
            # Gradual typing: arithmetic on Any stays Any.  Narrowing it to a
            # concrete numeric type produces false diagnostics and can prune
            # valid branches in untyped code.
            return AbstractTypeValue.from_type(ANY)
        if left.unknown or right.unknown:
            # ``u * 2`` where u is unmodelled is not necessarily int: u may be
            # a str, list, or an object implementing its own protocol.
            return AbstractTypeValue.unresolved()
        if self._all_bool_values(left, right) and isinstance(
            operator,
            (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.Pow, ast.LShift, ast.RShift),
        ):
            return self._instance(int)
        numeric = self._numeric_join((left, right))
        numeric_type = numeric.public_type()
        if numeric_type is not None:
            if (
                isinstance(numeric_type, Instance)
                and numeric_type.type.raw_type is bool
                and isinstance(
                    operator,
                    (
                        ast.Add,
                        ast.Sub,
                        ast.Mult,
                        ast.FloorDiv,
                        ast.Mod,
                        ast.Pow,
                        ast.LShift,
                        ast.RShift,
                    ),
                )
            ):
                # bool arithmetic produces int even when another union
                # alternative is non-numeric (for example ``bool | None``).
                return self._instance(int)
            return numeric
        return self._join(left, right).join(
            AbstractTypeValue.unresolved(),
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    @staticmethod
    def _flatten_union_parts(value: AbstractTypeValue) -> list[ProperType]:
        parts: list[ProperType] = []
        for typ in value.types:
            if isinstance(typ, UnionType):
                parts.extend(typ.items)
            else:
                parts.append(typ)
        return parts

    def _add_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Add each pair of alternatives without dropping union branches."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        raw_pairs = {
            (datetime.datetime, datetime.timedelta): datetime.datetime,
            (datetime.timedelta, datetime.datetime): datetime.datetime,
            (datetime.date, datetime.timedelta): datetime.date,
            (datetime.timedelta, datetime.date): datetime.date,
            (datetime.timedelta, datetime.timedelta): datetime.timedelta,
        }
        numeric = {bool, int, float, complex}
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if isinstance(left_part, TupleType) and isinstance(right_part, TupleType):
                    if left_part.unknown_size or right_part.unknown_size:
                        element = join_all(
                            (
                                AbstractTypeValue.from_type(item)
                                for item in (*left_part.args, *right_part.args)
                            ),
                            self.type_system,
                            max_union_size=self.options.max_union_size,
                        )
                        results.append(
                            TupleType((element.public_type() or ANY,), unknown_size=True)
                        )
                    else:
                        results.append(
                            TupleType(
                                (*left_part.args, *right_part.args),
                                unknown_size=False,
                            )
                        )
                    continue
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                mapped = raw_pairs.get((left_raw, right_raw))
                if mapped is not None:
                    results.append(self._proper_instance(mapped))
                    continue
                if left_raw in {str, bytes} and right_raw is left_raw:
                    results.append(left_part)
                    continue
                if left_raw is list and right_raw is list:
                    element = join_all(
                        (
                            AbstractTypeValue.from_type(
                                left_part.args[0] if left_part.args else ANY
                            ),
                            AbstractTypeValue.from_type(
                                right_part.args[0] if right_part.args else ANY
                            ),
                        ),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    )
                    results.append(self._proper_instance(list, element.public_type() or ANY))
                    continue
                if left_raw in numeric and right_raw in numeric:
                    if left_raw is bool and right_raw is bool:
                        results.append(self._proper_instance(int))
                    else:
                        joined = self._numeric_join(
                            (
                                AbstractTypeValue.from_type(left_part),
                                AbstractTypeValue.from_type(right_part),
                            )
                        )
                        if joined.public_type() is not None:
                            results.append(joined.public_type())
                        else:
                            unknown = True
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.type_system,
            max_union_size=self.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _set_difference_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue | None:
        """Model set/frozenset subtraction; return None for non-set operands."""
        left_parts = self._flatten_union_parts(left)
        right_parts = self._flatten_union_parts(right)
        has_set = any(
            isinstance(part, Instance) and part.type.raw_type in {set, frozenset}
            for part in (*left_parts, *right_parts)
        )
        if not has_set:
            return None
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in left_parts:
            for right_part in right_parts:
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                if left_raw in {set, frozenset} and right_raw in {set, frozenset}:
                    element = join_all(
                        (
                            AbstractTypeValue.from_type(
                                left_part.args[0] if left_part.args else ANY
                            ),
                            AbstractTypeValue.from_type(
                                right_part.args[0] if right_part.args else ANY
                            ),
                        ),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    )
                    results.append(self._proper_instance(left_raw, element.public_type() or ANY))
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.type_system,
            max_union_size=self.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _set_bitwise_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Model set/frozenset ``&`` and ``^`` without dropping unions."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                if left_raw in {set, frozenset} and right_raw in {set, frozenset}:
                    element = join_all(
                        (
                            AbstractTypeValue.from_type(
                                left_part.args[0] if left_part.args else ANY
                            ),
                            AbstractTypeValue.from_type(
                                right_part.args[0] if right_part.args else ANY
                            ),
                        ),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    )
                    results.append(self._proper_instance(left_raw, element.public_type() or ANY))
                    continue
                if left_raw in {bool, int} and right_raw in {bool, int}:
                    results.append(
                        self._proper_instance(
                            bool if left_raw is bool and right_raw is bool else int
                        )
                    )
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.type_system,
            max_union_size=self.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _bit_or_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Bitwise-or each pair of alternatives (sets, mappings, integers)."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if not isinstance(left_part, Instance) or not isinstance(right_part, Instance):
                    unknown = True
                    continue
                left_raw = left_part.type.raw_type
                right_raw = right_part.type.raw_type
                if left_raw in {set, frozenset} and right_raw in {set, frozenset}:
                    result_raw = set if left_raw is set else frozenset
                    element = join_all(
                        (
                            (
                                AbstractTypeValue.from_type(left_part.args[0])
                                if left_part.args
                                else AbstractTypeValue.from_type(ANY)
                            ),
                            (
                                AbstractTypeValue.from_type(right_part.args[0])
                                if right_part.args
                                else AbstractTypeValue.from_type(ANY)
                            ),
                        ),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    )
                    results.append(self._proper_instance(result_raw, element.public_type() or ANY))
                    continue
                if left_raw is dict and right_raw is dict:
                    parts = (left_part, right_part)
                    arguments = [
                        join_all(
                            (
                                AbstractTypeValue.from_type(
                                    part.args[position] if position < len(part.args) else ANY
                                )
                                for part in parts
                            ),
                            self.type_system,
                        ).public_type()
                        or ANY
                        for position in range(2)
                    ]
                    results.append(self._proper_instance(dict, *arguments))
                    continue
                if left_raw in {bool, int} and right_raw in {bool, int}:
                    results.append(
                        self._proper_instance(
                            bool if left_raw is bool and right_raw is bool else int
                        )
                    )
                    continue
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.type_system,
            max_union_size=self.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    def _mult_result(
        self,
        left: AbstractTypeValue,
        right: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Multiply all alternatives, preserving numeric and repetition results."""
        if self._contains_any(left) or self._contains_any(right):
            return AbstractTypeValue.from_type(ANY)
        numeric = {bool, int, float, complex}
        results: list[ProperType] = []
        unknown = left.unknown or right.unknown
        sequence_types = {str, bytes, bytearray, list}
        for left_part in self._flatten_union_parts(left):
            for right_part in self._flatten_union_parts(right):
                if (
                    isinstance(left_part, TupleType)
                    and isinstance(right_part, Instance)
                    and right_part.type.raw_type in {int, bool}
                ):
                    element = join_all(
                        (AbstractTypeValue.from_type(arg) for arg in left_part.args),
                        self.type_system,
                    )
                    results.append(TupleType((element.public_type() or ANY,), unknown_size=True))
                    continue
                if (
                    isinstance(right_part, TupleType)
                    and isinstance(left_part, Instance)
                    and left_part.type.raw_type in {int, bool}
                ):
                    element = join_all(
                        (AbstractTypeValue.from_type(arg) for arg in right_part.args),
                        self.type_system,
                    )
                    results.append(TupleType((element.public_type() or ANY,), unknown_size=True))
                    continue
                if (
                    isinstance(left_part, Instance)
                    and left_part.type.raw_type in sequence_types
                    and isinstance(right_part, Instance)
                    and right_part.type.raw_type in {int, bool}
                ):
                    results.append(left_part)
                    continue
                if (
                    isinstance(right_part, Instance)
                    and right_part.type.raw_type in sequence_types
                    and isinstance(left_part, Instance)
                    and left_part.type.raw_type in {int, bool}
                ):
                    results.append(right_part)
                    continue
                if (
                    isinstance(left_part, Instance)
                    and left_part.type.raw_type in numeric
                    and isinstance(right_part, Instance)
                    and right_part.type.raw_type in numeric
                ):
                    if left_part.type.raw_type is bool and right_part.type.raw_type is bool:
                        results.append(self._proper_instance(int))
                        continue
                    joined = self._numeric_join(
                        (
                            AbstractTypeValue.from_type(left_part),
                            AbstractTypeValue.from_type(right_part),
                        )
                    )
                    if joined.public_type() is not None:
                        results.append(joined.public_type())
                    else:
                        unknown = True
                    continue
                # An invalid alternative (for example ``str * float``) is not
                # part of the successful result, but must not be reported as a
                # concrete type.
                unknown = True
        if not results:
            return AbstractTypeValue.unresolved() if unknown else AbstractTypeValue.bottom()
        joined = join_all(
            (AbstractTypeValue.from_type(item) for item in results),
            self.type_system,
            max_union_size=self.options.max_union_size,
        )
        return replace(joined, unknown=joined.unknown or unknown)

    @staticmethod
    def _binary_protocol_names(operator: ast.operator) -> tuple[str | None, str | None]:
        methods = {
            ast.Add: ("__add__", "__radd__"),
            ast.Sub: ("__sub__", "__rsub__"),
            ast.Mult: ("__mul__", "__rmul__"),
            ast.MatMult: ("__matmul__", "__rmatmul__"),
            ast.Div: ("__truediv__", "__rtruediv__"),
            ast.FloorDiv: ("__floordiv__", "__rfloordiv__"),
            ast.Mod: ("__mod__", "__rmod__"),
            ast.Pow: ("__pow__", "__rpow__"),
            ast.LShift: ("__lshift__", "__rlshift__"),
            ast.RShift: ("__rshift__", "__rrshift__"),
            ast.BitOr: ("__or__", "__ror__"),
            ast.BitXor: ("__xor__", "__rxor__"),
            ast.BitAnd: ("__and__", "__rand__"),
        }
        return next(
            (names for kind, names in methods.items() if isinstance(operator, kind)),
            (None, None),
        )

    def _operator_result(
        self,
        node: ast.expr,
        left: AbstractTypeValue,
        right: AbstractTypeValue | None,
        methods: tuple[str | None, str | None],
        environment: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        results: list[AbstractTypeValue] = []
        direct, reflected = methods
        if direct is not None:
            attribute = ast.copy_location(
                ast.Attribute(value=node, attr=direct, ctx=ast.Load()), node
            )
            result = self._call_attribute(
                attribute,
                left,
                [] if right is None else [right],
                {},
                environment,
            )
            if result is not None:
                results.append(result)
        if reflected is not None and right is not None:
            attribute = ast.copy_location(
                ast.Attribute(value=node, attr=reflected, ctx=ast.Load()), node
            )
            result = self._call_attribute(
                attribute,
                right,
                [left],
                {},
                environment,
            )
            if result is not None:
                results.append(result)
        if not results:
            return None
        return join_all(
            results,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    @staticmethod
    def _comparison_protocol_names(
        operator: ast.cmpop,
    ) -> tuple[str | None, str | None]:
        methods = {
            ast.Eq: ("__eq__", "__eq__"),
            ast.NotEq: ("__ne__", "__ne__"),
            ast.Lt: ("__lt__", "__gt__"),
            ast.LtE: ("__le__", "__ge__"),
            ast.Gt: ("__gt__", "__lt__"),
            ast.GtE: ("__ge__", "__le__"),
        }
        return next(
            (names for kind, names in methods.items() if isinstance(operator, kind)),
            (None, None),
        )

    @staticmethod
    def _static_comparison_truth(
        left: ast.expr, operator_node: ast.cmpop, right: ast.expr
    ) -> bool | None:
        try:
            left_value = ast.literal_eval(left)
            right_value = ast.literal_eval(right)
        except (TypeError, ValueError):
            return None
        operations = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
            ast.Is: operator.is_,
            ast.IsNot: operator.is_not,
            ast.In: lambda left, right: operator.contains(right, left),
            ast.NotIn: lambda left, right: not operator.contains(right, left),
        }
        operation = next(
            (fn for kind, fn in operations.items() if isinstance(operator_node, kind)),
            None,
        )
        if operation is None:
            return None
        try:
            return bool(operation(left_value, right_value))
        except (TypeError, ValueError):
            return None

    def _comparison_result(
        self,
        node: ast.Compare,
        environment: dict[str, AbstractTypeValue],
        scope: str,
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue:
        left_node = node.left
        left = self._evaluate_expression(
            left_node,
            environment,
            scope=scope,
            current_function=current_function,
        )
        if self._is_never_value(left):
            return left
        results: list[AbstractTypeValue] = []
        last_index = len(node.ops) - 1
        for index, (operator_node, right_node) in enumerate(zip(node.ops, node.comparators)):
            right = self._evaluate_expression(
                right_node,
                environment,
                scope=scope,
                current_function=current_function,
            )
            if self._is_never_value(right):
                results.append(right)
                break
            if isinstance(operator_node, (ast.Is, ast.IsNot, ast.In, ast.NotIn)):
                pair = self._instance(bool)
            else:
                pair = self._operator_result(
                    node,
                    left,
                    right,
                    self._comparison_protocol_names(operator_node),
                    environment,
                ) or self._instance(bool)
            if index == last_index:
                results.append(pair)
                break
            truth = self._static_comparison_truth(left_node, operator_node, right_node)
            if truth is not True:
                results.append(pair)
            if truth is False:
                break
            left_node = right_node
            left = right
        return self._join_normal_results(results)

    def _pow_result(
        self,
        base: AbstractTypeValue,
        exponent: AbstractTypeValue,
    ) -> AbstractTypeValue:
        if self._contains_any(base) or self._contains_any(exponent):
            return AbstractTypeValue.from_type(ANY)
        if any(isinstance(part, Instance) and part.type.raw_type is complex for part in base.types):
            return self._instance(complex)
        if self._all_bool_values(base, exponent):
            return self._instance(int)
        negative_exponent = bool(exponent.literal_values) and all(
            isinstance(value, int) and value < 0 for value in exponent.literal_values
        )
        if negative_exponent:
            return self._instance(float)
        fractional_exponent = any(
            isinstance(value, float) and not value.is_integer() for value in exponent.literal_values
        )
        negative_base = any(
            isinstance(value, (int, float)) and not isinstance(value, bool) and value < 0
            for value in base.literal_values
        )
        if negative_base and fractional_exponent:
            return self._instance(complex)
        numeric = self._numeric_join((base, exponent))
        if numeric.public_type() is not None:
            return numeric
        return AbstractTypeValue.unresolved()

    @staticmethod
    def _all_bool_values(*values: AbstractTypeValue) -> bool:
        return all(
            value.types
            and all(
                isinstance(part, Instance) and part.type.raw_type is bool for part in value.types
            )
            for value in values
        )

    @staticmethod
    def _contains_any(value: AbstractTypeValue) -> bool:
        def contains(part: ProperType) -> bool:
            if isinstance(part, AnyType):
                return True
            if isinstance(part, UnionType):
                return any(contains(item) for item in part.items)
            return False

        return any(contains(part) for part in value.types)

    def _numeric_join(self, values: Iterable[AbstractTypeValue]) -> AbstractTypeValue:
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
            return self._narrow_environment(condition.operand, environment, truthy=not truthy)
        if isinstance(condition, ast.BoolOp):
            sequential = (isinstance(condition.op, ast.And) and truthy) or (
                isinstance(condition.op, ast.Or) and not truthy
            )
            if sequential:
                for expression in condition.values:
                    result = self._narrow_environment(expression, result, truthy=truthy)
                return result
            paths = []
            for expression in condition.values:
                paths.append(self._narrow_environment(expression, result, truthy=truthy))
                result = self._narrow_environment(expression, result, truthy=not truthy)
            return self._join_many_environments(paths)

        def key(expression):
            if isinstance(expression, ast.NamedExpr):
                expression = expression.target
            return (
                ast.unparse(expression)
                if isinstance(expression, (ast.Name, ast.Attribute, ast.Subscript))
                else None
            )

        def current(expression):
            name = key(expression)
            if name in result:
                return result[name]
            if isinstance(expression, ast.Attribute):
                return self._attribute_value(current(expression.value), expression.attr)
            if isinstance(expression, ast.Subscript):
                return self._subscript_value(current(expression.value), expression.slice)
            return AbstractTypeValue.unresolved()

        if isinstance(condition, ast.NamedExpr) and isinstance(condition.target, ast.Name):
            name = condition.target.id
            if name in result:
                result[name] = self._remove_none(result[name])
            return result
        if key(condition) is not None and truthy:
            result[key(condition)] = self._remove_none(current(condition))
            return result
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "isinstance"
            and len(condition.args) >= 2
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            narrowed = self._evaluate_type_expression(condition.args[1])
            if narrowed.unknown and isinstance(condition.args[1], ast.Name):
                # Local aliases such as ``_Segment = Segment`` are runtime
                # class objects, not annotation aliases.  A tuple of classes
                # (``expected = (str, bytes)``) narrows to the union of its
                # elements rather than to the tuple itself.
                runtime_alias = current(condition.args[1])
                runtime_types = self._runtime_isinstance_types(runtime_alias)
                if runtime_types is not None:
                    narrowed = runtime_types
            if not narrowed.unknown:
                if truthy:
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    if old.unknown or any(isinstance(part, AnyType) for part in alternatives):
                        result[key(expression)] = narrowed
                    else:
                        accepted = set()
                        for part in alternatives:
                            for expected in narrowed.types:
                                if self.type_system.is_subtype(part, expected):
                                    accepted.add(part)
                                elif self.type_system.is_subtype(expected, part):
                                    accepted.add(expected)
                        result[key(expression)] = AbstractTypeValue(types=frozenset(accepted))
                else:
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    result[key(expression)] = replace(
                        old,
                        types=frozenset(
                            part
                            for part in alternatives
                            if isinstance(part, AnyType)
                            or not any(
                                self.type_system.is_subtype(part, accepted)
                                for accepted in narrowed.types
                            )
                        ),
                    )
            return result
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], (ast.Is, ast.Eq))
        ):
            left, right = condition.left, condition.comparators[0]
            type_call = (
                left
                if isinstance(left, ast.Call)
                and isinstance(left.func, ast.Name)
                and left.func.id == "type"
                and len(left.args) == 1
                else (
                    right
                    if isinstance(right, ast.Call)
                    and isinstance(right.func, ast.Name)
                    and right.func.id == "type"
                    and len(right.args) == 1
                    else None
                )
            )
            expected_node = right if type_call is left else left
            if type_call is not None and key(type_call.args[0]) is not None:
                expected = self._evaluate_type_expression(expected_node)
                if not expected.unknown:
                    expression = type_call.args[0]
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    expected_raw = {
                        part.type.raw_type for part in expected.types if isinstance(part, Instance)
                    }
                    filtered = [
                        part
                        for part in alternatives
                        if (isinstance(part, Instance) and part.type.raw_type in expected_raw)
                        == truthy
                    ]
                    result[key(expression)] = AbstractTypeValue(
                        types=frozenset(filtered), unknown=old.unknown
                    )
                    return result
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], (ast.Is, ast.IsNot, ast.Eq, ast.NotEq))
        ):
            left, right = condition.left, condition.comparators[0]
            expression = (
                left
                if key(left) is not None and self._is_none_literal(right)
                else right if key(right) is not None and self._is_none_literal(left) else None
            )
            if expression is not None:
                keep_none = truthy == isinstance(condition.ops[0], (ast.Is, ast.Eq))
                old = current(expression)
                if keep_none:
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    possible = old.unknown or any(
                        isinstance(part, (NoneType, AnyType))
                        or isinstance(part, Instance)
                        and part.type.raw_type is object
                        for part in alternatives
                    )
                    result[key(expression)] = (
                        AbstractTypeValue.from_type(NONE_TYPE)
                        if possible
                        else AbstractTypeValue.bottom()
                    )
                else:
                    result[key(expression)] = self._remove_none(old)
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], (ast.Eq, ast.NotEq))
        ):
            left, right = condition.left, condition.comparators[0]
            expression = (
                left
                if key(left) is not None
                and isinstance(right, ast.Constant)
                and right.value is not None
                else (
                    right
                    if key(right) is not None
                    and isinstance(left, ast.Constant)
                    and left.value is not None
                    else None
                )
            )
            value_node = right if expression is left else left
            if expression is not None and isinstance(value_node, ast.Constant):
                value = value_node.value
                base = self._proper_instance(type(value))
                if isinstance(base, Instance):
                    old = current(expression)
                    literal = AbstractTypeValue.from_type(base, literal_values=frozenset((value,)))
                    old_literals = old.literal_values or frozenset(
                        part.value
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                        if isinstance(part, LiteralType)
                    )
                    equal_branch = truthy == isinstance(condition.ops[0], ast.Eq)
                    if equal_branch:
                        if old_literals:
                            possible = value in old_literals
                        else:
                            possible = old.unknown or any(
                                isinstance(part, AnyType)
                                or self.type_system.is_subtype(
                                    base,
                                    part.base if isinstance(part, LiteralType) else part,
                                )
                                for part in old.types
                            )
                        result[key(expression)] = (
                            literal if possible else AbstractTypeValue.bottom()
                        )
                    elif value in old_literals:
                        remaining = old_literals - {value}
                        if remaining:
                            result[key(expression)] = replace(
                                old, literal_values=frozenset(remaining)
                            )
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "hasattr"
            and len(condition.args) >= 2
            and isinstance(condition.args[1], ast.Constant)
            and isinstance(condition.args[1].value, str)
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            attribute = condition.args[1].value
            old = current(expression)
            alternatives = [
                part
                for typ in old.types
                for part in (typ.items if isinstance(typ, UnionType) else (typ,))
            ]
            if attribute == "__iter__":
                filtered = [part for part in alternatives if self._type_is_iterable(part) == truthy]
            else:
                filtered = [
                    part
                    for part in alternatives
                    if (
                        self._attribute_value(
                            AbstractTypeValue.from_type(part), attribute
                        ).public_type()
                        is not None
                    )
                    == truthy
                ]
            result[key(expression)] = AbstractTypeValue(
                types=frozenset(filtered), unknown=old.unknown
            )
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "callable"
            and len(condition.args) == 1
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            old = current(expression)
            alternatives = [
                part
                for typ in old.types
                for part in (typ.items if isinstance(typ, UnionType) else (typ,))
            ]
            filtered = [part for part in alternatives if self._type_is_callable(part) == truthy]
            result[key(expression)] = AbstractTypeValue(
                types=frozenset(filtered), unknown=old.unknown
            )
            return result
        if (
            isinstance(condition, ast.Call)
            and condition.args
            and key(condition.args[0]) is not None
        ):
            callee_name = self._qualified_callee_name(condition.func)
            function_info = self._functions.get(callee_name) if callee_name else None
            if function_info is None and isinstance(condition.func, ast.Name):
                function_info = self._functions.get(f"{self._module_name}.{condition.func.id}")
            if function_info is not None and function_info.type_guard_target is not None:
                guard_param, guard_type, is_type_is = function_info.type_guard_target
                expression = condition.args[0]
                if truthy:
                    result[key(expression)] = guard_type
                elif is_type_is:
                    old = current(expression)
                    alternatives = [
                        part
                        for typ in old.types
                        for part in (typ.items if isinstance(typ, UnionType) else (typ,))
                    ]
                    result[key(expression)] = replace(
                        old,
                        types=frozenset(
                            part
                            for part in alternatives
                            if not any(
                                self.type_system.is_subtype(part, accepted)
                                for accepted in guard_type.types
                            )
                        ),
                    )
        if (
            isinstance(condition, ast.Call)
            and isinstance(condition.func, ast.Name)
            and condition.func.id == "callable"
            and condition.args
            and key(condition.args[0]) is not None
        ):
            expression = condition.args[0]
            old = current(expression)
            alternatives = [
                part
                for typ in old.types
                for part in (typ.items if isinstance(typ, UnionType) else (typ,))
            ]
            if truthy:
                callable_parts: set[ProperType] = set()
                for part in alternatives:
                    if isinstance(part, (CallableType, TypeType, AnyType)):
                        callable_parts.add(part)
                    elif isinstance(part, Instance):
                        class_info = self._classes.get(part.type.full_name)
                        has_call = part.type.raw_type is type or "__call__" in part.type.members
                        if class_info is not None:
                            has_call = has_call or (
                                self._class_method(class_info.qualified_name, "__call__")
                                is not None
                            )
                        if has_call:
                            callable_parts.add(part)
                if old.unknown and not callable_parts:
                    callable_parts.add(CallableType(None, ANY))
                result[key(expression)] = AbstractTypeValue(
                    types=frozenset(callable_parts), unknown=old.unknown
                )
            else:
                non_callable_parts: set[ProperType] = set()
                for part in alternatives:
                    is_call = isinstance(part, (CallableType, TypeType))
                    if isinstance(part, Instance):
                        class_info = self._classes.get(part.type.full_name)
                        has_call = part.type.raw_type is type or "__call__" in part.type.members
                        if class_info is not None:
                            has_call = has_call or (
                                self._class_method(class_info.qualified_name, "__call__")
                                is not None
                            )
                        is_call = is_call or has_call
                    if not is_call:
                        non_callable_parts.add(part)
                result[key(expression)] = replace(old, types=frozenset(non_callable_parts))
        if (
            isinstance(condition, ast.Compare)
            and len(condition.ops) == 1
            and isinstance(condition.ops[0], ast.In)
            and truthy
            and key(condition.left) is not None
        ):
            allowed = self._membership_element_types(condition.comparators[0], current)
            if allowed is not None:
                result[key(condition.left)] = self._narrow_to_allowed(
                    current(condition.left), allowed
                )
        return result

    def _type_is_iterable(self, typ: ProperType) -> bool:
        if isinstance(typ, TupleType) or isinstance(typ, AnyType):
            return True
        if not isinstance(typ, Instance):
            return False
        raw = typ.type.raw_type
        if raw in {
            str,
            bytes,
            bytearray,
            list,
            set,
            frozenset,
            dict,
            tuple,
            range,
            cabc.Iterable,
            cabc.Iterator,
            cabc.Generator,
            cabc.Sequence,
            cabc.Mapping,
        }:
            return True
        if "__iter__" in typ.type.members:
            return True
        info = self._classes.get(typ.type.full_name)
        return bool(
            info is not None and self._class_method(info.qualified_name, "__iter__") is not None
        )

    def _type_is_callable(self, typ: ProperType) -> bool:
        if isinstance(typ, (AnyType, CallableType, TypeType)):
            return True
        if not isinstance(typ, Instance):
            return False
        if typ.type.raw_type is type:
            return True
        if "__call__" in typ.type.members:
            return True
        info = self._classes.get(typ.type.full_name)
        return bool(
            info is not None and self._class_method(info.qualified_name, "__call__") is not None
        )

    def _membership_element_types(
        self,
        container: ast.expr,
        current: Callable[[ast.expr], AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        """Return the element type of a literal membership container."""
        elements: list[ast.expr] | None = None
        if isinstance(container, (ast.Set, ast.List, ast.Tuple)):
            elements = list(container.elts)
        elif isinstance(container, ast.Constant) and isinstance(container.value, (str, bytes)):
            elements = [container]
        elif (
            isinstance(container, ast.Call)
            and isinstance(container.func, ast.Name)
            and container.func.id in {"set", "frozenset"}
            and container.args
        ):
            return self._membership_element_types(container.args[0], current)
        if elements is None:
            return None
        values: list[AbstractTypeValue] = []
        for element in elements:
            if isinstance(element, ast.Constant):
                values.append(
                    AbstractTypeValue.from_type(
                        NONE_TYPE
                        if element.value is None
                        else self._proper_instance(type(element.value))
                    )
                )
            else:
                values.append(current(element))
        if any(value.unknown for value in values):
            return None
        return join_all(
            values,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    def _value_may_match(
        self,
        old: AbstractTypeValue,
        expected: AbstractTypeValue,
    ) -> bool:
        if old.literal_values and expected.literal_values:
            return bool(old.literal_values & expected.literal_values)
        for left in old.types:
            for right in expected.types:
                if self.type_system.is_subtype(left, right) or self.type_system.is_subtype(
                    right, left
                ):
                    return True
        return old.unknown or expected.unknown

    def _runtime_isinstance_types(self, value: AbstractTypeValue) -> AbstractTypeValue | None:
        """Convert runtime class objects supplied to ``isinstance`` into types."""
        normalized: list[AbstractTypeValue] = []

        def add(typ: ProperType) -> bool:
            if isinstance(typ, TypeType):
                normalized.append(AbstractTypeValue.from_type(typ.item))
                return True
            if isinstance(typ, TupleType):
                return all(add(item) for item in typ.args)
            if isinstance(typ, UnionType):
                return all(add(item) for item in typ.items)
            if isinstance(typ, Instance):
                if typ.type.raw_type in {tuple, list, set, frozenset} and typ.args:
                    return all(add(item) for item in typ.args)
                # Class objects are also represented as instances in some
                # specialized call environments (``cls`` in classmethods).
                normalized.append(AbstractTypeValue.from_type(typ))
                return True
            return False

        if value.unknown or not value.types:
            return None
        if not all(add(typ) for typ in value.types):
            return None
        return join_all(
            normalized,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    def _narrow_to_allowed(
        self,
        old: AbstractTypeValue,
        allowed: AbstractTypeValue,
    ) -> AbstractTypeValue:
        allowed_parts = [
            part
            for typ in allowed.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        if not allowed_parts:
            return old
        alternatives = [
            part
            for typ in old.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        if not alternatives:
            return (
                AbstractTypeValue(types=frozenset(allowed_parts), unknown=True)
                if old.unknown
                else old
            )
        accepted: set[ProperType] = set()
        for part in alternatives:
            for candidate in allowed_parts:
                if self.type_system.is_subtype(part, candidate):
                    accepted.add(part)
                elif self.type_system.is_subtype(candidate, part):
                    accepted.add(candidate)
        return AbstractTypeValue(
            types=frozenset(accepted),
            unknown=old.unknown,
        )

    def _class_pattern_fields(
        self, class_type: AbstractTypeValue
    ) -> tuple[dict[str, AbstractTypeValue], list[str]]:
        """Return field types and positional ``__match_args__`` order."""
        fields: dict[str, AbstractTypeValue] = {}
        order: list[str] = []
        for typ in class_type.types:
            if not isinstance(typ, Instance):
                continue
            info = self._classes.get(typ.type.full_name)
            if info is not None:
                for name, value in info.attributes.items():
                    if name not in fields:
                        fields[name] = value
                        order.append(name)
            for name, value in typ.type.members.items():
                if name.startswith("_") or name in fields:
                    continue
                fields[name] = AbstractTypeValue.from_type(value)
                order.append(name)
        return fields, order

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
                old = result.get(subject_node.id, subject)
                result[subject_node.id] = self._narrow_to_allowed(old, narrowed)
            fields, field_order = self._class_pattern_fields(narrowed)
            dummy = ast.Constant(value=None)
            for index, child in enumerate(pattern.patterns):
                field_name = field_order[index] if index < len(field_order) else None
                child_value = (
                    fields[field_name] if field_name is not None else AbstractTypeValue.unresolved()
                )
                result = self._narrow_pattern(
                    child,
                    dummy,
                    child_value,
                    result,
                    current_function,
                )
            for attribute, child in zip(pattern.kwd_attrs, pattern.kwd_patterns):
                result = self._narrow_pattern(
                    child,
                    dummy,
                    fields.get(attribute, AbstractTypeValue.unresolved()),
                    result,
                    current_function,
                )
        elif isinstance(pattern, ast.MatchValue):
            scope = (
                current_function.qualified_name
                if current_function is not None
                else self._module_name
            )
            val = self._evaluate_expression(
                pattern.value, result, scope=scope, current_function=current_function
            )
            if isinstance(subject_node, ast.Name) and not val.unknown:
                old = result.get(subject_node.id, subject)
                if self._value_may_match(old, val):
                    result[subject_node.id] = val
                else:
                    result[subject_node.id] = AbstractTypeValue.bottom()
        elif isinstance(pattern, ast.MatchAs):
            scope = (
                current_function.qualified_name
                if current_function is not None
                else self._module_name
            )
            bound_value = subject
            if pattern.pattern is not None:
                result = self._narrow_pattern(
                    pattern.pattern,
                    subject_node,
                    subject,
                    result,
                    current_function,
                )
                if isinstance(subject_node, ast.Name) and subject_node.id in result:
                    bound_value = result[subject_node.id]
                elif isinstance(pattern.pattern, ast.MatchClass):
                    narrowed = self._evaluate_type_expression(pattern.pattern.cls)
                    if not narrowed.unknown:
                        bound_value = narrowed
                elif isinstance(pattern.pattern, ast.MatchValue):
                    val = self._evaluate_expression(
                        pattern.pattern.value,
                        result,
                        scope=scope,
                        current_function=current_function,
                    )
                    if not val.unknown:
                        bound_value = val
                elif isinstance(pattern.pattern, ast.MatchSingleton):
                    if pattern.pattern.value is None:
                        bound_value = AbstractTypeValue.from_type(NONE_TYPE)
                    elif isinstance(pattern.pattern.value, bool):
                        bound_value = self._instance(bool)
            if pattern.name is not None:
                result[pattern.name] = bound_value
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name is not None:
                element = self._iterable_element(subject)
                result[pattern.name] = self._instance(list, element.public_type() or ANY)
        elif isinstance(pattern, ast.MatchSequence):
            star_index = next(
                (
                    index
                    for index, child in enumerate(pattern.patterns)
                    if isinstance(child, ast.MatchStar)
                ),
                None,
            )
            if star_index is None:
                unpacked = self._unpack_value(subject, len(pattern.patterns))
                for child, child_value in zip(pattern.patterns, unpacked):
                    result = self._narrow_pattern(
                        child,
                        subject_node,
                        child_value,
                        result,
                        current_function,
                    )
            else:
                tuple_args: list[ProperType] = []
                if len(subject.types) == 1:
                    only = next(iter(subject.types))
                    if isinstance(only, TupleType) and not only.unknown_size:
                        tuple_args = list(only.args)
                element = self._iterable_element(subject)
                for index, child in enumerate(pattern.patterns):
                    if isinstance(child, ast.MatchStar):
                        child_value = self._instance(list, element.public_type() or ANY)
                    elif tuple_args:
                        child_value = AbstractTypeValue.from_type(
                            tuple_args[min(index, len(tuple_args) - 1)]
                        )
                    else:
                        child_value = element
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

    @staticmethod
    def _is_empty_dict_value(value: AbstractTypeValue) -> bool:
        return bool(value.types) and all(
            isinstance(candidate, Instance)
            and candidate.type.raw_type is dict
            and len(candidate.args) >= 2
            and isinstance(candidate.args[0], NeverType)
            and isinstance(candidate.args[1], NeverType)
            for candidate in value.types
        )

    def _runtime_value_type(self, value: AbstractTypeValue) -> ProperType:
        """Proper type for a runtime value, keeping class-object alternatives.

        ``public_type()`` flattens a runtime class object to its instance type.
        Containers built from class objects (dict keyword values, variadic
        argument tuples) must retain ``type[...]`` so they are checked against
        class-object annotations instead of instances.
        """
        typ = value.public_type() or ANY

        def wrap(item: ProperType) -> ProperType:
            return TypeType(item) if isinstance(item, Instance) else item

        if not value.class_targets:
            return typ
        if isinstance(typ, Instance):
            return TypeType(typ)
        if isinstance(typ, UnionType):
            return UnionType(tuple(wrap(item) for item in typ.items))
        return typ

    def _is_type_variable_annotation(self, node, type_variables=None) -> bool:
        """Whether *node* is a bare type-variable reference."""
        if not isinstance(node, ast.Name):
            return False
        variables = self._type_vars if type_variables is None else type_variables
        return node.id in variables

    def _is_substituted_type_variable_annotation(
        self, node, value: AbstractTypeValue, type_variables=None
    ) -> bool:
        """A bare type-variable annotation analyzed under a concrete substitution.

        Base-class methods are analyzed for each subclass specialization.  A
        body that is not genuinely parameterized (for example one reading a
        concrete class attribute) must not be checked against an arbitrary
        subclass type argument.
        """
        if not self._is_type_variable_annotation(node, type_variables):
            return False
        return not isinstance(value.public_type(), TypeVarType)

    def _check_annotation_compatibility(
        self,
        inferred: AbstractTypeValue,
        annotated: AbstractTypeValue,
        node: ast.AST,
        *,
        context: str,
    ) -> None:
        expected = annotated.public_type()
        if (
            expected is None
            or not inferred.types
            or annotated.unknown
            or self._has_unresolved_annotation(expected)
            or self._contains_type_var(expected)
        ):
            return
        inspected_node = (
            node.value
            if isinstance(node, (ast.AnnAssign, ast.Assign, ast.Return)) and node.value is not None
            else node
        )
        expected_parts = expected.items if isinstance(expected, UnionType) else (expected,)
        if self._is_empty_dict_value(inferred):
            if any(
                isinstance(part, Instance)
                and part.type.raw_type in {dict, cabc.Mapping, cabc.MutableMapping}
                for part in expected_parts
            ):
                return
        constructor = (
            _expression_name(inspected_node.func)
            if isinstance(inspected_node, ast.Call) and isinstance(inspected_node.func, ast.Name)
            else None
        )
        if constructor in {"list", "set", "frozenset", "dict"}:
            # Contextual typing for fresh container constructors: the literal
            # is checked against the expected element type, not invariantly.
            for part in expected_parts:
                if not isinstance(part, Instance):
                    continue
                if constructor == "dict":
                    if part.type.raw_type not in {dict, cabc.Mapping, cabc.MutableMapping}:
                        continue
                    if len(part.args) < 2:
                        return
                    actuals = [
                        typ
                        for typ in inferred.types
                        if isinstance(typ, Instance)
                        and typ.type.raw_type is dict
                        and len(typ.args) >= 2
                    ]
                    if actuals and all(
                        self.type_system.is_subtype(self._proper_instance(str), part.args[0])
                        and self.type_system.is_subtype(typ.args[1], part.args[1])
                        for typ in actuals
                    ):
                        return
                else:
                    raw = {"list": list, "set": set, "frozenset": frozenset}[constructor]
                    if part.type.raw_type is not raw:
                        continue
                    if not part.args:
                        return
                    actuals = [
                        typ
                        for typ in inferred.types
                        if isinstance(typ, Instance) and typ.type.raw_type is raw and typ.args
                    ]
                    if actuals and all(
                        self.type_system.is_subtype(typ.args[0], part.args[0]) for typ in actuals
                    ):
                        return
        expected_literals = self._literal_expected_values(expected)
        if expected_literals is not None and inferred.literal_values:
            if inferred.literal_values.issubset(expected_literals):
                return
            self._add_diagnostic(
                "annotation-mismatch",
                f"Inferred {sorted(map(self._format_literal_value, inferred.literal_values))} "
                f"is incompatible with annotated {expected} for {context}",
                node=node,
                severity="error" if self.options.strict_annotations else "warning",
            )
            return
        if expected_literals is not None:
            # Without literal evidence for the inferred value, we cannot prove
            # that it violates the literal constraint.
            return
        if isinstance(expected, Instance) and expected.type.typed_dict_fields is not None:
            if (
                inferred.types
                and not inferred.dict_shapes
                and all(
                    isinstance(candidate, Instance)
                    and candidate.type.raw_type is dict
                    and len(candidate.args) >= 2
                    and isinstance(candidate.args[0], NeverType)
                    and isinstance(candidate.args[1], NeverType)
                    for candidate in inferred.types
                )
            ):
                missing = expected.type.required_keys
                if missing:
                    self._add_diagnostic(
                        "annotation-mismatch",
                        f"TypedDict {expected} has missing keys {sorted(missing)} "
                        "and unexpected keys []",
                        node=node,
                        severity="error" if self.options.strict_annotations else "warning",
                    )
                return
            if inferred.dict_shapes and all(
                isinstance(candidate, Instance) and candidate.type.raw_type is dict
                for candidate in inferred.types
            ):
                fields = expected.type.typed_dict_fields
                literal_nodes: dict[str, ast.expr] = {}
                if isinstance(inspected_node, ast.Dict):
                    for key, value in zip(inspected_node.keys, inspected_node.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            literal_nodes[key.value] = value
                for shape in inferred.dict_shapes:
                    actual = dict(shape)
                    missing = expected.type.required_keys - actual.keys()
                    extra = actual.keys() - fields.keys()
                    if missing or extra:
                        self._add_diagnostic(
                            "annotation-mismatch",
                            f"TypedDict {expected} has missing keys {sorted(missing)} "
                            f"and unexpected keys {sorted(extra)}",
                            node=node,
                            severity="error" if self.options.strict_annotations else "warning",
                        )
                    for name in actual.keys() & fields.keys():
                        actual_value = AbstractTypeValue.from_type(actual[name])
                        child = literal_nodes.get(name)
                        if isinstance(child, ast.Constant):
                            actual_value = AbstractTypeValue.from_type(
                                actual[name], literal_values=frozenset((child.value,))
                            )
                        self._check_annotation_compatibility(
                            actual_value,
                            AbstractTypeValue.from_type(fields[name]),
                            child or node,
                            context=f"TypedDict key {name}",
                        )
                return
        if self._expected_contains_literal(expected):
            self._check_literal_container_elements(expected, inspected_node, context)
            return
        if (
            isinstance(expected, Instance)
            and len(inferred.types) > 1
            and expected.args
            and all(
                isinstance(candidate, Instance)
                and candidate.type == expected.type
                and len(candidate.args) == len(expected.args)
                and all(
                    self.type_system.is_subtype(actual, wanted)
                    for actual, wanted in zip(candidate.args, expected.args)
                )
                for candidate in inferred.types
            )
        ):
            # A flow join of alternative container branches is compatible
            # with the corresponding joined element annotation.
            return
        if isinstance(expected, Instance) and expected.args and inferred.element_dict_shapes:
            element_expected = expected.args[0]
            if (
                isinstance(element_expected, Instance)
                and element_expected.type.typed_dict_fields is not None
            ):
                fields = element_expected.type.typed_dict_fields
                for shape in inferred.element_dict_shapes:
                    actual = dict(shape)
                    missing = element_expected.type.required_keys - actual.keys()
                    extra = actual.keys() - fields.keys()
                    if missing or extra:
                        self._add_diagnostic(
                            "annotation-mismatch",
                            f"TypedDict {element_expected} has missing keys {sorted(missing)} "
                            f"and unexpected keys {sorted(extra)}",
                            node=node,
                            severity="error" if self.options.strict_annotations else "warning",
                        )
                    for name in actual.keys() & fields.keys():
                        self._check_annotation_compatibility(
                            AbstractTypeValue.from_type(actual[name]),
                            AbstractTypeValue.from_type(fields[name]),
                            node,
                            context=f"TypedDict key {name}",
                        )
                return
        incompatible = []
        for candidate in inferred.types:
            if self._has_unresolved_annotation(candidate) or self._contains_type_var(candidate):
                continue
            if (
                isinstance(candidate, Instance)
                and isinstance(expected, Instance)
                and candidate.type == expected.type
                and not candidate.args
                and expected.args
            ):
                candidate = Instance(candidate.type, (ANY,) * len(expected.args))
            if (
                isinstance(candidate, Instance)
                and isinstance(expected, Instance)
                and candidate.type == expected.type
                and not expected.args
                and candidate.args
            ):
                expected = Instance(expected.type, (ANY,) * len(candidate.args))
            if isinstance(candidate, UnionType) and isinstance(expected, Instance):
                container_items = candidate.items
                if all(
                    isinstance(item, Instance)
                    and item.type == expected.type
                    and len(item.args) == len(expected.args)
                    and all(
                        self.type_system.is_subtype(actual, wanted)
                        for actual, wanted in zip(item.args, expected.args)
                    )
                    for item in container_items
                ):
                    candidate = expected
            expected_parts = expected.items if isinstance(expected, UnionType) else (expected,)
            if (
                isinstance(candidate, Instance)
                and not candidate.args
                and any(
                    isinstance(part, Instance) and candidate.type == part.type and part.args
                    for part in expected_parts
                )
            ):
                target_part = next(
                    part
                    for part in expected_parts
                    if isinstance(part, Instance) and candidate.type == part.type and part.args
                )
                candidate = Instance(candidate.type, (ANY,) * len(target_part.args))
            if isinstance(candidate, Instance) and any(
                isinstance(part, Instance) and candidate.type == part.type and not part.args
                for part in expected_parts
            ):
                continue
            if (
                isinstance(candidate, Instance)
                and inferred.class_targets
                and any(
                    isinstance(part, (TypeType, CallableType))
                    or (isinstance(part, Instance) and part.type.raw_type in {type, cabc.Callable})
                    for part in expected_parts
                )
            ):
                candidate = TypeType(candidate)
            try:
                compatible = (
                    isinstance(candidate, Instance)
                    and isinstance(expected, Instance)
                    and self._generic_arguments_compatible(candidate, expected)
                ) or self.type_system.is_subtype(candidate, expected)
                if not compatible and self._fresh_collection_context(node):
                    expected_parts = (
                        expected.items if isinstance(expected, UnionType) else (expected,)
                    )
                    compatible = any(
                        isinstance(candidate, Instance)
                        and isinstance(part, Instance)
                        and candidate.type.raw_type is part.type.raw_type
                        and candidate.type.raw_type in {list, set, frozenset, dict}
                        and candidate.args
                        and len(candidate.args) == len(part.args)
                        and all(
                            self.type_system.is_subtype(actual, wanted)
                            for actual, wanted in zip(candidate.args, part.args)
                        )
                        for part in expected_parts
                    )
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

    def _generic_arguments_compatible(
        self,
        candidate: Instance,
        expected: Instance,
    ) -> bool:
        """Compare invariant generic arguments, treating bare containers as Any-like."""
        if candidate.type != expected.type or not candidate.args or not expected.args:
            return False
        if len(candidate.args) != len(expected.args):
            return False
        for actual, wanted in zip(candidate.args, expected.args):
            if isinstance(actual, NeverType):
                continue
            if isinstance(actual, Instance) and isinstance(wanted, Instance):
                if actual.type == wanted.type and (not actual.args or not wanted.args):
                    continue
                if actual.type == wanted.type and self._generic_arguments_compatible(
                    actual, wanted
                ):
                    continue
            if isinstance(actual, TupleType) and isinstance(wanted, TupleType):
                if wanted.unknown_size and wanted.args == (ANY,):
                    continue
                if actual.unknown_size and actual.args == (ANY,):
                    continue
            if not (
                self.type_system.is_subtype(actual, wanted)
                and self.type_system.is_subtype(wanted, actual)
            ):
                return False
        return True

    @staticmethod
    def _format_literal_value(value: object) -> str:
        if isinstance(value, tuple) and len(value) == 3 and value[0] == "enum":
            return f"{value[1]}.{value[2]}"
        return repr(value)

    @staticmethod
    def _expected_contains_literal(expected: ProperType) -> bool:
        if isinstance(expected, LiteralType):
            return True
        if isinstance(expected, UnionType):
            return any(
                StaticTypeInferenceEngine._expected_contains_literal(item)
                for item in expected.items
            )
        if isinstance(expected, TupleType):
            return any(
                StaticTypeInferenceEngine._expected_contains_literal(item) for item in expected.args
            )
        if isinstance(expected, Instance):
            return any(
                StaticTypeInferenceEngine._expected_contains_literal(item) for item in expected.args
            )
        return False

    def _check_literal_container_elements(
        self,
        expected: ProperType,
        node: ast.AST | None,
        context: str,
    ) -> None:
        if node is None:
            return
        if isinstance(expected, Instance):
            raw = expected.type.raw_type
            if (
                raw in {list, set, frozenset}
                and expected.args
                and isinstance(node, (ast.List, ast.Set, ast.Tuple))
            ):
                for element in node.elts:
                    if isinstance(element, ast.Constant):
                        self._check_annotation_compatibility(
                            self._literal_constant_value(element.value),
                            AbstractTypeValue.from_type(expected.args[0]),
                            element,
                            context=f"{context} element",
                        )
                return
            if raw is dict and len(expected.args) >= 2 and isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant):
                        self._check_annotation_compatibility(
                            self._literal_constant_value(key.value),
                            AbstractTypeValue.from_type(expected.args[0]),
                            key,
                            context=f"{context} key",
                        )
                    if isinstance(value, ast.Constant):
                        self._check_annotation_compatibility(
                            self._literal_constant_value(value.value),
                            AbstractTypeValue.from_type(expected.args[1]),
                            value,
                            context=f"{context} value",
                        )
                return
        if isinstance(expected, TupleType) and isinstance(node, ast.Tuple):
            for actual, wanted, element in zip(node.elts, expected.args, node.elts):
                if isinstance(actual, ast.Constant):
                    self._check_annotation_compatibility(
                        self._literal_constant_value(actual.value),
                        AbstractTypeValue.from_type(wanted),
                        element,
                        context=f"{context} element",
                    )

    def _literal_constant_value(self, value: object) -> AbstractTypeValue:
        base = NONE_TYPE if value is None else self._proper_instance(type(value))
        return AbstractTypeValue.from_type(base, literal_values=frozenset((value,)))

    @staticmethod
    def _literal_expected_values(expected: ProperType) -> frozenset[object] | None:
        if isinstance(expected, LiteralType):
            return frozenset((expected.value,))
        if isinstance(expected, UnionType):
            values: set[object] = set()
            saw_literal = False
            for item in expected.items:
                if isinstance(item, LiteralType):
                    values.add(item.value)
                    saw_literal = True
                elif isinstance(item, NoneType):
                    values.add(None)
                else:
                    # A non-literal alternative may accept values that are not
                    # represented by the literal subset.
                    return None
            return frozenset(values) if saw_literal else None
        return None

    @staticmethod
    def _fresh_collection_context(node):
        def fresh(expression):
            if isinstance(
                expression, (ast.List, ast.Set, ast.Dict, ast.ListComp, ast.SetComp, ast.DictComp)
            ):
                return True
            return (
                isinstance(expression, ast.BinOp)
                and isinstance(expression.op, (ast.Add, ast.Mult))
                and (fresh(expression.left) or fresh(expression.right))
            ) or (
                isinstance(expression, ast.IfExp)
                and fresh(expression.body)
                and fresh(expression.orelse)
            )

        # Call arguments and other bare expressions are checked against the
        # argument node itself rather than an enclosing statement.
        if fresh(node):
            return True
        if isinstance(node, (ast.Return, ast.AnnAssign, ast.Assign)):
            return fresh(node.value)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        returns = []

        def collect(statement):
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                return
            if isinstance(statement, ast.Return):
                returns.append(statement.value)
            for child in ast.iter_child_nodes(statement):
                collect(child)

        for statement in node.body:
            collect(statement)
        return bool(returns) and all(
            fresh(value) or value is None or isinstance(value, ast.Constant) and value.value is None
            for value in returns
        )

    @staticmethod
    def _call_argument_node(node, function, name):
        if not isinstance(node, ast.Call):
            return None
        arguments = function.node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        if function.owner is not None and function.method_kind != "static" and positional:
            # The receiver is already bound and is not present in node.args.
            positional = positional[1:]
        if name in {argument.arg for argument in positional}:
            index = next(i for i, argument in enumerate(positional) if argument.arg == name)
            return node.args[index] if index < len(node.args) else None
        return next(
            (keyword.value for keyword in node.keywords if keyword.arg == name),
            None,
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
        if scope != self._module_name:
            module_value = self._module_environment.get(name)
            if module_value is not None:
                return module_value
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
            external = BuiltinTypeLookup()(imported)
            builtin_class = external is not None
            if external is None:
                external = self._external_type(imported)
            if isinstance(external, TypeType):
                # External class facts are exposed as the runtime type
                # ``type[T]``.  Internally a class object is represented by
                # ``T`` plus a class target so calls can construct ``T``.
                external = external.item
            return AbstractTypeValue.from_type(
                external,
                unknown=external is None,
                class_target=self._external_class_target(
                    external,
                    imported.rsplit(".", 1)[-1],
                    builtin_class=builtin_class,
                ),
            )
        builtin = getattr(builtins, name, None)
        if isinstance(builtin, type):
            return AbstractTypeValue.from_type(
                self._proper_instance(builtin), class_target=f"builtins.{name}"
            )
        return AbstractTypeValue.unresolved()

    _ENUM_KIND_NAMES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}

    def _enum_base_kind(self, base: str, seen: set[str] | None = None) -> str | None:
        """Return the enum base kind for a direct or inherited enum base."""
        short = base.rsplit(".", 1)[-1]
        if short in self._ENUM_KIND_NAMES:
            return short
        seen = set() if seen is None else seen
        if base in seen:
            return None
        seen.add(base)
        info = self._classes.get(base)
        if info is None:
            alias = self._class_aliases.get(short)
            if alias is not None:
                info = self._classes.get(alias)
        if info is None:
            descriptor = self.type_system.class_descriptor(base)
            if descriptor is not None and descriptor.enum_kind is not None:
                return descriptor.enum_kind
            return None
        for parent in info.bases:
            kind = self._enum_base_kind(parent, seen)
            if kind is not None:
                return kind
        return None

    def _is_enum_class_info(self, info: _ClassInfo | None) -> bool:
        return info is not None and any(
            self._enum_base_kind(base) is not None for base in info.bases
        )

    def _mro_names(self, class_name: str) -> list[str]:
        """Approximate C3 linearization over classes known to this engine."""
        if class_name in self._mro_cache:
            return list(self._mro_cache[class_name])
        info = self._classes.get(class_name)
        if info is None:
            return [class_name]
        bases = [base for base in info.bases if base in self._classes]
        if not bases:
            result = [class_name]
        else:
            sequences = [self._mro_names(base) for base in bases] + [list(bases)]
            result = [class_name]
            while sequences:
                for sequence in sequences:
                    head = sequence[0]
                    if not any(head in other[1:] for other in sequences):
                        break
                else:
                    result.extend(base for base in bases if base not in result)
                    break
                result.append(head)
                for sequence in sequences:
                    if sequence and sequence[0] == head:
                        sequence.pop(0)
                sequences = [sequence for sequence in sequences if sequence]
        self._mro_cache[class_name] = result
        return list(result)

    def _super_value(
        self,
        node: ast.Call,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> AbstractTypeValue | None:
        if current_function is None or current_function.owner is None:
            return None
        owner = current_function.owner
        receiver_class: str | None = None
        if current_function.parameter_names:
            receiver = environment.get(current_function.parameter_names[0])
            if receiver is not None:
                for typ in receiver.types:
                    if isinstance(typ, Instance):
                        receiver_class = typ.type.full_name
                        break
        mro = self._mro_names(receiver_class or owner)
        if owner in mro:
            for candidate in mro[mro.index(owner) + 1 :]:
                info = self._classes.get(candidate)
                if info is not None:
                    return AbstractTypeValue.from_type(info.instance)
        info = self._classes.get(owner)
        if info is not None:
            for base in info.bases:
                base_info = self._classes.get(base)
                if base_info is not None:
                    return AbstractTypeValue.from_type(base_info.instance)
            for superclass in self.type_system.get_superclasses(info.instance.type):
                if superclass.full_name in {info.instance.type.full_name, "builtins.object"}:
                    continue
                return AbstractTypeValue.from_type(Instance(superclass))
        return None

    def _external_class_target(
        self,
        external: ProperType | None,
        name: str,
        *,
        builtin_class: bool = False,
    ) -> str | None:
        """Return the defining class name when an external symbol is a class."""
        if not isinstance(external, Instance):
            return None
        if not builtin_class and not self._looks_like_class(name):
            return None
        raw = external.type.raw_type
        module = getattr(raw, "__module__", "")
        if not builtin_class and module in {"builtins", "typing", "typing_extensions"}:
            return None
        # The external value is a class object only if the requested member is
        # the class itself, not an enum member or other uppercase attribute.
        if external.type.full_name.rsplit(".", 1)[-1] != name:
            aliased = _STDLIB_CLASS_ALIASES.get(name)
            if aliased is None or external.type.full_name != aliased:
                return None
        return external.type.full_name

    def _name_is_shadowed(
        self,
        name: str,
        environment: dict[str, AbstractTypeValue],
        scope: str,
    ) -> bool:
        """Whether a bare name resolves locally rather than to a builtin."""
        if name in environment:
            return True
        if self._resolve_lexical_function(name, scope) is not None:
            return True
        if self._class_aliases.get(name) is not None:
            return True
        return self._resolve_import_name(name) is not None

    def _refresh_effective_returns(self) -> None:
        """Recompute decorator results after all class methods are known."""
        for function in self._functions.values():
            decorators = getattr(function.node, "decorator_list", ())
            if not decorators:
                continue
            computed = self._decorator_effective_return(
                function.node,
                function.qualified_name.rpartition(".")[0],
            )
            if computed is not None:
                function.effective_return = computed
            extras = self._decorator_extra_keywords(
                function.node,
                function.qualified_name.rpartition(".")[0],
            )
            if extras:
                function.extra_keywords.update(extras)

    def _decorator_extra_keywords(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent: str,
    ) -> dict[str, AbstractTypeValue]:
        """Collect keyword-only parameters added by a decorator wrapper."""
        original = {argument.arg for argument in _all_arguments(node.args)}
        extras: dict[str, AbstractTypeValue] = {}
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = self._qualified_callee_name(target)
            if name is None:
                continue
            local = self._resolve_lexical_function(name, parent)
            if local is None:
                local = self._resolve_lexical_function(name.rsplit(".", 1)[-1], parent)
            if local is None:
                candidate = f"{parent}.{name}"
                if candidate in self._functions:
                    local = candidate
            if local is None:
                continue
            for wrapper in self._functions.values():
                if not wrapper.qualified_name.startswith(f"{local}."):
                    continue
                if not isinstance(wrapper.node, ast.FunctionDef):
                    continue
                short = wrapper.qualified_name.rsplit(".", 1)[-1]
                if short not in {"wrapper", "inner", "decorated"}:
                    continue
                arguments = wrapper.node.args
                if arguments.vararg is None and arguments.kwarg is None:
                    continue
                for argument in arguments.kwonlyargs:
                    if argument.arg in original:
                        continue
                    annotation = (
                        self._annotation_value(argument.annotation)
                        if argument.annotation is not None
                        else AbstractTypeValue.unresolved()
                    )
                    extras.setdefault(argument.arg, annotation)
        return extras

    def _decorator_effective_return(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, parent: str
    ) -> AbstractTypeValue | None:
        """Return the decorated callable's result type for simple decorators."""
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            func_expr = call.func if call is not None else decorator
            name = self._qualified_callee_name(func_expr)
            if name is None:
                continue
            local = self._resolve_lexical_function(name, parent)
            if local is None:
                local = self._resolve_lexical_function(name.rsplit(".", 1)[-1], parent)
            decorator_type: ProperType | None
            if local is not None:
                decorator_type = self._function_value(self._functions[local]).public_type()
            else:
                imported = self._resolve_import_name(name) or name
                decorator_type = self._external_type(imported)
            if not isinstance(decorator_type, CallableType):
                # A callable class decorator (``@Deco``) replaces the
                # decorated function with an instance.  The call result is
                # the return type of that class's ``__call__`` method.
                if call is None:
                    class_name = self._class_aliases.get(name) or self._class_aliases.get(
                        name.rsplit(".", 1)[-1]
                    )
                    call_method = (
                        self._class_method(class_name, "__call__")
                        if class_name is not None
                        else None
                    )
                    if call_method is not None:
                        signature = self._function_value(self._functions[call_method]).public_type()
                        if (
                            isinstance(signature, CallableType)
                            and signature.return_type is not None
                            and not self._contains_type_var(signature.return_type)
                        ):
                            return AbstractTypeValue.from_type(signature.return_type)
                    member = None
                    if isinstance(decorator_type, TypeType) and isinstance(
                        decorator_type.item, Instance
                    ):
                        member = decorator_type.item.type.members.get("__call__")
                    elif isinstance(decorator_type, Instance):
                        member = decorator_type.type.members.get("__call__")
                    if (
                        isinstance(member, CallableType)
                        and member.return_type is not None
                        and not self._contains_type_var(member.return_type)
                    ):
                        return AbstractTypeValue.from_type(member.return_type)
                continue
            value: ProperType = decorator_type.return_type
            unwraps = 2 if call is not None else 1
            for _ in range(unwraps):
                if not isinstance(value, CallableType):
                    value = None  # type: ignore[assignment]
                    break
                value = value.return_type
            if value is not None and not self._contains_type_var(value):
                return AbstractTypeValue.from_type(value)
        return None

    def _function_value(self, function: _FunctionInfo) -> AbstractTypeValue:
        parameters: list[ProperType] = []
        for name in function.parameter_names:
            explicit = function.explicit_parameters.get(name)
            evidence = function.parameter_evidence.get(name)
            parameter = explicit or evidence or function.documented_parameters.get(name)
            parameter_type = None if parameter is None else parameter.public_type()
            parameters.append(parameter_type or ANY)
        if function.effective_return is not None:
            returns = function.effective_return.public_type() or ANY
        elif function.explicit_return is not None:
            returns = function.explicit_return.public_type() or ANY
        elif function.summary is not None:
            returns = function.summary.return_type or ANY
        elif function.documented_return is not None:
            returns = function.documented_return.public_type() or ANY
        else:
            returns = ANY
        generator = function.is_generator_source or (
            function.summary is not None and function.summary.is_generator
        )
        if generator and function.effective_return is None:
            yield_value = (
                function.summary.yield_value
                if function.summary is not None
                else AbstractTypeValue.unresolved()
            )
            element = (
                yield_value.public_type()
                if yield_value is not None and not yield_value.is_bottom
                else None
            ) or ANY
            decorators = {
                self._qualified_callee_name(decorator)
                for decorator in getattr(function.node, "decorator_list", ())
            }
            if "contextlib.contextmanager" in decorators:
                returns = self._proper_instance(contextlib.AbstractContextManager, element)
            elif "contextlib.asynccontextmanager" in decorators:
                returns = self._proper_instance(contextlib.AbstractAsyncContextManager, element)
            elif not (
                isinstance(returns, Instance)
                and returns.type.raw_type
                in {
                    cabc.Generator,
                    cabc.AsyncGenerator,
                    cabc.Iterator,
                    cabc.AsyncIterator,
                    cabc.Iterable,
                    cabc.AsyncIterable,
                }
            ):
                if isinstance(function.node, ast.AsyncFunctionDef):
                    returns = self._proper_instance(cabc.AsyncGenerator, element, ANY)
                else:
                    returns = self._proper_instance(cabc.Generator, element, ANY, NONE_TYPE)
        if isinstance(function.node, ast.AsyncFunctionDef) and not generator:
            if not (isinstance(returns, Instance) and returns.type.raw_type is cabc.Coroutine):
                returns = self._proper_instance(cabc.Coroutine, ANY, ANY, returns)
        arguments = getattr(function.node, "args", None)
        if arguments is not None and (
            arguments.vararg is not None or arguments.kwarg is not None or arguments.kwonlyargs
        ):
            # ``Callable[[...], R]`` cannot encode *args, **kwargs, or
            # keyword-only parameters.  Ellipsis is the honest projection.
            parameters = None
        return AbstractTypeValue.from_type(
            CallableType(None if parameters is None else tuple(parameters), returns),
            callable_target=function.qualified_name,
        )

    def _check_call_arity(
        self,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        target: str,
        node: ast.AST | None,
    ) -> None:
        arguments_node = function.node.args
        positional = [*arguments_node.posonlyargs, *arguments_node.args]
        if (
            not self._call_unknown_positional
            and arguments_node.vararg is None
            and len(arguments) > len(positional)
        ):
            self._add_diagnostic(
                "call-arity-mismatch",
                f"Too many positional arguments for {target}",
                node=node or function.node,
                severity="warning",
            )
        bound = self._bind_call_arguments(function, arguments, keywords)
        missing = self._required_parameter_names(function) - bound.keys()
        if missing and not (self._call_unknown_positional or self._call_unknown_keywords):
            self._add_diagnostic(
                "call-arity-mismatch",
                f"Missing required arguments for {target}: {sorted(missing)}",
                node=node or function.node,
                severity="warning",
            )
        positional_only = {argument.arg for argument in arguments_node.posonlyargs}
        known = {argument.arg for argument in (*positional, *arguments_node.kwonlyargs)}
        known.update(function.extra_keywords)
        for name in keywords:
            if name in positional_only:
                self._add_diagnostic(
                    "call-arity-mismatch",
                    f"Positional-only argument {name!r} passed by keyword to {target}",
                    node=node or function.node,
                    severity="warning",
                )
            elif (
                name not in known
                and arguments_node.kwarg is None
                and not self._call_unknown_keywords
            ):
                self._add_diagnostic(
                    "call-arity-mismatch",
                    f"Unexpected keyword argument {name!r} for {target}",
                    node=node or function.node,
                    severity="warning",
                )

    def _apply_function(
        self,
        target: str,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        *,
        node: ast.AST | None = None,
    ) -> AbstractTypeValue:
        function = self._functions.get(target)
        if function is None:
            external = self._external_type(target)
            if isinstance(external, CallableType):
                return AbstractTypeValue.from_type(external.return_type)
            return AbstractTypeValue.unresolved()
        selected = self._select_overload(function, arguments, keywords)
        if selected is not None:
            return self._apply_overload(target, selected, arguments, keywords, node)
        self._last_argument_mutations = []
        self._check_call_arity(function, arguments, keywords, target, node)
        bound_arguments = self._bind_call_arguments(function, arguments, keywords)
        substitutions = self._generic_substitutions(function, bound_arguments)
        for name, annotated in function.explicit_parameters.items():
            actual = bound_arguments.get(name)
            if actual is None:
                continue
            if function.node.args.vararg and name == function.node.args.vararg.arg:
                actual = self._iterable_element(actual)
            elif function.node.args.kwarg and name == function.node.args.kwarg.arg:
                actual = join_all(
                    (
                        AbstractTypeValue.from_type(typ.args[1])
                        for typ in actual.types
                        if isinstance(typ, Instance) and len(typ.args) > 1
                    ),
                    self.type_system,
                )
            expected = annotated.public_type()
            if expected is not None:
                for variable in collect_type_vars(expected):
                    actual_type = substitutions.get(variable.name)
                    constraint = variable.bound or (
                        UnionType(variable.constraints) if variable.constraints else None
                    )
                    if actual_type is not None and constraint is not None:
                        self._check_annotation_compatibility(
                            AbstractTypeValue.from_type(actual_type),
                            AbstractTypeValue.from_type(constraint),
                            node or function.node,
                            context=f"type variable {variable.name} of {target}",
                        )
            if expected is not None and substitutions:
                annotated = AbstractTypeValue.from_type(
                    substitute_type_vars(expected, substitutions)
                )
            argument_node = self._call_argument_node(node, function, name)
            self._check_annotation_compatibility(
                actual,
                annotated,
                argument_node or node or function.node,
                context=f"argument {name} of {target}",
            )
        for name, value in bound_arguments.items():
            self._queue_parameter_evidence(target, name, value)
        if self._collect_specializations:
            specialization = self._register_specialization(function, bound_arguments)
        else:
            key, _ = self._specialization_key(function, bound_arguments)
            specialization = function.specializations.get(key)
        if specialization is not None and function.owner is None and isinstance(node, ast.Call):
            for name, final in specialization.mutated_parameters:
                argument_node = self._call_argument_node(node, function, name)
                if argument_node is not None:
                    self._last_argument_mutations.append((argument_node, final))
        if (
            function.explicit_return is None
            and function.summary is not None
            and len(function.summary.return_dependencies) == 1
        ):
            dependency = next(iter(function.summary.return_dependencies))
            if dependency in bound_arguments:
                return self._wrap_call_result(function, bound_arguments[dependency])
        if function.effective_return is not None:
            returned = function.effective_return.public_type() or ANY
            if substitutions:
                returned = substitute_type_vars(returned, substitutions)
            return self._wrap_call_result(function, AbstractTypeValue.from_type(returned))
        if function.explicit_return is not None:
            substitutions = self._generic_substitutions(function, bound_arguments)
            returned = function.explicit_return.public_type()
            if returned is not None and substitutions:
                returned = substitute_type_vars(returned, substitutions)
                return self._wrap_call_result(function, AbstractTypeValue.from_type(returned))
            return self._wrap_call_result(function, function.explicit_return)
        if specialization is not None:
            return self._wrap_call_result(
                function,
                specialization.return_value,
                yield_value=specialization.yield_value,
            )
        if function.summary is not None:
            return self._wrap_call_result(function, function.summary.return_value)
        if function.documented_return is not None:
            return self._wrap_call_result(function, function.documented_return)
        return AbstractTypeValue.unresolved()

    def _select_overload(
        self,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> _FunctionInfo | None:
        for overload in function.overloads:
            arguments_node = overload.node.args
            positional = [*arguments_node.posonlyargs, *arguments_node.args]
            positional_only = {argument.arg for argument in arguments_node.posonlyargs}
            accepted_keywords = {
                argument.arg
                for argument in (
                    *arguments_node.posonlyargs,
                    *arguments_node.args,
                    *arguments_node.kwonlyargs,
                )
            }
            if arguments_node.kwarg is None and any(
                name not in accepted_keywords for name in keywords
            ):
                continue
            if any(name in positional_only for name in keywords):
                continue
            if arguments_node.vararg is None and len(arguments) > len(positional):
                continue
            bound = self._bind_call_arguments(overload, arguments, keywords)
            if any(name not in bound for name in self._required_parameter_names(overload)):
                continue
            accepted = True
            for name, annotated in overload.explicit_parameters.items():
                actual = bound.get(name)
                if actual is None or actual.unknown:
                    continue
                expected = annotated.public_type()
                actual_type = actual.public_type()
                if expected is None or actual_type is None:
                    continue
                if self.type_system.is_subtype(
                    actual_type, expected
                ) or self.type_system.is_maybe_subtype(actual_type, expected):
                    continue
                expected_literals = self._literal_expected_values(expected)
                if (
                    expected_literals is not None
                    and actual.literal_values
                    and actual.literal_values.issubset(expected_literals)
                ):
                    continue
                accepted = False
                break
            if accepted:
                return overload
        return None

    @staticmethod
    def _required_parameter_names(function: _FunctionInfo) -> set[str]:
        arguments = function.node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        required = positional[: -len(arguments.defaults)] if arguments.defaults else positional
        names = {argument.arg for argument in required}
        names.update(
            argument.arg
            for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults)
            if default is None
        )
        return names

    def _select_callable_overload(
        self,
        callable_type: CallableType,
        arguments: list[AbstractTypeValue],
    ) -> CallableType | None:
        if not callable_type.overloads:
            return None
        for overload in callable_type.overloads:
            if overload.arg_types is None:
                return overload
            if len(arguments) > len(overload.arg_types):
                continue
            accepted = True
            for actual, expected in zip(arguments, overload.arg_types):
                actual_type = actual.public_type()
                if actual_type is None or actual.unknown:
                    continue
                if self._is_unresolved_external_type(expected):
                    continue
                if self.type_system.is_subtype(
                    actual_type, expected
                ) or self.type_system.is_maybe_subtype(actual_type, expected):
                    continue
                expected_literals = self._literal_expected_values(expected)
                if (
                    expected_literals is not None
                    and actual.literal_values
                    and actual.literal_values.issubset(expected_literals)
                ):
                    continue
                accepted = False
                break
            if accepted:
                return overload
        return None

    @staticmethod
    def _is_unresolved_external_type(typ: ProperType) -> bool:
        if isinstance(typ, Instance):
            if getattr(typ.type.raw_type, "__pyflow_unresolved_external__", False):
                return True
            if typ.type.full_name.startswith(("_typeshed.", "typing._SpecialForm")):
                return True
            return any(
                StaticTypeInferenceEngine._is_unresolved_external_type(item) for item in typ.args
            )
        if isinstance(typ, (UnionType, TupleType)):
            return any(
                StaticTypeInferenceEngine._is_unresolved_external_type(item)
                for item in (typ.items if isinstance(typ, UnionType) else typ.args)
            )
        return False

    def _apply_overload(
        self,
        target: str,
        overload: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.AST | None,
    ) -> AbstractTypeValue:
        self._check_call_arity(overload, arguments, keywords, target, node)
        bound = self._bind_call_arguments(overload, arguments, keywords)
        substitutions = self._generic_substitutions(overload, bound)
        for name, annotated in overload.explicit_parameters.items():
            actual = bound.get(name)
            expected = annotated.public_type()
            if actual is None or expected is None:
                continue
            if substitutions:
                expected = substitute_type_vars(expected, substitutions)
            self._check_annotation_compatibility(
                actual,
                AbstractTypeValue.from_type(expected),
                node or overload.node,
                context=f"argument {name} of {target}",
            )
        for name, value in bound.items():
            self._queue_parameter_evidence(target, name, value)
        returned = (
            overload.explicit_return
            or overload.effective_return
            or overload.documented_return
            or AbstractTypeValue.unresolved()
        )
        returned_type = returned.public_type()
        if returned_type is not None and substitutions:
            returned_type = substitute_type_vars(returned_type, substitutions)
            returned = AbstractTypeValue.from_type(returned_type)
        return self._wrap_call_result(overload, returned)

    def _wrap_call_result(
        self,
        function: _FunctionInfo,
        returned: AbstractTypeValue,
        *,
        yield_value: AbstractTypeValue | None = None,
    ) -> AbstractTypeValue:
        if function.effective_return is not None:
            return function.effective_return
        summary = function.summary
        effective_yield = yield_value
        if effective_yield is None and summary is not None and summary.is_generator:
            effective_yield = summary.yield_value
        if effective_yield is not None and not effective_yield.is_bottom:
            element = effective_yield.public_type() or ANY
            decorators = {
                self._qualified_callee_name(decorator)
                for decorator in getattr(function.node, "decorator_list", ())
            }
            if "contextlib.contextmanager" in decorators:
                return self._instance(contextlib.AbstractContextManager, element)
            if "contextlib.asynccontextmanager" in decorators:
                return self._instance(contextlib.AbstractAsyncContextManager, element)
            for returned_type in returned.types:
                if isinstance(returned_type, Instance) and returned_type.type.raw_type in {
                    cabc.Generator,
                    cabc.AsyncGenerator,
                }:
                    # Preserve the explicit Generator[Y, S, R] annotation;
                    # rebuilding Iterator[Y] would lose ``send`` and return
                    # types that callers may rely on.
                    return returned
            if isinstance(function.node, ast.AsyncFunctionDef):
                return self._instance(cabc.AsyncGenerator, element, ANY)
            return self._instance(cabc.Generator, element, ANY, NONE_TYPE)
        if isinstance(function.node, ast.AsyncFunctionDef):
            result = returned.public_type() or ANY
            return self._instance(cabc.Coroutine, ANY, ANY, result)
        return returned

    def _specialization_key(
        self,
        function: _FunctionInfo,
        bound_arguments: dict[str, AbstractTypeValue],
    ) -> tuple[_SpecializationKey, dict[str, AbstractTypeValue]]:
        parameters = self._call_context_parameters(function, bound_arguments)
        key = _SpecializationKey(
            tuple((name, parameters[name]) for name in function.parameter_names)
        )
        return key, parameters

    def _register_specialization(
        self,
        function: _FunctionInfo,
        bound_arguments: dict[str, AbstractTypeValue],
    ) -> FunctionSpecialization:
        key, parameters = self._specialization_key(function, bound_arguments)
        existing = function.specializations.get(key)
        if existing is not None:
            return existing

        normal_count = sum(not candidate.widened for candidate in function.specializations)
        if normal_count < self.options.max_specializations_per_function:
            specialization = FunctionSpecialization(
                parameters=key.parameters,
                return_value=AbstractTypeValue.bottom(),
            )
            function.specializations[key] = specialization
            return specialization

        widened_key = _SpecializationKey(widened=True)
        for name, value in parameters.items():
            previous_value = function.widened_parameters.get(name, AbstractTypeValue.bottom())
            function.widened_parameters[name] = self._join(previous_value, value)
        widened_parameters = tuple(
            (name, function.widened_parameters[name]) for name in function.parameter_names
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
            elif function.owner is not None and function.method_kind != "static" and index == 0:
                parameters[name] = AbstractTypeValue.from_type(
                    self._classes[function.owner].instance,
                    class_target=function.owner if function.method_kind == "class" else None,
                )
            else:
                explicit = function.explicit_parameters.get(name)
                if explicit is not None:
                    parameters[name] = explicit
                else:
                    default = function.default_parameters.get(name)
                    if default is not None:
                        parameters[name] = self._evaluate_expression(
                            default,
                            self._module_environment,
                            scope=function.qualified_name,
                            current_function=None,
                        )
                    else:
                        parameters[name] = function.documented_parameters.get(
                            name, AbstractTypeValue.unresolved()
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
            types=frozenset(typ for typ in value.types if not isinstance(typ, CallableType)),
            unknown=value.unknown,
            callable_targets=value.callable_targets,
            class_targets=value.class_targets,
            dict_shapes=value.dict_shapes,
        )

    def _bind_call_arguments(
        self,
        function: _FunctionInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> dict[str, AbstractTypeValue]:
        node_arguments = function.node.args
        positional_names = [arg.arg for arg in (*node_arguments.posonlyargs, *node_arguments.args)]
        positional_only = {arg.arg for arg in node_arguments.posonlyargs}
        keyword_only = {arg.arg for arg in node_arguments.kwonlyargs}
        bound: dict[str, AbstractTypeValue] = {}

        for index, value in enumerate(arguments[: len(positional_names)]):
            bound[positional_names[index]] = value

        extra_positional = arguments[len(positional_names) :]
        if node_arguments.vararg is not None and extra_positional:
            element = join_all(
                (
                    AbstractTypeValue.from_type(self._runtime_value_type(value))
                    for value in extra_positional
                ),
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            element_type = element.public_type() or ANY
            bound[node_arguments.vararg.arg] = AbstractTypeValue.from_type(
                TupleType((element_type,), unknown_size=True)
            )

        unmatched_keywords: list[AbstractTypeValue] = []
        for name, value in keywords.items():
            if name in function.extra_keywords:
                continue
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
        if self._call_unknown_positional or self._call_unknown_keywords:
            for name in self._required_parameter_names(function):
                if name in bound:
                    continue
                if name in keyword_only:
                    if self._call_unknown_keywords:
                        bound[name] = AbstractTypeValue.unresolved()
                elif name in positional_names:
                    if self._call_unknown_positional or self._call_unknown_keywords:
                        bound[name] = AbstractTypeValue.unresolved()
        if (
            self._call_unknown_positional
            and node_arguments.vararg is not None
            and node_arguments.vararg.arg not in bound
        ):
            bound[node_arguments.vararg.arg] = AbstractTypeValue.from_type(
                TupleType((ANY,), unknown_size=True)
            )
        if (
            self._call_unknown_keywords
            and node_arguments.kwarg is not None
            and node_arguments.kwarg.arg not in bound
        ):
            bound[node_arguments.kwarg.arg] = self._instance(dict, self._proper_instance(str), ANY)
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
        mutated: set[str] = set()
        saw_return = False
        invalid = False

        def visit(node: ast.AST, *, root: bool = False) -> None:
            nonlocal saw_return, invalid
            if invalid:
                return
            if not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if node.id in function.parameter_names:
                    mutated.add(node.id)
            elif (
                isinstance(node, ast.ExceptHandler)
                and node.name is not None
                and node.name in function.parameter_names
            ):
                mutated.add(node.name)
            if isinstance(node, ast.Return):
                saw_return = True
                if isinstance(node.value, ast.Name) and node.value.id in function.parameter_names:
                    dependencies.add(node.value.id)
                else:
                    invalid = True
                return
            for child in ast.iter_child_nodes(node):
                visit(child)

        visit(function.node, root=True)
        if not saw_return or invalid:
            return frozenset()
        # A parameter that is reassigned or mutated no longer carries its
        # call-site type through to the return value.
        return frozenset(dependencies - mutated)

    def _generic_constructor_args(
        self,
        class_info: _ClassInfo,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
    ) -> tuple[ProperType, ...] | None:
        """Infer generics for dataclass/NamedTuple constructors without __init__."""
        if class_info.instance.type.tuple_fields is not None:
            field_names = list(class_info.instance.type.tuple_fields)
        else:
            field_names = [name for name in class_info.attributes if not name.startswith("_")]
        substitutions: dict[str, ProperType] = {}
        fixed: set[str] = set()
        for name, value in zip(field_names, arguments):
            annotation = class_info.attributes.get(name)
            formal = None if annotation is None else annotation.public_type()
            actual = value.public_type()
            if formal is not None and actual is not None:
                self._match_type_variables(formal, actual, substitutions, fixed)
        for name, value in keywords.items():
            annotation = class_info.attributes.get(name)
            formal = None if annotation is None else annotation.public_type()
            actual = value.public_type()
            if formal is not None and actual is not None:
                self._match_type_variables(formal, actual, substitutions, fixed)
        if not class_info.type_variables:
            return None
        if not substitutions:
            return tuple(ANY for _ in class_info.type_variables)
        return tuple(substitutions.get(name, ANY) for name in class_info.type_variables)

    def _generic_substitutions(
        self,
        function: _FunctionInfo,
        actuals: dict[str, AbstractTypeValue],
    ) -> dict[str, ProperType]:
        substitutions: dict[str, ProperType] = {}
        fixed: set[str] = set()
        if function.owner and function.method_kind != "static" and function.parameter_names:
            receiver = actuals.get(function.parameter_names[0])
            if receiver is not None:
                substitutions["Self"] = (
                    receiver.public_type() or self._classes[function.owner].instance
                )
                for typ in receiver.types:
                    if isinstance(typ, Instance):
                        receiver_info = self._classes.get(typ.type.full_name)
                        if receiver_info is not None:
                            if (
                                function.owner != typ.type.full_name
                                and getattr(function.node, "name", "") != "__init__"
                            ):
                                substitutions.update(receiver_info.type_var_bindings)
                            for k, v in receiver_info.type_var_bindings.items():
                                if not isinstance(v, TypeVarType):
                                    substitutions[k] = v
                                    fixed.add(k)
                        for parameter, argument in zip(typ.type.type_parameters, typ.args):
                            self._match_type_variables(parameter, argument, substitutions, fixed)
        vararg_name = (
            function.node.args.vararg.arg if function.node.args.vararg is not None else None
        )
        kwarg_name = function.node.args.kwarg.arg if function.node.args.kwarg is not None else None
        for name, formal_value in function.explicit_parameters.items():
            formal = formal_value.public_type()
            actual = actuals.get(name)
            if formal is None or actual is None:
                continue
            if name == vararg_name:
                # ``*args: T`` binds T from each element, not from the tuple.
                actual = self._iterable_element(actual)
            elif name == kwarg_name:
                actual = join_all(
                    (
                        AbstractTypeValue.from_type(typ.args[1])
                        for typ in actual.types
                        if isinstance(typ, Instance) and len(typ.args) > 1
                    ),
                    self.type_system,
                )
            actual_type = actual.public_type()
            if (
                actual_type is not None
                and isinstance(formal, TypeType)
                and actual.class_targets
                and isinstance(actual_type, Instance)
            ):
                # Class objects are represented internally as Instance +
                # class_targets; ``type[T]`` matching needs the explicit form.
                actual_type = TypeType(actual_type)
            if actual_type is not None:
                self._match_type_variables(formal, actual_type, substitutions, fixed)
        if substitutions:
            chained = {}
            for k, v in substitutions.items():
                chained[k] = substitute_type_vars(v, substitutions)
            return chained
        return substitutions

    def _match_type_variables(
        self,
        formal: ProperType,
        actual: ProperType,
        substitutions: dict[str, ProperType],
        fixed: set[str] | None = None,
    ) -> None:
        fixed = fixed or set()
        if isinstance(formal, TypeVarType):
            if formal.name in fixed:
                return
            existing = substitutions.get(formal.name)
            if existing is None or isinstance(existing, TypeVarType):
                substitutions[formal.name] = actual
            else:
                joined = self._join(
                    AbstractTypeValue.from_type(existing),
                    AbstractTypeValue.from_type(actual),
                ).public_type()
                if joined is not None:
                    substitutions[formal.name] = joined
            return
        if isinstance(formal, UnionType):
            for item in formal.items:
                if isinstance(item, TypeVarType):
                    self._match_type_variables(item, actual, substitutions, fixed)
                elif item == actual or self.type_system.is_subtype(actual, item):
                    self._match_type_variables(item, actual, substitutions, fixed)
            return
        if isinstance(formal, TypeType) and isinstance(actual, TypeType):
            self._match_type_variables(formal.item, actual.item, substitutions, fixed)
            return
        if isinstance(formal, CallableType) and isinstance(actual, CallableType):
            if formal.return_type is not None and actual.return_type is not None:
                self._match_type_variables(
                    formal.return_type, actual.return_type, substitutions, fixed
                )
            if formal.arg_types is not None and actual.arg_types is not None:
                for formal_arg, actual_arg in zip(formal.arg_types, actual.arg_types):
                    self._match_type_variables(formal_arg, actual_arg, substitutions, fixed)
            return
        if isinstance(formal, Instance) and isinstance(actual, Instance):
            if formal.type.raw_type is actual.type.raw_type:
                for formal_arg, actual_arg in zip(formal.args, actual.args):
                    self._match_type_variables(formal_arg, actual_arg, substitutions, fixed)
                return

            # A TypeVar may appear under an abstract container annotation while
            # the call supplies a concrete container (``Sequence[T]`` versus
            # ``list[int]``).  Project the concrete type parameters onto the
            # abstract shape instead of requiring identical raw classes.
            target = formal.type.raw_type
            iterable_targets = {
                cabc.Iterable,
                cabc.Iterator,
                cabc.Collection,
                cabc.Sequence,
                cabc.Reversible,
                cabc.Container,
                cabc.Set,
                cabc.AsyncIterable,
                cabc.AsyncIterator,
            }
            mapping_targets = {cabc.Mapping, cabc.MutableMapping}
            if target in iterable_targets and formal.args:
                raw = actual.type.raw_type
                if raw is dict and actual.args:
                    element = actual.args[0]
                elif raw is str:
                    element = self._proper_instance(str)
                elif raw is bytes:
                    element = self._proper_instance(int)
                elif raw is range:
                    element = self._proper_instance(int)
                else:
                    element = actual.args[0] if actual.args else ANY
                self._match_type_variables(formal.args[0], element, substitutions, fixed)
            elif target in mapping_targets and len(formal.args) >= 2:
                if actual.type.raw_type is dict and len(actual.args) >= 2:
                    self._match_type_variables(formal.args[0], actual.args[0], substitutions, fixed)
                    self._match_type_variables(formal.args[1], actual.args[1], substitutions, fixed)
        elif isinstance(formal, TupleType) and isinstance(actual, TupleType):
            for formal_arg, actual_arg in zip(formal.args, actual.args):
                self._match_type_variables(formal_arg, actual_arg, substitutions, fixed)

    def _queue_parameter_evidence(
        self, target: str, parameter: str, value: AbstractTypeValue
    ) -> None:
        if not value.types and not value.callable_targets and not value.class_targets:
            return
        key = (target, parameter)
        old = self._pending_parameter_evidence.get(key, AbstractTypeValue.bottom())
        self._pending_parameter_evidence[key] = self._join(old, value)

    def _attribute_value(self, base: AbstractTypeValue, attribute: str) -> AbstractTypeValue:
        if self._contains_any(base):
            return AbstractTypeValue.from_type(ANY)
        values: list[AbstractTypeValue] = []
        for typ in base.types:
            if attribute == "__class__":
                values.append(AbstractTypeValue.from_type(TypeType(typ)))
                continue
            class_object = (
                typ.item
                if isinstance(typ, TypeType) and isinstance(typ.item, Instance)
                else typ if isinstance(typ, Instance) and base.class_targets else None
            )
            if class_object is not None:
                nested_name = f"{class_object.type.full_name}.{attribute}"
                nested = self._classes.get(nested_name)
                if nested is not None:
                    values.append(
                        AbstractTypeValue.from_type(
                            nested.instance, class_target=nested.qualified_name
                        )
                    )
                    continue
            if isinstance(typ, UnionType):
                values.extend(
                    self._attribute_value(AbstractTypeValue.from_type(item), attribute)
                    for item in typ.items
                )
                continue
            if not isinstance(typ, Instance):
                continue
            class_info = self._classes.get(typ.type.full_name)
            if self._is_enum_class_info(class_info):
                if attribute in class_info.enum_values:
                    values.append(
                        AbstractTypeValue.from_type(
                            class_info.instance,
                            literal_values=frozenset(
                                (("enum", class_info.qualified_name, attribute),)
                            ),
                        )
                    )
                    continue
                if attribute == "name":
                    return self._instance(str)
                if attribute == "value":
                    enum_values = list(class_info.enum_values.values())
                    return (
                        join_all(
                            enum_values,
                            self.type_system,
                            max_union_size=self.options.max_union_size,
                        )
                        if enum_values
                        else AbstractTypeValue.from_type(ANY)
                    )
            if class_info is not None:
                if attribute == "__members__" and self._is_enum_class_info(class_info):
                    values.append(self._instance(dict, self._proper_instance(str), typ))
                    continue
                if class_info.instance.type.tuple_fields is not None:
                    if attribute in {"_fields", "__match_args__"}:
                        values.append(
                            AbstractTypeValue.from_type(
                                TupleType((self._proper_instance(str),), unknown_size=True)
                            )
                        )
                        continue
                    if attribute == "_field_defaults":
                        values.append(self._instance(dict, self._proper_instance(str), ANY))
                        continue
                getter = self._class_property(class_info.qualified_name, attribute)
                if getter is not None:
                    function = self._functions[getter]
                    values.append(
                        function.explicit_return
                        or (
                            function.summary.return_value
                            if function.summary
                            else AbstractTypeValue.unresolved()
                        )
                    )
                    continue
                has_known_attribute = False
                member = self._class_attribute(class_info.qualified_name, attribute)
                if member is not None:
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    substitutions.update(class_info.type_var_bindings)
                    if substitutions:
                        member = replace(
                            member,
                            types=frozenset(
                                substitute_type_vars(item, substitutions) for item in member.types
                            ),
                        )
                    descriptor_values: list[AbstractTypeValue] = []
                    for member_type in member.types:
                        if not isinstance(member_type, Instance):
                            continue
                        descriptor = self._class_method(member_type.type.full_name, "__get__")
                        if descriptor is None:
                            continue
                        descriptor_values.append(
                            self._apply_function(
                                descriptor,
                                [
                                    member,
                                    base,
                                    AbstractTypeValue.from_type(TypeType(typ)),
                                ],
                                {},
                            )
                        )
                    if descriptor_values:
                        values.extend(descriptor_values)
                    else:
                        values.append(member)
                    has_known_attribute = True
                method = self._class_method(class_info.qualified_name, attribute)
                if method is not None:
                    values.append(self._bound_method_value(self._functions[method], base))
                    has_known_attribute = True
                if not has_known_attribute:
                    dynamic_getter = self._class_method(class_info.qualified_name, "__getattr__")
                    key = (class_info.qualified_name, attribute)
                    if dynamic_getter is not None and key not in self._resolving_attributes:
                        self._resolving_attributes.add(key)
                        try:
                            values.append(
                                self._apply_function(
                                    dynamic_getter,
                                    [base, self._instance(str)],
                                    {},
                                )
                            )
                        finally:
                            self._resolving_attributes.remove(key)
            else:
                if typ.type.raw_type is subprocess.CompletedProcess:
                    text = typ.args[0] if typ.args else ANY
                    if attribute in {"stdout", "stderr"}:
                        values.append(
                            self._join(
                                AbstractTypeValue.from_type(text),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                    if attribute == "returncode":
                        values.append(self._instance(int))
                        continue
                if typ.type.raw_type is subprocess.Popen:
                    if attribute == "returncode":
                        values.append(
                            self._join(
                                AbstractTypeValue.from_type(self._proper_instance(int)),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                    if attribute == "pid":
                        values.append(self._instance(int))
                        continue
                    if attribute in {"stdout", "stderr", "stdin"}:
                        values.append(
                            self._join(
                                AbstractTypeValue.from_type(self._proper_instance(io.IOBase)),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if typ.type.raw_type is logging.Logger:
                    if attribute == "name":
                        values.append(self._instance(str))
                        continue
                    if attribute == "level":
                        values.append(self._instance(int))
                        continue
                if typ.type.raw_type is threading.Thread:
                    if attribute == "name":
                        values.append(self._instance(str))
                        continue
                    if attribute == "daemon":
                        values.append(self._instance(bool))
                        continue
                    if attribute in {"ident", "native_id"}:
                        values.append(
                            self._join(
                                AbstractTypeValue.from_type(self._proper_instance(int)),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if isinstance(typ.type.raw_type, type) and issubclass(typ.type.raw_type, io.IOBase):
                    if attribute == "name":
                        values.append(self._instance(str))
                        continue
                    if attribute == "mode":
                        values.append(self._instance(str))
                        continue
                    if attribute == "encoding":
                        values.append(
                            self._join(
                                AbstractTypeValue.from_type(self._proper_instance(str)),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if typ.type.raw_type in {
                    asyncio.Lock,
                    asyncio.Event,
                    asyncio.Semaphore,
                    asyncio.BoundedSemaphore,
                }:
                    if attribute == "__aenter__":
                        values.append(self._instance(cabc.Coroutine, ANY, ANY, typ))
                        continue
                    if attribute == "__aexit__":
                        values.append(AbstractTypeValue.from_type(NONE_TYPE))
                        continue
                if typ.type.raw_type is contextvars.ContextVar and attribute == "name":
                    values.append(self._instance(str))
                    continue
                if typ.type.raw_type is re.Pattern:
                    text = typ.args[0] if typ.args else ANY
                    if attribute == "pattern":
                        values.append(AbstractTypeValue.from_type(text))
                        continue
                    if attribute in {"flags", "groups"}:
                        values.append(self._instance(int))
                        continue
                    if attribute == "groupindex":
                        values.append(
                            self._instance(
                                dict,
                                self._proper_instance(str),
                                self._proper_instance(int),
                            )
                        )
                        continue
                if typ.type.raw_type is re.Match:
                    text = typ.args[0] if typ.args else ANY
                    if attribute == "string":
                        values.append(AbstractTypeValue.from_type(text))
                        continue
                    if attribute == "re":
                        values.append(self._instance(re.Pattern, text))
                        continue
                    if attribute in {"pos", "endpos"}:
                        values.append(self._instance(int))
                        continue
                    if attribute in {"lastindex", "lastgroup"}:
                        values.append(
                            self._join(
                                (
                                    AbstractTypeValue.from_type(text)
                                    if attribute == "lastgroup"
                                    else self._instance(int)
                                ),
                                AbstractTypeValue.from_type(NONE_TYPE),
                            )
                        )
                        continue
                if typ.type.raw_type is datetime.timedelta and attribute in {
                    "days",
                    "seconds",
                    "microseconds",
                }:
                    values.append(self._instance(int))
                    continue
                if typ.type.raw_type in {datetime.datetime, datetime.date} and attribute in {
                    "year",
                    "month",
                    "day",
                    "hour",
                    "minute",
                    "second",
                    "microsecond",
                }:
                    values.append(self._instance(int))
                    continue
                if typ.type.raw_type is datetime.datetime and attribute == "tzinfo":
                    values.append(
                        self._join(
                            self._instance(datetime.tzinfo),
                            AbstractTypeValue.from_type(NONE_TYPE),
                        )
                    )
                    continue
                if typ.type.raw_type is datetime.datetime and attribute == "fold":
                    values.append(self._instance(int))
                    continue
                if self._is_pathlib_type(typ):
                    if attribute in {"name", "stem", "suffix", "drive", "root", "anchor"}:
                        values.append(self._instance(str))
                        continue
                    if attribute in {"suffixes", "parts"}:
                        if attribute == "parts":
                            values.append(
                                AbstractTypeValue.from_type(
                                    TupleType((self._proper_instance(str),), unknown_size=True)
                                )
                            )
                        else:
                            values.append(self._instance(list, self._proper_instance(str)))
                        continue
                    if attribute in {"parent", "parents"}:
                        values.append(AbstractTypeValue.from_type(typ))
                        continue
                member_type = typ.type.members.get(attribute)
                if member_type is not None:
                    substitutions = {
                        parameter.name: argument
                        for parameter, argument in zip(typ.type.type_parameters, typ.args)
                    }
                    if substitutions:
                        member_type = substitute_type_vars(member_type, substitutions)
                    values.append(AbstractTypeValue.from_type(member_type))
                    continue
                external = self._external_type(f"{typ.type.full_name}.{attribute}")
                if external is not None:
                    if (
                        isinstance(external, CallableType)
                        and not base.class_targets
                        and external.arg_types
                    ):
                        external = CallableType(external.arg_types[1:], external.return_type)
                    values.append(AbstractTypeValue.from_type(external))
                    continue
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

    def _bound_method_value(
        self,
        function: _FunctionInfo,
        base: AbstractTypeValue,
    ) -> AbstractTypeValue:
        """Project a method lookup to a runtime callable value.

        Accessing an instance method through an instance binds ``self`` and
        removes it from the callable's public parameter list.  The same applies
        to ``classmethod`` through either a class or an instance.  Accessing an
        instance method through the class keeps the unbound signature.
        """

        value = self._function_value(function)
        signature = value.public_type()
        if not isinstance(signature, CallableType) or function.method_kind == "static":
            return value
        if signature.arg_types is None:
            return value
        if function.method_kind == "instance" and base.class_targets:
            return value
        arguments = signature.arg_types
        return AbstractTypeValue.from_type(
            CallableType(
                arguments[1:] if arguments else (),
                signature.return_type,
            )
        )

    def _subscript_value(
        self,
        base: AbstractTypeValue,
        slice_node: ast.expr,
        index_value: AbstractTypeValue | None = None,
    ) -> AbstractTypeValue:
        if self._contains_any(base):
            return AbstractTypeValue.from_type(ANY)
        if base.class_targets:
            for target in base.class_targets:
                class_info = self._classes.get(target)
                if class_info is None or not class_info.enum_values:
                    continue
                if (
                    isinstance(slice_node, ast.Constant)
                    and isinstance(slice_node.value, str)
                    and slice_node.value in class_info.enum_values
                ):
                    return AbstractTypeValue.from_type(class_info.instance)
                return AbstractTypeValue.unresolved()
            arguments = slice_node.elts if isinstance(slice_node, ast.Tuple) else [slice_node]
            parameters = tuple(
                self._annotation_value(item).public_type() or ANY for item in arguments
            )
            return replace(
                base,
                types=frozenset(
                    Instance(typ.type, parameters) if isinstance(typ, Instance) else typ
                    for typ in base.types
                ),
            )
        values: list[AbstractTypeValue] = []
        for typ in base.types:
            if isinstance(typ, UnionType):
                values.extend(
                    self._subscript_value(
                        AbstractTypeValue.from_type(item), slice_node, index_value=index_value
                    )
                    for item in typ.items
                )
                continue
            if isinstance(typ, Instance) and typ.type.typed_dict_fields is None:
                projected = self._builtin_projection(typ)
                if projected is not None:
                    typ = projected
            if isinstance(typ, Instance) and typ.type.tuple_fields is not None:
                typ = TupleType(
                    tuple(typ.type.members.get(name, ANY) for name in typ.type.tuple_fields)
                )
            if isinstance(slice_node, ast.Slice):
                if isinstance(typ, TupleType):
                    try:
                        bounds = [
                            ast.literal_eval(item) if item is not None else None
                            for item in (slice_node.lower, slice_node.upper, slice_node.step)
                        ]
                        result = typ if typ.unknown_size else TupleType(typ.args[slice(*bounds)])
                    except (ValueError, TypeError):
                        result = TupleType(
                            (
                                self._iterable_element(
                                    AbstractTypeValue.from_type(typ)
                                ).public_type()
                                or ANY,
                            ),
                            unknown_size=True,
                        )
                    values.append(AbstractTypeValue.from_type(result))
                elif isinstance(typ, Instance) and typ.type.raw_type in {
                    list,
                    str,
                    bytes,
                    bytearray,
                    range,
                    memoryview,
                    cabc.Sequence,
                    cabc.MutableSequence,
                }:
                    values.append(AbstractTypeValue.from_type(typ))
                continue
            if isinstance(typ, TupleType):
                try:
                    index = ast.literal_eval(slice_node)
                except (ValueError, TypeError):
                    index = None
                if isinstance(index, int):
                    if -len(typ.args) <= index < len(typ.args):
                        values.append(AbstractTypeValue.from_type(typ.args[index]))
                        continue
                values.extend(AbstractTypeValue.from_type(item) for item in typ.args)
            elif isinstance(typ, Instance):
                raw = typ.type.raw_type
                if raw in {cabc.Mapping, cabc.MutableMapping} and len(typ.args) >= 2:
                    values.append(AbstractTypeValue.from_type(typ.args[1]))
                    continue
                if raw in {cabc.Sequence, cabc.MutableSequence} and typ.args:
                    values.append(AbstractTypeValue.from_type(typ.args[0]))
                    continue
                if typ.type.typed_dict_fields is not None:
                    field_key = (
                        slice_node.value
                        if isinstance(slice_node, ast.Constant)
                        and isinstance(slice_node.value, str)
                        else None
                    )
                    if field_key is None and index_value is not None and index_value.literal_values:
                        for lit in index_value.literal_values:
                            if isinstance(lit, str) and lit in typ.type.typed_dict_fields:
                                field_key = lit
                                break
                    if field_key is not None and field_key in typ.type.typed_dict_fields:
                        values.append(
                            AbstractTypeValue.from_type(typ.type.typed_dict_fields.get(field_key))
                        )
                    else:
                        values.append(AbstractTypeValue.unresolved())
                    continue
                getitem = self._class_method(typ.type.full_name, "__getitem__")
                if getitem is not None:
                    result = self._apply_function(
                        getitem,
                        [
                            AbstractTypeValue.from_type(typ),
                            AbstractTypeValue.unresolved(),
                        ],
                        {},
                    )
                    values.append(self._filter_subscript_result(result, slice_node))
                    continue
                member = typ.type.members.get("__getitem__")
                if isinstance(member, CallableType):
                    values.append(
                        self._filter_subscript_result(
                            AbstractTypeValue.from_type(member.return_type),
                            slice_node,
                        )
                    )
                    continue
                if raw in {list, set, frozenset, collections.deque} and typ.args:
                    values.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw is collections.Counter:
                    values.append(self._instance(int))
                elif (
                    raw
                    in {
                        dict,
                        collections.defaultdict,
                        collections.OrderedDict,
                        collections.ChainMap,
                    }
                    and len(typ.args) > 1
                ):
                    if (
                        base.dict_shapes
                        and isinstance(slice_node, ast.Constant)
                        and isinstance(slice_node.value, str)
                    ):
                        for shape in base.dict_shapes:
                            field = dict(shape).get(slice_node.value)
                            values.append(
                                AbstractTypeValue.from_type(field)
                                if field is not None
                                else AbstractTypeValue.unresolved()
                            )
                    else:
                        values.append(AbstractTypeValue.from_type(typ.args[1]))
                elif raw in {bytes, bytearray}:
                    values.append(self._instance(int))
                elif raw in {memoryview, range}:
                    values.append(self._instance(int))
                elif raw is str:
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

    def _is_widened_container(self, original: AbstractTypeValue, final: AbstractTypeValue) -> bool:
        """Whether *final* widened a mutable container argument in place."""
        if original.unknown or final.unknown or not original.types or not final.types:
            return False
        for before in original.types:
            if not isinstance(before, Instance) or before.type.raw_type not in {
                list,
                set,
                frozenset,
                dict,
            }:
                continue
            for after in final.types:
                if (
                    not isinstance(after, Instance)
                    or after.type.raw_type is not before.type.raw_type
                    or len(after.args) != len(before.args)
                ):
                    continue
                if all(
                    self.type_system.is_subtype(old_arg, new_arg)
                    for old_arg, new_arg in zip(before.args, after.args)
                ) and any(
                    not self.type_system.is_subtype(new_arg, old_arg)
                    for old_arg, new_arg in zip(before.args, after.args)
                ):
                    return True
        return False

    def _dict_key_value(self, value: AbstractTypeValue) -> AbstractTypeValue:
        """Project class-object keys to ``type[...]`` for dictionary literals."""
        parts: list[ProperType] = []
        for item in value.types:
            if isinstance(item, Instance) and item.type.full_name in value.class_targets:
                parts.append(TypeType(item))
            elif isinstance(item, TupleType) and "builtins.tuple" in value.class_targets:
                parts.append(TypeType(item))
            else:
                parts.append(item)
        return replace(value, types=frozenset(parts))

    def _mapping_key_value(
        self, value: AbstractTypeValue
    ) -> tuple[AbstractTypeValue, AbstractTypeValue]:
        """Return the joined key/value types contributed by a mapping value."""
        keys: list[AbstractTypeValue] = []
        items: list[AbstractTypeValue] = []
        for typ in value.types:
            if isinstance(typ, Instance) and typ.type.raw_type is dict and len(typ.args) >= 2:
                keys.append(AbstractTypeValue.from_type(typ.args[0]))
                items.append(AbstractTypeValue.from_type(typ.args[1]))
            elif isinstance(typ, Instance) and typ.type.typed_dict_fields is not None:
                keys.append(self._instance(str))
                fields = list(typ.type.typed_dict_fields.values())
                items.append(
                    join_all(
                        (AbstractTypeValue.from_type(item) for item in fields),
                        self.type_system,
                        max_union_size=self.options.max_union_size,
                    )
                    if fields
                    else AbstractTypeValue.from_type(ANY)
                )
            else:
                keys.append(AbstractTypeValue.from_type(ANY))
                items.append(AbstractTypeValue.from_type(ANY))
        if value.unknown:
            keys.append(AbstractTypeValue.unresolved())
            items.append(AbstractTypeValue.unresolved())
        return (
            (
                join_all(
                    keys,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
                if keys
                else AbstractTypeValue.unresolved()
            ),
            (
                join_all(
                    items,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )
                if items
                else AbstractTypeValue.unresolved()
            ),
        )

    @staticmethod
    def _is_container_type(typ: ProperType) -> bool:
        if isinstance(typ, TupleType):
            return True
        return isinstance(typ, Instance) and typ.type.raw_type in {
            list,
            tuple,
            set,
            frozenset,
            dict,
            cabc.Sequence,
            cabc.MutableSequence,
            cabc.Iterable,
        }

    def _filter_subscript_result(
        self, result: AbstractTypeValue, slice_node: ast.expr
    ) -> AbstractTypeValue:
        """Select overload alternatives compatible with an int/slice index."""
        alternatives = [
            part
            for typ in result.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        if len(alternatives) < 2:
            return result
        wants_container = isinstance(slice_node, ast.Slice)
        selected = [
            part for part in alternatives if self._is_container_type(part) == wants_container
        ]
        return replace(result, types=frozenset(selected)) if selected else result

    def _join_many_values(self, values: list[AbstractTypeValue]) -> AbstractTypeValue:
        return join_all(
            values,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )

    def _is_awaitable_value(self, value: AbstractTypeValue) -> bool:
        """Return whether any alternative can be awaited."""
        for typ in value.types:
            if isinstance(typ, UnionType):
                if any(
                    self._is_awaitable_value(AbstractTypeValue.from_type(item))
                    for item in typ.items
                ):
                    return True
            elif isinstance(typ, Instance) and typ.type.raw_type in {
                cabc.Coroutine,
                cabc.Awaitable,
                asyncio.Future,
                asyncio.Task,
            }:
                return True
        return False

    def _await_result(self, value: AbstractTypeValue) -> AbstractTypeValue:
        results: list[AbstractTypeValue] = []
        for typ in value.types:
            if self._contains_any(AbstractTypeValue.from_type(typ)):
                results.append(AbstractTypeValue.from_type(ANY))
                continue
            if isinstance(typ, Instance):
                raw = typ.type.raw_type
                if raw is cabc.Coroutine and len(typ.args) >= 3:
                    results.append(AbstractTypeValue.from_type(typ.args[2]))
                    continue
                if raw in {cabc.Awaitable, asyncio.Future, asyncio.Task} and typ.args:
                    results.append(AbstractTypeValue.from_type(typ.args[0]))
                    continue
            if isinstance(typ, UnionType):
                # ``from_type`` would wrap the union as a single proper type
                # and this method would recurse on the same value forever.
                results.extend(
                    self._await_result(AbstractTypeValue.from_type(item)) for item in typ.items
                )
        if results:
            return join_all(
                results,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
        return AbstractTypeValue.unresolved() if value.unknown else AbstractTypeValue.from_type(ANY)

    def _iterable_element(self, value: AbstractTypeValue, *, _depth: int = 0) -> AbstractTypeValue:
        if _depth > 4:
            return AbstractTypeValue.unresolved()
        elements: list[AbstractTypeValue] = []
        for typ in value.types:
            if isinstance(typ, UnionType):
                elements.extend(
                    self._iterable_element(AbstractTypeValue.from_type(item), _depth=_depth + 1)
                    for item in typ.items
                )
                continue
            if isinstance(typ, TupleType):
                elements.extend(AbstractTypeValue.from_type(item) for item in typ.args)
            elif isinstance(typ, Instance):
                projected = self._builtin_projection(typ)
                if projected is not None:
                    elements.append(
                        self._iterable_element(
                            AbstractTypeValue.from_type(projected), _depth=_depth + 1
                        )
                    )
                    continue
                raw = typ.type.raw_type
                if typ.type.tuple_fields is not None:
                    elements.extend(
                        AbstractTypeValue.from_type(typ.type.members.get(name, ANY))
                        for name in typ.type.tuple_fields
                    )
                elif (
                    raw
                    in {
                        dict,
                        collections.defaultdict,
                        collections.OrderedDict,
                        collections.ChainMap,
                        collections.Counter,
                    }
                    and typ.args
                ):
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw in {list, set, frozenset, collections.deque} and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif (
                    raw
                    in {
                        cabc.Iterable,
                        cabc.Iterator,
                        cabc.Generator,
                        zip,
                        cabc.AsyncIterable,
                        cabc.AsyncIterator,
                        cabc.AsyncGenerator,
                    }
                    and typ.args
                ):
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw in {cabc.KeysView, cabc.ValuesView} and typ.args:
                    elements.append(AbstractTypeValue.from_type(typ.args[0]))
                elif raw is cabc.ItemsView and len(typ.args) >= 2:
                    elements.append(
                        AbstractTypeValue.from_type(TupleType((typ.args[0], typ.args[1])))
                    )
                elif raw is str:
                    elements.append(self._instance(str))
                elif raw is bytes:
                    elements.append(self._instance(int))
                elif raw is memoryview:
                    elements.append(self._instance(int))
                elif raw is range:
                    elements.append(self._instance(int))
                else:
                    info = self._classes.get(typ.type.full_name)
                    if info is not None and self._is_enum_class_info(info):
                        elements.append(AbstractTypeValue.from_type(info.instance))
                    elif info is not None:
                        iter_method = self._class_method(info.qualified_name, "__iter__")
                        next_method = self._class_method(info.qualified_name, "__next__")
                        getitem_method = self._class_method(info.qualified_name, "__getitem__")
                        aiter_method = self._class_method(info.qualified_name, "__aiter__")
                        anext_method = self._class_method(info.qualified_name, "__anext__")
                        if (
                            iter_method is None
                            and next_method is None
                            and getitem_method is None
                            and (aiter_method is not None or anext_method is not None)
                        ):
                            method = aiter_method or anext_method
                            function = self._functions.get(method)
                            signature = (
                                self._function_value(function).public_type()
                                if function is not None
                                else None
                            )
                            if (
                                isinstance(signature, CallableType)
                                and signature.return_type is not None
                            ):
                                returned_type = signature.return_type
                                used_anext = False
                                if (
                                    aiter_method is not None
                                    and anext_method is not None
                                    and isinstance(returned_type, Instance)
                                    and returned_type.type.full_name == info.instance.type.full_name
                                ):
                                    anext_function = self._functions.get(anext_method)
                                    anext_signature = (
                                        self._function_value(anext_function).public_type()
                                        if anext_function is not None
                                        else None
                                    )
                                    if (
                                        isinstance(anext_signature, CallableType)
                                        and anext_signature.return_type is not None
                                    ):
                                        returned_type = anext_signature.return_type
                                        used_anext = True
                                        if (
                                            isinstance(returned_type, Instance)
                                            and returned_type.type.raw_type is cabc.Coroutine
                                            and len(returned_type.args) >= 3
                                        ):
                                            returned_type = returned_type.args[2]
                                    else:
                                        returned_type = None
                                if returned_type is not None:
                                    if used_anext:
                                        elements.append(AbstractTypeValue.from_type(returned_type))
                                    else:
                                        elements.append(
                                            self._iterable_element(
                                                AbstractTypeValue.from_type(returned_type),
                                                _depth=_depth + 1,
                                            )
                                        )
                            continue
                        method = iter_method or next_method or getitem_method
                        function = self._functions.get(method) if method is not None else None
                        if function is not None:
                            signature = self._function_value(function).public_type()
                            if (
                                isinstance(signature, CallableType)
                                and signature.return_type is not None
                            ):
                                returned_type = signature.return_type
                                used_next_method = False
                                if (
                                    iter_method is not None
                                    and isinstance(returned_type, Instance)
                                    and returned_type.type.full_name == info.instance.type.full_name
                                    and next_method is not None
                                ):
                                    next_function = self._functions.get(next_method)
                                    next_signature = (
                                        self._function_value(next_function).public_type()
                                        if next_function is not None
                                        else None
                                    )
                                    if (
                                        isinstance(next_signature, CallableType)
                                        and next_signature.return_type is not None
                                    ):
                                        returned_type = next_signature.return_type
                                        used_next_method = True
                                returned = AbstractTypeValue.from_type(returned_type)
                                if iter_method is not None and not used_next_method:
                                    if not (
                                        isinstance(returned_type, Instance)
                                        and returned_type.type.full_name
                                        == info.instance.type.full_name
                                    ):
                                        returned = self._iterable_element(
                                            returned, _depth=_depth + 1
                                        )
                                elements.append(returned)
        return (
            join_all(
                elements,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            if elements
            else AbstractTypeValue.unresolved()
        )

    def _builtin_projection(self, typ: Instance) -> Instance | None:
        """Project a user subclass of a builtin container to its generic base."""
        info = self._classes.get(typ.type.full_name)
        if info is None or info.builtin_base is None:
            return None
        raw, args = info.builtin_base
        return Instance(self.type_system.to_class_descriptor(raw), args)

    @staticmethod
    def _is_pathlib_type(typ: Instance) -> bool:
        full_name = typ.type.full_name
        return full_name.startswith("pathlib.") and full_name.rsplit(".", 1)[-1] in {
            "Path",
            "PosixPath",
            "WindowsPath",
            "PurePath",
            "PurePosixPath",
            "PureWindowsPath",
        }

    def _callable_return_type(self, value: AbstractTypeValue) -> AbstractTypeValue:
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

    @staticmethod
    def _augment_element_shapes(
        value: AbstractTypeValue, *sources: AbstractTypeValue
    ) -> AbstractTypeValue:
        shapes = set(value.element_dict_shapes)
        for source in sources:
            shapes.update(source.dict_shapes or ())
            shapes.update(source.element_dict_shapes)
        return replace(value, element_dict_shapes=frozenset(shapes)) if shapes else value

    def _update_environment_receiver(
        self,
        environment: dict[str, AbstractTypeValue],
        receiver: ast.expr,
        new_value: AbstractTypeValue,
    ) -> None:
        """Widen a mutated container and every environment name aliasing it."""
        key = receiver.id if isinstance(receiver, ast.Name) else ast.unparse(receiver)
        old = environment.get(key)
        environment[key] = new_value
        if isinstance(receiver, ast.Name):
            current = self._current_function_info
            if current is not None:
                name = receiver.id
                if name in current.closure_evidence:
                    current.closure_evidence[name] = new_value
                    current.mutated_closure_names.add(name)
                    parent = self._enclosing_function(current)
                    if parent is not None:
                        previous = parent.closure_evidence.get(name, AbstractTypeValue.bottom())
                        parent.closure_evidence[name] = self._join(previous, new_value)
                        parent.mutated_closure_names.add(name)
                if name in current.global_names:
                    self._module_environment[name] = new_value
        if old is None:
            return
        # Abstract values are immutable, so an actual alias (``b = a``)
        # shares the same object.  Do not compare with ``==``: two distinct
        # empty list/set literals compare equal and widening one must not
        # silently change the inferred element type of the other.
        for name, value in list(environment.items()):
            if name != key and value is old:
                environment[name] = new_value

    def _enclosing_function(self, function: _FunctionInfo) -> _FunctionInfo | None:
        current = function.qualified_name
        while "." in current:
            current = current.rpartition(".")[0]
            parent = self._functions.get(current)
            if parent is not None and parent is not function:
                return parent
        return None

    def _update_nested_closure_evidence(
        self,
        name: str,
        value: AbstractTypeValue,
        current_function: _FunctionInfo,
    ) -> None:
        """Propagate a later enclosing assignment into nested closures."""
        prefix = f"{current_function.qualified_name}."
        for function in self._functions.values():
            if not function.qualified_name.startswith(prefix):
                continue
            previous = function.closure_evidence.get(name)
            if previous is None:
                continue
            function.closure_evidence[name] = self._join(previous, value)

    def _assign_starred_unpack(
        self,
        targets: list[ast.expr],
        value: AbstractTypeValue,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> None:
        star_index = next(
            index for index, target in enumerate(targets) if isinstance(target, ast.Starred)
        )
        tuple_args: list[ProperType] = []
        if len(value.types) == 1:
            only = next(iter(value.types))
            if isinstance(only, TupleType) and not only.unknown_size:
                tuple_args = list(only.args)
        if tuple_args:
            before = targets[:star_index]
            after = targets[star_index + 1 :]
            for target, element in zip(before, tuple_args[: len(before)]):
                self._assign_target(
                    target,
                    AbstractTypeValue.from_type(element),
                    environment,
                    current_function,
                )
            middle_end = len(tuple_args) - len(after)
            middle = tuple_args[len(before) : max(middle_end, len(before))]
            element = join_all(
                (AbstractTypeValue.from_type(item) for item in middle),
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
            star_target = targets[star_index]
            if isinstance(star_target, ast.Starred):
                self._assign_target(
                    star_target.value,
                    self._instance(list, element.public_type() or ANY),
                    environment,
                    current_function,
                )
            for target, element in zip(after, tuple_args[-len(after) :] if after else ()):
                self._assign_target(
                    target,
                    AbstractTypeValue.from_type(element),
                    environment,
                    current_function,
                )
            return
        element = self._iterable_element(value)
        for index, target in enumerate(targets):
            if isinstance(target, ast.Starred):
                self._assign_target(
                    target.value,
                    self._instance(list, element.public_type() or ANY),
                    environment,
                    current_function,
                )
            else:
                self._assign_target(target, element, environment, current_function)

    def _assign_target(
        self,
        target: ast.expr,
        value: AbstractTypeValue,
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> None:
        if isinstance(target, ast.Name):
            self._invalidate_refinements(environment, target)
            environment[target.id] = value
            self._record_expression(target, value)
            if current_function is not None:
                if target.id in current_function.global_names:
                    self._module_environment[target.id] = value
                if target.id in current_function.nonlocal_names:
                    parent = self._enclosing_function(current_function)
                    if parent is not None:
                        old = parent.closure_evidence.get(target.id, AbstractTypeValue.bottom())
                        parent.closure_evidence[target.id] = self._join(old, value)
                self._update_nested_closure_evidence(target.id, value, current_function)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if any(isinstance(child, ast.Starred) for child in target.elts):
                self._assign_starred_unpack(
                    target.elts,
                    value,
                    environment,
                    current_function,
                )
                return
            unpacked = self._unpack_value(value, len(target.elts))
            for child, child_value in zip(target.elts, unpacked):
                self._assign_target(child, child_value, environment, current_function)
            return
        if isinstance(target, ast.Attribute):
            key = ast.unparse(target)
            self._invalidate_refinements(environment, target)
            property_value = self._property_assignment_value(target, environment)
            if property_value is not None:
                # A property setter's parameter type does not change the
                # getter result type observed by subsequent reads.
                value = property_value
            environment[key] = value
            self._record_expression(target, value)
            if (
                current_function is not None
                and current_function.owner is not None
                and isinstance(target.value, ast.Name)
                and current_function.parameter_names
                and target.value.id == current_function.parameter_names[0]
            ):
                key = (current_function.owner, target.attr)
                old = self._pending_attributes.get(key, AbstractTypeValue.bottom())
                self._pending_attributes[key] = self._join(old, value)
            return
        if isinstance(target, ast.Subscript):
            self._invalidate_refinements(environment, target)
            if not isinstance(target.slice, ast.Slice):
                environment[ast.unparse(target)] = value
            self._record_expression(target, value)
            if not isinstance(target.value, ast.Name):
                return
            if isinstance(target.slice, ast.Slice):
                value = self._iterable_element(value)
            name = target.value.id
            base = environment.get(name, AbstractTypeValue.unresolved())
            updated: list[AbstractTypeValue] = []
            for typ in base.types:
                if isinstance(typ, Instance) and typ.type.raw_type is dict:
                    key_type = typ.args[0] if typ.args else ANY
                    old_value = typ.args[1] if len(typ.args) > 1 else ANY
                    if isinstance(target.slice, ast.Constant):
                        new_key = self._proper_instance(type(target.slice.value))
                        if isinstance(key_type, (AnyType, NeverType)):
                            key_type = new_key
                        else:
                            key_type = (
                                self._join(
                                    AbstractTypeValue.from_type(key_type),
                                    AbstractTypeValue.from_type(new_key),
                                ).public_type()
                                or ANY
                            )
                    if isinstance(old_value, (AnyType, NeverType)):
                        joined = value
                    else:
                        joined = self._join(AbstractTypeValue.from_type(old_value), value)
                    updated.append(self._instance(dict, key_type, joined.public_type() or ANY))
                elif isinstance(typ, Instance) and typ.type.raw_type is list:
                    old_value = typ.args[0] if typ.args else ANY
                    joined = self._join(AbstractTypeValue.from_type(old_value), value)
                    updated.append(self._instance(list, joined.public_type() or ANY))
            if updated:
                environment[name] = join_all(
                    updated,
                    self.type_system,
                    max_union_size=self.options.max_union_size,
                )

    def _property_assignment_value(
        self,
        target: ast.Attribute,
        environment: dict[str, AbstractTypeValue],
    ) -> AbstractTypeValue | None:
        if not isinstance(target.value, ast.Name):
            return None
        base = environment.get(target.value.id)
        if base is None:
            return None
        for typ in base.types:
            if not isinstance(typ, Instance):
                continue
            info = self._classes.get(typ.type.full_name)
            if info is None or target.attr not in info.properties:
                continue
            getter = self._class_property(info.qualified_name, target.attr)
            function = self._functions.get(getter) if getter is not None else None
            if function is not None:
                if function.explicit_return is not None:
                    return function.explicit_return
                if function.summary is not None and function.summary.return_type is not None:
                    return AbstractTypeValue.from_type(function.summary.return_type)
        return None

    @staticmethod
    def _invalidate_refinements(environment, target):
        assigned = ast.unparse(target)
        for key in tuple(environment):
            if key.startswith((assigned + ".", assigned + "[")):
                environment.pop(key)
            elif "[" in key:
                if isinstance(target, ast.Subscript):
                    environment.pop(key)
                    continue
                try:
                    expression = ast.parse(key, mode="eval")
                except SyntaxError:
                    continue
                if any(
                    isinstance(child, (ast.Name, ast.Attribute)) and ast.unparse(child) == assigned
                    for child in ast.walk(expression)
                ):
                    environment.pop(key)

    def _unpack_value(self, value: AbstractTypeValue, count: int) -> list[AbstractTypeValue]:
        value = replace(
            value,
            types=frozenset(
                (
                    TupleType(
                        tuple(typ.type.members.get(name, ANY) for name in typ.type.tuple_fields)
                    )
                    if isinstance(typ, Instance) and typ.type.tuple_fields is not None
                    else typ
                )
                for typ in value.types
            ),
        )
        alternatives = [
            part
            for typ in value.types
            for part in (typ.items if isinstance(typ, UnionType) else (typ,))
        ]
        tuples = [
            typ
            for typ in alternatives
            if isinstance(typ, TupleType) and (typ.unknown_size or len(typ.args) == count)
        ]
        if tuples and all(isinstance(typ, TupleType) for typ in alternatives):
            return [
                join_all(
                    (
                        AbstractTypeValue.from_type(
                            (typ.args[0] if typ.args else ANY)
                            if typ.unknown_size
                            else typ.args[position]
                        )
                        for typ in tuples
                    ),
                    self.type_system,
                )
                for position in range(count)
            ]
        element = self._iterable_element(value)
        return [element] * count

    def _propagate_comprehension_walrus(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        local_environment: dict[str, AbstractTypeValue],
        environment: dict[str, AbstractTypeValue],
        current_function: _FunctionInfo | None,
    ) -> None:
        expressions: list[ast.expr] = []
        for generator in node.generators:
            expressions.extend(generator.ifs)
        if isinstance(node, ast.DictComp):
            expressions.extend((node.key, node.value))
        else:
            expressions.append(node.elt)
        for expression in expressions:
            for child in ast.walk(expression):
                if (
                    isinstance(child, ast.NamedExpr)
                    and isinstance(child.target, ast.Name)
                    and child.target.id in local_environment
                ):
                    self._assign_target(
                        child.target,
                        local_environment[child.target.id],
                        environment,
                        current_function,
                    )

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
                if any(isinstance(child, ast.NamedExpr) for child in ast.walk(condition)):
                    # Comprehension filters are only narrowed today, so a
                    # walrus target would otherwise never receive its value.
                    self._evaluate_expression(
                        condition,
                        result,
                        scope=scope,
                        current_function=current_function,
                    )
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
                aliases=self._annotation_aliases(),
                type_parameters={
                    name: tuple(parameters)
                    for name, parameters in self._alias_type_variables.items()
                },
            )
        )

    def _join(self, left: AbstractTypeValue, right: AbstractTypeValue) -> AbstractTypeValue:
        joined = left.join(
            right,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )
        return self._bound_type_depth(joined)

    def _bound_type_depth(self, value: AbstractTypeValue) -> AbstractTypeValue:
        """Widen recursively nested type structures beyond the configured limit.

        A bounded number of union alternatives does not bound structures such
        as ``tuple[tuple[...]]`` produced by loop-carried assignments.  Keep
        the outer tuple shape and known alternatives, but replace only the
        overly deep suffix with an unknown-size tuple containing Any.
        """
        limit = max(1, self.options.max_type_depth)

        def bound(typ: ProperType, depth: int) -> ProperType:
            if depth >= limit:
                if isinstance(typ, TupleType):
                    return TupleType((ANY,), unknown_size=True)
                return ANY
            if isinstance(typ, TupleType):
                return TupleType(
                    tuple(bound(item, depth + 1) for item in typ.args),
                    unknown_size=typ.unknown_size,
                )
            if isinstance(typ, Instance) and typ.args:
                return Instance(
                    typ.type,
                    tuple(bound(item, depth + 1) for item in typ.args),
                )
            if isinstance(typ, UnionType):
                return UnionType(tuple(bound(item, depth + 1) for item in typ.items))
            if isinstance(typ, CallableType):
                args = (
                    None
                    if typ.arg_types is None
                    else tuple(bound(item, depth + 1) for item in typ.arg_types)
                )
                return CallableType(args, bound(typ.return_type, depth + 1))
            if isinstance(typ, TypeType):
                return TypeType(bound(typ.item, depth + 1))
            return typ

        bounded = frozenset(bound(typ, 0) for typ in value.types)
        if bounded == value.types:
            return value
        return AbstractTypeValue(
            bounded,
            unknown=value.unknown,
            callable_targets=value.callable_targets,
            class_targets=value.class_targets,
            dict_shapes=value.dict_shapes,
        )

    def _join_normal_results(self, values: Iterable[AbstractTypeValue]) -> AbstractTypeValue:
        """Join values from branches that can complete normally."""
        candidates = list(values)
        normal = [value for value in candidates if not self._is_never_value(value)]
        result = join_all(
            normal or candidates,
            self.type_system,
            max_union_size=self.options.max_union_size,
        )
        return self._bound_type_depth(result)

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

    def _fill_missing_attribute_joins(
        self,
        baseline: dict[str, AbstractTypeValue],
        left: dict[str, AbstractTypeValue],
        right: dict[str, AbstractTypeValue],
    ) -> None:
        """Keep branch-local attribute writes from replacing the old value.

        Attribute writes are represented in the environment as dotted keys
        (``c.x``).  Without a value in the branch that did not write the
        attribute, a join would use only the written branch and report the
        mutation as unconditional.  Seed the missing side with the attribute's
        pre-branch value when it can be resolved.
        """
        for present, missing in ((left, right), (right, left)):
            for key, value in list(present.items()):
                if "." not in key or key in missing:
                    continue
                base_name, _, attribute = key.partition(".")
                if "." in attribute:
                    continue
                base = baseline.get(base_name) or self._module_environment.get(base_name)
                if base is None:
                    continue
                previous = self._attribute_value(base, attribute)
                if previous.public_type() is not None:
                    missing[key] = previous

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

    def _proper_instance(self, raw_type: type, *args: ProperType) -> Instance | TupleType:
        if raw_type is tuple:
            return TupleType(tuple(args) or (ANY,), unknown_size=not args)
        self._register_type_hierarchy(raw_type)
        return Instance(self.type_system.to_class_descriptor(raw_type), tuple(args))

    def _register_type_hierarchy(self, raw_type: type) -> None:
        # tuple has a dedicated structural representation and must never be
        # inserted into the nominal class graph.  Tuple subclasses still get
        # registered, but their builtin tuple base is intentionally skipped.
        if raw_type is tuple:
            return
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

    def _synthetic_instance(self, full_name: str, *, unresolved=False) -> Instance | TupleType:
        if full_name == "builtins.tuple":
            return TupleType(())
        raw = self._synthetic_types.get(full_name)
        if raw is None:
            module, _, name = full_name.rpartition(".")
            raw = type(
                name, (), {"__module__": module, "__pyflow_unresolved_external__": unresolved}
            )
            self._synthetic_types[full_name] = raw
        # Synthetic source classes are freshly created nominal classes,
        # never the builtin tuple constructor handled above.
        return cast(Instance, self._proper_instance(raw))

    def _contains_raw(self, value: AbstractTypeValue, raw_type: type) -> bool:
        return any(
            isinstance(typ, Instance) and typ.type.raw_type is raw_type for typ in value.types
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

    def _unwrap_single_generic(self, value: AbstractTypeValue) -> AbstractTypeValue:
        values = []
        for typ in value.types:
            if isinstance(typ, Instance) and typ.args:
                values.append(AbstractTypeValue.from_type(typ.args[-1]))
        return join_all(values, self.type_system) if values else AbstractTypeValue.unresolved()

    def _resolve_lexical_function(self, name: str, scope: str) -> str | None:
        current = scope
        while current:
            candidate = f"{current}.{name}"
            function = self._functions.get(candidate)
            # Class namespaces are not lexical closures for method bodies:
            # ``render(...)`` inside another method does not mean
            # ``self.render(...)``.  Nested functions have ``owner is None``.
            if function is not None and function.owner is None:
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
            for star_module in self._star_imports:
                candidate = f"{star_module}.{name}"
                if self._external_type(candidate) is not None:
                    return candidate
            return None
        target = self._imports[prefix]
        if name == target or name.startswith(f"{target}."):
            return name
        return f"{target}.{remainder}"

    def _qualified_callee_name(self, node: ast.expr) -> str | None:
        name = _expression_name(node)
        if name is None:
            return None
        return self._resolve_import_name(name) or name

    def _resolve_class_expression(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Subscript):
            node = node.value
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

    def _call_property_value(
        self,
        value: AbstractTypeValue,
        arguments: list[AbstractTypeValue],
        keywords: dict[str, AbstractTypeValue],
        node: ast.Call | ast.Attribute,
    ) -> AbstractTypeValue:
        """Apply a call to the value produced by a property getter."""
        if self._contains_any(value) or value.unknown:
            return AbstractTypeValue.from_type(ANY)
        results: list[AbstractTypeValue] = []
        for typ in value.types:
            if isinstance(typ, CallableType):
                selected = self._select_callable_overload(typ, arguments)
                results.append(
                    AbstractTypeValue.from_type(
                        selected.return_type if selected is not None else typ.return_type
                    )
                )
            elif isinstance(typ, Instance):
                class_info = self._classes.get(typ.type.full_name)
                if class_info is None:
                    continue
                call_method = self._class_method(class_info.qualified_name, "__call__")
                if call_method is not None:
                    results.append(
                        self._apply_function(
                            call_method,
                            [AbstractTypeValue.from_type(typ), *arguments],
                            keywords,
                            node=node,
                        )
                    )
        if results:
            return join_all(
                results,
                self.type_system,
                max_union_size=self.options.max_union_size,
            )
        return AbstractTypeValue.unresolved()

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

    def _class_property(self, class_name, name, seen=frozenset()):
        if class_name in seen:
            return None
        info = self._classes.get(class_name)
        if info is None:
            return None
        if name in info.properties:
            return info.properties[name]
        if name in info.methods:
            return None
        for base in info.bases:
            result = self._class_property(base, name, seen | {class_name})
            if result is not None:
                return result
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
        if attribute in class_info.attribute_templates:
            return class_info.attribute_templates[attribute]
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

    def _record_expression(self, node: ast.AST, value: AbstractTypeValue) -> None:
        span = _span(node)
        old = self._expressions.get(span)
        self._expressions[span] = value if old is None else self._join(old, value)
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
        # ``N().set`` is a method name, not the global ``set`` builtin.  A
        # bare attribute fallback here makes every chained call with a
        # builtin-named method resolve to that builtin.
        return f"{base}.{node.attr}" if base else None
    return None


def _span(node: ast.AST) -> SourceSpan:
    return SourceSpan(
        lineno=getattr(node, "lineno", 1),
        col_offset=getattr(node, "col_offset", 0),
        end_lineno=getattr(node, "end_lineno", None),
        end_col_offset=getattr(node, "end_col_offset", None),
    )
