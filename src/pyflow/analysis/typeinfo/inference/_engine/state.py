"""Shared declaration records, flow outcomes, and AST helpers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from pyflow.analysis.typeinfo.core.typesystem import Instance, ProperType, TypeVarType
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue
from pyflow.analysis.typeinfo.inference.models import (
    FunctionSpecialization,
    FunctionSummary,
    SourceSpan,
)


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
    match_args: tuple[str, ...] | None = None
    constructor_fields: dict[str, AbstractTypeValue] = field(default_factory=dict)
    field_defaults: set[str] = field(default_factory=set)
    keyword_only_fields: set[str] = field(default_factory=set)


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
