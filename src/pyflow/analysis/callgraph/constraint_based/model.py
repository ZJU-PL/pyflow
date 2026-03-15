"""Core model/types for constraint-based call graph analysis.

The analysis tracks sets of `AbstractValue` objects in environments and heap-
like maps. The solver computes a fixpoint over these sets.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from typing import (
    DefaultDict,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    Set,
    Tuple,
    TypeAlias,
)

FUNC_KIND = "func"
CLASS_KIND = "class"
INSTANCE_KIND = "instance"
MODULE_KIND = "module"
CONTAINER_KIND = "container"
PARTIAL_KIND = "partial"
BOUND_METHOD_KIND = "bound_method"
BOUND_CLASS_METHOD_KIND = "bound_class_method"
COROUTINE_KIND = "coroutine"
GENERATOR_KIND = "generator"
STRING_KIND = "string"
NONE_KIND = "none"
UNKNOWN_KIND = "unknown"

ContextKey: TypeAlias = Tuple[str, ...]
GLOBAL_CONTEXT: ContextKey = ("<global>",)


@dataclass(frozen=True)
class AbstractValue:
    """Single abstract atom flowing through constraints."""

    kind: str
    name: str


UNKNOWN_VALUE = AbstractValue(UNKNOWN_KIND, "<unknown>")
NONE_VALUE = AbstractValue(NONE_KIND, "None")


@dataclass(frozen=True)
class AnalysisOptions:
    """Behavioral knobs for precision/runtime tradeoffs and diagnostics."""

    context_sensitive: bool = False
    context_depth: int = 1
    fixpoint_max_iterations: Optional[int] = None
    warn_on_fixpoint_truncation: bool = True
    allocation_site_sensitive_instances: bool = False
    use_type_hints: bool = True
    refine_type_guards: bool = True
    allow_fixture_graph_loading: bool = True
    max_values_per_binding: int = 128
    max_contexts_per_scope: int = 64
    requeue_policy: Literal["fifo", "priority"] = "priority"
    emit_solver_stats: bool = False
    strict_precision_mode: bool = False


@dataclass
class SolverStats:
    """Fixpoint/scheduling telemetry for diagnostics and tuning."""

    iterations: int = 0
    states_analyzed: int = 0
    states_requeued: int = 0
    max_queue_size: int = 0
    bindings_capped: int = 0
    contexts_capped: int = 0
    dynamic_summary_edges: int = 0
    closure_context_fallbacks: int = 0


@dataclass
class ModuleInfo:
    """Loaded module AST and optional originating filesystem path."""

    name: str
    tree: ast.Module
    path: Optional[str]


@dataclass
class ClassInfo:
    """Collected class metadata used for attribute/method resolution."""

    qualname: str
    module: str
    node: ast.ClassDef
    parent_scope: Optional[str]
    global_names: set[str]
    nonlocal_names: set[str]
    closure_vars: set[str]
    bases_raw: List[ast.expr]
    metaclass_raw: Optional[ast.expr]
    bases: List[str]
    metaclass: Optional[str]
    methods: Dict[str, str]
    static_methods: Set[str]
    class_methods: Set[str]


@dataclass
class FunctionInfo:
    """Collected function/lambda metadata from symbol collection."""

    qualname: str
    module: str
    node: ast.AST
    posonly_params: List[str]
    pos_or_kw_params: List[str]
    kwonly_params: List[str]
    params: List[str]
    vararg: Optional[str]
    kwarg: Optional[str]
    is_method: bool
    is_staticmethod: bool
    is_classmethod: bool
    owner_class: Optional[str]
    global_names: set[str]
    nonlocal_names: set[str]
    parent_scope: Optional[str]
    closure_vars: set[str]
    param_annotations: Dict[str, ast.expr]
    return_annotation: Optional[ast.expr]
    is_async: bool
    is_generator: bool


@dataclass
class ScopeInfo:
    """Executable scope view consumed by the analyzer/evaluator."""

    name: str
    module: str
    body: List[ast.stmt]
    posonly_params: List[str]
    pos_or_kw_params: List[str]
    kwonly_params: List[str]
    params: List[str]
    vararg: Optional[str]
    kwarg: Optional[str]
    method_self_param: Optional[str]
    method_cls_param: Optional[str]
    global_names: set[str]
    nonlocal_names: set[str]
    parent_scope: Optional[str]
    closure_vars: set[str]
    param_annotations: Dict[str, ast.expr]
    class_owner: Optional[str]
    is_async: bool
    is_generator: bool


@dataclass
class ScopeResult:
    """Per-scope fixpoint delta returned by `_analyze_scope`."""

    callees: Set[str]
    returns: Set[AbstractValue]
    input_changed_scope_contexts: Set[Tuple[str, ContextKey]]
    module_binding_changed: bool
    changed_instance_fields: Set[Tuple[str, str]]
    changed_class_fields: Set[Tuple[str, str]]
    changed_container_keys: Set[Tuple[str, str]]
    nonlocal_binding_changed: bool
    singledispatch_changed: bool


def make_value(kind: str, name: str) -> AbstractValue:
    return AbstractValue(kind, name)


def make_func(name: str) -> AbstractValue:
    return make_value(FUNC_KIND, name)


def make_class(name: str) -> AbstractValue:
    return make_value(CLASS_KIND, name)


INSTANCE_ALLOC_SEPARATOR = "#"


def make_instance(name: str, allocation_site: Optional[str] = None) -> AbstractValue:
    """Create an instance abstract value (optionally allocation-site-sensitive)."""
    if allocation_site:
        return make_value(
            INSTANCE_KIND, f"{name}{INSTANCE_ALLOC_SEPARATOR}{allocation_site}"
        )
    return make_value(INSTANCE_KIND, name)


def parse_instance_name(name: str) -> Tuple[str, Optional[str]]:
    """Split encoded instance name into `(class_name, allocation_site)`."""
    class_name, separator, allocation_site = name.partition(INSTANCE_ALLOC_SEPARATOR)
    if not separator:
        return name, None
    return class_name, allocation_site or None


def instance_class_name(value: AbstractValue) -> str:
    """Return the class component for an instance abstract value."""
    class_name, _allocation_site = parse_instance_name(value.name)
    return class_name


def make_module(name: str) -> AbstractValue:
    return make_value(MODULE_KIND, name)


def make_container(name: str) -> AbstractValue:
    return make_value(CONTAINER_KIND, name)


def make_partial(kind: str, name: str) -> AbstractValue:
    return make_value(PARTIAL_KIND, f"{kind}|{name}")


def parse_partial(value: AbstractValue) -> Tuple[str, str]:
    kind, _sep, name = value.name.partition("|")
    return kind, name


def make_string(name: str) -> AbstractValue:
    return make_value(STRING_KIND, name)


def make_coroutine(name: str) -> AbstractValue:
    return make_value(COROUTINE_KIND, name)


def make_generator(name: str) -> AbstractValue:
    return make_value(GENERATOR_KIND, name)


def make_none() -> AbstractValue:
    return NONE_VALUE


def make_bound_method(method_qualname: str, receiver_class: str) -> AbstractValue:
    return make_value(BOUND_METHOD_KIND, f"{method_qualname}|{receiver_class}")


def parse_bound_method(value: AbstractValue) -> Tuple[str, str]:
    method, receiver_class = value.name.split("|", 1)
    return method, receiver_class


def make_bound_class_method(method_qualname: str, receiver_class: str) -> AbstractValue:
    return make_value(BOUND_CLASS_METHOD_KIND, f"{method_qualname}|{receiver_class}")


def parse_bound_class_method(value: AbstractValue) -> Tuple[str, str]:
    method, receiver_class = value.name.split("|", 1)
    return method, receiver_class


def copy_env(env: Mapping[str, Set[AbstractValue]]) -> Dict[str, Set[AbstractValue]]:
    """Shallow-copy environment where each symbol set is cloned."""
    return {name: set(values) for name, values in env.items()}


def join_envs(
    left: Mapping[str, Set[AbstractValue]], right: Mapping[str, Set[AbstractValue]]
) -> Dict[str, Set[AbstractValue]]:
    """Pointwise union join of two environments."""
    out: DefaultDict[str, Set[AbstractValue]] = defaultdict(set)
    for name, values in left.items():
        out[name].update(values)
    for name, values in right.items():
        out[name].update(values)
    return dict(out)


def decorator_id(expr: ast.expr) -> Optional[str]:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        if isinstance(expr.value, ast.Name):
            return f"{expr.value.id}.{expr.attr}"
        return expr.attr
    return None
