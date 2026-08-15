"""Pre-call validation for Python argument binding.

The binder deliberately runs before a callee context or body is activated.  It
uses exact information for literal ``*``/``**`` sources when available and
otherwise reports a maybe-valid call, allowing the pointer analysis to retain
the conservative call edge.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum
from itertools import product
from typing import FrozenSet, Optional, Tuple

from .object import ConstantObject
from .variable import VariableKind


class BindingStatus(Enum):
    VALID = "valid"
    MAYBE_VALID = "maybe_valid"
    DEFINITELY_INVALID = "definitely_invalid"


@dataclass(frozen=True)
class ArgumentBinding:
    status: BindingStatus
    diagnostics: Tuple[str, ...] = ()

    @property
    def definitely_invalid(self) -> bool:
        return self.status is BindingStatus.DEFINITELY_INVALID


def _star_lengths(state, source_var) -> Optional[FrozenSet[int]]:
    lengths = set()
    points_to = state.get_points_to(source_var)
    if points_to.is_empty():
        return None
    for obj in points_to:
        stmt = getattr(obj.alloc_site, "stmt", None)
        rval = stmt.get_rval() if hasattr(stmt, "get_rval") else None
        # Tuple length is immutable.  A list allocation's original syntax is
        # not a current-shape fact after append/extend/slice mutation.
        if not isinstance(rval, ast.Tuple):
            return None
        lengths.add(len(rval.elts))
    return frozenset(lengths)


def _constant_name_value(state, source_var, name: str):
    for kind in (VariableKind.TEMPORARY, VariableKind.LOCAL, VariableKind.GLOBAL):
        ctx_var = state._get_variable_direct(
            source_var.scope, source_var.context, name, kind
        )
        if ctx_var is None:
            continue
        values = {
            obj.value
            for obj in state.get_points_to(ctx_var)
            if isinstance(obj, ConstantObject)
        }
        if len(values) == 1:
            return next(iter(values))
    for defining_scope, defining_context, constraint in state.constraint_definitions:
        target = getattr(constraint, "target", None)
        alloc_site = getattr(constraint, "alloc_site", None)
        stmt = getattr(alloc_site, "stmt", None)
        rval = stmt.get_rval() if hasattr(stmt, "get_rval") else None
        if (
            defining_scope == source_var.scope
            and defining_context == source_var.context
            and getattr(target, "name", None) == name
            and isinstance(rval, ast.Constant)
        ):
            return rval.value
    scope_ast = source_var.scope.stmt.get_ast()
    for node in ast.walk(scope_ast):
        if not isinstance(node, ast.Assign) or not node.targets:
            continue
        target = node.targets[0]
        if (
            isinstance(target, ast.Name)
            and target.id == name
            and isinstance(node.value, ast.Constant)
        ):
            return node.value.value
    return None


def mapping_key_hints(state, source_var) -> Optional[Tuple[FrozenSet[str], ...]]:
    """Return literal allocation keys as flow hints, never as absence facts."""
    possibilities = set()
    points_to = state.get_points_to(source_var)
    if points_to.is_empty():
        return None
    for obj in points_to:
        stmt = getattr(obj.alloc_site, "stmt", None)
        rval = stmt.get_rval() if hasattr(stmt, "get_rval") else None
        if not isinstance(rval, ast.Dict):
            return None
        keys = set()
        for item in rval.keys:
            if item is None:
                return None
            if isinstance(item, ast.Constant):
                key_value = item.value
            elif isinstance(item, ast.Name):
                key_value = _constant_name_value(state, source_var, item.id)
            else:
                return None
            if not isinstance(key_value, str):
                return None
            keys.add(key_value)
        possibilities.add(frozenset(keys))
    return tuple(sorted(possibilities, key=lambda keys: tuple(sorted(keys))))


def bind_arguments(state, scope, context, func_args, call, *, leading_positional=0):
    """Classify a call using Python's positional/keyword binding rules.

    Unknown unpacking sources produce ``MAYBE_VALID``.  A call is rejected only
    when every represented runtime alternative is invalid.
    """
    positional = [*getattr(func_args, "posonlyargs", ()), *func_args.args]
    positional_names = [param.arg for param in positional]
    regular_names = {param.arg for param in func_args.args}
    posonly_names = {param.arg for param in getattr(func_args, "posonlyargs", ())}
    kwonly_names = {param.arg for param in func_args.kwonlyargs}
    keyword_names = regular_names | kwonly_names
    accepted_keyword_names = keyword_names

    possible_counts = {leading_positional}
    uncertain = False
    for source, is_starred in call.iter_args():
        if not is_starred:
            possible_counts = {count + 1 for count in possible_counts}
            continue
        source_var = state.get_variable(scope, context, source)
        lengths = _star_lengths(state, source_var)
        if lengths is None:
            uncertain = True
            possible_counts = None
            break
        possible_counts = {
            count + length for count, length in product(possible_counts, lengths)
        }

    explicit_keywords = [name for name, _ in call.kwargs if name is not None]
    dstar_key_options = []
    for name, source in call.kwargs:
        if name is not None:
            continue
        source_var = state.get_variable(scope, context, source)
        # Dicts are mutable and may alias; allocation-site keys cannot prove
        # current presence or absence at the call.
        uncertain = True

    diagnostics = []
    invalid_for_all = False

    guaranteed_keywords = set(explicit_keywords)
    possible_keywords = set(explicit_keywords)
    for options in dstar_key_options:
        if not options:
            continue
        guaranteed_keywords.update(set.intersection(*(set(keys) for keys in options)))
        possible_keywords.update(set.union(*(set(keys) for keys in options)))

    # A positional argument always binds before keywords are considered.
    for name in possible_keywords & regular_names:
        index = positional_names.index(name)
        if possible_counts is None:
            uncertain = True
        elif (
            name in guaranteed_keywords
            and possible_counts
            and all(count > index for count in possible_counts)
        ):
            diagnostics.append(f"multiple values for argument '{name}'")
            invalid_for_all = True
        elif any(count > index for count in possible_counts):
            uncertain = True

    if not func_args.vararg and possible_counts is not None:
        capacity = len(positional)
        if possible_counts and all(count > capacity for count in possible_counts):
            diagnostics.append(
                f"too many positional arguments (expected at most {capacity})"
            )
            invalid_for_all = True
        elif any(count > capacity for count in possible_counts):
            uncertain = True

    if not func_args.kwarg:
        unexpected = [
            name for name in explicit_keywords
            if name not in accepted_keyword_names
        ]
        if unexpected:
            diagnostics.append(
                "unexpected keyword argument(s): " + ", ".join(unexpected)
            )
            invalid_for_all = True
        for options in dstar_key_options:
            if options and all(
                any(key not in accepted_keyword_names for key in keys)
                for keys in options
            ):
                diagnostics.append("** mapping contains unexpected keyword(s)")
                invalid_for_all = True
            elif any(
                any(key not in accepted_keyword_names for key in keys)
                for keys in options
            ):
                uncertain = True

    # Positional-only names passed explicitly are unexpected unless **kwargs
    # collects them (PEP 570).
    if not func_args.kwarg and any(name in posonly_names for name in explicit_keywords):
        diagnostics.append("positional-only argument passed as keyword")
        invalid_for_all = True

    # Duplicate known keyword keys, including across multiple ** mappings.
    if all(len(options) == 1 for options in dstar_key_options):
        seen = set(explicit_keywords)
        for options in dstar_key_options:
            keys = set(options[0])
            overlap = seen & keys
            if overlap:
                diagnostics.append(
                    "multiple values for keyword(s): " + ", ".join(sorted(overlap))
                )
                invalid_for_all = True
            seen.update(keys)
    elif dstar_key_options:
        uncertain = True

    positional_defaults = len(func_args.defaults)
    required_positional = len(positional) - positional_defaults
    supplied_known_keywords = set(explicit_keywords)
    if all(len(options) == 1 for options in dstar_key_options):
        for options in dstar_key_options:
            supplied_known_keywords.update(options[0])
    elif dstar_key_options:
        uncertain = True

    if possible_counts is not None and not uncertain:
        missing_in_every_alternative = []
        for index, name in enumerate(positional_names[:required_positional]):
            if name in posonly_names:
                supplied = any(count > index for count in possible_counts)
            else:
                supplied = (
                    any(count > index for count in possible_counts)
                    or name in supplied_known_keywords
                )
            if not supplied:
                missing_in_every_alternative.append(name)
        required_kwonly = {
            param.arg
            for index, param in enumerate(func_args.kwonlyargs)
            if not func_args.kw_defaults or func_args.kw_defaults[index] is None
        }
        missing_in_every_alternative.extend(
            sorted(required_kwonly - supplied_known_keywords)
        )
        if missing_in_every_alternative:
            diagnostics.append(
                "missing required argument(s): "
                + ", ".join(missing_in_every_alternative)
            )
            invalid_for_all = True

    if invalid_for_all:
        return ArgumentBinding(BindingStatus.DEFINITELY_INVALID, tuple(diagnostics))
    if uncertain:
        return ArgumentBinding(BindingStatus.MAYBE_VALID, tuple(diagnostics))
    return ArgumentBinding(BindingStatus.VALID, tuple(diagnostics))
