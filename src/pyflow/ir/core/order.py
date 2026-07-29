"""Deterministic structural ordering for analysis-owned context objects."""

from __future__ import annotations

import json

from pyflow.language.python import ast

from .catalog import IRCatalog
from .ids import ContextSignature


def _object_name(value: object) -> tuple[object, ...] | None:
    pyobj = getattr(value, "pyobj", None)
    if pyobj is None:
        return None
    module = getattr(pyobj, "__module__", None)
    qualname = getattr(pyobj, "__qualname__", None)
    if module is not None or qualname is not None:
        return ("python", module or "", qualname or repr(pyobj))
    if isinstance(pyobj, (str, bytes, int, float, bool, type(None))):
        return ("literal", type(pyobj).__name__, repr(pyobj))
    return ("object", type(pyobj).__module__, type(pyobj).__qualname__)


def stable_ir_key(
    value: object,
    catalog: IRCatalog,
    code: ast.Code,
    seen: frozenset[int] = frozenset(),
) -> tuple[object, ...]:
    """Return a process-independent ordering key for contexts/signatures."""
    if value is None or isinstance(value, (str, bytes, int, float, bool)):
        return (type(value).__name__, repr(value))
    if isinstance(value, (tuple, list)):
        return (
            type(value).__name__,
            *(stable_ir_key(item, catalog, code, seen) for item in value),
        )
    if isinstance(value, (set, frozenset)):
        return (
            type(value).__name__,
            *sorted(stable_ir_key(item, catalog, code, seen) for item in value),
        )
    if isinstance(value, ast.Code):
        try:
            return ("code", str(catalog.procedure(value).code_id))
        except KeyError:
            return ("code", value.codeName())
    if isinstance(value, ast.PythonASTNode):
        owner = getattr(value, "code", None)
        owner = owner if isinstance(owner, ast.Code) else code
        try:
            return ("node", str(catalog.node_id(value, owner)))
        except KeyError:
            return ("node", type(value).__name__, getattr(value, "name", None))

    named = _object_name(value)
    if named is not None:
        return named

    marker = id(value)
    if marker in seen:
        return ("cycle", type(value).__module__, type(value).__qualname__)
    nested_seen = seen | {marker}

    signature = getattr(value, "signature", None)
    if signature is not None:
        return (
            "context",
            stable_ir_key(signature, catalog, code, nested_seen),
            stable_ir_key(getattr(value, "opPath", None), catalog, code, nested_seen),
        )
    if all(hasattr(value, name) for name in ("code", "selfparam", "params")):
        signature_code = getattr(value, "code")
        return (
            "signature",
            stable_ir_key(signature_code, catalog, code, nested_seen),
            stable_ir_key(getattr(value, "selfparam"), catalog, code, nested_seen),
            stable_ir_key(getattr(value, "params"), catalog, code, nested_seen),
            stable_ir_key(getattr(value, "vparams", ()), catalog, code, nested_seen),
        )
    if all(hasattr(value, name) for name in ("code", "op", "context")):
        operation_code = getattr(value, "code")
        return (
            "operation-context",
            stable_ir_key(operation_code, catalog, code, nested_seen),
            stable_ir_key(getattr(value, "op"), catalog, operation_code, nested_seen),
            stable_ir_key(
                getattr(value, "context"), catalog, operation_code, nested_seen
            ),
        )

    slots = getattr(type(value), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    fields = []
    for name in slots:
        if name in {"group", "annotation"} or not hasattr(value, name):
            continue
        fields.append(
            (
                name,
                stable_ir_key(getattr(value, name), catalog, code, nested_seen),
            )
        )
    if fields:
        return (type(value).__module__, type(value).__qualname__, *fields)
    return (type(value).__module__, type(value).__qualname__)


def canonical_context_signature(
    context: object, catalog: IRCatalog, code: ast.Code
) -> ContextSignature:
    """Encode a solver context without discovery order or object addresses."""
    key = stable_ir_key(context, catalog, code)
    return ContextSignature(
        json.dumps(key, ensure_ascii=False, separators=(",", ":"))
    )


__all__ = ["canonical_context_signature", "stable_ir_key"]
