"""Lian-compatible GIR (graph intermediate representation) support.

GIR is emitted directly from pyflow's python AST and mirrors the
representation produced by Lian's Python frontend. The full lowering pipeline
for a ``pyflow.language.python.ast.Code`` object is::

    emit_unit -> unify_python_self -> adjust_variable_decls
        -> flatten -> add_main_func -> add_unit_gir

``build_gir`` wraps those steps and returns the flattened GIR rows (dicts)
stamped with the owning module id.
"""

from typing import Any, Dict, List

from pyflow.ir.gir.emitter import GirCompatibilityWarning, GirEmitter
from pyflow.ir.gir.flatten import GirFlattener
from pyflow.ir.gir.postprocess import (
    add_main_func,
    add_unit_gir,
    adjust_variable_decls,
    unify_python_self,
)
from pyflow.language.python import ast

__all__ = [
    "GirEmitter",
    "GirCompatibilityWarning",
    "GirFlattener",
    "add_main_func",
    "add_unit_gir",
    "adjust_variable_decls",
    "build_gir",
    "build_function_gir",
    "unify_python_self",
]


def _finish_gir(
    tree: List[Dict[str, Any]], module_id: str, start_id: int
) -> List[Dict[str, Any]]:
    unify_python_self(tree)
    adjust_variable_decls(tree)
    _, rows = GirFlattener(start_id=start_id).flatten(tree)
    rows = add_main_func(rows)
    add_unit_gir(rows, module_id)
    return rows


def build_gir(
    code: "ast.Code", module_id: str, *, start_id: int = 1
) -> List[Dict[str, Any]]:
    """Run the full GIR lowering pipeline over a pyflow Code object.

    Returns flattened GIR rows (dicts) stamped with ``module_id``.
    """
    tree = GirEmitter().emit_unit(code)
    return _finish_gir(tree, module_id, start_id)


def build_function_gir(
    code: "ast.Code", module_id: str, *, start_id: int = 1
) -> List[Dict[str, Any]]:
    """Build GIR for one function while preserving its method declaration."""
    tree = GirEmitter().emit_code(code)
    return _finish_gir(tree, module_id, start_id)
