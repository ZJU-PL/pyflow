"""Lian-compatible GIR post-processing passes.

The three passes here replicate ``lian.events.default_event_handlers``:

* :func:`unify_python_self`      - ``basic.unify_python_self``: drop the
  implicit ``self`` parameter of class methods and rewrite references to
  ``%this``.
* :func:`adjust_variable_decls`  - ``add_var_decl.adjust_variable_decls``:
  merge ``d = %vvN`` back into the statement that produced ``%vvN``, then
  hoist and deduplicate ``variable_decl`` rows to the enclosing
  function/class top level (Python-style).
* :func:`add_main_func`          - ``basic.add_main_func``: wrap top-level
  executable statements into a synthetic ``%unit_init`` method.

Order of application (matching Lian's pipeline): unify_python_self and
adjust_variable_decls operate on the *unflattened* tree; add_main_func
operates on the *flattened* row list, followed by
:func:`add_unit_gir` which stamps ``unit_id`` on every row.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pyflow.ir.gir.constants import LIAN_INTERNAL

# Statement types that can produce a temporary variable and therefore are
# eligible for ``d = %vvN`` fusion. Mirrors add_var_decl.CAN_OPTIMIZE_OPS.
CAN_OPTIMIZE_OPS = frozenset(
    {
        "array_read",
        "assign_stmt",
        "call_stmt",
        "addr_of",
        "field_read",
        "asm_stmt",
        "mem_read",
        "type_cast_stmt",
        "new_object",
    }
)

# Flattened row operations that keep a row at module top level instead of
# wrapping it into %unit_init. Mirrors basic.add_main_func.
_EXCLUDED_TOP_LEVEL_OPS = frozenset(
    {"import_stmt", "from_import_stmt", "export_stmt", "type_alias_decl"}
)


# ---------------------------------------------------------------------------
# unify_python_self
# ---------------------------------------------------------------------------
def find_python_method_first_parameter(method_decl: Dict[str, Any]) -> str:
    if "method_decl" not in method_decl:
        return ""
    decl = method_decl["method_decl"]
    if "attrs" in decl and "staticmethod" in decl["attrs"]:
        return ""
    if "parameters" in decl:
        parameters = decl["parameters"]
        for counter, stmt in enumerate(parameters):
            if "parameter_decl" in stmt:
                decl["parameters"] = parameters[counter + 1 :]
                return stmt["parameter_decl"].get("name", "")
    return ""


def _adjust_python_self(
    obj: Any,
    first_parameter_name: str = "",
    new_name: str = LIAN_INTERNAL.THIS,
    under_class_decl: bool = False,
) -> None:
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (list, dict)):
                _adjust_python_self(
                    item, first_parameter_name, new_name, under_class_decl
                )
            elif (
                under_class_decl
                and isinstance(item, str)
                and item == first_parameter_name
            ):
                obj[i] = new_name
        return

    if isinstance(obj, dict):
        if "class_decl" in obj:
            current_class = obj["class_decl"]
            if "methods" in current_class:
                for each_method in current_class["methods"]:
                    first_one = find_python_method_first_parameter(each_method)
                    decl = each_method.get("method_decl", {})
                    if "attrs" not in decl:
                        continue
                    if (
                        first_one
                        and "body" in decl
                        and "staticmethod" not in decl["attrs"]
                    ):
                        _adjust_python_self(
                            decl["body"], first_one, under_class_decl=True
                        )
            return
        if "method_decl" in obj:
            decl = obj["method_decl"]
            if "body" in decl:
                if "attrs" not in decl:
                    _adjust_python_self(decl["body"])
                elif "staticmethod" not in decl["attrs"]:
                    _adjust_python_self(decl["body"])
            return
        for key, value in obj.items():
            if key == "attrs":
                continue
            if isinstance(value, (list, dict)):
                _adjust_python_self(
                    value, first_parameter_name, new_name, under_class_decl
                )
            elif (
                first_parameter_name
                and isinstance(value, str)
                and value == first_parameter_name
            ):
                obj[key] = new_name


def unify_python_self(tree: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop implicit ``self`` from class methods and rewrite to ``%this``."""
    _adjust_python_self(tree)
    return tree


# ---------------------------------------------------------------------------
# remove_unnecessary_tmp_variables (tree form)
# ---------------------------------------------------------------------------
def _extract_stmt_info(
    stmt_dict: Any,
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not isinstance(stmt_dict, dict) or not stmt_dict:
        return None, None
    op = next(iter(stmt_dict.keys()))
    content = stmt_dict[op]
    return (op, content) if isinstance(content, dict) else (None, None)


def _remove_unnecessary_tmp_variables_in_list(stmts: List[Any]) -> None:
    if len(stmts) < 2:
        return
    lookback_limit = 3
    for i in range(len(stmts) - 1, 0, -1):
        curr_op, curr_content = _extract_stmt_info(stmts[i])
        if (
            curr_op != "assign_stmt"
            or not curr_content
            or curr_content.get("operand2")
            or curr_content.get("operator")
        ):
            continue
        final_target = curr_content.get("target")
        temp_var = curr_content.get("operand")
        if not temp_var or not temp_var.startswith(LIAN_INTERNAL.VARIABLE_DECL_PREF):
            continue
        search_limit = max(-1, i - 1 - lookback_limit)
        for k in range(i - 1, search_limit, -1):
            prev_op, prev_content = _extract_stmt_info(stmts[k])
            if not prev_op:
                break
            if prev_op == "variable_decl":
                continue
            prev_target = prev_content.get("target")
            if prev_target == temp_var and prev_op in CAN_OPTIMIZE_OPS:
                prev_content["target"] = final_target
                del stmts[i]
                break
            break


def _recursive_remove_tmp_vars(obj: Any) -> None:
    if isinstance(obj, list):
        _remove_unnecessary_tmp_variables_in_list(obj)
        for item in obj:
            _recursive_remove_tmp_vars(item)
    elif isinstance(obj, dict):
        for value in obj.values():
            _recursive_remove_tmp_vars(value)


# ---------------------------------------------------------------------------
# adjust_variable_decls (tree form)
# ---------------------------------------------------------------------------
@dataclass
class StackFrame:
    stmts: List[Any]
    variables: Dict[str, bool] = field(default_factory=dict)
    in_block: bool = False
    hoist_collector: List[Dict[str, Any]] = field(default_factory=list)
    index: int = 0
    to_delete_indices: List[int] = field(default_factory=list)


def _process_variable_decl(
    frame: StackFrame,
    value: Dict[str, Any],
    index: int,
    is_python_like: bool,
    global_stmts: List[Dict[str, Any]],
) -> None:
    name = value.get("name")
    attrs = value.get("attrs", [])
    if is_python_like:
        if name in frame.variables:
            frame.to_delete_indices.append(index)
        else:
            frame.variables[name] = True
            frame.to_delete_indices.append(index)
            if frame.hoist_collector is not None:
                frame.hoist_collector.append({"variable_decl": value})
    else:
        if "var" in attrs:
            if name in frame.variables:
                frame.to_delete_indices.append(index)
            else:
                frame.variables[name] = True
                frame.to_delete_indices.append(index)
                if frame.hoist_collector is not None:
                    frame.hoist_collector.append({"variable_decl": value})
        elif "global" in attrs:
            if name in frame.variables:
                frame.to_delete_indices.append(index)
            else:
                frame.variables[name] = True
                frame.to_delete_indices.append(index)
                global_stmts.append({"variable_decl": value})
        elif "let" in attrs or "const" in attrs:
            if name in frame.variables and frame.variables.get(name) is False:
                frame.to_delete_indices.append(index)
            else:
                frame.variables[name] = False


def _finalize_frame(frame: StackFrame, is_python_like: bool) -> None:
    stmts = frame.stmts
    for idx in sorted(frame.to_delete_indices, reverse=True):
        if idx < len(stmts):
            stmts.pop(idx)
    if is_python_like:
        if not frame.in_block and frame.hoist_collector:
            for stmt in frame.hoist_collector:
                stmts.insert(0, stmt)
            frame.hoist_collector.clear()
    else:
        if frame.hoist_collector:
            for stmt in frame.hoist_collector:
                stmts.insert(0, stmt)
    if not is_python_like and frame.in_block:
        vars_to_remove = [k for k, v in frame.variables.items() if v is False]
        for k in vars_to_remove:
            del frame.variables[k]


def adjust_variable_decls(
    tree: List[Dict[str, Any]], is_python_like: bool = True
) -> List[Dict[str, Any]]:
    """Fuse temporary assignments, then hoist and dedupe variable_decls."""
    _recursive_remove_tmp_vars(tree)

    global_stmts_to_insert: List[Dict[str, Any]] = []
    stack: List[StackFrame] = [StackFrame(stmts=tree)]

    while stack:
        frame = stack[-1]
        if frame.index >= len(frame.stmts):
            stack.pop()
            _finalize_frame(frame, is_python_like)
            continue

        stmt = frame.stmts[frame.index]
        current_stmt_index = frame.index
        frame.index += 1

        if not isinstance(stmt, dict):
            continue

        key = next(iter(stmt.keys()))
        value = stmt[key]
        sub_frames: List[StackFrame] = []

        if key in (
            "class_decl",
            "interface_decl",
            "record_decl",
            "annotation_type_decl",
            "enum_decl",
            "struct_decl",
        ):
            for sub_key in ("methods", "fields", "nested"):
                if sub_key in value and value[sub_key]:
                    sub_frames.append(StackFrame(stmts=value[sub_key]))

        elif key == "method_decl":
            method_vars: Dict[str, bool] = {}
            if "parameters" in value:
                for param in value["parameters"]:
                    if isinstance(param, dict):
                        p_key = next(iter(param.keys()))
                        if p_key == "parameter_decl":
                            method_vars[param[p_key]["name"]] = True
            if "body" in value and value["body"]:
                sub_frames.append(
                    StackFrame(stmts=value["body"], variables=method_vars)
                )

        elif key == "variable_decl":
            _process_variable_decl(
                frame,
                value,
                current_stmt_index,
                is_python_like,
                global_stmts_to_insert,
            )

        elif key in ("global_stmt", "nonlocal_stmt"):
            name = value.get("name")
            if name in frame.variables:
                warnings.warn(
                    f"global or nonlocal variable <{name}> has defined!",
                    stacklevel=2,
                )
            else:
                frame.variables[name] = True

        elif key.endswith("_stmt"):
            for sub_key, sub_val in value.items():
                if sub_key.endswith("body") and isinstance(sub_val, list) and sub_val:
                    next_collector = frame.hoist_collector if is_python_like else []
                    sub_frames.append(
                        StackFrame(
                            stmts=sub_val,
                            variables=frame.variables,
                            in_block=True,
                            hoist_collector=next_collector,
                        )
                    )

        if sub_frames:
            for sub_frame in reversed(sub_frames):
                stack.append(sub_frame)

    for stmt in global_stmts_to_insert:
        tree.insert(0, stmt)

    return tree


# ---------------------------------------------------------------------------
# add_main_func (flattened row form)
# ---------------------------------------------------------------------------
def add_main_func(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Wrap top-level executable statements into a synthetic %unit_init."""
    out_data: List[Dict[str, Any]] = []
    top_stmts: List[Dict[str, Any]] = []
    regular_stmts: List[Dict[str, Any]] = []
    last_stmt_id = -1
    length = len(rows)
    index = 0

    while index < length:
        stmt = rows[index]
        last_stmt_id = max(last_stmt_id, stmt["stmt_id"])
        if stmt["parent_stmt_id"] == 0:
            if (
                stmt["operation"].endswith("_decl")
                or stmt["operation"] in _EXCLUDED_TOP_LEVEL_OPS
            ):
                regular_stmts.append(stmt)
                index += 1
            else:
                top_stmts.append(stmt)
                index += 1
                while index < length and rows[index]["parent_stmt_id"] != 0:
                    cur_top_stmt = rows[index]
                    top_stmts.append(cur_top_stmt)
                    last_stmt_id = max(last_stmt_id, cur_top_stmt["stmt_id"])
                    index += 1
        else:
            regular_stmts.append(stmt)
            index += 1

    out_data = regular_stmts
    if len(top_stmts) == 0:
        return rows

    main_method_stmt_id = last_stmt_id + 1
    main_method_body_id = last_stmt_id + 2
    out_data.append(
        {
            "operation": "method_decl",
            "parent_stmt_id": 0,
            "stmt_id": main_method_stmt_id,
            "name": LIAN_INTERNAL.UNIT_INIT,
            "body": main_method_body_id,
        }
    )
    out_data.append(
        {
            "operation": "block_start",
            "stmt_id": main_method_body_id,
            "parent_stmt_id": main_method_stmt_id,
        }
    )
    for stmt in top_stmts:
        if stmt["parent_stmt_id"] == 0:
            stmt["parent_stmt_id"] = main_method_body_id
        out_data.append(stmt)
    out_data.append(
        {
            "operation": "block_end",
            "stmt_id": main_method_body_id,
            "parent_stmt_id": main_method_stmt_id,
        }
    )
    return out_data


# ---------------------------------------------------------------------------
# add_unit_gir (flattened row form)
# ---------------------------------------------------------------------------
def add_unit_gir(rows: List[Dict[str, Any]], module_id: str) -> List[Dict[str, Any]]:
    """Stamp the owning module id on every row (mirrors lang_analysis.add_unit_gir)."""
    for stmt in rows:
        stmt["unit_id"] = module_id
    return rows
