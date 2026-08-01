"""Human-readable rendering of flattened GIR rows.

The output style follows Lian's ``util.readable_gir`` where applicable; the
top-level header uses pyflow's ``cli/ir.write_ir_file`` convention
(``{ir_type} for function: {function_name}`` + rule line) so the GIR dump
integrates with the existing ``pyflow ir`` CLI.
"""

from __future__ import annotations

import ast as python_ast
from typing import Any, Dict, List

_INDENT = "    "


def _fmt_arg(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, str) and value.startswith("[") and value.endswith("]"):
        # Flattened rows stringify argument lists (see flatten.py); recover
        # them so calls render as f(x, y) instead of f(['x', 'y']).
        try:
            return ", ".join(str(v) for v in python_ast.literal_eval(value))
        except (ValueError, SyntaxError):
            pass
    return str(value)


def _fmt_params(params: Any) -> str:
    if not params:
        return ""
    parts = []
    for param in params:
        if not isinstance(param, dict):
            continue
        if "parameter_decl" in param:
            decl = param["parameter_decl"]
        elif param.get("operation") == "parameter_decl":
            decl = param
        else:
            continue
        if isinstance(decl, dict):
            name = decl.get("name", "")
            attrs = _as_collection(decl.get("attrs"))
            if "%packed_pos_pmt" in attrs:
                name = f"*{name}"
            elif "%packed_named_pmt" in attrs:
                name = f"**{name}"
            data_type = decl.get("data_type")
            if data_type:
                name = f"{name}: {data_type}"
            if decl.get("default_value") is not None:
                parts.append(f"{name}={decl['default_value']}")
            else:
                parts.append(name)
    return ", ".join(parts)


def _as_collection(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = python_ast.literal_eval(value)
            if isinstance(parsed, (list, tuple, set)):
                return list(parsed)
        except (ValueError, SyntaxError):
            pass
    return [value]


def _fmt_call_args(row: Dict[str, Any]) -> str:
    args = [str(value) for value in _as_collection(row.get("positional_args"))]
    packed_positional = row.get("packed_positional_args")
    if packed_positional:
        args.append(f"*{packed_positional}")
    named = row.get("named_args")
    if isinstance(named, str):
        try:
            named = python_ast.literal_eval(named)
        except (ValueError, SyntaxError):
            named = None
    if isinstance(named, dict):
        args.extend(f"{key}={value}" for key, value in named.items())
    packed_named = row.get("packed_named_args")
    if packed_named:
        args.append(f"**{packed_named}")
    return ", ".join(args)


def _fmt_block(rows: List[Dict[str, Any]], level: int) -> List[str]:
    out: List[str] = []
    for index in range(len(rows)):
        out.extend(_fmt_row(rows, index, level))
    return out


def _method_param_rows(
    rows: List[Dict[str, Any]], start_index: int
) -> List[Dict[str, Any]]:
    """Collect the flattened parameter_decl rows owned by a method_decl."""
    block_id = rows[start_index].get("parameters")
    if not isinstance(block_id, int):
        return []
    params: List[Dict[str, Any]] = []
    for row in rows[start_index + 1 :]:
        if row.get("operation") == "block_end" and row.get("stmt_id") == block_id:
            break
        if row.get("operation") == "parameter_decl" and row.get(
            "parent_stmt_id"
        ) == block_id:
            params.append(row)
    return params


def _fmt_row(rows: List[Dict[str, Any]], index: int, level: int) -> List[str]:
    row = rows[index]
    op = row.get("operation", "")
    indent = _INDENT * level
    out: List[str] = []

    if op == "block_start":
        out.append(f"{indent}{{")
        return out
    if op == "block_end":
        out.append(f"{indent}}}")
        return out

    if op == "variable_decl":
        name = row.get("name", "")
        out.append(f"{indent}decl {name}")
    elif op == "parameter_decl":
        out.append(f"{indent}param {row.get('name', '')}")
    elif op == "method_decl":
        attrs = _as_collection(row.get("attrs"))
        prefix = "async " if "async" in attrs else ""
        return_type = f" -> {row['data_type']}" if row.get("data_type") else ""
        out.append(
            f"{indent}{prefix}def {row.get('name', '')}("
            f"{_fmt_params(_method_param_rows(rows, index))}){return_type}:"
        )
    elif op == "class_decl":
        type_parameters = row.get("type_parameters")
        generic = f"[{type_parameters}]" if type_parameters else ""
        out.append(
            f"{indent}class {row.get('name', '')}{generic}"
            f"({_fmt_arg(row.get('supers'))}):"
        )
    elif op == "assign_stmt":
        if row.get("operator"):
            out.append(
                f"{indent}{row.get('target', '')} = "
                f"{_fmt_arg(row.get('operand'))} {row.get('operator')} "
                f"{_fmt_arg(row.get('operand2'))}"
            )
        else:
            out.append(
                f"{indent}{row.get('target', '')} = "
                f"{_fmt_arg(row.get('operand'))}"
            )
    elif op == "call_stmt":
        out.append(
            f"{indent}{row.get('target', '')} = "
            f"{row.get('name', '')}({_fmt_call_args(row)})"
        )
    elif op == "object_call_stmt":
        out.append(
            f"{indent}{row.get('target', '')} = "
            f"{row.get('receiver_object', '')}.{row.get('field', '')}("
            f"{_fmt_call_args(row)})"
        )
    elif op == "field_read":
        out.append(
            f"{indent}{row.get('target', '')} = "
            f"{row.get('receiver_object', '')}.{row.get('field', '')}"
        )
    elif op == "field_write":
        out.append(
            f"{indent}{row.get('receiver_object', '')}.{row.get('field', '')} = "
            f"{_fmt_arg(row.get('source'))}"
        )
    elif op == "array_read":
        out.append(
            f"{indent}{row.get('target', '')} = "
            f"{row.get('array', '')}[{_fmt_arg(row.get('index'))}]"
        )
    elif op == "array_write":
        out.append(
            f"{indent}{row.get('array', '')}[{_fmt_arg(row.get('index'))}] = "
            f"{_fmt_arg(row.get('source'))}"
        )
    elif op == "array_append":
        out.append(
            f"{indent}{row.get('array', '')}.append({_fmt_arg(row.get('source'))})"
        )
    elif op == "array_extend":
        out.append(
            f"{indent}{row.get('array', '')}.extend({_fmt_arg(row.get('source'))})"
        )
    elif op == "slice_read":
        out.append(
            f"{indent}{row.get('target', '')} = "
            f"{row.get('array', '')}[{_fmt_arg(row.get('start'))}:"
            f"{_fmt_arg(row.get('end'))}:{_fmt_arg(row.get('step'))}]"
        )
    elif op == "slice_write":
        out.append(
            f"{indent}{row.get('array', '')}[{_fmt_arg(row.get('start'))}:"
            f"{_fmt_arg(row.get('end'))}] = {_fmt_arg(row.get('source'))}"
        )
    elif op == "new_array":
        out.append(f"{indent}{row.get('target', '')} = []")
    elif op == "new_record":
        out.append(f"{indent}{row.get('target', '')} = {{}}")
    elif op == "record_write":
        out.append(
            f"{indent}{row.get('receiver_record', '')}"
            f"[{_fmt_arg(row.get('key'))}] = {_fmt_arg(row.get('value'))}"
        )
    elif op == "record_extend":
        out.append(
            f"{indent}{row.get('record', '')}.update({_fmt_arg(row.get('source'))})"
        )
    elif op == "if_stmt":
        out.append(f"{indent}if ({_fmt_arg(row.get('condition'))}):")
    elif op == "while_stmt":
        out.append(f"{indent}while ({_fmt_arg(row.get('condition'))}):")
    elif op == "forin_stmt":
        out.append(
            f"{indent}for {_fmt_arg(row.get('name'))} in "
            f"{_fmt_arg(row.get('receiver'))}:"
        )
    elif op == "return_stmt":
        out.append(f"{indent}return {_fmt_arg(row.get('name'))}")
    elif op == "throw_stmt":
        out.append(f"{indent}raise {_fmt_arg(row.get('name'))}")
    elif op == "assert_stmt":
        out.append(f"{indent}assert {_fmt_arg(row.get('condition'))}")
    elif op == "break_stmt":
        out.append(f"{indent}break")
    elif op == "continue_stmt":
        out.append(f"{indent}continue")
    elif op == "pass_stmt":
        out.append(f"{indent}pass")
    elif op == "del_stmt":
        out.append(f"{indent}del {_fmt_arg(row.get('name'))}")
    elif op == "global_stmt":
        out.append(f"{indent}global {_fmt_arg(row.get('name'))}")
    elif op == "nonlocal_stmt":
        out.append(f"{indent}nonlocal {_fmt_arg(row.get('name'))}")
    elif op == "yield_stmt":
        out.append(f"{indent}yield {_fmt_arg(row.get('target'))}")
    elif op == "await_stmt":
        out.append(f"{indent}await {_fmt_arg(row.get('target'))}")
    elif op == "try_stmt":
        out.append(f"{indent}try:")
    elif op == "catch_clause":
        out.append(
            f"{indent}except {_fmt_arg(row.get('expcetion'))} as "
            f"{_fmt_arg(row.get('as'))}:"
        )
    elif op == "with_stmt":
        out.append(f"{indent}with {_fmt_arg(row.get('receiver'))}:")
    elif op == "switch_stmt":
        out.append(f"{indent}switch ({_fmt_arg(row.get('condition'))}):")
    elif op == "case_stmt":
        out.append(f"{indent}case {_fmt_arg(row.get('condition'))}:")
    elif op == "default_stmt":
        out.append(f"{indent}default:")
    elif op == "type_alias_decl":
        out.append(
            f"{indent}type {row.get('name', '')} = {_fmt_arg(row.get('data_type'))}"
        )
    elif op == "import_stmt":
        name = row.get("name", "")
        alias = row.get("alias")
        if alias and alias != name:
            out.append(f"{indent}import {name} as {alias}")
        else:
            out.append(f"{indent}import {name}")
    elif op == "from_import_stmt":
        source = row.get("source", "")
        name = row.get("name", "")
        alias = row.get("alias")
        suffix = f" as {alias}" if alias and alias != name else ""
        out.append(f"{indent}from {source} import {name}{suffix}")
    elif op == "phi_stmt":
        out.append(f"{indent}{row.get('target', '')} = phi")
    else:
        out.append(f"{indent}{op} {_fmt_arg(row.get('stmt_id'))}")
    return out


def readable_gir(rows: List[Dict[str, Any]]) -> str:
    """Render flattened rows into a readable, indented block layout."""
    return "\n".join(_fmt_block(rows, 0))


def dump_gir_content(rows: List[Dict[str, Any]]) -> str:
    """Produce the full dump body for a unit (module-level GIR)."""
    return readable_gir(rows) + "\n"
