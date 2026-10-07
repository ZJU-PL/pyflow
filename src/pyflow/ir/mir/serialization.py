"""Strict, data-only loading of version-1 MIR JSON dumps.

Term names are selected from a fixed constructor table.  Decoding never
evaluates source, imports a class named by input data, or executes a payload.
"""

from __future__ import annotations

import json
from typing import Any

from .model import (
    Alloc,
    Assume,
    Attr,
    Binary,
    Bind,
    Call,
    CFG,
    Delete,
    DictExpr,
    Env,
    Expr,
    Instruction,
    Lambda,
    Length,
    ListExpr,
    Literal,
    LValue,
    MIRValidationError,
    NewObject,
    Node,
    Not,
    Program,
    Skip,
    Var,
)

_TERMS = {
    "Var": (Var, {"name": "string"}),
    "Attr": (Attr, {"base": "lvalue", "key": "expr"}),
    "Literal": (Literal, {"value": "literal"}),
    "NewObject": (NewObject, {}),
    "ListExpr": (ListExpr, {"items": "references"}),
    "DictExpr": (DictExpr, {"items": "pairs"}),
    "Lambda": (
        Lambda,
        {
            "args_param": "string",
            "kwargs_param": "string",
            "parent_param": "string",
            "body": "string",
            "return_var": "string",
        },
    ),
    "Not": (Not, {"operand": "expr"}),
    "Length": (Length, {"operand": "expr"}),
    "Binary": (Binary, {"op": "string", "left": "expr", "right": "expr"}),
    "Skip": (Skip, {}),
    "Assume": (Assume, {"condition": "expr"}),
    "Alloc": (Alloc, {"target": "string", "value": "expr"}),
    "Bind": (Bind, {"target": "lvalue", "source": "lvalue"}),
    "Env": (Env, {"target": "string"}),
    "Delete": (Delete, {"target": "lvalue"}),
    "Call": (
        Call,
        {
            "target": "string",
            "function": "expr",
            "args": "lvalue",
            "kwargs": "lvalue",
        },
    ),
}


def _error(path: str, message: str):
    raise MIRValidationError(f"{path}: {message}")


def _object(data, path: str, keys=None):
    if type(data) is not dict or any(type(key) is not str for key in data):
        _error(path, "expected an object with string keys")
    if keys is not None and set(data) != set(keys):
        missing, extra = set(keys) - set(data), set(data) - set(keys)
        _error(path, f"invalid fields (missing={sorted(missing)}, unknown={sorted(extra)})")
    return data


def _string(value, path: str):
    if type(value) is not str:
        _error(path, "expected a string")
    return value


def _integer(value, path: str):
    if type(value) is not int:
        _error(path, "expected an integer, not a Boolean or string")
    return value


def _array(value, path: str):
    if type(value) is not list:
        _error(path, "expected an array")
    return value


def _value(value, schema: str, path: str):
    if schema == "string":
        return _string(value, path)
    if schema == "literal":
        if type(value) not in (bool, int, str):
            _error(path, "a MIR literal must be a Boolean, integer, or string")
        return value
    if schema in {"expr", "lvalue"}:
        return _term(value, path, LValue if schema == "lvalue" else Expr)
    if schema == "references":
        return tuple(
            _term(item, f"{path}[{index}]", LValue)
            for index, item in enumerate(_array(value, path))
        )
    pairs = []
    for index, pair in enumerate(_array(value, path)):
        item_path = f"{path}[{index}]"
        if len(_array(pair, item_path)) != 2:
            _error(item_path, "expected a [string, l-value] pair")
        pairs.append(
            (
                _string(pair[0], f"{item_path}[0]"),
                _term(pair[1], f"{item_path}[1]", LValue),
            )
        )
    return tuple(pairs)


def _term(data, path: str, expected):
    _object(data, path)
    kind = data.get("kind")
    if type(kind) is not str or kind not in _TERMS:
        _error(path, f"unknown MIR term kind {kind!r}")
    constructor, schema = _TERMS[kind]
    _object(data, path, {"kind", *schema})
    if not issubclass(constructor, expected):
        _error(path, f"{kind} is not a {expected.__name__}")
    arguments = {
        name: _value(data[name], field_schema, f"{path}.{name}")
        for name, field_schema in schema.items()
    }
    return constructor(**arguments)


def program_from_dict(data: dict[str, Any]) -> Program:
    """Decode ``Program.to_dict()`` output and validate grammar and CFG links.

    The version-1 schema is exact: required metadata must be present, unknown
    fields are rejected, node-map keys are canonical integer strings, and
    instruction/expression kinds come only from the seven-instruction model.
    """
    _object(data, "program", {"version", "entry", "cfgs"})
    if type(data["version"]) is not int or data["version"] != 1:
        _error("program.version", "only MIR schema version 1 is supported")
    entry = _string(data["entry"], "program.entry")
    cfgs = {}
    for name, raw_cfg in _object(data["cfgs"], "program.cfgs").items():
        path = f"program.cfgs[{name!r}]"
        _object(raw_cfg, path, {"name", "entry", "exit", "is_synthetic", "filename", "nodes"})
        if type(raw_cfg["is_synthetic"]) is not bool:
            _error(f"{path}.is_synthetic", "expected a Boolean")
        nodes = {}
        for key, raw_node in _object(raw_cfg["nodes"], f"{path}.nodes").items():
            node_path = f"{path}.nodes[{key!r}]"
            try:
                node_id = int(key)
            except ValueError:
                _error(node_path, "node key must be a canonical integer string")
            if str(node_id) != key:
                _error(node_path, "node key must be a canonical integer string")
            _object(raw_node, node_path, {"id", "instruction", "successors", "lineno"})
            lineno = raw_node["lineno"]
            if lineno is not None:
                _integer(lineno, f"{node_path}.lineno")
            nodes[node_id] = Node(
                _integer(raw_node["id"], f"{node_path}.id"),
                _term(raw_node["instruction"], f"{node_path}.instruction", Instruction),
                tuple(
                    _integer(value, f"{node_path}.successors[{index}]")
                    for index, value in enumerate(
                        _array(raw_node["successors"], f"{node_path}.successors")
                    )
                ),
                lineno,
            )
        cfgs[name] = CFG(
            _string(raw_cfg["name"], f"{path}.name"),
            nodes,
            _integer(raw_cfg["entry"], f"{path}.entry"),
            _integer(raw_cfg["exit"], f"{path}.exit"),
            raw_cfg["is_synthetic"],
            _string(raw_cfg["filename"], f"{path}.filename"),
        )
    program = Program(cfgs, entry)
    program.validate()
    return program


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _error("JSON", f"duplicate object key {key!r}")
        value[key] = item
    return value


def program_from_json(source: str) -> Program:
    """Parse MIR JSON without accepting duplicate object keys or NaN literals."""
    if type(source) is not str:
        _error("JSON", "expected a JSON string")
    try:
        data = json.loads(
            source,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: _error("JSON", f"invalid constant {value!r}"),
        )
    except json.JSONDecodeError as exc:
        raise MIRValidationError(f"Invalid MIR JSON: {exc}") from exc
    return program_from_dict(data)


__all__ = ["program_from_dict", "program_from_json"]
