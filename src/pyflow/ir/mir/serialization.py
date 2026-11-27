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

_TERM_SPECS = {
    kind: (
        constructor,
        frozenset(("kind", *schema)),
        tuple(schema.items()),
        issubclass(constructor, Instruction),
        issubclass(constructor, Expr),
        issubclass(constructor, LValue),
    )
    for kind, (constructor, schema) in _TERMS.items()
}
_PROGRAM_KEYS = frozenset(("version", "entry", "cfgs"))
_CFG_KEYS = frozenset(("name", "entry", "exit", "is_synthetic", "filename", "nodes"))
_NODE_KEYS = frozenset(("id", "instruction", "successors", "lineno"))


def _error(path: str, message: str):
    raise MIRValidationError(f"{path}: {message}")


def _object(data, path: str, keys: frozenset[str] | None = None):
    if type(data) is not dict:
        _error(path, "expected an object with string keys")
    if keys is not None:
        if data.keys() != keys:
            if any(type(key) is not str for key in data):
                _error(path, "expected an object with string keys")
            missing, extra = keys - data.keys(), data.keys() - keys
            _error(path, f"invalid fields (missing={sorted(missing)}, unknown={sorted(extra)})")
        return data
    if any(type(key) is not str for key in data):
        _error(path, "expected an object with string keys")
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


def _value(value, schema: str, path_fn):
    if schema == "string":
        if type(value) is not str:
            _error(path_fn(), "expected a string")
        return value
    if schema == "literal":
        if type(value) not in (bool, int, str):
            _error(path_fn(), "a MIR literal must be a Boolean, integer, or string")
        return value
    if schema == "expr":
        return _term(value, path_fn, Expr)
    if schema == "lvalue":
        return _term(value, path_fn, LValue)
    if schema == "references":
        if type(value) is not list:
            _error(path_fn(), "expected an array")
        return tuple(
            _term(item, lambda i=index: f"{path_fn()}[{i}]", LValue)
            for index, item in enumerate(value)
        )
    if type(value) is not list:
        _error(path_fn(), "expected an array")
    pairs = []
    for index, pair in enumerate(value):
        if type(pair) is not list:
            _error(f"{path_fn()}[{index}]", "expected an array")
        if len(pair) != 2:
            _error(f"{path_fn()}[{index}]", "expected a [string, l-value] pair")
        k = pair[0]
        if type(k) is not str:
            _error(f"{path_fn()}[{index}][0]", "expected a string")
        pairs.append((k, _term(pair[1], lambda i=index: f"{path_fn()}[{i}][1]", LValue)))
    return tuple(pairs)


def _term(data, path_fn, expected):
    if type(data) is not dict:
        _error(path_fn(), "expected an object with string keys")
    kind = data.get("kind")
    spec = _TERM_SPECS.get(kind) if type(kind) is str else None
    if spec is None:
        if any(type(key) is not str for key in data):
            _error(path_fn(), "expected an object with string keys")
        _error(path_fn(), f"unknown MIR term kind {kind!r}")
    constructor, expected_keys, fields, is_instr, is_expr, is_lvalue = spec
    if data.keys() != expected_keys:
        if any(type(key) is not str for key in data):
            _error(path_fn(), "expected an object with string keys")
        missing, extra = expected_keys - data.keys(), data.keys() - expected_keys
        _error(path_fn(), f"invalid fields (missing={sorted(missing)}, unknown={sorted(extra)})")
    if expected is Instruction:
        valid = is_instr
    elif expected is Expr:
        valid = is_expr
    elif expected is LValue:
        valid = is_lvalue
    else:
        valid = issubclass(constructor, expected)
    if not valid:
        _error(path_fn(), f"{kind} is not a {expected.__name__}")
    if not fields:
        return constructor()
    arguments = {
        name: _value(data[name], field_schema, lambda n=name: f"{path_fn()}.{n}")
        for name, field_schema in fields
    }
    return constructor(**arguments)


def program_from_dict(data: dict[str, Any]) -> Program:
    """Decode ``Program.to_dict()`` output and validate grammar and CFG links.

    The version-1 schema is exact: required metadata must be present, unknown
    fields are rejected, node-map keys are canonical integer strings, and
    instruction/expression kinds come only from the seven-instruction model.
    """
    _object(data, "program", _PROGRAM_KEYS)
    if type(data["version"]) is not int or data["version"] != 1:
        _error("program.version", "only MIR schema version 1 is supported")
    entry = _string(data["entry"], "program.entry")
    cfgs = {}
    for name, raw_cfg in _object(data["cfgs"], "program.cfgs").items():
        cfg_path = lambda n=name: f"program.cfgs[{n!r}]"
        if type(raw_cfg) is not dict or raw_cfg.keys() != _CFG_KEYS:
            _object(raw_cfg, cfg_path(), _CFG_KEYS)
        is_synthetic = raw_cfg["is_synthetic"]
        if type(is_synthetic) is not bool:
            _error(f"{cfg_path()}.is_synthetic", "expected a Boolean")
        raw_nodes = raw_cfg["nodes"]
        if type(raw_nodes) is not dict:
            _error(f"{cfg_path()}.nodes", "expected an object with string keys")
        nodes = {}
        for key, raw_node in raw_nodes.items():
            if type(key) is not str:
                _error(f"{cfg_path()}.nodes", "expected an object with string keys")
            try:
                node_id = int(key)
            except ValueError:
                _error(
                    f"{cfg_path()}.nodes[{key!r}]", "node key must be a canonical integer string"
                )
            if str(node_id) != key:
                _error(
                    f"{cfg_path()}.nodes[{key!r}]", "node key must be a canonical integer string"
                )
            if type(raw_node) is not dict or raw_node.keys() != _NODE_KEYS:
                _object(raw_node, f"{cfg_path()}.nodes[{key!r}]", _NODE_KEYS)
            lineno = raw_node["lineno"]
            if lineno is not None and type(lineno) is not int:
                _error(
                    f"{cfg_path()}.nodes[{key!r}].lineno",
                    "expected an integer, not a Boolean or string",
                )
            nid = raw_node["id"]
            if type(nid) is not int:
                _error(
                    f"{cfg_path()}.nodes[{key!r}].id",
                    "expected an integer, not a Boolean or string",
                )
            raw_succs = raw_node["successors"]
            if type(raw_succs) is not list:
                _error(f"{cfg_path()}.nodes[{key!r}].successors", "expected an array")
            succs = []
            for index, value in enumerate(raw_succs):
                if type(value) is not int:
                    _error(
                        f"{cfg_path()}.nodes[{key!r}].successors[{index}]",
                        "expected an integer, not a Boolean or string",
                    )
                succs.append(value)
            instr = _term(
                raw_node["instruction"],
                lambda cp=cfg_path, k=key: f"{cp()}.nodes[{k!r}].instruction",
                Instruction,
            )
            nodes[node_id] = Node(nid, instr, tuple(succs), lineno)
        cfg_name = raw_cfg["name"]
        if type(cfg_name) is not str:
            _error(f"{cfg_path()}.name", "expected a string")
        cfg_entry = raw_cfg["entry"]
        if type(cfg_entry) is not int:
            _error(f"{cfg_path()}.entry", "expected an integer, not a Boolean or string")
        cfg_exit = raw_cfg["exit"]
        if type(cfg_exit) is not int:
            _error(f"{cfg_path()}.exit", "expected an integer, not a Boolean or string")
        cfg_filename = raw_cfg["filename"]
        if type(cfg_filename) is not str:
            _error(f"{cfg_path()}.filename", "expected a string")
        cfgs[name] = CFG(cfg_name, nodes, cfg_entry, cfg_exit, is_synthetic, cfg_filename)
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
