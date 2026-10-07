"""The seven-instruction MIR language from the IFIP 2026 presentation.

The syntax follows slides 9--10 of ``ifip26.pdf``.  Expressions are pure;
allocation and reference binding are deliberately different instructions.
Python protocols belong in the lowering layer, not in this core language.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, fields
from typing import Any


class Expr:
    """A side-effect-free MIR expression."""

    def __str__(self) -> str:
        return format_expr(self)


class LValue(Expr):
    """A reference, dereferenced when used as an expression."""


@dataclass(frozen=True)
class Var(LValue):
    name: str


@dataclass(frozen=True)
class Attr(LValue):
    base: LValue
    key: Expr


@dataclass(frozen=True)
class Literal(Expr):
    value: bool | int | str

    def __post_init__(self) -> None:
        if type(self.value) not in (bool, int, str):
            raise TypeError("MIR literals must be booleans, integers, or strings")


@dataclass(frozen=True)
class NewObject(Expr):
    pass


@dataclass(frozen=True)
class ListExpr(Expr):
    items: tuple[LValue, ...]


@dataclass(frozen=True)
class DictExpr(Expr):
    items: tuple[tuple[str, LValue], ...]


@dataclass(frozen=True)
class Lambda(Expr):
    args_param: str
    kwargs_param: str
    parent_param: str
    body: str
    return_var: str


@dataclass(frozen=True)
class Not(Expr):
    operand: Expr


@dataclass(frozen=True)
class Length(Expr):
    operand: Expr


@dataclass(frozen=True)
class Binary(Expr):
    op: str
    left: Expr
    right: Expr


class Instruction:
    """One of MIR's seven memory-transforming commands."""

    def __str__(self) -> str:
        return format_instruction(self)


@dataclass(frozen=True)
class Skip(Instruction):
    pass


@dataclass(frozen=True)
class Assume(Instruction):
    condition: Expr


@dataclass(frozen=True)
class Alloc(Instruction):
    target: str
    value: Expr


@dataclass(frozen=True)
class Bind(Instruction):
    target: LValue
    source: LValue


@dataclass(frozen=True)
class Env(Instruction):
    target: str


@dataclass(frozen=True)
class Delete(Instruction):
    target: LValue


@dataclass(frozen=True)
class Call(Instruction):
    target: str
    function: Expr
    args: LValue
    kwargs: LValue


@dataclass
class Node:
    id: int
    instruction: Instruction
    successors: tuple[int, ...] = ()
    lineno: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "instruction": _encode(self.instruction),
            "successors": list(self.successors),
            "lineno": self.lineno,
        }


@dataclass
class CFG:
    name: str
    nodes: dict[int, Node]
    entry: int
    exit: int
    is_synthetic: bool = False
    filename: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "entry": self.entry,
            "exit": self.exit,
            "is_synthetic": self.is_synthetic,
            "filename": self.filename,
            "nodes": {str(key): self.nodes[key].to_dict() for key in sorted(self.nodes)},
        }


class MIRValidationError(ValueError):
    """A malformed MIR program, before execution or analysis."""


@dataclass
class Program:
    cfgs: dict[str, CFG]
    entry: str

    def validate(self) -> None:
        """Check graph references and the core grammar without requiring an AST.

        Unreachable nodes and a structurally unreachable exit are allowed: an
        infinite loop is a valid program.  Name availability is a runtime or
        static-analysis question, so this is not a definite-assignment check.
        """
        if self.entry not in self.cfgs:
            raise MIRValidationError(f"Unknown entry CFG: {self.entry!r}")
        for name, cfg in self.cfgs.items():
            if name != cfg.name:
                raise MIRValidationError(f"CFG key {name!r} does not match {cfg.name!r}")
            if cfg.entry not in cfg.nodes or cfg.exit not in cfg.nodes:
                raise MIRValidationError(f"CFG {name!r} has a missing entry or exit node")
            if cfg.nodes[cfg.exit].successors:
                raise MIRValidationError(f"CFG {name!r} exit must not have successors")
            for node_id, node in cfg.nodes.items():
                prefix = f"CFG {name!r}, node {node_id}"
                if type(node_id) is not int or node.id != node_id:
                    raise MIRValidationError(f"{prefix}: inconsistent node identifier")
                if len(set(node.successors)) != len(node.successors):
                    raise MIRValidationError(f"{prefix}: duplicate successor")
                for successor in node.successors:
                    if type(successor) is not int or successor not in cfg.nodes:
                        raise MIRValidationError(f"{prefix}: unknown successor {successor!r}")
                try:
                    _validate_instruction(node.instruction, self)
                except MIRValidationError as exc:
                    raise MIRValidationError(f"{prefix}: {exc}") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "entry": self.entry,
            "cfgs": {name: self.cfgs[name].to_dict() for name in sorted(self.cfgs)},
        }


def _identifier(value: Any) -> None:
    if not isinstance(value, str) or not value:
        raise MIRValidationError(f"Expected a nonempty identifier, got {value!r}")


def _validate_expr(expr: Expr, program: Program, lvalue: bool = False) -> None:
    if lvalue and not isinstance(expr, LValue):
        raise MIRValidationError(f"Expected an l-value, got {expr!r}")
    if isinstance(expr, Var):
        _identifier(expr.name)
    elif isinstance(expr, Attr):
        _validate_expr(expr.base, program, lvalue=True)
        _validate_expr(expr.key, program)
    elif isinstance(expr, Literal):
        if type(expr.value) not in (bool, int, str):
            raise MIRValidationError("Invalid primitive literal")
    elif isinstance(expr, NewObject):
        pass
    elif isinstance(expr, ListExpr):
        for item in expr.items:
            _validate_expr(item, program, lvalue=True)
    elif isinstance(expr, DictExpr):
        for key, value in expr.items:
            if not isinstance(key, str):
                raise MIRValidationError("Dictionary keys must be strings")
            _validate_expr(value, program, lvalue=True)
    elif isinstance(expr, Lambda):
        for name in (expr.args_param, expr.kwargs_param, expr.parent_param, expr.return_var):
            _identifier(name)
        if len({expr.args_param, expr.kwargs_param, expr.parent_param}) != 3:
            raise MIRValidationError("Lambda argument and parent identifiers must be distinct")
        if expr.body not in program.cfgs:
            raise MIRValidationError(f"Unknown lambda body CFG: {expr.body!r}")
    elif isinstance(expr, (Not, Length)):
        _validate_expr(expr.operand, program)
    elif isinstance(expr, Binary):
        if expr.op not in {"+", "-", "=", "<", "or", "∨", "in"}:
            raise MIRValidationError(f"Unknown primitive operator: {expr.op!r}")
        _validate_expr(expr.left, program)
        _validate_expr(expr.right, program)
    else:
        raise MIRValidationError(f"Unknown expression: {expr!r}")


def _validate_instruction(instruction: Instruction, program: Program) -> None:
    if isinstance(instruction, Skip):
        return
    if isinstance(instruction, Assume):
        _validate_expr(instruction.condition, program)
    elif isinstance(instruction, Alloc):
        _identifier(instruction.target)
        _validate_expr(instruction.value, program)
    elif isinstance(instruction, Bind):
        _validate_expr(instruction.target, program, lvalue=True)
        _validate_expr(instruction.source, program, lvalue=True)
    elif isinstance(instruction, Env):
        _identifier(instruction.target)
    elif isinstance(instruction, Delete):
        _validate_expr(instruction.target, program, lvalue=True)
    elif isinstance(instruction, Call):
        _identifier(instruction.target)
        _validate_expr(instruction.function, program)
        _validate_expr(instruction.args, program, lvalue=True)
        _validate_expr(instruction.kwargs, program, lvalue=True)
    else:
        raise MIRValidationError(f"Unknown instruction: {instruction!r}")


def _encode(value: Any) -> Any:
    if isinstance(value, (Expr, Instruction)):
        return {
            "kind": type(value).__name__,
            **{field.name: _encode(getattr(value, field.name)) for field in fields(value)},
        }
    if isinstance(value, (tuple, list)):
        return [_encode(item) for item in value]
    return value


def format_expr(expr: Expr) -> str:
    if isinstance(expr, Var):
        return expr.name
    if isinstance(expr, Attr):
        return f"{format_expr(expr.base)}[{format_expr(expr.key)}]"
    if isinstance(expr, Literal):
        return json.dumps(expr.value, ensure_ascii=False)
    if isinstance(expr, NewObject):
        return "object{}"
    if isinstance(expr, ListExpr):
        return "[" + ", ".join(format_expr(item) for item in expr.items) + "]"
    if isinstance(expr, DictExpr):
        return (
            "dict{"
            + ", ".join(
                f"{json.dumps(key, ensure_ascii=False)}: {format_expr(value)}"
                for key, value in expr.items
            )
            + "}"
        )
    if isinstance(expr, Lambda):
        return (
            f"lambda({expr.args_param}, {expr.kwargs_param}, {expr.parent_param})."
            f"({expr.body}, {expr.return_var})"
        )
    if isinstance(expr, Not):
        return f"not({format_expr(expr.operand)})"
    if isinstance(expr, Length):
        return f"len({format_expr(expr.operand)})"
    if isinstance(expr, Binary):
        return f"({format_expr(expr.left)} {expr.op} {format_expr(expr.right)})"
    raise TypeError(f"Unknown MIR expression: {expr!r}")


def format_instruction(instruction: Instruction) -> str:
    if isinstance(instruction, Skip):
        return "SKIP"
    if isinstance(instruction, Assume):
        return f"ASSUME {instruction.condition}"
    if isinstance(instruction, Alloc):
        return f"ALLOC {instruction.target} = {instruction.value}"
    if isinstance(instruction, Bind):
        return f"BIND {instruction.target} = {instruction.source}"
    if isinstance(instruction, Env):
        return f"ENV {instruction.target}"
    if isinstance(instruction, Delete):
        return f"DEL {instruction.target}"
    if isinstance(instruction, Call):
        return (
            f"CALL {instruction.target} = {instruction.function}"
            f"({instruction.args}, {instruction.kwargs})"
        )
    raise TypeError(f"Unknown MIR instruction: {instruction!r}")


def _text_cfg(cfg: CFG) -> str:
    synthetic = " synthetic" if cfg.is_synthetic else ""
    lines = [f"cfg {cfg.name} entry={cfg.entry} exit={cfg.exit}{synthetic}"]
    for node_id in sorted(cfg.nodes):
        node = cfg.nodes[node_id]
        successors = ", ".join(str(item) for item in node.successors) or "exit"
        location = f"  # line {node.lineno}" if node.lineno is not None else ""
        lines.append(f"  {node_id}: {node.instruction} -> {successors}{location}")
    return "\n".join(lines)


def _dot_cfgs(cfgs: list[CFG]) -> str:
    lines = ["digraph MIR {", "  compound=true;"]
    for index, cfg in enumerate(cfgs):
        lines.extend(
            [
                f"  subgraph cluster_{index} {{",
                f"    label={json.dumps(cfg.name, ensure_ascii=False)};",
            ]
        )
        for node_id in sorted(cfg.nodes):
            node = cfg.nodes[node_id]
            label = json.dumps(f"{node_id}: {node.instruction}", ensure_ascii=False)
            shape = "oval" if node_id in {cfg.entry, cfg.exit} else "box"
            lines.append(f'    "{index}:{node_id}" [label={label}, shape={shape}];')
        for node_id in sorted(cfg.nodes):
            for successor in cfg.nodes[node_id].successors:
                lines.append(f'    "{index}:{node_id}" -> "{index}:{successor}";')
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def format_cfg(cfg: CFG, format: str = "text") -> str:
    """Return a stable text, JSON, or Graphviz DOT representation of one CFG."""
    if format == "text":
        return _text_cfg(cfg) + "\n"
    if format == "json":
        return json.dumps(cfg.to_dict(), indent=2, ensure_ascii=False) + "\n"
    if format == "dot":
        return _dot_cfgs([cfg])
    raise ValueError(f"Unsupported MIR format: {format!r}")


def format_program(program: Program, format: str = "text", scope: str | None = None) -> str:
    """Return deterministic MIR text/JSON/DOT, optionally for one exact CFG name."""
    if scope is not None:
        return format_cfg(program.cfgs[scope], format=format)
    cfgs = [program.cfgs[name] for name in sorted(program.cfgs)]
    if format == "text":
        return f"mir entry {program.entry}\n\n" + "\n\n".join(map(_text_cfg, cfgs)) + "\n"
    if format == "json":
        return json.dumps(program.to_dict(), indent=2, ensure_ascii=False) + "\n"
    if format == "dot":
        return _dot_cfgs(cfgs)
    raise ValueError(f"Unsupported MIR format: {format!r}")


__all__ = [
    "Expr",
    "LValue",
    "Var",
    "Attr",
    "Literal",
    "NewObject",
    "ListExpr",
    "DictExpr",
    "Lambda",
    "Not",
    "Length",
    "Binary",
    "Instruction",
    "Skip",
    "Assume",
    "Alloc",
    "Bind",
    "Env",
    "Delete",
    "Call",
    "Node",
    "CFG",
    "Program",
    "MIRValidationError",
    "format_expr",
    "format_instruction",
    "format_cfg",
    "format_program",
]
