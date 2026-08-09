"""Parsing and registration for side-effect-free contracts."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Iterable

from ..core.runtime import ConcolicError, FunctionNode

_HEADER = re.compile(r"^\s*(pre|post|raises|inv)(?:\[([^\]]*)\])?\s*:\s*(.*?)\s*$")
_REGISTERED_CONTRACTS: dict[str, "FunctionContracts"] = {}


@dataclass(frozen=True)
class Precondition:
    source: str
    expression: ast.expr


@dataclass(frozen=True)
class Postcondition:
    source: str
    expression: ast.expr
    snapshots: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionContracts:
    preconditions: tuple[Precondition, ...] = ()
    postconditions: tuple[Postcondition, ...] = ()
    expected_exceptions: tuple[str, ...] = ()


class _OldStateTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Attribute(self, node: ast.Attribute) -> ast.expr:
        node = self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id == "__old__":
            self.names.add(node.attr)
            return ast.copy_location(ast.Name(id=f"__old_{node.attr}", ctx=ast.Load()), node)
        return node


class _ReturnNameTransformer(ast.NodeTransformer):
    def visit_Name(self, node: ast.Name) -> ast.expr:
        if node.id in {"result", "return_value"}:
            return ast.copy_location(ast.Name(id="__return__", ctx=node.ctx), node)
        return node


def parse_postconditions(function: FunctionNode) -> tuple[Postcondition, ...]:
    return parse_contracts(function).postconditions


def parse_contracts(function: FunctionNode) -> FunctionContracts:
    """Parse multiline PEP 316 and supported decorator contracts."""

    preconditions: list[Precondition] = []
    postconditions: list[Postcondition] = []
    expected_exceptions: list[str] = []
    docstring = ast.get_docstring(function, clean=False)
    if docstring is not None:
        for kind, declarations, source in _contract_sections(docstring):
            if kind == "pre":
                preconditions.append(_precondition(function.name, source))
            elif kind == "post":
                postconditions.append(
                    _postcondition(function.name, source, _declarations(declarations))
                )
            elif kind == "raises":
                expected_exceptions.extend(_exception_names(source))
    for decorator in function.decorator_list:
        parsed = _decorator_contract(function.name, decorator)
        if parsed is None:
            continue
        kind, expression = parsed
        if kind == "pre":
            source = ast.unparse(expression)
            preconditions.append(Precondition(source, expression))
        elif kind == "post":
            expression = _ReturnNameTransformer().visit(expression)
            ast.fix_missing_locations(expression)
            source = ast.unparse(expression)
            postconditions.append(_postcondition(function.name, source, ()))
        else:
            expected_exceptions.extend(_decorator_exception_names(decorator))
    return FunctionContracts(
        tuple(preconditions),
        tuple(postconditions),
        tuple(dict.fromkeys(expected_exceptions)),
    )


def parse_class_invariants(class_node: ast.ClassDef) -> tuple[Precondition, ...]:
    docstring = ast.get_docstring(class_node, clean=False)
    if docstring is None:
        return ()
    return tuple(
        _precondition(class_node.name, source)
        for kind, _declaration, source in _contract_sections(docstring)
        if kind == "inv"
    )


def with_invariants(
    contracts: FunctionContracts,
    invariants: Iterable[Precondition],
    method_name: str,
) -> FunctionContracts:
    invariants = tuple(invariants)
    if not invariants:
        return contracts
    invariant_posts = tuple(
        Postcondition(invariant.source, invariant.expression) for invariant in invariants
    )
    preconditions = contracts.preconditions
    if method_name != "__init__":
        preconditions = (*invariants, *preconditions)
    return FunctionContracts(
        tuple(preconditions),
        (*contracts.postconditions, *invariant_posts),
        contracts.expected_exceptions,
    )


def register_contract(
    identifier: str,
    *,
    pre: str | Iterable[str] = (),
    post: str | Iterable[str] = (),
    raises: str | Iterable[str] = (),
) -> None:
    """Register contract expressions for an entry name or ``module:entry`` identifier."""

    pre_sources = (pre,) if isinstance(pre, str) else tuple(pre)
    post_sources = (post,) if isinstance(post, str) else tuple(post)
    raise_sources = (raises,) if isinstance(raises, str) else tuple(raises)
    _REGISTERED_CONTRACTS[identifier] = FunctionContracts(
        tuple(_precondition(identifier, source) for source in pre_sources),
        tuple(_postcondition(identifier, source, ()) for source in post_sources),
        tuple(dict.fromkeys(name for source in raise_sources for name in _exception_names(source))),
    )


def clear_registered_contracts() -> None:
    _REGISTERED_CONTRACTS.clear()


def registered_contracts(*identifiers: str) -> FunctionContracts:
    return merge_contracts(
        *(_REGISTERED_CONTRACTS[name] for name in identifiers if name in _REGISTERED_CONTRACTS)
    )


def merge_contracts(*contracts: FunctionContracts) -> FunctionContracts:
    return FunctionContracts(
        tuple(clause for contract in contracts for clause in contract.preconditions),
        tuple(clause for contract in contracts for clause in contract.postconditions),
        tuple(
            dict.fromkeys(name for contract in contracts for name in contract.expected_exceptions)
        ),
    )


def is_contract_decorator(node: ast.expr) -> bool:
    call = node if isinstance(node, ast.Call) else None
    name = _decorator_name(call.func if call is not None else node)
    return name.rsplit(".", 1)[-1] in {
        "require",
        "ensure",
        "pre",
        "post",
        "raises",
        "invariant",
    }


def _contract_sections(docstring: str) -> tuple[tuple[str, str | None, str], ...]:
    sections: list[tuple[str, str | None, str]] = []
    current: tuple[str, str | None] | None = None
    for raw_line in docstring.splitlines():
        match = _HEADER.match(raw_line)
        if match is not None:
            kind, declarations, source = match.groups()
            current = (kind, declarations)
            if source:
                sections.append((kind, declarations, source))
            continue
        if current is not None and raw_line[:1].isspace() and raw_line.strip():
            sections.append((*current, raw_line.strip()))
            continue
        if raw_line.strip():
            current = None
    return tuple(sections)


def _precondition(owner: str, source: str) -> Precondition:
    return Precondition(source, _parse_expression("precondition", owner, source))


def _postcondition(owner: str, source: str, declarations: tuple[str, ...]) -> Postcondition:
    expression = _parse_expression("postcondition", owner, source)
    transformer = _OldStateTransformer()
    expression = transformer.visit(expression)
    ast.fix_missing_locations(expression)
    snapshots = tuple(dict.fromkeys((*declarations, *sorted(transformer.names))))
    return Postcondition(source, expression, snapshots)


def _parse_expression(kind: str, owner: str, source: str) -> ast.expr:
    try:
        return ast.parse(source, mode="eval").body
    except SyntaxError as error:
        raise ConcolicError(f"invalid {kind} on {owner}: {source!r}") from error


def _declarations(source: str | None) -> tuple[str, ...]:
    return tuple(name.strip() for name in (source or "").split(",") if name.strip())


def _exception_names(source: str) -> tuple[str, ...]:
    return tuple(name.strip().rsplit(".", 1)[-1] for name in source.split(",") if name.strip())


def _decorator_contract(owner: str, decorator: ast.expr) -> tuple[str, ast.expr] | None:
    if not isinstance(decorator, ast.Call):
        return None
    name = _decorator_name(decorator.func).rsplit(".", 1)[-1]
    if name in {"require", "pre"} and decorator.args:
        return "pre", _lambda_body(owner, decorator.args[0])
    if name in {"ensure", "post"} and decorator.args:
        return "post", _lambda_body(owner, decorator.args[0])
    if name == "raises":
        return "raises", ast.Constant(True)
    return None


def _lambda_body(owner: str, node: ast.expr) -> ast.expr:
    if not isinstance(node, ast.Lambda):
        raise ConcolicError(f"contract decorator on {owner} requires a lambda")
    return node.body


def _decorator_exception_names(decorator: ast.expr) -> tuple[str, ...]:
    assert isinstance(decorator, ast.Call)
    return tuple(
        name.rsplit(".", 1)[-1]
        for argument in decorator.args
        if (name := _decorator_name(argument))
    )


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""
