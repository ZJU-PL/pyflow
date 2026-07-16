"""Conservative type-information collectors.

The collector records evidence from source annotations and simple syntactic
facts.  It is intentionally separate from IFDS annotation synthesis so IFDS,
call-graph, and query clients can opt into type hints without making CFG or
fallback annotation construction responsible for type inference.
"""

from __future__ import annotations

import ast as py_ast
from dataclasses import dataclass, field
from typing import Iterable

from pyflow.language.python import ast as pyflow_ast


@dataclass(frozen=True)
class TypeEvidence:
    """One observed type fact for a symbol or expression."""

    name: str
    type_name: str
    kind: str
    scope: tuple[str, ...] = ()
    source: str = "syntactic"
    confidence: str = "explicit"
    lineno: int | None = None


@dataclass
class TypeInfo:
    """Collected type evidence indexed by qualified symbol name."""

    evidence: dict[str, list[TypeEvidence]] = field(default_factory=dict)

    def add(self, item: TypeEvidence) -> None:
        self.evidence.setdefault(item.name, []).append(item)

    def types_for(self, name: str) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(item.type_name for item in self.evidence.get(name, ()))
        )

    def items(self):
        return self.evidence.items()


def collect_python_type_info(source: str, *, filename: str | None = None) -> TypeInfo:
    """Collect source-level type evidence from Python syntax."""

    tree = py_ast.parse(source, filename=filename or "<unknown>")
    collector = _PythonTypeCollector()
    collector.visit(tree)
    return collector.result


def collect_pyflow_type_info(codes: Iterable[object]) -> TypeInfo:
    """Collect best-effort type evidence from PyFlow IR nodes."""

    collector = _PyFlowTypeCollector()
    for code in codes:
        collector.visit(code, scope=(getattr(code, "name", None) or "<code>",))
    return collector.result


class _PythonTypeCollector(py_ast.NodeVisitor):
    def __init__(self) -> None:
        self.result = TypeInfo()
        self.scope: list[str] = []

    def _qualified(self, name: str) -> str:
        return ".".join((*self.scope, name)) if self.scope else name

    def _add(
        self,
        name: str,
        type_name: str,
        kind: str,
        node: py_ast.AST,
        *,
        confidence: str = "explicit",
    ) -> None:
        self.result.add(
            TypeEvidence(
                name=self._qualified(name),
                type_name=type_name,
                kind=kind,
                scope=tuple(self.scope),
                source="python_ast",
                confidence=confidence,
                lineno=getattr(node, "lineno", None),
            )
        )

    def visit_FunctionDef(self, node: py_ast.FunctionDef) -> None:
        self._collect_function(node)

    def visit_AsyncFunctionDef(self, node: py_ast.AsyncFunctionDef) -> None:
        self._collect_function(node)

    def _collect_function(
        self, node: py_ast.FunctionDef | py_ast.AsyncFunctionDef
    ) -> None:
        if node.returns is not None:
            self._add(
                node.name,
                _unparse_annotation(node.returns),
                "function_return",
                node,
            )

        self.scope.append(node.name)
        for arg in _iter_arguments(node.args):
            if arg.annotation is not None:
                self._add(
                    arg.arg,
                    _unparse_annotation(arg.annotation),
                    "parameter",
                    arg,
                )
        for stmt in node.body:
            self.visit(stmt)
        self.scope.pop()

    def visit_ClassDef(self, node: py_ast.ClassDef) -> None:
        if node.bases:
            self._add(
                node.name,
                ", ".join(_unparse_annotation(base) for base in node.bases),
                "class_bases",
                node,
            )
        self.scope.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.scope.pop()

    def visit_AnnAssign(self, node: py_ast.AnnAssign) -> None:
        target_name = _python_target_name(node.target)
        if target_name is not None:
            self._add(
                target_name,
                _unparse_annotation(node.annotation),
                "variable",
                node,
            )
            if node.value is not None:
                inferred = _infer_python_expr_type(node.value)
                if inferred is not None:
                    self._add(
                        target_name,
                        inferred,
                        "variable",
                        node,
                        confidence="inferred",
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: py_ast.Assign) -> None:
        inferred = _infer_python_expr_type(node.value)
        if inferred is not None:
            for target in node.targets:
                target_name = _python_target_name(target)
                if target_name is not None:
                    self._add(
                        target_name,
                        inferred,
                        "variable",
                        node,
                        confidence="inferred",
                    )
        self.generic_visit(node)

    if hasattr(py_ast, "TypeAlias"):

        def visit_TypeAlias(self, node) -> None:  # type: ignore[no-untyped-def]
            name = getattr(node.name, "id", None) or getattr(node.name, "name", None)
            if isinstance(name, str):
                self._add(
                    name,
                    _unparse_annotation(node.value),
                    "type_alias",
                    node,
                )
            self.generic_visit(node)


class _PyFlowTypeCollector:
    def __init__(self) -> None:
        self.result = TypeInfo()

    def _add(
        self,
        name: str,
        type_name: str,
        kind: str,
        scope: tuple[str, ...],
        *,
        confidence: str = "explicit",
    ) -> None:
        qualified = ".".join((*scope, name)) if scope else name
        self.result.add(
            TypeEvidence(
                name=qualified,
                type_name=type_name,
                kind=kind,
                scope=scope,
                source="pyflow_ir",
                confidence=confidence,
            )
        )

    def visit(self, node: object, *, scope: tuple[str, ...] = ()) -> None:
        if node is None or isinstance(node, pyflow_ast.leafTypes):
            return
        if isinstance(node, (list, tuple)):
            for child in node:
                self.visit(child, scope=scope)
            return
        if not hasattr(node, "visitChildren"):
            return

        if isinstance(node, pyflow_ast.Code):
            code_scope = (*scope[:-1], node.name) if scope else (node.name,)
            self.visit(node.codeparameters, scope=code_scope)
            self.visit(node.ast, scope=code_scope)
            return

        if isinstance(node, pyflow_ast.TypeAlias):
            self._add(
                node.name,
                _pyflow_expr_type_name(node.value),
                "type_alias",
                scope,
            )
        elif isinstance(node, pyflow_ast.AnnAssign):
            target = getattr(node.target, "name", None)
            if isinstance(target, str):
                self._add(
                    target,
                    _pyflow_expr_type_name(node.annotation),
                    "variable",
                    scope,
                )
        elif isinstance(node, pyflow_ast.Assign):
            inferred = _infer_pyflow_expr_type(node.expr)
            if inferred is not None:
                for target in node.lcls:
                    target_name = getattr(target, "name", None)
                    if isinstance(target_name, str):
                        self._add(
                            target_name,
                            inferred,
                            "variable",
                            scope,
                            confidence="inferred",
                        )

        node.visitChildren(lambda child: self.visit(child, scope=scope))


def _iter_arguments(args: py_ast.arguments):
    yield from args.posonlyargs
    yield from args.args
    if args.vararg is not None:
        yield args.vararg
    yield from args.kwonlyargs
    if args.kwarg is not None:
        yield args.kwarg


def _python_target_name(target: py_ast.AST) -> str | None:
    if isinstance(target, py_ast.Name):
        return target.id
    if isinstance(target, py_ast.Attribute):
        base = _python_target_name(target.value)
        return f"{base}.{target.attr}" if base else target.attr
    return None


def _unparse_annotation(node: py_ast.AST) -> str:
    try:
        return py_ast.unparse(node)
    except Exception:
        return type(node).__name__


def _infer_python_expr_type(node: py_ast.AST) -> str | None:
    if isinstance(node, py_ast.Constant):
        if node.value is None:
            return "None"
        return type(node.value).__name__
    if isinstance(node, py_ast.List):
        return "list"
    if isinstance(node, py_ast.Tuple):
        return "tuple"
    if isinstance(node, py_ast.Dict):
        return "dict"
    if isinstance(node, py_ast.Set):
        return "set"
    if isinstance(node, py_ast.Call):
        name = _python_call_name(node.func)
        if name in {
            "dict",
            "list",
            "tuple",
            "set",
            "str",
            "int",
            "float",
            "bool",
            "bytes",
        }:
            return name
    return None


def _python_call_name(node: py_ast.AST) -> str | None:
    if isinstance(node, py_ast.Name):
        return node.id
    if isinstance(node, py_ast.Attribute):
        base = _python_call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _pyflow_expr_type_name(node: object) -> str:
    if isinstance(node, pyflow_ast.Existing):
        value = getattr(node.object, "pyobj", None)
        if isinstance(value, type):
            return value.__name__
        if isinstance(value, str):
            return value
        if value is None:
            return "None"
        return type(value).__name__
    if isinstance(node, pyflow_ast.Local) and node.name is not None:
        return node.name
    return _infer_pyflow_expr_type(node) or type(node).__name__


def _infer_pyflow_expr_type(node: object) -> str | None:
    if isinstance(node, pyflow_ast.Existing):
        value = getattr(node.object, "pyobj", None)
        if value is None:
            return "None"
        return type(value).__name__
    if isinstance(node, pyflow_ast.BuildList):
        return "list"
    if isinstance(node, pyflow_ast.BuildTuple):
        return "tuple"
    if isinstance(node, pyflow_ast.BuildMap):
        return "dict"
    if isinstance(node, pyflow_ast.BuildSet):
        return "set"
    if isinstance(node, pyflow_ast.BuildSlice):
        return "slice"
    if isinstance(node, pyflow_ast.Import):
        return "module"
    return None
