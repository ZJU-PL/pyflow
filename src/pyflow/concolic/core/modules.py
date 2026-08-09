"""Safe local-module loading and static declaration parsing."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from .runtime import (
    FunctionNode,
    _ClassValue,
    _EnumClass,
    _FunctionValue,
    _ImportlibFunction,
    _ImportlibModule,
    _ModuleValue,
    _NamedTupleClass,
    _RegexModule,
    _SummaryFunction,
    _SummaryModule,
)


def _load_module(path: Path, cache: dict[Path, _ModuleValue]) -> _ModuleValue:
    if path in cache:
        return cache[path]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module = _ModuleValue(path, {}, {}, {}, loading=True)
    cache[path] = module
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module.functions[statement.name] = statement
        elif isinstance(statement, ast.ClassDef):
            enum_class = _static_enum_class(statement)
            if enum_class is _UNSUPPORTED_LITERAL:
                module.classes[statement.name] = _ClassValue(statement, module)
            else:
                module.globals[statement.name] = enum_class
        elif (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            literal = _static_literal(statement.value, module.globals)
            if literal is not _UNSUPPORTED_LITERAL:
                module.globals[statement.targets[0].id] = literal
            else:
                namedtuple_class = _static_namedtuple(statement.value)
                if namedtuple_class is not _UNSUPPORTED_LITERAL:
                    module.globals[statement.targets[0].id] = namedtuple_class

    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name == "re":
                    module.globals[alias.asname or "re"] = _RegexModule()
                    continue
                if alias.name == "importlib":
                    module.globals[alias.asname or "importlib"] = _ImportlibModule(path, cache)
                    continue
                if alias.name in {"os.path", "urllib.parse"}:
                    bound_name = alias.asname or alias.name.split(".")[0]
                    summary_name = alias.name if alias.asname else bound_name
                    module.globals[bound_name] = _SummaryModule(summary_name)
                    continue
                if alias.name in _SUMMARY_MODULES:
                    module.globals[alias.asname or alias.name] = _SummaryModule(alias.name)
                    continue
                resolved = _import_local_module(path, alias.name, cache)
                if resolved is not None:
                    package, imported = resolved
                    module.globals[alias.asname or alias.name.split(".")[0]] = (
                        imported if alias.asname else package
                    )
        elif isinstance(statement, ast.ImportFrom) and statement.module:
            if statement.level == 0 and statement.module == "importlib":
                for alias in statement.names:
                    if alias.name == "import_module":
                        module.globals[alias.asname or alias.name] = _ImportlibFunction(path, cache)
                continue
            if statement.level == 0 and statement.module in _SUMMARY_MODULES:
                for alias in statement.names:
                    if alias.name == "*":
                        continue
                    module.globals[alias.asname or alias.name] = _SummaryFunction(
                        statement.module, alias.name
                    )
                continue
            imported_module = _resolve_local_module(path, statement.module, cache, statement.level)
            if imported_module is None:
                continue
            for alias in statement.names:
                if alias.name == "*":
                    module.globals.update(
                        {
                            name: _FunctionValue(function, {}, imported_module)
                            for name, function in imported_module.functions.items()
                        }
                    )
                    module.classes.update(imported_module.classes)
                    module.globals.update(imported_module.globals)
                elif alias.name in imported_module.functions:
                    module.globals[alias.asname or alias.name] = _FunctionValue(
                        imported_module.functions[alias.name], {}, imported_module
                    )
                elif alias.name in imported_module.classes:
                    module.classes[alias.asname or alias.name] = imported_module.classes[alias.name]
                elif alias.name in imported_module.globals:
                    module.globals[alias.asname or alias.name] = imported_module.globals[alias.name]
                else:
                    resolved = _import_local_module(imported_module.path, alias.name, cache)
                    if resolved is not None:
                        _, child = resolved
                        module.globals[alias.asname or alias.name] = child
        elif isinstance(statement, ast.ImportFrom) and statement.level:
            for alias in statement.names:
                relative_module = _resolve_local_module(path, alias.name, cache, statement.level)
                if relative_module is not None:
                    module.globals[alias.asname or alias.name] = relative_module
    module.loading = False
    return module


def _resolve_local_module(
    path: Path, name: str, cache: dict[Path, _ModuleValue], level: int = 0
) -> _ModuleValue | None:
    base = path.parent
    if level:
        for _ in range(level - 1):
            base = base.parent
    module_path = base.joinpath(*name.split("."))
    candidate = module_path.with_suffix(".py")
    if candidate.is_file():
        return _load_module(candidate, cache)
    initializer = module_path / "__init__.py"
    return _load_module(initializer, cache) if initializer.is_file() else None


def _import_local_module(
    path: Path, name: str, cache: dict[Path, _ModuleValue], level: int = 0
) -> tuple[_ModuleValue, _ModuleValue] | None:
    """Resolve an import and expose each child beneath its parent package.

    Python binds the package for ``import package.child`` but binds the child
    for ``import package.child as alias``.  Keeping the package hierarchy in
    the lightweight module values gives normal chained attribute access the
    same shape without importing arbitrary installed modules.
    """
    parts = name.split(".")
    package = _resolve_local_module(path, parts[0], cache, level)
    if package is None:
        return None
    imported = package
    for part in parts[1:]:
        child = _resolve_local_module(imported.path, part, cache)
        if child is None:
            return None
        imported.globals[part] = child
        imported = child
    return package, imported


_UNSUPPORTED_LITERAL = object()
_SUMMARY_MODULES = {
    "asyncio",
    "base64",
    "binascii",
    "bisect",
    "collections",
    "codecs",
    "copy",
    "contextlib",
    "dataclasses",
    "datetime",
    "functools",
    "fnmatch",
    "hashlib",
    "heapq",
    "html",
    "itertools",
    "json",
    "math",
    "operator",
    "os.path",
    "pathlib",
    "statistics",
    "struct",
    "unicodedata",
    "urllib.parse",
    "zlib",
}


def _contains_yield(function: FunctionNode) -> bool:
    """Return whether this function body itself yields values."""

    class _Finder(ast.NodeVisitor):
        found = False

        def visit_Yield(self, node: ast.Yield) -> None:  # noqa: N802
            self.found = True

        def visit_YieldFrom(self, node: ast.YieldFrom) -> None:  # noqa: N802
            self.found = True

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
            return

    finder = _Finder()
    for statement in function.body:
        finder.visit(statement)
    return finder.found


def _static_literal(node: ast.expr, bindings: dict[str, Any] | None = None) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        pass
    if isinstance(node, ast.Name) and bindings is not None:
        return bindings.get(node.id, _UNSUPPORTED_LITERAL)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _static_literal(node.operand, bindings)
        if not isinstance(value, (int, float)):
            return _UNSUPPORTED_LITERAL
        return value if isinstance(node.op, ast.UAdd) else -value
    if isinstance(node, ast.BinOp):
        left = _static_literal(node.left, bindings)
        right = _static_literal(node.right, bindings)
        if left is _UNSUPPORTED_LITERAL or right is _UNSUPPORTED_LITERAL:
            return _UNSUPPORTED_LITERAL
        operations = {
            ast.Add: lambda: left + right,
            ast.Sub: lambda: left - right,
            ast.Mult: lambda: left * right,
            ast.FloorDiv: lambda: left // right,
            ast.Mod: lambda: left % right,
            ast.Pow: lambda: left**right,
        }
        operation = next(
            (callback for kind, callback in operations.items() if isinstance(node.op, kind)),
            None,
        )
        if operation is None:
            return _UNSUPPORTED_LITERAL
        try:
            result = operation()
        except (ArithmeticError, TypeError, ValueError):
            return _UNSUPPORTED_LITERAL
        return (
            result
            if isinstance(result, (int, float, str, bytes, tuple, list))
            else _UNSUPPORTED_LITERAL
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [_static_literal(element, bindings) for element in node.elts]
        if any(value is _UNSUPPORTED_LITERAL for value in values):
            return _UNSUPPORTED_LITERAL
        if isinstance(node, ast.List):
            return values
        if isinstance(node, ast.Tuple):
            return tuple(values)
        try:
            return set(values)
        except TypeError:
            return _UNSUPPORTED_LITERAL
    if isinstance(node, ast.Dict):
        dictionary: dict[Any, Any] = {}
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                return _UNSUPPORTED_LITERAL
            key = _static_literal(key_node, bindings)
            value = _static_literal(value_node, bindings)
            if key is _UNSUPPORTED_LITERAL or value is _UNSUPPORTED_LITERAL:
                return _UNSUPPORTED_LITERAL
            try:
                dictionary[key] = value
            except TypeError:
                return _UNSUPPORTED_LITERAL
        return dictionary
    return _UNSUPPORTED_LITERAL


def _static_namedtuple(node: ast.expr) -> _NamedTupleClass | object:
    """Build a module-level ``collections.namedtuple`` declaration safely."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "namedtuple"
        and len(node.args) == 2
        and not node.keywords
    ):
        return _UNSUPPORTED_LITERAL
    class_name = _static_literal(node.args[0])
    field_specification = _static_literal(node.args[1])
    if not isinstance(class_name, str):
        return _UNSUPPORTED_LITERAL
    if isinstance(field_specification, str):
        fields = tuple(field for field in field_specification.replace(",", " ").split() if field)
    elif isinstance(field_specification, (list, tuple)) and all(
        isinstance(field, str) for field in field_specification
    ):
        fields = tuple(field_specification)
    else:
        return _UNSUPPORTED_LITERAL
    if not fields or len(set(fields)) != len(fields):
        return _UNSUPPORTED_LITERAL
    return _NamedTupleClass(class_name, fields)


def _static_enum_class(node: ast.ClassDef) -> _EnumClass | object:
    """Build a simple local scalar enum declaration without executing code."""
    kind = next(
        (
            base.id
            for base in node.bases
            if isinstance(base, ast.Name) and base.id in {"Enum", "IntEnum", "StrEnum"}
        ),
        next(
            (
                base.attr
                for base in node.bases
                if isinstance(base, ast.Attribute) and base.attr in {"Enum", "IntEnum", "StrEnum"}
            ),
            None,
        ),
    )
    if kind is None:
        return _UNSUPPORTED_LITERAL
    members: dict[str, int | str | bool] = {}
    for statement in node.body:
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            continue
        value = _static_literal(statement.value)
        if not isinstance(value, (int, str, bool)):
            return _UNSUPPORTED_LITERAL
        if kind == "IntEnum" and not isinstance(value, int):
            return _UNSUPPORTED_LITERAL
        if kind == "StrEnum" and not isinstance(value, str):
            return _UNSUPPORTED_LITERAL
        members[statement.targets[0].id] = value
    if not members or len(set(members.values())) != len(members):
        return _UNSUPPORTED_LITERAL
    return _EnumClass(node.name, members, kind)


def _find_entry(tree: ast.Module, entry: str) -> FunctionNode:
    for statement in tree.body:
        if (
            isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name == entry
        ):
            _parameter_nodes(statement)
            return statement
    raise ValueError(f"entry function {entry!r} was not found")


def _parameter_nodes(function: FunctionNode) -> tuple[ast.arg, ...]:
    arguments = function.args
    return tuple(arguments.posonlyargs) + tuple(arguments.args)


def _required_positional_count(function: FunctionNode) -> int:
    return len(function.args.posonlyargs) + len(function.args.args) - len(function.args.defaults)
