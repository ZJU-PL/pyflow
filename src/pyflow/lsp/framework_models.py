"""Explicit framework contracts with source-backed editor definitions.

Only known qualified APIs are modeled. Reading a package never imports it.
Observed request-state fields and application-state fields have separate owners.
"""

import ast
from importlib.machinery import PathFinder
from pathlib import Path

from pyflow.frontend.source import read_python_source

REQUEST_STATE = "starlette.requests.HTTPConnection.state"
APPLICATION_STATE = "starlette.applications.Starlette.state"
STATE_DOMAINS = frozenset({REQUEST_STATE, APPLICATION_STATE, "starlette.datastructures.State"})
CLASS_ALIASES = {
    "flask.Flask": "flask.app.Flask",
    "fastapi.Request": "starlette.requests.Request",
    "fastapi.WebSocket": "starlette.websockets.WebSocket",
    "fastapi.FastAPI": "fastapi.applications.FastAPI",
}
KNOWN_CLASSES = frozenset(
    {
        *CLASS_ALIASES.values(),
        "starlette.requests.HTTPConnection",
        "starlette.datastructures.State",
        "starlette.applications.Starlette",
    }
)
VALUE_TYPES = {
    "flask.current_app": "flask.app.Flask",
    "flask.globals.current_app": "flask.app.Flask",
}


class FrameworkModels:
    def __init__(self, sources, modules):
        self.sources = sources
        self.paths = {module: path for path, module in modules.items()}
        self._packages = {}
        self._trees = {}
        self._symbols = {}

    def canonical_class(self, name):
        name = CLASS_ALIASES.get(name, name)
        return name if name in KNOWN_CLASSES else None

    def member_type(self, owner, name):
        owner = CLASS_ALIASES.get(owner, owner)
        if name == "state":
            if owner in {
                "starlette.requests.Request",
                "starlette.requests.HTTPConnection",
                "starlette.websockets.WebSocket",
            }:
                return REQUEST_STATE
            if owner in {"fastapi.applications.FastAPI", "starlette.applications.Starlette"}:
                return APPLICATION_STATE
        if owner in {"flask.app.Flask", "flask.sansio.app.App"} and name in {
            "config",
            "blueprints",
        }:
            return "builtins.dict"
        return None

    def module(self, name):
        if name in self._trees:
            return self._trees[name]
        if name.split(".")[0] not in {"flask", "werkzeug", "starlette", "fastapi"}:
            return None
        path = self.paths.get(name)
        if path is None:
            package, _, rest = name.partition(".")
            if package not in self._packages:
                spec = PathFinder.find_spec(package)
                self._packages[package] = Path(spec.origin).parent if spec and spec.origin else None
            root = self._packages[package]
            if root:
                base = root.joinpath(*rest.split(".")) if rest else root
                candidate = base.with_suffix(".py") if rest else root / "__init__.py"
                path = candidate if candidate.is_file() else base / "__init__.py"
        if path is None or not Path(path).is_file():
            fallback = (
                Path(__file__).parents[1] / "stubs" / "lsp" / (name.replace(".", "_") + ".pyi")
            )
            path = fallback if fallback.is_file() else None
        result = None
        if path is not None:
            try:
                source = self.sources.get(str(path))
                if source is None:
                    source = read_python_source(path)
                tree = ast.parse(source, filename=str(path))
                imports = {}
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports[alias.asname or alias.name.split(".")[0]] = (
                                alias.name if alias.asname else alias.name.split(".")[0]
                            )
                    elif isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        if node.level:
                            package = (
                                name
                                if Path(path).name == "__init__.py"
                                else name.rpartition(".")[0]
                            )
                            parts = package.split(".")
                            module = ".".join(
                                [
                                    *parts[: len(parts) - node.level + 1],
                                    *([module] if module else []),
                                ]
                            )
                        for alias in node.names:
                            imports[alias.asname or alias.name] = f"{module}.{alias.name}".strip(
                                "."
                            )
                result = Path(path), source, tree, imports
            except (OSError, SyntaxError, UnicodeError, RecursionError):
                pass
        self._trees[name] = result
        return result

    def _class(self, owner):
        owner = CLASS_ALIASES.get(owner, owner)
        module, _, name = owner.rpartition(".")
        data = self.module(module)
        if not data:
            return None
        node = next(
            (
                node
                for node in ast.walk(data[2])
                if isinstance(node, ast.ClassDef) and node.name == name
            ),
            None,
        )
        return (owner, module, node, data) if node else None

    def _symbol(self, owner, name, node, data, kind, annotation=None):
        from .signatures import parameters
        from .workspace import (
            SourceSymbol,
            SymbolId,
            SymbolKind,
            SourceRange,
            _byte_col_to_char,
            offset_to_lsp_character,
        )

        qualified = owner if kind == 5 else f"{owner}.{name}"
        key = qualified, str(data[0]), node.lineno
        if key in self._symbols:
            return self._symbols[key]
        lines = data[1].splitlines()
        row, end_row = node.lineno - 1, (node.end_lineno or node.lineno) - 1
        start = _byte_col_to_char(lines[row], node.col_offset)
        end = _byte_col_to_char(lines[end_row], node.end_col_offset or node.col_offset)
        if isinstance(node, ast.Attribute):
            selected_row, selected = end_row, end - len(name)
        else:
            selected_row, selected = row, lines[row].find(name, start)
        selected = max(selected, start if selected_row == row else 0)
        uri = data[0].absolute().as_uri()
        location = SourceRange(
            uri,
            row,
            offset_to_lsp_character(lines[row], start),
            end_row,
            offset_to_lsp_character(lines[end_row], end),
        )
        selection = SourceRange(
            uri,
            selected_row,
            offset_to_lsp_character(lines[selected_row], selected),
            selected_row,
            offset_to_lsp_character(lines[selected_row], selected + len(name)),
        )
        category = (
            SymbolKind.CLASS
            if kind == 5
            else SymbolKind.METHOD if kind == 6 else SymbolKind.VARIABLE
        )
        detail = (
            f"class {name}"
            if kind == 5
            else f"{name}: {ast.unparse(annotation)}" if annotation else name
        )
        accessor = ""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            detail = f"def {name}({ast.unparse(node.args)})" + (
                " -> " + ast.unparse(node.returns) if node.returns else ""
            )
            accessor = (
                "getter"
                if any(
                    isinstance(decorator, ast.Name) and decorator.id == "property"
                    for decorator in node.decorator_list
                )
                else ""
            )
        symbol = SourceSymbol(
            SymbolId(
                owner.rpartition(".")[0],
                qualified,
                category,
                uri,
                selection.start_line,
                selection.start_character,
            ),
            name,
            qualified,
            owner.rpartition(".")[0],
            kind,
            location,
            selection,
            owner if kind != 5 else owner.rpartition(".")[0],
            detail,
            (
                (ast.get_docstring(node) or "")
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                else ""
            ),
            accessor,
            parameters=(
                parameters(node)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                else ()
            ),
            binding="instance" if kind == 6 else "",
        )
        self._symbols[key] = symbol
        return symbol

    def class_symbol(self, name):
        name = self.canonical_class(name)
        info = self._class(name) if name else None
        return self._symbol(info[0], info[2].name, info[2], info[3], 5) if info else None

    def member(self, owner, name, seen=frozenset()):
        owner = (
            "starlette.datastructures.State"
            if owner in STATE_DOMAINS
            else CLASS_ALIASES.get(owner, owner)
        )
        if owner in seen or len(seen) > 32:
            return None
        info = self._class(owner)
        if not info:
            return None
        _, module, node, data = info
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name:
                return self._symbol(owner, name, item, data, 6)
            if (
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.target.id == name
            ):
                return self._symbol(owner, name, item.target, data, 8, item.annotation)
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(item):
                    targets = (
                        child.targets
                        if isinstance(child, ast.Assign)
                        else [child.target] if isinstance(child, ast.AnnAssign) else ()
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"
                            and target.attr == name
                        ):
                            return self._symbol(
                                owner,
                                name,
                                target,
                                data,
                                8,
                                child.annotation if isinstance(child, ast.AnnAssign) else None,
                            )
        for base in node.bases:
            base = base.value if isinstance(base, ast.Subscript) else base
            spelling = ast.unparse(base)
            head, separator, tail = spelling.partition(".")
            qualified = data[3].get(head, module + "." + head) + (
                separator + tail if separator else ""
            )
            candidate = self.member(qualified, name, seen | {owner})
            if candidate:
                return candidate
        return None

    def members(self, owner, seen=frozenset()):
        if owner in STATE_DOMAINS or owner in seen:
            return []
        info = self._class(owner)
        if not info:
            return []
        _, module, node, data = info
        names = set()
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(item.name)
                names.update(
                    child.attr
                    for child in ast.walk(item)
                    if isinstance(child, ast.Attribute)
                    and isinstance(child.ctx, ast.Store)
                    and isinstance(child.value, ast.Name)
                    and child.value.id == "self"
                )
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                names.add(item.target.id)
        result = {name: self.member(owner, name) for name in names}
        for base in node.bases:
            spelling = ast.unparse(base.value if isinstance(base, ast.Subscript) else base)
            head, sep, tail = spelling.partition(".")
            qualified = data[3].get(head, module + "." + head) + (sep + tail if sep else "")
            for symbol in self.members(qualified, seen | {owner}):
                result.setdefault(symbol.name, symbol)
        return [symbol for symbol in result.values() if symbol]
