"""Workspace documents and source locations used by protocol adapters.

The compiler IR intentionally does not retain every token-level source range.
LSP, however, is a source protocol.  This module keeps that concern separate by
building a lightweight AST index over the exact document snapshot analyzed by
the server.
"""

from __future__ import annotations

import ast
import os
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import unquote, urlparse

from pyflow.language.modules.project_resolution import ModuleIdentityResolver

_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")


def uri_to_path(uri: str) -> str:
    """Convert a file URI to a normalized local path."""
    parsed = urlparse(uri)
    if parsed.scheme and parsed.scheme != "file":
        raise ValueError(f"Unsupported URI scheme: {parsed.scheme}")
    if not parsed.scheme:
        return os.path.abspath(unquote(uri))
    path = unquote(parsed.path)
    if parsed.netloc and parsed.netloc not in {"", "localhost"}:
        path = f"//{parsed.netloc}{path}"
    if os.name == "nt" and re.match(r"^/[A-Za-z]:", path):
        path = path[1:]
    return os.path.abspath(path)


def path_to_uri(path: str | os.PathLike[str]) -> str:
    return Path(path).absolute().as_uri()


def _byte_col_to_char(line: str, byte_col: int) -> int:
    raw = line.encode("utf-8")[:byte_col]
    return len(raw.decode("utf-8", errors="ignore"))


def lsp_character_to_offset(line: str, character: int) -> int:
    """Translate an LSP UTF-16 character offset to a Python string offset."""
    units = 0
    for index, char in enumerate(line):
        if units >= character:
            return index
        units += 2 if ord(char) > 0xFFFF else 1
    return len(line)


def offset_to_lsp_character(line: str, offset: int) -> int:
    return sum(2 if ord(char) > 0xFFFF else 1 for char in line[:offset])


@dataclass(frozen=True)
class SourceRange:
    uri: str
    start_line: int
    start_character: int
    end_line: int
    end_character: int

    def to_lsp(self) -> dict:
        return {
            "start": {"line": self.start_line, "character": self.start_character},
            "end": {"line": self.end_line, "character": self.end_character},
        }

    def location(self) -> dict:
        return {"uri": self.uri, "range": self.to_lsp()}

    def contains(self, line: int, character: int = 0) -> bool:
        return (
            (self.start_line, self.start_character)
            <= (line, character)
            <= (
                self.end_line,
                self.end_character,
            )
        )


class SymbolKind(str, Enum):
    """Stable language-level kinds, independent from LSP numeric kinds."""

    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    PARAMETER = "parameter"
    VARIABLE = "variable"
    IMPORT = "import"


@dataclass(frozen=True)
class SymbolId:
    """Workspace-stable identity for a definition.

    Names alone are intentionally insufficient: the definition location keeps
    local shadowing and same-named methods in different classes distinct.
    """

    module: str
    qualname: str
    kind: SymbolKind
    uri: str
    line: int
    character: int

    def to_data(self) -> dict[str, str | int]:
        return {
            "module": self.module,
            "qualname": self.qualname,
            "kind": self.kind.value,
            "uri": self.uri,
            "line": self.line,
            "character": self.character,
        }

    @classmethod
    def from_data(cls, value: object) -> Optional["SymbolId"]:
        if not isinstance(value, dict):
            return None
        try:
            return cls(
                module=str(value["module"]),
                qualname=str(value["qualname"]),
                kind=SymbolKind(str(value["kind"])),
                uri=str(value["uri"]),
                line=int(value["line"]),
                character=int(value["character"]),
            )
        except (KeyError, TypeError, ValueError):
            return None


@dataclass(frozen=True)
class SourceSymbol:
    symbol_id: SymbolId
    name: str
    qualified_name: str
    module: str
    kind: int
    full_range: SourceRange
    selection_range: SourceRange
    container_name: Optional[str] = None

    def document_symbol(self) -> dict:
        result = {
            "name": self.name,
            "kind": self.kind,
            "range": self.full_range.to_lsp(),
            "selectionRange": self.selection_range.to_lsp(),
        }
        if self.container_name:
            result["detail"] = self.container_name
        return result

    def symbol_information(self) -> dict:
        result = {
            "name": self.name,
            "kind": self.kind,
            "location": self.selection_range.location(),
        }
        if self.container_name:
            result["containerName"] = self.container_name
        return result


@dataclass(frozen=True)
class SourceReference:
    name: str
    location: SourceRange
    enclosing_function: Optional[str]
    symbol_id: Optional[SymbolId] = None


@dataclass(frozen=True)
class SourceCall:
    caller: Optional[str]
    callee: str
    location: SourceRange
    caller_id: Optional[SymbolId] = None
    callee_id: Optional[SymbolId] = None


class _ScopeKind(str, Enum):
    """Lexical execution contexts relevant to source symbol resolution."""

    MODULE = "module"
    FUNCTION = "function"
    LAMBDA = "lambda"
    CLASS = "class"
    COMPREHENSION = "comprehension"


@dataclass
class _Scope:
    """Bindings and lookup rules for one Python lexical scope."""

    kind: _ScopeKind
    bindings: dict[str, SymbolId]
    function_id: Optional[SymbolId] = None
    class_id: Optional[SymbolId] = None
    global_names: set[str] = field(default_factory=set)
    nonlocal_names: set[str] = field(default_factory=set)
    predeclared: set[SymbolId] = field(default_factory=set)


class WorkspaceDocuments:
    """Open-document overlays with monotonically increasing revisions."""

    def __init__(self) -> None:
        self._documents: dict[str, tuple[str, Optional[int]]] = {}
        self.revision = 0
        self._lock = threading.RLock()

    def open(self, path: str, text: str, version: Optional[int]) -> bool:
        with self._lock:
            normalized = os.path.abspath(path)
            current = self._documents.get(normalized)
            if (
                current is not None
                and version is not None
                and current[1] is not None
                and version <= current[1]
            ):
                return False
            self._documents[normalized] = (text, version)
            self.revision += 1
            return True

    def change(
        self, path: str, changes: list[dict[str, object]], version: Optional[int]
    ) -> bool:
        """Apply sequential LSP full or ranged edits, rejecting stale versions."""
        with self._lock:
            normalized = os.path.abspath(path)
            current = self._documents.get(normalized)
            if (
                current is not None
                and version is not None
                and current[1] is not None
                and version <= current[1]
            ):
                return False
            text = current[0] if current is not None else _read_text(normalized)
            for change in changes:
                replacement = str(change.get("text", ""))
                edit_range = change.get("range")
                if edit_range is None:
                    text = replacement
                    continue
                if not isinstance(edit_range, dict):
                    raise ValueError("LSP content change range must be an object")
                start = edit_range.get("start")
                end = edit_range.get("end")
                if not isinstance(start, dict) or not isinstance(end, dict):
                    raise ValueError("LSP content change range needs start and end")
                start_offset = _position_to_offset(
                    text, int(start.get("line", 0)), int(start.get("character", 0))
                )
                end_offset = _position_to_offset(
                    text, int(end.get("line", 0)), int(end.get("character", 0))
                )
                if end_offset < start_offset:
                    raise ValueError("LSP content change end precedes start")
                text = f"{text[:start_offset]}{replacement}{text[end_offset:]}"
            self._documents[normalized] = (text, version)
            self.revision += 1
            return True

    def close(self, path: str) -> bool:
        with self._lock:
            existed = self._documents.pop(os.path.abspath(path), None) is not None
            if not existed:
                return False
            self.revision += 1
            return True

    def source_overrides(self) -> dict[str, str]:
        with self._lock:
            return {path: value[0] for path, value in self._documents.items()}

    def text(self, path: str) -> Optional[str]:
        with self._lock:
            item = self._documents.get(os.path.abspath(path))
            return item[0] if item else None

    def version(self, path: str) -> Optional[int]:
        with self._lock:
            item = self._documents.get(os.path.abspath(path))
            return item[1] if item else None


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


def _position_to_offset(text: str, line: int, character: int) -> int:
    lines = text.splitlines(keepends=True)
    if line < 0:
        raise ValueError("LSP content change line cannot be negative")
    if line >= len(lines):
        return len(text)
    line_text = lines[line]
    return sum(len(item) for item in lines[:line]) + lsp_character_to_offset(
        line_text, character
    )


class SourceIndex:
    """AST-backed index for source-accurate navigation and hierarchy results."""

    def __init__(
        self,
        source_files: dict[str, str],
        workspace_roots: Iterable[str | os.PathLike[str]] = (),
    ):
        self.workspace_roots = tuple(
            Path(root).absolute() for root in workspace_roots
        )
        self.module_identity = ModuleIdentityResolver(self.workspace_roots)
        self.source_files = {
            os.path.abspath(path): text for path, text in source_files.items()
        }
        self.symbols: list[SourceSymbol] = []
        self.references: list[SourceReference] = []
        self.calls: list[SourceCall] = []
        self._modules: dict[str, str] = {}
        self._symbols_by_id: dict[SymbolId, SourceSymbol] = {}
        self._references_by_range: dict[SourceRange, SymbolId] = {}
        self._import_targets: dict[SymbolId, str] = {}
        self._resolved_import_aliases: dict[SymbolId, SymbolId] = {}
        for path, source in self.source_files.items():
            self._index_file(path, source)
        self._resolve_import_aliases()

    def _module_name(self, path: str) -> str:
        return self.module_identity.module_name_from_path(path) or Path(path).stem

    def _index_file(self, path: str, source: str) -> None:
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            return
        module = self._module_name(path)
        self._modules[path] = module
        visitor = _IndexVisitor(self, path, source, module)
        # Module bindings are known before any function body is resolved.
        # This gives forward definitions and ``global`` declarations stable
        # SymbolIds without turning the source index into a type checker.
        visitor.predeclare_module(tree)
        for statement in tree.body:
            visitor.visit(statement)

    def _resolve_import_aliases(self) -> None:
        """Resolve ``from pkg import name as alias`` after all modules exist."""
        aliases = {
            symbol_id: next(
                (
                    candidate.symbol_id
                    for candidate in self.symbols
                    if candidate.qualified_name == target
                ),
                symbol_id,
            )
            for symbol_id, target in self._import_targets.items()
        }
        self._resolved_import_aliases = {
            source: target for source, target in aliases.items() if source != target
        }
        self.references = [
            SourceReference(
                reference.name,
                reference.location,
                reference.enclosing_function,
                aliases.get(reference.symbol_id, reference.symbol_id),
            )
            for reference in self.references
        ]
        self.calls = [
            SourceCall(
                call.caller,
                call.callee,
                call.location,
                call.caller_id,
                aliases.get(call.callee_id, call.callee_id),
            )
            for call in self.calls
        ]

    def module_for_uri(self, uri: str) -> Optional[str]:
        try:
            return self._modules.get(uri_to_path(uri))
        except ValueError:
            return None

    def text_for_uri(self, uri: str) -> Optional[str]:
        try:
            return self.source_files.get(uri_to_path(uri))
        except ValueError:
            return None

    def document_symbols(self, uri: str) -> list[SourceSymbol]:
        return [
            s
            for s in self.symbols
            if s.full_range.uri == uri and s.kind in {5, 6, 12}
        ]

    def workspace_symbols(self, query: str) -> list[SourceSymbol]:
        query = query.casefold()
        return [
            s for s in self.symbols if not query or query in s.qualified_name.casefold()
        ]

    def word_at(self, uri: str, line: int, character: int) -> Optional[str]:
        text = self.text_for_uri(uri)
        if text is None:
            return None
        lines = text.splitlines()
        if line < 0 or line >= len(lines):
            return None
        source_line = lines[line]
        offset = lsp_character_to_offset(source_line, character)
        for match in _IDENTIFIER.finditer(source_line):
            if match.start() <= offset <= match.end():
                return match.group(0)
        return None

    def python_column(self, uri: str, line: int, character: int) -> int:
        """Convert an LSP UTF-16 offset to Python AST's UTF-8 byte column."""
        text = self.text_for_uri(uri)
        if text is None:
            return character
        lines = text.splitlines()
        if line < 0 or line >= len(lines):
            return character
        offset = lsp_character_to_offset(lines[line], character)
        return len(lines[line][:offset].encode("utf-8"))

    def symbol_at(self, uri: str, line: int, character: int) -> Optional[SourceSymbol]:
        for symbol in self.symbols:
            if symbol.selection_range.uri == uri and symbol.selection_range.contains(
                line, character
            ):
                target = self._resolved_import_aliases.get(symbol.symbol_id)
                return self._symbols_by_id.get(target, symbol)
        for reference in self.references:
            if reference.location.uri == uri and reference.location.contains(
                line, character
            ):
                if reference.symbol_id is not None:
                    return self._symbols_by_id.get(reference.symbol_id)
        word = self.word_at(uri, line, character)
        if not word:
            return None
        candidates = [s for s in self.symbols if s.name == word]
        return candidates[0] if len(candidates) == 1 else None

    def definitions_at(self, uri: str, line: int, character: int) -> list[SourceRange]:
        symbol = self.symbol_at(uri, line, character)
        return [symbol.selection_range] if symbol else []

    def references_at(
        self, uri: str, line: int, character: int, *, include_declaration: bool
    ) -> list[SourceRange]:
        symbol = self.symbol_at(uri, line, character)
        if symbol is None:
            return []
        result = [
            reference.location
            for reference in self.references
            if reference.symbol_id == symbol.symbol_id
        ]
        if include_declaration:
            result.insert(0, symbol.selection_range)
        return _deduplicate_ranges(result)

    def rename_ranges_at(
        self, uri: str, line: int, character: int
    ) -> list[SourceRange]:
        """Return declaration and identity-matched references for LSP rename."""
        symbol = self.symbol_at(uri, line, character)
        if symbol is None:
            return []
        return _deduplicate_ranges(
            [symbol.selection_range]
            + [
                reference.location
                for reference in self.references
                if reference.symbol_id == symbol.symbol_id
            ]
        )

    def diagnostics_for_uri(self, uri: str) -> list[dict[str, object]]:
        text = self.text_for_uri(uri)
        if text is None:
            return []
        try:
            ast.parse(text, filename=uri_to_path(uri))
        except SyntaxError as error:
            line = max((error.lineno or 1) - 1, 0)
            character = max((error.offset or 1) - 1, 0)
            return [
                {
                    "range": SourceRange(uri, line, character, line, character + 1).to_lsp(),
                    "severity": 1,
                    "source": "pyflow",
                    "message": error.msg,
                }
            ]
        return []

    def function_at(
        self, uri: str, line: int, character: int = 0
    ) -> Optional[SourceSymbol]:
        candidates = [
            s
            for s in self.symbols
            if s.kind in {6, 12}
            and s.full_range.uri == uri
            and s.full_range.contains(line, character)
        ]
        candidates.sort(
            key=lambda s: (
                s.full_range.end_line - s.full_range.start_line,
                -s.qualified_name.count("."),
            )
        )
        return candidates[0] if candidates else None

    def symbol_by_name(self, name: str) -> Optional[SourceSymbol]:
        exact = [s for s in self.symbols if s.qualified_name == name]
        if len(exact) == 1:
            return exact[0]
        suffix = [
            s
            for s in self.symbols
            if s.name == name or s.qualified_name.endswith(f".{name}")
        ]
        return suffix[0] if len(suffix) == 1 else None

    def symbol_by_id(self, symbol_id: SymbolId) -> Optional[SourceSymbol]:
        return self._symbols_by_id.get(symbol_id)

    def incoming_calls(
        self, target: SymbolId | str
    ) -> list[tuple[SourceSymbol, list[SourceRange]]]:
        grouped: dict[SourceSymbol, list[SourceRange]] = {}
        target_symbol = (
            self.symbol_by_id(target)
            if isinstance(target, SymbolId)
            else self.symbol_by_name(target)
        )
        if target_symbol is None:
            return []
        for call in self.calls:
            if call.callee_id != target_symbol.symbol_id:
                continue
            caller = (
                self.symbol_by_id(call.caller_id)
                if call.caller_id
                else self.symbol_by_name(call.caller)
            )
            if caller:
                grouped.setdefault(caller, []).append(call.location)
        return list(grouped.items())

    def outgoing_calls(
        self, caller_id: SymbolId | str
    ) -> list[tuple[SourceSymbol, list[SourceRange]]]:
        grouped: dict[SourceSymbol, list[SourceRange]] = {}
        caller = (
            self.symbol_by_id(caller_id)
            if isinstance(caller_id, SymbolId)
            else self.symbol_by_name(caller_id)
        )
        if caller is None:
            return []
        for call in self.calls:
            if call.caller_id != caller.symbol_id:
                continue
            callee = (
                self.symbol_by_id(call.callee_id)
                if call.callee_id
                else self.symbol_by_name(call.callee)
            )
            if callee:
                grouped.setdefault(callee, []).append(call.location)
        return list(grouped.items())


class _IndexVisitor(ast.NodeVisitor):
    def __init__(self, index: SourceIndex, path: str, source: str, module: str):
        self.index = index
        self.path = path
        self.uri = path_to_uri(path)
        self.source = source
        self.lines = source.splitlines()
        self.module = module
        self.scope: list[str] = []
        self._scopes: list[_Scope] = [_Scope(_ScopeKind.MODULE, {})]

    @property
    def _current_scope(self) -> _Scope:
        return self._scopes[-1]

    def _range(self, node: ast.AST, *, name: Optional[str] = None) -> SourceRange:
        start_line = max(getattr(node, "lineno", 1) - 1, 0)
        end_line = max(getattr(node, "end_lineno", start_line + 1) - 1, start_line)
        start_raw = getattr(node, "col_offset", 0)
        end_raw = getattr(node, "end_col_offset", start_raw + 1)
        start_text = self.lines[start_line] if start_line < len(self.lines) else ""
        end_text = self.lines[end_line] if end_line < len(self.lines) else ""
        start_char = _byte_col_to_char(start_text, start_raw)
        end_char = _byte_col_to_char(end_text, end_raw)
        if name:
            found = start_text.find(name, start_char)
            if found >= 0:
                start_char, end_line, end_char = found, start_line, found + len(name)
        return SourceRange(
            self.uri,
            start_line,
            offset_to_lsp_character(start_text, start_char),
            end_line,
            offset_to_lsp_character(end_text, end_char),
        )

    def _qualified(self, name: str) -> str:
        return ".".join([self.module, *self.scope, name])

    def _add_definition(
        self,
        node: ast.AST,
        name: str,
        kind: int,
        identity_kind: SymbolKind,
    ) -> SourceSymbol:
        qualified = self._qualified(name)
        container = ".".join([self.module, *self.scope]) if self.scope else self.module
        selection_range = self._range(node, name=name)
        symbol = SourceSymbol(
            symbol_id=SymbolId(
                module=self.module,
                qualname=qualified,
                kind=identity_kind,
                uri=selection_range.uri,
                line=selection_range.start_line,
                character=selection_range.start_character,
            ),
            name=name,
            qualified_name=qualified,
            module=self.module,
            kind=kind,
            full_range=self._range(node),
            selection_range=selection_range,
            container_name=container,
        )
        self.index.symbols.append(symbol)
        self.index._symbols_by_id[symbol.symbol_id] = symbol
        self._current_scope.bindings[name] = symbol.symbol_id
        return symbol

    def _push_scope(
        self,
        name: str,
        *,
        kind: _ScopeKind,
        function: Optional[SymbolId] = None,
        class_symbol: Optional[SymbolId] = None,
    ) -> None:
        self.scope.append(name)
        parent = self._current_scope
        self._scopes.append(
            _Scope(
                kind,
                {},
                function_id=function or parent.function_id,
                class_id=class_symbol or parent.class_id,
            )
        )

    def _pop_scope(self) -> None:
        self.scope.pop()
        self._scopes.pop()

    def _resolve(self, name: str) -> Optional[SymbolId]:
        current = len(self._scopes) - 1
        current_scope = self._current_scope
        if current_scope.kind is _ScopeKind.FUNCTION:
            if name in current_scope.global_names:
                return self._scopes[0].bindings.get(name)
            if name in current_scope.nonlocal_names:
                for index in range(current - 1, -1, -1):
                    scope = self._scopes[index]
                    if (
                        scope.kind in {_ScopeKind.FUNCTION, _ScopeKind.LAMBDA}
                        and name in scope.bindings
                    ):
                        return scope.bindings[name]
                return None
        inside_lexical_scope = any(
            scope.kind
            in {_ScopeKind.FUNCTION, _ScopeKind.LAMBDA, _ScopeKind.COMPREHENSION}
            for scope in self._scopes
        )
        for index in range(current, -1, -1):
            # Python class bodies are execution namespaces, not lexical parent
            # scopes for functions, lambdas, or comprehensions. ``self.attr``
            # is resolved separately.
            scope = self._scopes[index]
            if inside_lexical_scope and scope.kind is _ScopeKind.CLASS:
                continue
            if name in scope.bindings:
                return scope.bindings[name]
        return None

    def _add_local_definition(
        self, node: ast.AST, name: str, kind: SymbolKind, lsp_kind: int = 13
    ) -> SourceSymbol:
        existing = self._current_scope.bindings.get(name)
        if existing is not None:
            return self.index._symbols_by_id[existing]
        return self._add_definition(node, name, lsp_kind, kind)

    def predeclare_module(self, tree: ast.Module) -> None:
        self._predeclare_bindings(tree.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Decorators, defaults, and annotations are evaluated before the new
        # function binding becomes visible in its enclosing scope.
        self._visit_function_outer_expressions(node)
        existing = self._current_scope.bindings.get(node.name)
        if existing is not None and existing in self._current_scope.predeclared:
            symbol = self.index._symbols_by_id[existing]
        else:
            symbol = self._add_definition(
                node,
                node.name,
                6 if self.scope else 12,
                SymbolKind.METHOD
                if self._current_scope.kind is _ScopeKind.CLASS
                else SymbolKind.FUNCTION,
            )
        self._push_scope(
            node.name, kind=_ScopeKind.FUNCTION, function=symbol.symbol_id
        )
        self._predeclare_function_bindings(node)
        for statement in node.body:
            self.visit(statement)
        self._pop_scope()

    def _visit_function_outer_expressions(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.args.vararg and node.args.vararg.annotation is not None:
            self.visit(node.args.vararg.annotation)
        if node.args.kwarg and node.args.kwarg.annotation is not None:
            self.visit(node.args.kwarg.annotation)
        if node.returns is not None:
            self.visit(node.returns)

    def _predeclare_function_bindings(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        self._predeclare_bindings(
            node.body,
            arguments=[
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *([node.args.vararg] if node.args.vararg is not None else []),
                *([node.args.kwarg] if node.args.kwarg is not None else []),
            ],
        )

    def _predeclare_bindings(
        self, statements: list[ast.stmt], *, arguments: list[ast.arg] | None = None
    ) -> None:
        collector = _ScopeBindingCollector(
            function_lsp_kind=12
            if self._current_scope.kind is _ScopeKind.MODULE
            else 6
        )
        for argument in arguments or []:
            collector.visit(argument)
        for statement in statements:
            collector.visit(statement)
        self._current_scope.global_names.update(collector.global_names)
        self._current_scope.nonlocal_names.update(collector.nonlocal_names)
        for binding in collector.bindings:
            if binding.name in (
                self._current_scope.global_names | self._current_scope.nonlocal_names
            ):
                continue
            symbol = self._add_local_definition(
                binding.node, binding.name, binding.identity_kind, binding.lsp_kind
            )
            self._current_scope.predeclared.add(symbol.symbol_id)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Class decorators, bases and keyword expressions execute in the
        # enclosing scope.  The class namespace exists only for its body.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        existing = self._current_scope.bindings.get(node.name)
        if existing is not None and existing in self._current_scope.predeclared:
            symbol = self.index._symbols_by_id[existing]
        else:
            symbol = self._add_definition(node, node.name, 5, SymbolKind.CLASS)
        self._push_scope(
            node.name, kind=_ScopeKind.CLASS, class_symbol=symbol.symbol_id
        )
        for statement in node.body:
            self.visit(statement)
        self._pop_scope()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambda defaults execute outside its anonymous function scope.
        for argument in [
            *node.args.defaults,
            *node.args.kw_defaults,
        ]:
            if argument is not None:
                self.visit(argument)
        self._push_scope(
            f"<lambda@{node.lineno}:{node.col_offset}>", kind=_ScopeKind.LAMBDA
        )
        self._predeclare_bindings(
            [],
            arguments=[
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *([node.args.vararg] if node.args.vararg is not None else []),
                *([node.args.kwarg] if node.args.kwarg is not None else []),
            ],
        )
        self.visit(node.body)
        self._pop_scope()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node, [node.key, node.value])

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        result_expressions: list[ast.expr],
    ) -> None:
        if not node.generators:
            return
        # Python evaluates the first iterable before entering the implicit
        # comprehension scope; later iterables and filters use that scope.
        first, *remaining = node.generators
        self.visit(first.iter)
        self._push_scope(
            f"<comprehension@{node.lineno}:{node.col_offset}>",
            kind=_ScopeKind.COMPREHENSION,
        )
        self.visit(first.target)
        for condition in first.ifs:
            self.visit(condition)
        for generator in remaining:
            self.visit(generator.iter)
            self.visit(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for expression in result_expressions:
            self.visit(expression)
        self._pop_scope()

    def visit_arg(self, node: ast.arg) -> None:
        self._add_local_definition(node, node.arg, SymbolKind.PARAMETER)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".", 1)[0]
            symbol = self._add_local_definition(alias, name, SymbolKind.IMPORT)
            self.index._import_targets[symbol.symbol_id] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                symbol = self._add_local_definition(
                    alias, alias.asname or alias.name, SymbolKind.IMPORT
                )
                if node.module:
                    self.index._import_targets[symbol.symbol_id] = (
                        f"{node.module}.{alias.name}"
                    )

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            if (
                node.id in self._current_scope.global_names
                or node.id in self._current_scope.nonlocal_names
            ):
                self.index.references.append(
                    SourceReference(
                        node.id,
                        self._range(node),
                        self._current_function(),
                        self._resolve(node.id),
                    )
                )
                return
            self._add_local_definition(node, node.id, SymbolKind.VARIABLE)
            return
        self.index.references.append(
            SourceReference(
                node.id,
                self._range(node),
                self._current_function(),
                self._resolve(node.id),
            )
        )

    def visit_Global(self, node: ast.Global) -> None:
        self._current_scope.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self._current_scope.nonlocal_names.update(node.names)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        location = self._range(node)
        end_line = location.end_line
        line = self.lines[end_line] if end_line < len(self.lines) else ""
        end_offset = lsp_character_to_offset(line, location.end_character)
        start_offset = max(end_offset - len(node.attr), 0)
        attr_range = SourceRange(
            self.uri,
            end_line,
            offset_to_lsp_character(line, start_offset),
            end_line,
            offset_to_lsp_character(line, end_offset),
        )
        self.index.references.append(
            SourceReference(
                node.attr,
                attr_range,
                self._current_function(),
                self._resolve_attribute(node),
            )
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = _call_name(node.func)
        if callee:
            self.index.calls.append(
                SourceCall(
                    self._current_function(),
                    callee,
                    self._range(node.func),
                    self._current_scope.function_id,
                    self._resolve_call(node.func),
                )
            )
        self.generic_visit(node)

    def _current_function(self) -> Optional[str]:
        function_id = self._current_scope.function_id
        return function_id.qualname if function_id else None

    def _resolve_attribute(self, node: ast.Attribute) -> Optional[SymbolId]:
        if isinstance(node.value, ast.Name):
            owner = self._resolve(node.value.id)
            if owner is not None and owner.kind is SymbolKind.CLASS:
                return self._symbol_id_for_qualname(f"{owner.qualname}.{node.attr}")
            if node.value.id == "self" and self._current_scope.class_id is not None:
                return self._symbol_id_for_qualname(
                    f"{self._current_scope.class_id.qualname}.{node.attr}"
                )
        return None

    def _resolve_call(self, node: ast.AST) -> Optional[SymbolId]:
        if isinstance(node, ast.Name):
            return self._resolve(node.id)
        if isinstance(node, ast.Attribute):
            return self._resolve_attribute(node)
        return None

    def _symbol_id_for_qualname(self, qualname: str) -> Optional[SymbolId]:
        for symbol in self.index.symbols:
            if symbol.qualified_name == qualname:
                return symbol.symbol_id
        return None


@dataclass(frozen=True)
class _FunctionBinding:
    node: ast.AST
    name: str
    identity_kind: SymbolKind
    lsp_kind: int = 13


class _ScopeBindingCollector(ast.NodeVisitor):
    """Collect scope-local bindings without descending into child scopes."""

    def __init__(self, *, function_lsp_kind: int = 6) -> None:
        self.bindings: list[_FunctionBinding] = []
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()
        self._function_lsp_kind = function_lsp_kind

    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_names.update(node.names)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bindings.append(_FunctionBinding(node, node.id, SymbolKind.VARIABLE))

    def visit_arg(self, node: ast.arg) -> None:
        self.bindings.append(
            _FunctionBinding(node, node.arg, SymbolKind.PARAMETER)
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.bindings.append(
                _FunctionBinding(
                    alias,
                    alias.asname or alias.name.split(".", 1)[0],
                    SymbolKind.IMPORT,
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.bindings.append(
                    _FunctionBinding(alias, alias.asname or alias.name, SymbolKind.IMPORT)
                )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.bindings.append(
            _FunctionBinding(
                node,
                node.name,
                SymbolKind.FUNCTION,
                lsp_kind=self._function_lsp_kind,
            )
        )

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.bindings.append(
            _FunctionBinding(
                node,
                node.name,
                SymbolKind.FUNCTION,
                lsp_kind=self._function_lsp_kind,
            )
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bindings.append(
            _FunctionBinding(node, node.name, SymbolKind.CLASS, lsp_kind=5)
        )

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambda creates a nested scope; its internal assignments do not bind
        # the enclosing function.
        return None

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    @staticmethod
    def _visit_comprehension(
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
    ) -> None:
        # Comprehension targets are local to an implicit nested scope.  Only
        # the leftmost iterable runs in the enclosing scope, and it contains
        # no declaration that should predeclare a name in that scope.
        return None


def _call_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _deduplicate_ranges(ranges: Iterable[SourceRange]) -> list[SourceRange]:
    seen: set[SourceRange] = set()
    result: list[SourceRange] = []
    for item in ranges:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


__all__ = [
    "SourceIndex",
    "SourceRange",
    "SymbolId",
    "SymbolKind",
    "SourceSymbol",
    "WorkspaceDocuments",
    "lsp_character_to_offset",
    "offset_to_lsp_character",
    "path_to_uri",
    "uri_to_path",
]
