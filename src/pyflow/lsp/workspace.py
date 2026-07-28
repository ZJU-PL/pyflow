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
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import unquote, urlparse

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


@dataclass(frozen=True)
class SourceSymbol:
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


@dataclass(frozen=True)
class SourceCall:
    caller: Optional[str]
    callee: str
    location: SourceRange


class WorkspaceDocuments:
    """Open-document overlays with monotonically increasing revisions."""

    def __init__(self) -> None:
        self._documents: dict[str, tuple[str, Optional[int]]] = {}
        self.revision = 0
        self._lock = threading.RLock()

    def open(self, path: str, text: str, version: Optional[int]) -> int:
        with self._lock:
            self._documents[os.path.abspath(path)] = (text, version)
            self.revision += 1
            return self.revision

    def change(self, path: str, text: str, version: Optional[int]) -> int:
        return self.open(path, text, version)

    def close(self, path: str) -> int:
        with self._lock:
            self._documents.pop(os.path.abspath(path), None)
            self.revision += 1
            return self.revision

    def source_overrides(self) -> dict[str, str]:
        with self._lock:
            return {path: value[0] for path, value in self._documents.items()}

    def text(self, path: str) -> Optional[str]:
        with self._lock:
            item = self._documents.get(os.path.abspath(path))
            return item[0] if item else None


class SourceIndex:
    """AST-backed index for source-accurate navigation and hierarchy results."""

    def __init__(self, source_files: dict[str, str], root_path: Optional[str] = None):
        self.root_path = os.path.abspath(root_path) if root_path else None
        self.source_files = {
            os.path.abspath(path): text for path, text in source_files.items()
        }
        self.symbols: list[SourceSymbol] = []
        self.references: list[SourceReference] = []
        self.calls: list[SourceCall] = []
        self._modules: dict[str, str] = {}
        for path, source in self.source_files.items():
            self._index_file(path, source)

    def _module_name(self, path: str) -> str:
        relative: Path
        if self.root_path:
            try:
                relative = Path(path).relative_to(self.root_path)
            except ValueError:
                relative = Path(Path(path).name)
        else:
            relative = Path(Path(path).name)
        parts = list(relative.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts) or Path(path).stem

    def _index_file(self, path: str, source: str) -> None:
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            return
        module = self._module_name(path)
        self._modules[path] = module
        visitor = _IndexVisitor(self, path, source, module)
        visitor.visit(tree)

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
        return [s for s in self.symbols if s.full_range.uri == uri]

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
                return symbol
        word = self.word_at(uri, line, character)
        if not word:
            return None
        module = self.module_for_uri(uri)
        candidates = [s for s in self.symbols if s.name == word]
        candidates.sort(key=lambda s: (s.module != module, s.qualified_name.count(".")))
        return candidates[0] if candidates else None

    def definitions_at(self, uri: str, line: int, character: int) -> list[SourceRange]:
        symbol = self.symbol_at(uri, line, character)
        return [symbol.selection_range] if symbol else []

    def references_at(
        self, uri: str, line: int, character: int, *, include_declaration: bool
    ) -> list[SourceRange]:
        symbol = self.symbol_at(uri, line, character)
        if symbol is None:
            return []
        result = [r.location for r in self.references if r.name == symbol.name]
        if include_declaration:
            result.insert(0, symbol.selection_range)
        return _deduplicate_ranges(result)

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
        if exact:
            return exact[0]
        suffix = [
            s
            for s in self.symbols
            if s.name == name or s.qualified_name.endswith(f".{name}")
        ]
        return suffix[0] if suffix else None

    def incoming_calls(self, name: str) -> list[tuple[SourceSymbol, list[SourceRange]]]:
        grouped: dict[SourceSymbol, list[SourceRange]] = {}
        target = self.symbol_by_name(name)
        target_name = target.name if target else name.rsplit(".", 1)[-1]
        for call in self.calls:
            if call.callee.rsplit(".", 1)[-1] != target_name or not call.caller:
                continue
            caller = self.symbol_by_name(call.caller)
            if caller:
                grouped.setdefault(caller, []).append(call.location)
        return list(grouped.items())

    def outgoing_calls(self, name: str) -> list[tuple[SourceSymbol, list[SourceRange]]]:
        grouped: dict[SourceSymbol, list[SourceRange]] = {}
        caller = self.symbol_by_name(name)
        caller_name = caller.qualified_name if caller else name
        for call in self.calls:
            if call.caller != caller_name:
                continue
            callee = self.symbol_by_name(call.callee)
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

    def _add_definition(self, node: ast.AST, name: str, kind: int) -> None:
        qualified = self._qualified(name)
        container = ".".join([self.module, *self.scope]) if self.scope else self.module
        self.index.symbols.append(
            SourceSymbol(
                name=name,
                qualified_name=qualified,
                module=self.module,
                kind=kind,
                full_range=self._range(node),
                selection_range=self._range(node, name=name),
                container_name=container,
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._add_definition(node, node.name, 6 if self.scope else 12)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._add_definition(node, node.name, 5)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Name(self, node: ast.Name) -> None:
        self.index.references.append(
            SourceReference(node.id, self._range(node), self._current_function())
        )

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
            SourceReference(node.attr, attr_range, self._current_function())
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = _call_name(node.func)
        if callee:
            self.index.calls.append(
                SourceCall(self._current_function(), callee, self._range(node.func))
            )
        self.generic_visit(node)

    def _current_function(self) -> Optional[str]:
        if not self.scope:
            return None
        return ".".join([self.module, *self.scope])


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
    "SourceSymbol",
    "WorkspaceDocuments",
    "lsp_character_to_offset",
    "offset_to_lsp_character",
    "path_to_uri",
    "uri_to_path",
]
