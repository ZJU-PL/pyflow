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
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import unquote, urlparse

from pyflow.language.modules.project_resolution import ModuleIdentityResolver
from pyflow.frontend.source import read_python_source

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

    MODULE = "module"
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
    detail: str = ""
    documentation: str = ""

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


@dataclass(frozen=True)
class _FileIndex:
    """Immutable AST-indexed contribution of one source file."""

    path: str
    source: str
    module: Optional[str]
    symbols: tuple[SourceSymbol, ...]
    references: tuple[SourceReference, ...]
    calls: tuple[SourceCall, ...]
    import_targets: tuple[tuple[SymbolId, str], ...]
    reference_targets: tuple = ()
    call_targets: tuple = ()
    value_targets: tuple = ()
    return_targets: tuple = ()
    class_bases: tuple = ()
    scopes: tuple = ()
    syntax_stale: bool = False


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
    path: tuple[str, ...] = ()
    function_id: Optional[SymbolId] = None
    class_id: Optional[SymbolId] = None
    receiver_id: Optional[SymbolId] = None
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

    def change(self, path: str, changes: list[dict[str, object]], version: Optional[int]) -> bool:
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

    def snapshot(self) -> tuple[dict[str, str], int]:
        """Return document overlays and their revision from one lock hold."""
        with self._lock:
            return (
                {path: value[0] for path, value in self._documents.items()},
                self.revision,
            )

    def current_revision(self) -> int:
        with self._lock:
            return self.revision

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
        return read_python_source(path)
    except (OSError, UnicodeError, SyntaxError):
        return ""


def _position_to_offset(text: str, line: int, character: int) -> int:
    lines = text.splitlines(keepends=True)
    if line < 0:
        raise ValueError("LSP content change line cannot be negative")
    if line >= len(lines):
        return len(text)
    line_text = lines[line]
    return sum(len(item) for item in lines[:line]) + lsp_character_to_offset(line_text, character)


class SourceIndex:
    """AST-backed index for source-accurate navigation and hierarchy results."""

    def __init__(
        self,
        source_files: dict[str, str],
        workspace_roots: Iterable[str | os.PathLike[str]] = (),
    ):
        self.workspace_roots = tuple(Path(root).absolute() for root in workspace_roots)
        self.module_identity = ModuleIdentityResolver(self.workspace_roots)
        self.source_files = {os.path.abspath(path): text for path, text in source_files.items()}
        self._file_indices: dict[str, _FileIndex] = {
            path: self._build_file_index(path, source) for path, source in self.source_files.items()
        }
        self._rebuild_workspace_maps()

    @classmethod
    def _from_file_indices(
        cls,
        source_files: dict[str, str],
        workspace_roots: tuple[Path, ...],
        file_indices: dict[str, _FileIndex],
    ) -> "SourceIndex":
        index = cls.__new__(cls)
        index.workspace_roots = workspace_roots
        index.module_identity = ModuleIdentityResolver(workspace_roots)
        index.source_files = source_files
        index._file_indices = file_indices
        index._rebuild_workspace_maps()
        return index

    def with_source_files(self, source_files: dict[str, str]) -> "SourceIndex":
        """Return an index that reparses only files whose text changed."""
        normalized = {os.path.abspath(path): text for path, text in source_files.items()}
        if normalized == self.source_files:
            return self
        file_indices: dict[str, _FileIndex] = {}
        for path, source in normalized.items():
            previous = self._file_indices.get(path)
            if previous is not None and previous.source == source:
                file_indices[path] = previous
                continue
            updated = self._build_file_index(path, source)
            file_indices[path] = (
                self._retain_valid_ranges(previous, source)
                if updated.module is None and previous is not None and previous.module is not None
                else updated
            )
        return self._from_file_indices(normalized, self.workspace_roots, file_indices)

    @staticmethod
    def _retain_valid_ranges(previous, source):
        """Keep unchanged declarations/references through a transient parse error.

        Rebase prefix/suffix coordinates after the edited interval. Never keep
        a reference whose token was edited, or permit rename on a stale shard.
        """
        old = previous.source
        prefix = 0
        for left, right in zip(old, source):
            if left != right:
                break
            prefix += 1
        suffix = 0
        for left, right in zip(reversed(old[prefix:]), reversed(source[prefix:])):
            if left != right:
                break
            suffix += 1
        old_lines = old.splitlines(keepends=True)
        new_lines = source.splitlines(keepends=True)
        old_starts = [0]
        new_starts = [0]
        for line in old_lines:
            old_starts.append(old_starts[-1] + len(line))
        for line in new_lines:
            new_starts.append(new_starts[-1] + len(line))

        def position(line, character):
            if line >= len(old_lines):
                return len(old)
            return old_starts[line] + lsp_character_to_offset(old_lines[line], character)

        # Line-level matches also retain declarations between disjoint edits,
        # e.g. an inserted header plus an unfinished call later in the file.
        from difflib import SequenceMatcher

        blocks = [
            (old_starts[i], old_starts[i + count], new_starts[j] - old_starts[i])
            for i, j, count in SequenceMatcher(
                None, old_lines, new_lines, autojunk=False
            ).get_matching_blocks()
            if count
        ]

        def mapped(offset):
            for start, stop, delta in blocks:
                if start <= offset <= stop:
                    return offset + delta
            if offset <= prefix:
                return offset
            if offset >= len(old) - suffix:
                return offset + len(source) - len(old)
            return None

        def coordinates(offset):
            from bisect import bisect_right

            row = min(max(bisect_right(new_starts, offset) - 1, 0), max(len(new_lines) - 1, 0))
            text = new_lines[row] if new_lines else ""
            return row, offset_to_lsp_character(text, offset - new_starts[row])

        def remap(location, *, full=False):
            start = position(location.start_line, location.start_character)
            end = position(location.end_line, location.end_character)
            new_start, new_end = mapped(start), mapped(end)
            if not full and (
                new_start is None or new_end is None or old[start:end] != source[new_start:new_end]
            ):
                return None
            if new_start is None:
                new_start = prefix
            if new_end is None:
                new_end = len(source) - suffix
            return SourceRange(
                location.uri, *coordinates(new_start), *coordinates(max(new_start, new_end))
            )

        symbols = tuple(
            replace(
                symbol, selection_range=selection, full_range=remap(symbol.full_range, full=True)
            )
            for symbol in previous.symbols
            if (selection := remap(symbol.selection_range)) is not None
        )
        references = tuple(
            replace(reference, location=location)
            for reference in previous.references
            if (location := remap(reference.location)) is not None
        )
        calls = tuple(
            replace(call, location=location)
            for call in previous.calls
            if (location := remap(call.location)) is not None
        )
        return replace(
            previous,
            source=source,
            symbols=symbols,
            references=references,
            calls=calls,
            reference_targets=tuple(
                (location, target)
                for old_range, target in previous.reference_targets
                if (location := remap(old_range)) is not None
            ),
            call_targets=tuple(
                (location, target)
                for old_range, target in previous.call_targets
                if (location := remap(old_range)) is not None
            ),
            scopes=tuple(
                (remap(location, full=True), kind, bindings)
                for location, kind, bindings in previous.scopes
            ),
            syntax_stale=True,
        )

    def _rebuild_workspace_maps(self) -> None:
        self.symbols: list[SourceSymbol] = []
        self.references: list[SourceReference] = []
        self.calls: list[SourceCall] = []
        self._modules: dict[str, str] = {}
        self._symbols_by_id: dict[SymbolId, SourceSymbol] = {}
        self._references_by_range: dict[SourceRange, SymbolId] = {}
        self._import_targets: dict[SymbolId, str] = {}
        self._resolved_import_aliases: dict[SymbolId, SymbolId] = {}
        self._reference_targets = {}
        self._call_targets = {}
        self._value_targets = {}
        self._return_targets = {}
        self._class_bases = {}
        self._scopes = []
        for path in sorted(self._file_indices):
            file_index = self._file_indices[path]
            if file_index.module is not None:
                self._modules[path] = file_index.module
            self.symbols.extend(file_index.symbols)
            self._symbols_by_id.update({symbol.symbol_id: symbol for symbol in file_index.symbols})
            self.references.extend(file_index.references)
            self.calls.extend(file_index.calls)
            self._import_targets.update(file_index.import_targets)
            self._reference_targets.update(file_index.reference_targets)
            self._call_targets.update(file_index.call_targets)
            self._value_targets.update(file_index.value_targets)
            self._return_targets.update(file_index.return_targets)
            self._class_bases.update(file_index.class_bases)
            self._scopes.extend(file_index.scopes)
        from .resolution import WorkspaceResolver

        self._resolver = WorkspaceResolver(
            self.symbols,
            self._import_targets,
            self._value_targets,
            self._return_targets,
            self._class_bases,
        )
        self._resolve_import_aliases()
        self._uncertain_member_ranges = {
            location
            for location, target in self._reference_targets.items()
            if not self._resolver.is_complete(target)
        }
        self.references = [
            replace(reference, symbol_id=(target.symbol_id if target else reference.symbol_id))
            for reference in self.references
            for target in [self._resolver.symbol(self._reference_targets.get(reference.location))]
        ]
        self.calls = [
            replace(call, callee_id=(target.symbol_id if target else call.callee_id))
            for call in self.calls
            for target in [self._resolver.callable_symbol(self._call_targets.get(call.location))]
        ]
        modules = {}
        for path, name in self._modules.items():
            uri = path_to_uri(path)
            lines = self.source_files[path].splitlines()
            location = SourceRange(
                uri,
                0,
                0,
                max(len(lines) - 1, 0),
                offset_to_lsp_character(lines[-1], len(lines[-1])) if lines else 0,
            )
            identity = SymbolId(name, name, SymbolKind.MODULE, uri, 0, 0)
            modules[uri] = SourceSymbol(
                identity, name, name, name, 2, location, SourceRange(uri, 0, 0, 0, 0)
            )
            self._symbols_by_id[identity] = modules[uri]
        self._module_symbols = modules
        self.calls = [
            (
                replace(
                    call,
                    caller=modules[call.location.uri].name,
                    caller_id=modules[call.location.uri].symbol_id,
                )
                if call.caller_id is None and call.location.uri in modules
                else call
            )
            for call in self.calls
        ]

    def _module_name(self, path: str) -> str:
        return self.module_identity.module_name_from_path(path) or Path(path).stem

    def _index_file(self, path: str, source: str) -> None:
        try:
            tree = ast.parse(source, filename=path)
        except (SyntaxError, RecursionError):
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
        visitor._record_scope(tree)

    def _build_file_index(self, path: str, source: str) -> _FileIndex:
        """Build one shard using the existing single-file visitor."""
        scratch = type(self).__new__(type(self))
        scratch.workspace_roots = self.workspace_roots
        scratch.module_identity = self.module_identity
        scratch.source_files = {path: source}
        scratch.symbols = []
        scratch.references = []
        scratch.calls = []
        scratch._modules = {}
        scratch._symbols_by_id = {}
        scratch._references_by_range = {}
        scratch._import_targets = {}
        scratch._resolved_import_aliases = {}
        scratch._reference_targets = {}
        scratch._call_targets = {}
        scratch._value_targets = {}
        scratch._return_targets = {}
        scratch._class_bases = {}
        scratch._scopes = []
        scratch._index_file(path, source)
        return _FileIndex(
            path,
            source,
            scratch._modules.get(path),
            tuple(scratch.symbols),
            tuple(scratch.references),
            tuple(scratch.calls),
            tuple(scratch._import_targets.items()),
            tuple(scratch._reference_targets.items()),
            tuple(scratch._call_targets.items()),
            tuple((key, tuple(values)) for key, values in scratch._value_targets.items()),
            tuple((key, tuple(values)) for key, values in scratch._return_targets.items()),
            tuple(scratch._class_bases.items()),
            tuple(scratch._scopes),
            syntax_stale=path not in scratch._modules,
        )

    def _resolve_import_aliases(self) -> None:
        """Resolve ``from pkg import name as alias`` after all modules exist."""
        aliases = {
            symbol_id: self._resolver._canonical(symbol_id) for symbol_id in self._import_targets
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
        return [s for s in self.symbols if s.full_range.uri == uri and s.kind in {5, 6, 12}]

    def workspace_symbols(self, query: str) -> list[SourceSymbol]:
        query = query.casefold()
        return [s for s in self.symbols if not query or query in s.qualified_name.casefold()]

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
            if reference.location.uri == uri and reference.location.contains(line, character):
                return self._symbols_by_id.get(reference.symbol_id)
        return None

    def visible_bindings_at(self, uri, line, character):
        scopes = [
            (location, kind, bindings)
            for location, kind, bindings in self._scopes
            if location.uri == uri and location.contains(line, character)
        ]
        scopes.sort(
            key=lambda item: (item[0].end_line - item[0].start_line, -item[0].start_line),
            reverse=True,
        )
        inside_function = any(
            kind in {_ScopeKind.FUNCTION, _ScopeKind.LAMBDA} for _, kind, _ in scopes
        )
        bindings = {}
        for _location, kind, entries in scopes:
            if inside_function and kind is _ScopeKind.CLASS:
                continue
            bindings.update(entries)
        return bindings

    def _position_target(self, expression, bindings):
        if isinstance(expression, ast.Name):
            symbol = bindings.get(expression.id)
            if symbol:
                return ("symbol", symbol)
            if expression.id in {"str", "list", "dict", "int"}:
                return ("external", "builtins." + expression.id)
        if isinstance(expression, ast.Attribute):
            return ("member", self._position_target(expression.value, bindings), expression.attr)
        if isinstance(expression, ast.Call):
            return ("instance", self._position_target(expression.func, bindings))
        return ("unknown",)

    def completion_items(self, uri, line, character):
        text = self.text_for_uri(uri)
        lines = text.splitlines() if text is not None else []
        if line < 0 or line >= len(lines):
            return []
        before = lines[line][: lsp_character_to_offset(lines[line], character)]
        bindings = self.visible_bindings_at(uri, line, character)
        member = re.search(r"\.([A-Za-z_]\w*)?$", before)
        external = []
        if member:
            prefix = member.group(1) or ""
            receiver_text = before[: member.start()]
            target = ("unknown",)
            for match in _IDENTIFIER.finditer(receiver_text):
                try:
                    expression = ast.parse(receiver_text[match.start() :], mode="eval").body
                except SyntaxError:
                    continue
                target = self._position_target(expression, bindings)
                break
            symbols = self._resolver.members(target)
            for owner in self._resolver.names(target):
                external.extend(self._external_members(owner, prefix))
        else:
            match = re.search(r"[A-Za-z_]\w*$", before)
            prefix = match.group(0) if match else ""
            symbols = [
                self._symbols_by_id[symbol]
                for symbol in bindings.values()
                if symbol in self._symbols_by_id
            ]
        items = [
            {
                "label": symbol.name,
                "kind": {5: 7, 6: 2, 12: 3}.get(symbol.kind, 6),
                "detail": symbol.detail or symbol.qualified_name,
                **(
                    {"documentation": {"kind": "markdown", "value": symbol.documentation}}
                    if symbol.documentation
                    else {}
                ),
            }
            for symbol in symbols
            if symbol.name.startswith(prefix)
        ]
        by_name = {item["label"]: item for item in [*external, *items]}
        return sorted(by_name.values(), key=lambda item: item["label"])

    @staticmethod
    def _external_members(owner, prefix):
        # Inspect only trusted stdlib namespaces; never import workspace code.
        import builtins
        import math
        import sys
        import os

        namespaces = {"math": math, "sys": sys, "os": os, "os.path": os.path}
        if owner.startswith("builtins."):
            namespace = getattr(builtins, owner.split(".", 1)[1], None)
        else:
            namespace = namespaces.get(owner)
        if namespace is None:
            return []
        return [
            {
                "label": name,
                "kind": 3 if callable(getattr(namespace, name, None)) else 21,
                "detail": f"{owner}.{name}",
            }
            for name in dir(namespace)
            if name.startswith(prefix) and not name.startswith("_")
        ]

    def hover_at(self, uri, line, character):
        symbol = self.symbol_at(uri, line, character)
        if symbol is None:
            return None
        declaration = symbol.detail or symbol.name
        if symbol.symbol_id.kind in {SymbolKind.VARIABLE, SymbolKind.PARAMETER}:
            names = self._resolver.names(("symbol", symbol.symbol_id))
            types = [
                name.removeprefix("builtins.")
                for name in names
                if name.startswith("builtins.")
                or (name in self._resolver.symbols and self._resolver.symbols[name].kind == 5)
            ]
            if types:
                declaration = symbol.name + ": " + " | ".join(sorted(types))
            elif declaration == symbol.name:
                return None
        elif symbol.symbol_id.kind is SymbolKind.IMPORT:
            declaration = "import " + self._import_targets.get(symbol.symbol_id, symbol.name)
        value = f"```python\n{declaration}\n```"
        if symbol.documentation:
            value += "\n\n" + symbol.documentation
        return {"contents": {"kind": "markdown", "value": value}}

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

    def token_range_at(self, uri, line, character):
        for reference in self.references:
            if reference.location.uri == uri and reference.location.contains(line, character):
                return reference.location
        for symbol in self.symbols:
            if symbol.selection_range.uri == uri and symbol.selection_range.contains(
                line, character
            ):
                return symbol.selection_range
        return None

    def rename_ranges_at(self, uri: str, line: int, character: int) -> list[SourceRange]:
        """Return declaration and identity-matched references for LSP rename."""
        symbol = self.symbol_at(uri, line, character)
        if symbol is None:
            return []
        owner = self._resolver.symbols.get(symbol.container_name)
        if (
            symbol.symbol_id.kind is SymbolKind.METHOD or (owner is not None and owner.kind == 5)
        ) and any(
            reference.name == symbol.name
            and (reference.symbol_id is None or reference.location in self._uncertain_member_ranges)
            and reference.location in self._reference_targets
            for reference in self.references
        ):
            return []
        if any(index.syntax_stale for index in self._file_indices.values()):
            return []
        return _deduplicate_ranges(
            [symbol.selection_range]
            + [
                reference.location
                for reference in self.references
                if reference.symbol_id == symbol.symbol_id and reference.name == symbol.name
            ]
        )

    def diagnostics_for_uri(self, uri: str) -> list[dict[str, object]]:
        text = self.text_for_uri(uri)
        if text is None:
            return []
        try:
            ast.parse(text, filename=uri_to_path(uri))
        except (SyntaxError, RecursionError) as error:
            line = max((getattr(error, "lineno", 1) or 1) - 1, 0)
            character = max((getattr(error, "offset", 1) or 1) - 1, 0)
            return [
                {
                    "range": SourceRange(uri, line, character, line, character + 1).to_lsp(),
                    "severity": 1,
                    "source": "pyflow",
                    "message": getattr(error, "msg", str(error)),
                }
            ]
        return []

    def function_at(self, uri: str, line: int, character: int = 0) -> Optional[SourceSymbol]:
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
            s for s in self.symbols if s.name == name or s.qualified_name.endswith(f".{name}")
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
            callee = self.symbol_by_id(call.callee_id) if call.callee_id else None
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
                end_text = start_text
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
        return self._add_definition_in_scope(self._current_scope, node, name, kind, identity_kind)

    def _add_definition_in_scope(
        self,
        scope: _Scope,
        node: ast.AST,
        name: str,
        kind: int,
        identity_kind: SymbolKind,
    ) -> SourceSymbol:
        qualified = ".".join([self.module, *scope.path, name])
        container = ".".join([self.module, *scope.path]) if scope.path else self.module
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
            detail=self._declaration(node, name),
            documentation=(
                (ast.get_docstring(node) or "")
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                else ""
            ),
        )
        self.index.symbols.append(symbol)
        self.index._symbols_by_id[symbol.symbol_id] = symbol
        scope.bindings[name] = symbol.symbol_id
        return symbol

    @staticmethod
    def _declaration(node, name):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result = f"{'async ' if isinstance(node, ast.AsyncFunctionDef) else ''}def {name}({ast.unparse(node.args)})"
            return result + (" -> " + ast.unparse(node.returns) if node.returns else "")
        if isinstance(node, ast.ClassDef):
            return f"class {name}" + (
                "(" + ", ".join(ast.unparse(base) for base in node.bases) + ")"
                if node.bases
                else ""
            )
        if isinstance(node, ast.arg) and node.annotation:
            return f"{name}: {ast.unparse(node.annotation)}"
        return name

    def _record_scope(self, node):
        scope = self._current_scope
        location = (
            self._range(node)
            if not isinstance(node, ast.Module)
            else SourceRange(self.uri, 0, 0, len(self.lines), 0)
        )
        self.index._scopes.append((location, scope.kind, tuple(scope.bindings.items())))

    def _target(self, node):
        if isinstance(node, ast.Name):
            symbol = self._resolve(node.id)
            if symbol:
                return ("symbol", symbol)
            if node.id in {"str", "int", "float", "bool", "bytes", "list", "dict", "set", "tuple"}:
                return ("external", "builtins." + node.id)
        if isinstance(node, ast.Attribute):
            return ("member", self._target(node.value), node.attr)
        if isinstance(node, ast.Call):
            return ("instance", self._target(node.func))
        if isinstance(node, ast.Constant):
            return ("external", "builtins." + type(node.value).__name__)
        return ("unknown",)

    def _annotation_target(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                node = ast.parse(node.value, mode="eval").body
            except SyntaxError:
                return ("unknown",)
        return ("instance", self._target(node))

    def _bind_value(self, target, value):
        if isinstance(target, ast.Name):
            symbol_id = self._resolve(target.id)
        elif (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and self._resolve(target.value.id) == self._current_scope.receiver_id
        ):
            class_scope = next(
                (scope for scope in reversed(self._scopes) if scope.kind is _ScopeKind.CLASS), None
            )
            symbol_id = (
                self._add_local_definition_in_scope(
                    class_scope, target, target.attr, SymbolKind.VARIABLE
                ).symbol_id
                if class_scope
                else None
            )
        else:
            symbol_id = None
        if symbol_id:
            self.index._value_targets.setdefault(symbol_id, []).append(value)

    def visit_Assign(self, node):
        self.generic_visit(node)
        for target in node.targets:
            self._bind_value(target, self._target(node.value))

    def visit_AnnAssign(self, node):
        self.generic_visit(node)
        self._bind_value(node.target, self._annotation_target(node.annotation))
        if node.value is not None:
            self._bind_value(node.target, self._target(node.value))

    def visit_Return(self, node):
        self.generic_visit(node)
        if node.value is not None and self._current_scope.function_id:
            self.index._return_targets.setdefault(self._current_scope.function_id, []).append(
                self._target(node.value)
            )

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
                kind=kind,
                bindings={},
                path=tuple(self.scope),
                function_id=function or parent.function_id,
                class_id=class_symbol or parent.class_id,
                receiver_id=parent.receiver_id,
            )
        )

    def _pop_scope(self) -> None:
        self.scope.pop()
        self._scopes.pop()

    def _resolve(self, name: str) -> Optional[SymbolId]:
        current = len(self._scopes) - 1
        current_scope = self._current_scope
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
        crossed_lexical_boundary = False
        for index in range(current, -1, -1):
            # Python class bodies are execution namespaces, not lexical parent
            # scopes after a function, lambda, or comprehension boundary.
            # ``self.attr`` is resolved separately.
            scope = self._scopes[index]
            if crossed_lexical_boundary and scope.kind is _ScopeKind.CLASS:
                continue
            if name in scope.bindings:
                return scope.bindings[name]
            if scope.kind in {
                _ScopeKind.FUNCTION,
                _ScopeKind.LAMBDA,
                _ScopeKind.COMPREHENSION,
            }:
                crossed_lexical_boundary = True
        return None

    def _add_local_definition(
        self, node: ast.AST, name: str, kind: SymbolKind, lsp_kind: int = 13
    ) -> SourceSymbol:
        existing = self._current_scope.bindings.get(name)
        if existing is not None:
            return self.index._symbols_by_id[existing]
        return self._add_definition(node, name, lsp_kind, kind)

    def _add_local_definition_in_scope(
        self, scope: _Scope, node: ast.AST, name: str, kind: SymbolKind
    ) -> SourceSymbol:
        existing = scope.bindings.get(name)
        if existing is not None:
            return self.index._symbols_by_id[existing]
        return self._add_definition_in_scope(scope, node, name, 13, kind)

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
        is_method = self._current_scope.kind is _ScopeKind.CLASS
        existing = self._current_scope.bindings.get(node.name)
        if existing is not None and existing in self._current_scope.predeclared:
            symbol = self.index._symbols_by_id[existing]
        else:
            symbol = self._add_definition(
                node,
                node.name,
                6 if self.scope else 12,
                SymbolKind.METHOD if is_method else SymbolKind.FUNCTION,
            )
        self._push_scope(node.name, kind=_ScopeKind.FUNCTION, function=symbol.symbol_id)
        self._predeclare_function_bindings(node)
        if is_method:
            positional = [*node.args.posonlyargs, *node.args.args]
            if (
                positional
                and positional[0].arg in {"self", "cls"}
                and not any(
                    isinstance(decorator, ast.Name) and decorator.id == "staticmethod"
                    for decorator in node.decorator_list
                )
            ):
                self._current_scope.receiver_id = self._current_scope.bindings.get(
                    positional[0].arg
                )
                self.index._value_targets[self._current_scope.receiver_id] = [
                    ("symbol", self._current_scope.class_id)
                ]
        for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            if argument.annotation and self._resolve(argument.arg):
                self.index._value_targets.setdefault(self._resolve(argument.arg), []).append(
                    self._annotation_target(argument.annotation)
                )
        if node.returns:
            self.index._return_targets.setdefault(symbol.symbol_id, []).append(
                self._annotation_target(node.returns)
            )
        for statement in node.body:
            self.visit(statement)
        self._record_scope(node)
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

    def _predeclare_function_bindings(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
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
            function_lsp_kind=12 if self._current_scope.kind is _ScopeKind.MODULE else 6
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

    def _predeclare_expression_bindings(
        self, expression: ast.expr, *, arguments: list[ast.arg]
    ) -> None:
        collector = _ScopeBindingCollector(function_lsp_kind=6)
        for argument in arguments:
            collector.visit(argument)
        collector.visit(expression)
        for binding in collector.bindings:
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
        self.index._class_bases[symbol.qualified_name] = tuple(
            self._target(base) for base in node.bases
        )
        self._push_scope(node.name, kind=_ScopeKind.CLASS, class_symbol=symbol.symbol_id)
        for statement in node.body:
            self.visit(statement)
        self._record_scope(node)
        self._pop_scope()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambda defaults execute outside its anonymous function scope.
        for argument in [
            *node.args.defaults,
            *node.args.kw_defaults,
        ]:
            if argument is not None:
                self.visit(argument)
        self._push_scope(f"<lambda@{node.lineno}:{node.col_offset}>", kind=_ScopeKind.LAMBDA)
        self._predeclare_expression_bindings(
            node.body,
            arguments=[
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *([node.args.vararg] if node.args.vararg is not None else []),
                *([node.args.kwarg] if node.args.kwarg is not None else []),
            ],
        )
        self.visit(node.body)
        self._record_scope(node)
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
        self._record_scope(node)
        self._pop_scope()

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        """Apply PEP 572's containing-scope rule for comprehensions."""
        if self._current_scope.kind is not _ScopeKind.COMPREHENSION:
            self.generic_visit(node)
            return
        target_scope = self._namedexpr_target_scope()
        if isinstance(node.target, ast.Name):
            symbol = self._bind_namedexpr_target(target_scope, node.target)
            if symbol is not None and (
                node.target.id in target_scope.global_names
                or node.target.id in target_scope.nonlocal_names
            ):
                self.index.references.append(
                    SourceReference(
                        node.target.id,
                        self._range(node.target),
                        self._current_function(),
                        symbol,
                    )
                )
        else:
            self.visit(node.target)
        self.visit(node.value)

    def _namedexpr_target_scope(self) -> _Scope:
        for scope in reversed(self._scopes):
            if scope.kind is not _ScopeKind.COMPREHENSION:
                return scope
        return self._scopes[0]

    def _bind_namedexpr_target(self, target_scope: _Scope, target: ast.Name) -> Optional[SymbolId]:
        if target.id in target_scope.global_names:
            return self._scopes[0].bindings.get(target.id)
        if target.id in target_scope.nonlocal_names:
            target_index = self._scopes.index(target_scope)
            for scope in reversed(self._scopes[:target_index]):
                if (
                    scope.kind in {_ScopeKind.FUNCTION, _ScopeKind.LAMBDA}
                    and target.id in scope.bindings
                ):
                    return scope.bindings[target.id]
            return None
        return self._add_local_definition_in_scope(
            target_scope, target, target.id, SymbolKind.VARIABLE
        ).symbol_id

    def visit_arg(self, node: ast.arg) -> None:
        self._add_local_definition(node, node.arg, SymbolKind.PARAMETER)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".", 1)[0]
            symbol = self._add_local_definition(alias, name, SymbolKind.IMPORT)
            self.index._import_targets[symbol.symbol_id] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                symbol = self._add_local_definition(
                    alias, alias.asname or alias.name, SymbolKind.IMPORT
                )
                module = node.module or ""
                if node.level:
                    package = (
                        self.module.split(".")
                        if Path(self.path).name == "__init__.py"
                        else self.module.split(".")[:-1]
                    )
                    module = ".".join(
                        [*package[: len(package) - node.level + 1], *([module] if module else [])]
                    )
                self.index._import_targets[symbol.symbol_id] = f"{module}.{alias.name}".lstrip(".")
                self.index.references.append(
                    SourceReference(
                        alias.name,
                        self._range(alias, name=alias.name),
                        self._current_function(),
                        symbol.symbol_id,
                    )
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
            symbol = self._add_local_definition(node, node.id, SymbolKind.VARIABLE)
            if self._range(node) != symbol.selection_range:
                self.index.references.append(
                    SourceReference(
                        node.id, self._range(node), self._current_function(), symbol.symbol_id
                    )
                )
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

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self._add_local_definition(node, node.name, SymbolKind.VARIABLE)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self._add_local_definition(node, node.name, SymbolKind.VARIABLE)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self._add_local_definition(node, node.name, SymbolKind.VARIABLE)
        self.generic_visit(node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self._add_local_definition(node, node.rest, SymbolKind.VARIABLE)
        self.generic_visit(node)

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
        self.index._reference_targets[attr_range] = self._target(node)
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
            self.index._call_targets[self._range(node.func)] = self._target(node.func)
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
            if (
                owner is not None
                and owner == self._current_scope.receiver_id
                and self._current_scope.class_id is not None
            ):
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

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        # Assignment-expression targets bind in this collector's lexical
        # scope, including the PEP 572 containing-scope rule for a nested
        # comprehension.  Do not walk the target again as an ordinary Store.
        if isinstance(node.target, ast.Name):
            self.bindings.append(_FunctionBinding(node.target, node.target.id, SymbolKind.VARIABLE))
        self.visit(node.value)

    def visit_arg(self, node: ast.arg) -> None:
        self.bindings.append(_FunctionBinding(node, node.arg, SymbolKind.PARAMETER))

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

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bindings.append(_FunctionBinding(node, node.name, SymbolKind.VARIABLE))
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.bindings.append(_FunctionBinding(node, node.name, SymbolKind.VARIABLE))
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.bindings.append(_FunctionBinding(node, node.name, SymbolKind.VARIABLE))
        self.generic_visit(node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.bindings.append(_FunctionBinding(node, node.rest, SymbolKind.VARIABLE))
        self.generic_visit(node)

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
        self.bindings.append(_FunctionBinding(node, node.name, SymbolKind.CLASS, lsp_kind=5))

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

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
    ) -> None:
        # Comprehension targets are local to an implicit nested scope.  Walk
        # non-target expressions solely to find assignment expressions, whose
        # targets belong to this containing lexical scope.
        for generator in node.generators:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)


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
