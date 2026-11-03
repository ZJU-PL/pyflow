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
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import unquote, urlparse

from pyflow.language.modules.project_resolution import ModuleIdentityResolver
from pyflow.frontend.source import read_python_source

_IDENTIFIER = re.compile(r"[^\W\d]\w*")


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


@lru_cache(maxsize=65536)
def _literal_payload(segment: str | None) -> Optional[str]:
    """Return the unquoted text of a simple string literal, if it is simple.

    Comparing the payload with the decoded value detects escapes reliably;
    a plain substring check fails for escapes that happen to spell the name
    (``"\x78"`` contains an ``x`` but denotes ``"x"``).
    """
    if not segment or len(segment) < 2:
        return None
    if segment[0] == segment[-1] and segment[0] in {"'", '"'}:
        return segment[1:-1]
    return None


def _strip_bom(text: str) -> str:
    """Drop a UTF-8 BOM; Python accepts it in files but not in ``ast.parse`` text."""
    return text[1:] if text.startswith("\ufeff") else text


def _cached_path_to_uri(path: str) -> str:
    return path_to_uri(path)


@lru_cache(maxsize=65536)
def _cached_uri_to_path(uri: str) -> str:
    return uri_to_path(uri)


def _byte_col_to_char(line: str, byte_col: int) -> int:
    if line.isascii():
        return min(byte_col, len(line))
    raw = line.encode("utf-8")[:byte_col]
    return len(raw.decode("utf-8", errors="ignore"))


def lsp_character_to_offset(line: str, character: int) -> int:
    """Translate an LSP UTF-16 character offset to a Python string offset."""
    if character <= 0:
        return 0
    if line.isascii():
        return min(character, len(line))
    units = 0
    for index, char in enumerate(line):
        if units >= character:
            return index
        units += 2 if ord(char) > 0xFFFF else 1
    return len(line)


def offset_to_lsp_character(line: str, offset: int) -> int:
    if offset <= 0:
        return 0
    if line.isascii():
        return min(offset, len(line))
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
    TYPE_PARAMETER = "type-parameter"
    TYPE_ALIAS = "type-alias"


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
    accessor: str = ""
    overload: bool = False
    parameters: tuple = ()
    binding: str = ""
    constructor_fields: Optional[tuple[str, ...]] = None
    aliased: bool = False

    def document_symbol(self) -> dict:
        result = {
            "name": self.name,
            "kind": 7 if self.accessor else self.kind,
            "range": self.full_range.to_lsp(),
            "selectionRange": self.selection_range.to_lsp(),
        }
        if self.container_name:
            result["detail"] = self.container_name
        return result

    def symbol_information(self) -> dict:
        result = {
            "name": self.name,
            "kind": 7 if self.accessor else self.kind,
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
    string_literal: bool = False
    # True for the imported name token in ``from pkg import name as alias``.
    # Unlike ordinary uses of the local binding, this token denotes the target
    # symbol and therefore follows import aliases.
    import_name: bool = False


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
    keyword_targets: tuple = ()
    keyword_parameters: tuple = ()
    fixtures: tuple = ()
    dynamic_writes: tuple = ()
    syntax_stale: bool = False


class _ScopeKind(str, Enum):
    """Lexical execution contexts relevant to source symbol resolution."""

    MODULE = "module"
    TYPE_PARAMETERS = "type-parameters"
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


def _expanded_scope_range(location, kind, lines, *, trailing_newline=False):
    """Include editable trailing lines until the next dedented statement."""
    if kind is _ScopeKind.MODULE:
        return SourceRange(location.uri, 0, 0, len(lines), 0)
    if not lines:
        return location
    header = lines[min(location.start_line, len(lines) - 1)]
    if kind is _ScopeKind.TYPE_PARAMETERS:
        if not re.match(r"\s*(?:async\s+def|def|class)\s", header):
            return location
    elif kind not in {_ScopeKind.FUNCTION, _ScopeKind.CLASS}:
        return location
    indent = len(header[: len(header) - len(header.lstrip(" \t"))].expandtabs(8))
    end_line, end_character = location.end_line, location.end_character
    if end_line < len(lines):
        line = lines[end_line].rstrip("\r\n")
        content = line.lstrip(" \t")
        depth = len(line[: len(line) - len(content)].expandtabs(8))
        if not content or content.startswith("#") or depth > indent:
            end_character = max(end_character, offset_to_lsp_character(line, len(line)))
        elif end_character == 0 and end_line > location.start_line:
            end_line -= 1
            line = lines[end_line].rstrip("\r\n")
            end_character = offset_to_lsp_character(line, len(line))
    for row in range(end_line + 1, len(lines)):
        line = lines[row].rstrip("\r\n")
        content = line.lstrip(" \t")
        if (
            content
            and not content.startswith("#")
            and len(line[: len(line) - len(content)].expandtabs(8)) <= indent
        ):
            break
        end_line, end_character = row, offset_to_lsp_character(line, len(line))
    if end_line == len(lines) - 1 and (trailing_newline or lines[-1].endswith(("\n", "\r"))):
        end_line, end_character = len(lines), 0
    return replace(location, end_line=end_line, end_character=end_character)


class SourceIndex:
    """AST-backed index for source-accurate navigation and hierarchy results."""

    def __init__(
        self,
        source_files: dict[str, str],
        workspace_roots: Iterable[str | os.PathLike[str]] = (),
    ):
        self.workspace_roots = tuple(Path(root).absolute() for root in workspace_roots)
        self.module_identity = ModuleIdentityResolver(self.workspace_roots)
        self.source_files = {
            os.path.abspath(path): _strip_bom(text) for path, text in source_files.items()
        }
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
        previous=None,
    ) -> "SourceIndex":
        index = cls.__new__(cls)
        index.workspace_roots = workspace_roots
        index.module_identity = ModuleIdentityResolver(workspace_roots)
        index.source_files = source_files
        index._file_indices = file_indices
        index._rebuild_workspace_maps(previous)
        return index

    def with_source_files(self, source_files: dict[str, str]) -> "SourceIndex":
        """Return an index that reparses only files whose text changed."""
        normalized = {
            os.path.abspath(path): _strip_bom(text) for path, text in source_files.items()
        }
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
        return self._from_file_indices(normalized, self.workspace_roots, file_indices, self)

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

        stripped_old = [line.lstrip(" \t") for line in old_lines]
        stripped_new = [line.lstrip(" \t") for line in new_lines]
        indented_rows = {}
        for old_row, new_row, count in SequenceMatcher(
            None, stripped_old, stripped_new, autojunk=False
        ).get_matching_blocks():
            for step in range(count):
                before, after = old_row + step, new_row + step
                old_indent = len(old_lines[before]) - len(stripped_old[before])
                new_indent = len(new_lines[after]) - len(stripped_new[after])
                indented_rows[before] = (
                    old_starts[before] + old_indent,
                    new_starts[after] + new_indent - old_starts[before] - old_indent,
                )

        def mapped(offset):
            from bisect import bisect_right

            row = bisect_right(old_starts, offset) - 1
            if row in indented_rows:
                content_start, delta = indented_rows[row]
                if content_start <= offset < old_starts[row + 1]:
                    return offset + delta
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
                (_expanded_scope_range(remap(location, full=True), kind, new_lines), kind, bindings)
                for location, kind, bindings in previous.scopes
            ),
            dynamic_writes=tuple(
                (location, value)
                for old_range, value in previous.dynamic_writes
                if (location := remap(old_range)) is not None
            ),
            keyword_targets=tuple(
                (location, target)
                for old_range, target in previous.keyword_targets
                if (location := remap(old_range)) is not None
            ),
            syntax_stale=True,
        )

    @staticmethod
    def _resolution_interface(shard):
        return (
            tuple(
                (symbol.symbol_id, symbol.overload, symbol.accessor, symbol.constructor_fields)
                for symbol in shard.symbols
            ),
            shard.import_targets,
            shard.value_targets,
            shard.return_targets,
            shard.class_bases,
            shard.keyword_parameters,
            shard.fixtures,
            shard.dynamic_writes,
            shard.syntax_stale,
        )

    def _affected_files(self, previous):
        if previous is None:
            return set(self._file_indices)
        # Previously unresolved imports can become resolvable when a module
        # appears. File-set changes are uncommon and require a full refresh.
        if self._file_indices.keys() != previous._file_indices.keys():
            return set(self._file_indices)
        changed = {
            path
            for path in self._file_indices.keys() | previous._file_indices.keys()
            if self._file_indices.get(path) is not previous._file_indices.get(path)
        }
        public = {
            path
            for path in changed
            if path not in self._file_indices
            or path not in previous._file_indices
            or self._resolution_interface(self._file_indices[path])
            != self._resolution_interface(previous._file_indices[path])
        }
        affected = set(changed)
        pending = list(public)
        expanded = set()
        while pending:
            path = pending.pop()
            if path in expanded:
                continue
            expanded.add(path)
            before, after = previous._file_indices.get(path), self._file_indices.get(path)
            if (before and before.fixtures) or (after and after.fixtures):
                return set(self._file_indices)
            for shard in (before, after):
                resolver = previous._resolver if shard is before else self._resolver
                if (
                    shard
                    and shard.dynamic_writes
                    and any(
                        resolver.dynamic_namespace(owner)
                        for _, (target, _name, _values, _module) in shard.dynamic_writes
                        for owner in resolver.names(target)
                    )
                ):
                    return set(self._file_indices)
            for dependent in previous._dependents.get(path, ()):
                affected.add(dependent)
                if dependent not in expanded:
                    pending.append(dependent)
        return affected

    def _resolve_file(self, path, shard):
        aliases = self._resolved_import_aliases
        # ``import x as y`` / ``from m import x as y`` introduce a local binding.
        # Its uses must retain the alias identity so rename stays local; only the
        # imported-name token (and unaliased imports) denotes the target symbol.
        aliased_bindings = {symbol.symbol_id for symbol in shard.symbols if symbol.aliased}
        refs = []
        for reference in shard.references:
            identity = reference.symbol_id
            if reference.import_name or identity not in aliased_bindings:
                identity = aliases.get(identity, identity)
            refs.append(
                reference
                if identity == reference.symbol_id
                else replace(reference, symbol_id=identity)
            )
        reference_targets = dict(shard.reference_targets)
        refs = [
            (
                replace(reference, symbol_id=target.symbol_id)
                if (target := self._resolver.symbol(reference_targets.get(reference.location)))
                else reference
            )
            for reference in refs
        ]
        uncertain = frozenset(
            location
            for location, target in shard.reference_targets
            if not self._resolver.is_complete(target)
        )
        keyword_ids, candidates, uncertain_keywords = {}, {}, set()
        for location, (target, name) in shard.keyword_targets:
            parameters = set()
            for callee in self._resolver.callable_candidates(target):
                if callee.kind == 5:
                    parameter = self._resolver.constructor_keyword(
                        callee, name, self._keyword_parameters
                    )
                    if parameter is not None:
                        parameters.add(parameter)
                    continue
                if callee:
                    parameter = dict(self._keyword_parameters.get(callee.symbol_id, ())).get(name)
                    if parameter:
                        parameters.add(parameter)
            candidates[location] = frozenset(parameters)
            if len(parameters) == 1:
                keyword_ids[location] = next(iter(parameters))
            if len(parameters) > 1 or not self._resolver.is_complete(target):
                uncertain_keywords.add(location)
        refs = tuple(
            (
                replace(reference, symbol_id=keyword_ids[reference.location])
                if reference.location in keyword_ids
                else reference
            )
            for reference in refs
        )
        calls = []
        targets = dict(shard.call_targets)
        for call in shard.calls:
            callee = self._resolver.callable_symbol(targets.get(call.location))
            caller = self._module_symbols.get(call.location.uri) if call.caller_id is None else None
            calls.append(
                replace(
                    call,
                    callee_id=(
                        callee.symbol_id if callee else aliases.get(call.callee_id, call.callee_id)
                    ),
                    caller=caller.name if caller else call.caller,
                    caller_id=caller.symbol_id if caller else call.caller_id,
                )
            )
        dependencies = {
            _cached_uri_to_path(reference.symbol_id.uri)
            for reference in refs
            if reference.symbol_id is not None
        }
        dependencies.update(
            _cached_uri_to_path(call.callee_id.uri) for call in calls if call.callee_id is not None
        )
        module_paths = self._module_paths
        for identity, imported in shard.import_targets:
            imported = self._resolver.import_target(identity) or imported
            while imported:
                if imported in module_paths:
                    dependencies.add(module_paths[imported])
                    break
                imported = imported.rpartition(".")[0]
        return (
            refs,
            tuple(calls),
            uncertain,
            candidates,
            frozenset(uncertain_keywords),
            frozenset(dependencies),
        )

    def _rebuild_workspace_maps(self, previous=None) -> None:
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
        self._keyword_targets = {}
        self._keyword_parameters = {}
        self._fixtures = {}
        self._dynamic_writes = {}
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
            self._keyword_targets.update(file_index.keyword_targets)
            self._keyword_parameters.update(file_index.keyword_parameters)
            self._fixtures.update(file_index.fixtures)
            self._dynamic_writes.update(file_index.dynamic_writes)
        modules = {}
        for path, name in self._modules.items():
            uri = _cached_path_to_uri(path)
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
                identity,
                name,
                name,
                name,
                2,
                location,
                SourceRange(uri, 0, 0, 0, 0),
                container_name=name.rpartition(".")[0] or None,
            )
            self._symbols_by_id[identity] = modules[uri]
        self._module_symbols = modules
        self._module_paths = {name: filename for filename, name in self._modules.items()}
        # Pytest injects fixture values into test/fixture parameters. Resolve
        # only explicit fixture declarations, with conftest directory scoping.
        fixtures = []
        for identity, name in self._fixtures.items():
            source = self._symbols_by_id.get(identity)
            if source and source.container_name == source.module:
                fixtures.append(
                    (source, name, Path(_cached_uri_to_path(source.selection_range.uri)))
                )
        for identity, parameters in self._keyword_parameters.items():
            function = self._symbols_by_id.get(identity)
            if function is None or not (
                function.name.startswith("test_") or identity in self._fixtures
            ):
                continue
            path = Path(_cached_uri_to_path(function.selection_range.uri))
            for name, parameter in parameters:
                if parameter in self._value_targets:
                    continue
                candidates = [
                    (source, fixture_path)
                    for source, fixture_name, fixture_path in fixtures
                    if fixture_name == name
                    and (
                        fixture_path == path
                        or fixture_path.name == "conftest.py"
                        and path.is_relative_to(fixture_path.parent)
                    )
                ]
                candidates.sort(
                    key=lambda item: (item[1] == path, len(item[1].parts)), reverse=True
                )
                if candidates:
                    self._value_targets[parameter] = (
                        ("instance", ("symbol", candidates[0][0].symbol_id)),
                    )
        from .resolution import WorkspaceResolver

        from .framework_models import FrameworkModels

        models = FrameworkModels(self.source_files, self._modules)
        self._resolver = WorkspaceResolver(
            self.symbols,
            self._import_targets,
            self._value_targets,
            self._return_targets,
            self._class_bases,
            modules=tuple(modules.values()),
            models=models,
        )
        # Materialize only writes to explicitly recognized state namespaces.
        for location, (owner_target, name, values, module) in self._dynamic_writes.items():
            owners = self._resolver.names(owner_target)
            if len(owners) != 1:
                continue
            owner = next(iter(owners))
            if not self._resolver.dynamic_namespace(owner):
                continue
            qualified = owner + "." + name
            identity = SymbolId(
                module,
                qualified,
                SymbolKind.VARIABLE,
                location.uri,
                location.start_line,
                location.start_character,
            )
            symbol = SourceSymbol(
                identity, name, qualified, module, 8, location, location, owner, name
            )
            group = self._resolver.dynamic_declarations.setdefault(qualified, [])
            group.append(symbol)
            self._resolver.symbols[qualified] = group[0]
            self._resolver.by_id[identity] = symbol
            self._symbols_by_id[identity] = symbol
            root = group[0].symbol_id
            self._resolver.values[root] = tuple(self._resolver.values.get(root, ())) + tuple(values)
        self._resolve_import_aliases()
        affected = self._affected_files(previous)
        self._resolved_files = {}
        self.references, self.calls = [], []
        self._uncertain_member_ranges = set()
        self._keyword_candidates = {}
        self._uncertain_keyword_ranges = set()
        self._dependents = {}
        for path, shard in self._file_indices.items():
            cached = (
                previous._resolved_files.get(path)
                if previous is not None and path not in affected
                else None
            )
            resolved = cached if cached is not None else self._resolve_file(path, shard)
            self._resolved_files[path] = resolved
            refs, calls, uncertain, keywords, uncertain_keywords, dependencies = resolved
            self.references.extend(refs)
            self.calls.extend(calls)
            self._uncertain_member_ranges.update(uncertain)
            self._keyword_candidates.update(keywords)
            self._uncertain_keyword_ranges.update(uncertain_keywords)
            for dependency in dependencies:
                if dependency != path:
                    self._dependents.setdefault(dependency, set()).add(path)
        self._string_literal_ranges = {
            reference.location for reference in self.references if reference.string_literal
        }
        if previous is not None:
            for identity, symbol in previous._symbols_by_id.items():
                if _cached_uri_to_path(symbol.selection_range.uri) not in previous.source_files:
                    self._resolver.by_id.setdefault(identity, symbol)
        self._symbols_by_id.update(self._resolver.by_id)

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
        scratch._keyword_targets = {}
        scratch._keyword_parameters = {}
        scratch._fixtures = {}
        scratch._dynamic_writes = {}
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
            tuple(scratch._keyword_targets.items()),
            tuple(scratch._keyword_parameters.items()),
            tuple(scratch._fixtures.items()),
            tuple(scratch._dynamic_writes.items()),
            syntax_stale=path not in scratch._modules,
        )

    def _resolve_import_aliases(self) -> None:
        """Resolve ``from pkg import name as alias`` after all modules exist."""
        aliases = {
            symbol_id: self._resolver._canonical(symbol_id) for symbol_id in self._import_targets
        }
        aliases.update(
            {
                symbol.symbol_id: self._resolver._canonical(symbol.symbol_id)
                for symbol in self.symbols
                if symbol.overload
            }
        )
        self._resolved_import_aliases = {
            source: target for source, target in aliases.items() if source != target
        }

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

    def _presentable_symbol(self, symbol):
        kind = symbol.symbol_id.kind
        if kind in {SymbolKind.PARAMETER, SymbolKind.TYPE_PARAMETER, SymbolKind.IMPORT}:
            return False
        if (symbol.accessor or symbol.overload) and self._resolver.symbols.get(
            symbol.qualified_name
        ) != symbol:
            return False
        if kind is SymbolKind.VARIABLE:
            owner = self._resolver.symbols.get(symbol.container_name)
            return symbol.container_name == symbol.module or (owner is not None and owner.kind == 5)
        return True

    def document_symbols(self, uri: str) -> list[SourceSymbol]:
        return [
            symbol
            for symbol in self.symbols
            if symbol.full_range.uri == uri and self._presentable_symbol(symbol)
        ]

    def document_symbol_tree(self, uri):
        symbols = self.document_symbols(uri)
        nodes = {symbol.symbol_id: symbol.document_symbol() for symbol in symbols}
        by_name = {symbol.qualified_name: symbol for symbol in symbols}
        roots = []
        for symbol in sorted(
            symbols,
            key=lambda item: (
                item.selection_range.start_line,
                item.selection_range.start_character,
            ),
        ):
            node = nodes[symbol.symbol_id]
            parent = by_name.get(symbol.container_name)
            if parent and parent.symbol_id != symbol.symbol_id:
                nodes[parent.symbol_id].setdefault("children", []).append(node)
            else:
                roots.append(node)
        return roots

    def workspace_symbols(self, query: str) -> list[SourceSymbol]:
        query = query.casefold()
        symbols = [
            symbol
            for symbol in (*self.symbols, *self._module_symbols.values())
            if self._presentable_symbol(symbol)
            and (not query or query in symbol.qualified_name.casefold())
        ]

        def rank(symbol):
            declaration = (
                0
                if symbol.symbol_id.kind
                in {SymbolKind.CLASS, SymbolKind.FUNCTION, SymbolKind.MODULE, SymbolKind.TYPE_ALIAS}
                else 1 if symbol.symbol_id.kind is SymbolKind.METHOD else 2
            )
            name = symbol.name.rsplit(".", 1)[-1].casefold()
            match = 0 if name == query else 1 if name.startswith(query) else 2
            return declaration, match, symbol.qualified_name.casefold(), symbol.selection_range.uri

        return sorted(symbols, key=rank)

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
                if symbol.symbol_id.kind is SymbolKind.IMPORT and not symbol.aliased:
                    # Unaliased imports denote the imported object itself.
                    target = self._resolved_import_aliases.get(symbol.symbol_id)
                    return self._symbols_by_id.get(target, symbol)
                return symbol
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
            key=lambda item: (
                item[0].end_line - item[0].start_line,
                -item[0].start_line,
                int(item[1] is _ScopeKind.TYPE_PARAMETERS),
            ),
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
            if expression.id in {
                "str",
                "int",
                "float",
                "bool",
                "bytes",
                "list",
                "dict",
                "set",
                "tuple",
            }:
                return ("external", "builtins." + expression.id)
        if isinstance(expression, ast.Attribute):
            return ("member", self._position_target(expression.value, bindings), expression.attr)
        if isinstance(expression, ast.BoolOp):
            # ``a and b`` / ``a or b``: offer the last operand's members, which
            # is the expression the user is usually completing.
            return (
                self._position_target(expression.values[-1], bindings)
                if expression.values
                else ("unknown",)
            )
        if isinstance(expression, ast.IfExp):
            return (
                "alternatives",
                (
                    self._position_target(expression.body, bindings),
                    self._position_target(expression.orelse, bindings),
                ),
            )
        if isinstance(expression, (ast.NamedExpr, ast.Await, ast.Starred)):
            return self._position_target(expression.value, bindings)
        if isinstance(expression, ast.Call):
            if (
                isinstance(expression.func, ast.Name)
                and expression.func.id == "super"
                and "super" not in bindings
            ):
                if expression.args:
                    return ("super", self._position_target(expression.args[0], bindings))
                candidates = []
                for identity in bindings.values():
                    parameter = self._symbols_by_id.get(identity)
                    method = (
                        self._resolver.symbols.get(parameter.container_name)
                        if parameter and parameter.symbol_id.kind is SymbolKind.PARAMETER
                        else None
                    )
                    owner = self._resolver.symbols.get(method.container_name) if method else None
                    if owner and owner.kind == 5 and method.binding != "static":
                        candidates.append(
                            (
                                method.full_range.end_line - method.full_range.start_line,
                                -method.full_range.start_line,
                                owner.symbol_id,
                            )
                        )
                if candidates:
                    return ("super", ("symbol", min(candidates, key=lambda item: item[:2])[2]))
            return ("instance", self._position_target(expression.func, bindings))
        return ("unknown",)

    def _receiver_target(self, receiver_text: str, bindings):
        """Resolve the primary expression immediately before a completion dot.

        Parsing the first identifier whose suffix happens to be valid picks the
        wrong expression for ``a + b.`` or ``cond and obj.``.  Walk a primary
        expression backwards from the dot instead (the same scan signature help
        uses for callees).
        """
        import io
        import tokenize

        from .signatures import receiver_expression

        tokens = []
        try:
            for token in tokenize.generate_tokens(io.StringIO(receiver_text).readline):
                if token.type not in {
                    tokenize.NL,
                    tokenize.NEWLINE,
                    tokenize.COMMENT,
                    tokenize.INDENT,
                    tokenize.DEDENT,
                    tokenize.ENDMARKER,
                }:
                    tokens.append(token)
        except (tokenize.TokenError, IndentationError):
            pass
        expression = receiver_expression(tokens, len(tokens))
        if expression is None:
            return ("unknown",)
        return self._position_target(expression, bindings)

    def completion_items(self, uri, line, character):
        text = self.text_for_uri(uri)
        lines = text.splitlines() if text is not None else []
        if text is not None and (not text or text.endswith(("\n", "\r"))):
            lines.append("")
        if line < 0 or line >= len(lines):
            return []
        before = lines[line][: lsp_character_to_offset(lines[line], character)]
        bindings = self.visible_bindings_at(uri, line, character)
        member = re.search(rf"\.({_IDENTIFIER.pattern})?$", before)
        external = []
        if member:
            prefix = member.group(1) or ""
            receiver_text = before[: member.start()]
            target = self._receiver_target(receiver_text, bindings)
            symbols = self._resolver.members(target)
            for owner in self._resolver.names(target):
                external.extend(self._external_members(owner, prefix))
        else:
            match = re.search(rf"{_IDENTIFIER.pattern}$", before)
            prefix = match.group(0) if match else ""
            symbols = [
                self._symbols_by_id[symbol]
                for symbol in bindings.values()
                if symbol in self._symbols_by_id
            ]
        items = [
            {
                "label": symbol.name,
                "kind": 10 if symbol.accessor else {5: 7, 6: 2, 12: 3}.get(symbol.kind, 6),
                "detail": "\n".join(
                    item.detail for item in self._resolver.overloads.get(symbol.qualified_name, ())
                )
                or symbol.detail
                or symbol.qualified_name,
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
        documentation = symbol.documentation
        if symbol.symbol_id.kind in {SymbolKind.VARIABLE, SymbolKind.PARAMETER}:
            class_object = next(
                (
                    value[1]
                    for value in self._resolver.values.get(symbol.symbol_id, ())
                    if value
                    and value[0] == "annotation"
                    and value[1]
                    and value[1][0] == "class-object"
                ),
                None,
            )
            if class_object is not None:
                declared = sorted(self._resolver.names(class_object[1]))
                if declared:
                    return {
                        "contents": {
                            "kind": "markdown",
                            "value": "```python\n"
                            + symbol.name
                            + ": "
                            + " | ".join(f"type[{name}]" for name in declared)
                            + "\n```",
                        }
                    }
            names = self._resolver.names(("symbol", symbol.symbol_id))
            types = [
                name.removeprefix("builtins.")
                for name in names
                if name.startswith("builtins.")
                or (name in self._resolver.symbols and self._resolver.symbols[name].kind == 5)
            ]
            callables = [
                self._resolver.symbols[name]
                for name in sorted(names)
                if name in self._resolver.symbols and self._resolver.symbols[name].kind in {6, 12}
            ]
            for function in callables:
                for signature in self._resolver.overloads.get(function.qualified_name, ()) or [
                    function
                ]:
                    detail = signature.detail
                    types.append(
                        "(" + detail.split("(", 1)[1] if "(" in detail else signature.qualified_name
                    )
                if not documentation and function.documentation:
                    documentation = function.documentation
            if types:
                declaration = symbol.name + ": " + " | ".join(sorted(types))
            elif declaration == symbol.name:
                return None
        elif symbol.symbol_id.kind is SymbolKind.IMPORT:
            target = self._import_targets.get(symbol.symbol_id, symbol.name)
            declaration = (
                "import "
                + target
                + (
                    " as " + symbol.name
                    if symbol.aliased and not target.endswith("." + symbol.name)
                    else ""
                )
            )
        value = f"```python\n{declaration}\n```"
        overloads = self._resolver.overloads.get(symbol.qualified_name, ())
        if overloads:
            value = "```python\n" + "\n".join(item.detail for item in overloads) + "\n```"
        if documentation:
            value += "\n\n" + documentation
        return {"contents": {"kind": "markdown", "value": value}}

    def callable_at(self, uri, line, character):
        for call in self.calls:
            if call.location.uri == uri and call.location.contains(line, character):
                symbol = self._symbols_by_id.get(call.callee_id)
                if symbol and symbol.symbol_id.kind in {
                    SymbolKind.CLASS,
                    SymbolKind.FUNCTION,
                    SymbolKind.METHOD,
                }:
                    return symbol
        symbol = self.symbol_at(uri, line, character)
        return (
            symbol
            if symbol
            and symbol.symbol_id.kind in {SymbolKind.CLASS, SymbolKind.FUNCTION, SymbolKind.METHOD}
            else None
        )

    def signature_help(self, uri, line, character):
        from .signatures import signature_help

        return signature_help(self, uri, line, character)

    def document_highlights(self, uri, line, character):
        locations = self.references_at(uri, line, character, include_declaration=True)
        kinds = {
            symbol.selection_range: 3
            for symbol in self.symbols
            if symbol.selection_range.uri == uri
        }
        text = self.text_for_uri(uri) or ""
        lines = text.splitlines()
        try:
            tree = ast.parse(text)
        except (SyntaxError, RecursionError):
            tree = None
        for node in ast.walk(tree) if tree is not None else ():
            if not isinstance(node, (ast.Name, ast.Attribute)):
                continue
            row, end_row = node.lineno - 1, node.end_lineno - 1
            end = _byte_col_to_char(lines[end_row], node.end_col_offset)
            start = _byte_col_to_char(lines[row], node.col_offset)
            if isinstance(node, ast.Attribute):
                row, start = end_row, end - len(node.attr)
            location = SourceRange(
                uri,
                row,
                offset_to_lsp_character(lines[row], start),
                end_row,
                offset_to_lsp_character(lines[end_row], end),
            )
            kinds[location] = 3 if isinstance(node.ctx, (ast.Store, ast.Del)) else 2
        return [
            {"range": location.to_lsp(), "kind": kinds.get(location, 1)}
            for location in locations
            if location.uri == uri
        ]

    def definitions_at(self, uri: str, line: int, character: int) -> list[SourceRange]:
        symbol = self.symbol_at(uri, line, character)
        if symbol is None:
            return []
        if symbol.symbol_id.kind is SymbolKind.IMPORT:
            target = self._resolved_import_aliases.get(symbol.symbol_id)
            target_symbol = self._symbols_by_id.get(target) if target is not None else None
            if target_symbol is not None:
                return [target_symbol.selection_range]
        return [symbol.selection_range]

    def references_at(
        self, uri: str, line: int, character: int, *, include_declaration: bool
    ) -> list[SourceRange]:
        symbol = self.symbol_at(uri, line, character)
        if symbol is None:
            return []
        group = self._resolver.property_group(symbol)
        identities = {candidate.symbol_id for candidate in group}
        result = [
            reference.location for reference in self.references if reference.symbol_id in identities
        ]
        if include_declaration:
            result = [candidate.selection_range for candidate in group] + result
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
        if (
            symbol is None
            or symbol.symbol_id.kind is SymbolKind.MODULE
            or uri_to_path(symbol.selection_range.uri) not in self.source_files
        ):
            return []
        identities = {candidate.symbol_id for candidate in self._resolver.property_group(symbol)}
        owner = self._resolver.symbols.get(symbol.container_name)
        if (
            symbol.symbol_id.kind is SymbolKind.METHOD
            or (owner is not None and owner.kind == 5)
            or self._resolver.dynamic_namespace(symbol.container_name)
        ):
            for reference in self.references:
                target = self._reference_targets.get(reference.location)
                if (
                    reference.name != symbol.name
                    or target is None
                    or reference.location not in self._uncertain_member_ranges
                ):
                    continue
                # Unrelated dynamic receivers do not veto this declaration.
                candidates = [
                    self._resolver.member(name, symbol.name)
                    for name in self._resolver.names(target[1])
                ]
                if any(candidate and candidate.symbol_id in identities for candidate in candidates):
                    return []
        if any(
            identities.intersection(self._keyword_candidates.get(location, ()))
            for location in self._uncertain_keyword_ranges
        ):
            return []
        affected = {
            candidate.selection_range.uri for candidate in self._resolver.property_group(symbol)
        } | {
            reference.location.uri
            for reference in self.references
            if reference.symbol_id in identities
        }
        if any(
            index.syntax_stale and _cached_path_to_uri(path) in affected
            for path, index in self._file_indices.items()
        ):
            return []
        return _deduplicate_ranges(
            [candidate.selection_range for candidate in self._resolver.property_group(symbol)]
            + [
                reference.location
                for reference in self.references
                if reference.symbol_id in identities and reference.name == symbol.name
            ]
        )

    def replacement_text(self, source_range, new_name):
        return repr(new_name) if source_range in self._string_literal_ranges else new_name

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
        self._annotation_depth = 0

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
        if name and isinstance(node, ast.MatchAs) and node.pattern is not None:
            found = end_text.rfind(name, 0, end_char)
            if found >= 0:
                start_line, start_text, start_char = end_line, end_text, found
                end_char = found + len(name)
        elif name:
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

    def _alias_range(self, alias: ast.alias, name: str) -> SourceRange:
        """Locate the ``as name`` token of an import alias.

        ``ast.alias.col_offset`` points at the module or imported name, not at
        the alias introduced by ``as``. Searching forward from that offset can
        therefore land on an identical character inside the module path (for
        example ``import pkg.models as m``). Search backwards from the end of
        the alias node instead.
        """
        line_no = max((getattr(alias, "end_lineno", None) or alias.lineno) - 1, 0)
        line = self.lines[line_no] if line_no < len(self.lines) else ""
        end = _byte_col_to_char(line, getattr(alias, "end_col_offset", 0) or len(line))
        start = line.rfind(name, 0, end)
        if start < 0:
            return self._range(alias, name=name)
        return SourceRange(
            self.uri,
            line_no,
            offset_to_lsp_character(line, start),
            line_no,
            offset_to_lsp_character(line, start + len(name)),
        )

    def _qualified(self, name: str) -> str:
        return ".".join([self.module, *self.scope, name])

    def _add_definition(
        self,
        node: ast.AST,
        name: str,
        kind: int,
        identity_kind: SymbolKind,
        *,
        aliased: bool = False,
        selection_range: Optional[SourceRange] = None,
    ) -> SourceSymbol:
        return self._add_definition_in_scope(
            self._current_scope,
            node,
            name,
            kind,
            identity_kind,
            aliased=aliased,
            selection_range=selection_range,
        )

    def _add_definition_in_scope(
        self,
        scope: _Scope,
        node: ast.AST,
        name: str,
        kind: int,
        identity_kind: SymbolKind,
        *,
        aliased: bool = False,
        selection_range: Optional[SourceRange] = None,
    ) -> SourceSymbol:
        if identity_kind is SymbolKind.VARIABLE:
            if scope.kind in {_ScopeKind.MODULE, _ScopeKind.CLASS} and name.isupper():
                kind = 14
            elif scope.kind is _ScopeKind.CLASS:
                kind = 8
        qualified = ".".join([self.module, *scope.path, name])
        container = ".".join([self.module, *scope.path]) if scope.path else self.module
        selection_range = selection_range or self._range(node, name=name)
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
            accessor=self._accessor(node),
            documentation=(
                (ast.get_docstring(node) or "")
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                else ""
            ),
            aliased=aliased,
        )
        self.index.symbols.append(symbol)
        self.index._symbols_by_id[symbol.symbol_id] = symbol
        scope.bindings[name] = symbol.symbol_id
        return symbol

    @staticmethod
    def _accessor(node):
        for decorator in getattr(node, "decorator_list", ()):
            if isinstance(decorator, ast.Name) and decorator.id in {"property", "cached_property"}:
                return "getter"
            if (
                isinstance(decorator, ast.Attribute)
                and decorator.attr in {"getter", "setter", "deleter"}
                and isinstance(decorator.value, ast.Name)
                and decorator.value.id == getattr(node, "name", None)
            ):
                return decorator.attr
        return ""

    @staticmethod
    def _declaration(node, name):
        parameters = getattr(node, "type_params", ())
        generic = (
            "[" + ", ".join(ast.unparse(parameter) for parameter in parameters) + "]"
            if parameters
            else ""
        )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result = f"{'async ' if isinstance(node, ast.AsyncFunctionDef) else ''}def {name}{generic}({ast.unparse(node.args)})"
            return result + (" -> " + ast.unparse(node.returns) if node.returns else "")
        if isinstance(node, ast.ClassDef):
            return f"class {name}{generic}" + (
                "(" + ", ".join(ast.unparse(base) for base in node.bases) + ")"
                if node.bases
                else ""
            )
        if type(node).__name__ in {"TypeAlias", "TypeVar", "TypeVarTuple", "ParamSpec"}:
            return ast.unparse(node)
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
        self.index._scopes.append(
            (
                _expanded_scope_range(
                    location,
                    scope.kind,
                    self.lines,
                    trailing_newline=self.source.endswith(("\n", "\r")),
                ),
                scope.kind,
                tuple(scope.bindings.items()),
            )
        )

    def _target(self, node):
        if isinstance(node, ast.Name):
            symbol = self._resolve(node.id)
            if symbol:
                return ("symbol", symbol)
            if node.id in {"str", "int", "float", "bool", "bytes", "list", "dict", "set", "tuple"}:
                return ("external", "builtins." + node.id)
        if isinstance(node, ast.Attribute):
            return (
                "member",
                self._target(node.value),
                node.attr,
                (
                    "write"
                    if isinstance(node.ctx, ast.Store)
                    else "delete" if isinstance(node.ctx, ast.Del) else "read"
                ),
            )
        if isinstance(node, ast.IfExp):
            body, other = self._target(node.body), self._target(node.orelse)
            test, nonnull_body = node.test, True
            if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                test, nonnull_body = test.operand, False
            if (
                isinstance(test, ast.Compare)
                and len(test.ops) == 1
                and isinstance(test.ops[0], (ast.Is, ast.IsNot))
                and isinstance(test.comparators[0], ast.Constant)
                and test.comparators[0].value is None
            ):
                nonnull_body = isinstance(test.ops[0], ast.IsNot)
                test = test.left
            if isinstance(test, (ast.Name, ast.Attribute)):
                if nonnull_body and ast.dump(node.body) == ast.dump(test):
                    body = ("nonnull", body)
                elif not nonnull_body and ast.dump(node.orelse) == ast.dump(test):
                    other = ("nonnull", other)
            return ("alternatives", (body, other))
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "super"
                and self._resolve("super") is None
            ):
                if node.args:
                    return ("super", self._target(node.args[0]))
                if self._current_scope.class_id is not None:
                    return ("super", ("symbol", self._current_scope.class_id))
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
        if isinstance(node, (ast.Name, ast.Attribute)):
            qualified = self._qualified_expression_name(node)
            if (
                qualified in {"typing.Self", "typing_extensions.Self"}
                and self._current_scope.class_id is not None
            ):
                return ("instance", ("symbol", self._current_scope.class_id))
        if isinstance(node, ast.Constant) and node.value is None:
            return ("external", "builtins.NoneType")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return (
                "alternatives",
                (self._annotation_target(node.left), self._annotation_target(node.right)),
            )
        if isinstance(node, ast.Subscript):
            name = _call_name(node.value) or ""
            head, separator, tail = name.partition(".")
            qualified = self.index._import_targets.get(self._resolve(head), head) + (
                separator + tail if separator else ""
            )
            if qualified in {"type", "builtins.type", "typing.Type", "typing_extensions.Type"}:
                argument = (
                    node.slice.elts[0]
                    if isinstance(node.slice, ast.Tuple) and node.slice.elts
                    else node.slice
                )
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    try:
                        argument = ast.parse(argument.value, mode="eval").body
                    except SyntaxError:
                        return ("unknown",)
                if isinstance(argument, (ast.Name, ast.Attribute)):
                    if (
                        self._qualified_expression_name(argument)
                        in {"typing.Self", "typing_extensions.Self"}
                        and self._current_scope.class_id is not None
                    ):
                        return ("class-object", ("symbol", self._current_scope.class_id))
                    return ("class-object", self._target(argument))
                return ("unknown",)
            arguments = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            if qualified in {"typing.Optional", "typing_extensions.Optional"}:
                return (
                    "alternatives",
                    (self._annotation_target(arguments[0]), ("external", "builtins.NoneType")),
                )
            if qualified in {"typing.Union", "typing_extensions.Union"}:
                return (
                    "alternatives",
                    tuple(self._annotation_target(argument) for argument in arguments),
                )
            if qualified in {"typing.Annotated", "typing_extensions.Annotated"}:
                return self._annotation_target(arguments[0])
            return self._annotation_target(node.value)
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
            if isinstance(target, ast.Attribute):
                base = self._range(target)
                text = self.lines[base.end_line]
                end = lsp_character_to_offset(text, base.end_character)
                location = SourceRange(
                    self.uri,
                    base.end_line,
                    offset_to_lsp_character(text, end - len(target.attr)),
                    base.end_line,
                    base.end_character,
                )
                previous = self.index._dynamic_writes.get(location)
                values = (*previous[2], value) if previous else (value,)
                self.index._dynamic_writes[location] = (
                    self._target(target.value),
                    target.attr,
                    values,
                    self.module,
                )
        if symbol_id:
            self.index._value_targets.setdefault(symbol_id, []).append(value)

    def visit_Assign(self, node):
        self.generic_visit(node)
        for target in node.targets:
            self._bind_value(target, self._target(node.value))
            if isinstance(target, ast.Name) and target.id == "__all__":
                self._record_exports(node.value)
            self._record_match_args(target, node.value)
            self._record_slots(target, node.value)

    def _record_match_args(self, target, value):
        if (
            self._current_scope.kind is not _ScopeKind.CLASS
            or not isinstance(target, ast.Name)
            or target.id != "__match_args__"
            or not isinstance(value, (ast.Tuple, ast.List))
        ):
            return
        if not all(
            isinstance(item, ast.Constant) and isinstance(item.value, str) for item in value.elts
        ):
            return
        identity = self._resolve("__match_args__")
        self.index._value_targets[identity] = [
            ("match-args", tuple(item.value for item in value.elts))
        ]
        owner = ("symbol", self._current_scope.class_id)
        for item in value.elts:
            escaped = _literal_payload(ast.get_source_segment(self.source, item)) != item.value
            location = self._range(item) if escaped else self._range(item, name=item.value)
            self.index._reference_targets[location] = ("member", owner, item.value, "read")
            self.index.references.append(
                SourceReference(
                    item.value, location, self._current_function(), string_literal=escaped
                )
            )

    def _record_dict_keys(self, annotation, value: ast.Dict) -> None:
        """Link string keys of an annotated dict literal to known members.

        TypedDict construction is the common case: ``m: Movie = {"title": ...}``
        must follow a rename of ``Movie.title``.
        """
        if not isinstance(value, ast.Dict):
            return
        target = self._annotation_target(annotation)
        for key in value.keys:
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                continue
            name = key.value
            if not name.isidentifier():
                continue
            escaped = _literal_payload(ast.get_source_segment(self.source, key)) != name
            location = self._range(key) if escaped else self._range(key, name=name)
            self.index._reference_targets[location] = ("member", target, name, "read")
            self.index.references.append(
                SourceReference(
                    name,
                    location,
                    self._current_function(),
                    string_literal=escaped,
                )
            )

    def _record_slots(self, target, value):
        """Declare and reference attribute names in a class ``__slots__`` literal."""
        if (
            self._current_scope.kind is not _ScopeKind.CLASS
            or not isinstance(target, ast.Name)
            or target.id != "__slots__"
        ):
            return
        if isinstance(value, ast.Constant):
            items = [value]
        elif isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            items = list(value.elts)
        elif isinstance(value, ast.Dict):
            items = [key for key in value.keys if key is not None]
        else:
            return
        owner = ("symbol", self._current_scope.class_id)
        for item in items:
            if not (isinstance(item, ast.Constant) and isinstance(item.value, str)):
                continue
            name = item.value
            if not name.isidentifier():
                continue
            escaped = _literal_payload(ast.get_source_segment(self.source, item)) != name
            location = self._range(item) if escaped else self._range(item, name=name)
            symbol = self._add_local_definition_in_scope(
                self._current_scope,
                item,
                name,
                SymbolKind.VARIABLE,
                selection_range=location,
            )
            self.index._reference_targets[location] = ("member", owner, name, "read")
            self.index.references.append(
                SourceReference(
                    name,
                    location,
                    self._current_function(),
                    symbol.symbol_id,
                    string_literal=escaped,
                )
            )

    def _record_exports(self, value):
        if self._current_scope.kind is not _ScopeKind.MODULE:
            return

        def literals(node):
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                for child in node.elts:
                    yield from literals(child)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                yield from literals(node.left)
                yield from literals(node.right)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                yield node

        for node in literals(value):
            symbol_id = self._resolve(node.value)
            if symbol_id and node.value.isidentifier():
                escaped = _literal_payload(ast.get_source_segment(self.source, node)) != node.value
                location = self._range(node) if escaped else self._range(node, name=node.value)
                self.index.references.append(
                    SourceReference(
                        node.value,
                        location,
                        self._current_function(),
                        symbol_id,
                        string_literal=escaped,
                    )
                )

    def visit_AugAssign(self, node):
        self.generic_visit(node)
        if isinstance(node.target, ast.Name) and node.target.id == "__all__":
            self._record_exports(node.value)

    def visit_AnnAssign(self, node):
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)
        self._visit_annotation(node.annotation)
        self._bind_value(node.target, ("annotation", self._annotation_target(node.annotation)))
        if node.value is not None:
            self._record_dict_keys(node.annotation, node.value)
            self._bind_value(node.target, self._target(node.value))
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                self._record_exports(node.value)
            self._record_match_args(node.target, node.value)
            self._record_slots(node.target, node.value)

    def visit_Yield(self, node):
        self.generic_visit(node)
        identity = self._current_scope.function_id
        if identity in self.index._fixtures and node.value is not None:
            self.index._return_targets.setdefault(identity, []).append(self._target(node.value))

    def visit_Return(self, node):
        self.generic_visit(node)
        if node.value is not None and self._current_scope.function_id:
            self.index._return_targets.setdefault(self._current_scope.function_id, []).append(
                self._target(node.value)
            )

    def _push_type_parameters(self, node, symbol):
        parameters = getattr(node, "type_params", ())
        if not parameters:
            return False
        parent = self._current_scope
        self._scopes.append(
            _Scope(
                _ScopeKind.TYPE_PARAMETERS,
                {},
                path=(*self.scope, symbol.name),
                function_id=parent.function_id,
                class_id=parent.class_id,
                receiver_id=parent.receiver_id,
            )
        )
        for parameter in parameters:
            self._add_definition(parameter, parameter.name, 26, SymbolKind.TYPE_PARAMETER)
        for parameter in parameters:
            for name in ("bound", "default_value"):
                value = getattr(parameter, name, None)
                if value is not None:
                    self._visit_annotation(value)
        return True

    def _pop_type_parameters(self, node):
        self._record_scope(node)
        self._scopes.pop()

    def visit_TypeAlias(self, node):
        name = node.name.id
        symbol = self._add_local_definition(node, name, SymbolKind.TYPE_ALIAS)
        scoped = self._push_type_parameters(node, symbol)
        self._visit_annotation(node.value)
        if scoped:
            self._pop_type_parameters(node)

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
        self,
        node: ast.AST,
        name: str,
        kind: SymbolKind,
        lsp_kind: int = 13,
        *,
        aliased: bool = False,
        selection_range: Optional[SourceRange] = None,
    ) -> SourceSymbol:
        existing = self._current_scope.bindings.get(name)
        if existing is not None:
            return self.index._symbols_by_id[existing]
        return self._add_definition(
            node,
            name,
            lsp_kind,
            kind,
            aliased=aliased,
            selection_range=selection_range,
        )

    def _add_local_definition_in_scope(
        self,
        scope: _Scope,
        node: ast.AST,
        name: str,
        kind: SymbolKind,
        *,
        aliased: bool = False,
        selection_range: Optional[SourceRange] = None,
    ) -> SourceSymbol:
        existing = scope.bindings.get(name)
        if existing is not None:
            return self.index._symbols_by_id[existing]
        return self._add_definition_in_scope(
            scope,
            node,
            name,
            13,
            kind,
            aliased=aliased,
            selection_range=selection_range,
        )

    def predeclare_module(self, tree: ast.Module) -> None:
        self._predeclare_bindings(tree.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Decorators, defaults, and annotations are evaluated before the new
        # function binding becomes visible in its enclosing scope.
        self._visit_function_outer_expressions(
            node, annotations=not bool(getattr(node, "type_params", ()))
        )
        is_method = self._current_scope.kind is _ScopeKind.CLASS
        existing = self._current_scope.bindings.get(node.name)
        if (
            existing is not None
            and existing in self._current_scope.predeclared
            and self.index._symbols_by_id[existing].selection_range
            == self._range(node, name=node.name)
        ):
            symbol = self.index._symbols_by_id[existing]
        else:
            symbol = self._add_definition(
                node,
                node.name,
                6 if is_method else 12,
                SymbolKind.METHOD if is_method else SymbolKind.FUNCTION,
            )
        from .signatures import parameters

        decorators = []
        for decorator in node.decorator_list:
            name = (
                _call_name(decorator.func if isinstance(decorator, ast.Call) else decorator) or ""
            )
            head, separator, tail = name.partition(".")
            decorators.append(
                self.index._import_targets.get(self._resolve(head), head)
                + (separator + tail if separator else "")
            )
        symbol = replace(
            symbol,
            overload=bool({"typing.overload", "typing_extensions.overload"} & set(decorators)),
            parameters=parameters(node),
            binding=(
                (
                    "static"
                    if "staticmethod" in decorators
                    else "class" if "classmethod" in decorators else "instance"
                )
                if is_method
                else ""
            ),
        )
        self.index._symbols_by_id[symbol.symbol_id] = symbol
        self.index.symbols = [
            symbol if item.symbol_id == symbol.symbol_id else item for item in self.index.symbols
        ]
        for decorator in node.decorator_list:
            expression = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = _call_name(expression) or ""
            head, separator, rest = name.partition(".")
            imported = self.index._import_targets.get(self._resolve(head), head)
            if imported + (separator + rest if separator else "") == "pytest.fixture":
                fixture_name = node.name
                for keyword in decorator.keywords if isinstance(decorator, ast.Call) else ():
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                    ):
                        fixture_name = keyword.value.value
                self.index._fixtures[symbol.symbol_id] = fixture_name
        scoped = self._push_type_parameters(node, symbol)
        if scoped:
            self._visit_function_annotations(node)
        self._push_scope(node.name, kind=_ScopeKind.FUNCTION, function=symbol.symbol_id)
        self._predeclare_function_bindings(node)
        self.index._keyword_parameters[symbol.symbol_id] = tuple(
            (argument.arg, self._resolve(argument.arg))
            for argument in [*node.args.args, *node.args.kwonlyargs]
        )
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
                receiver = ("symbol", self._current_scope.class_id)
                self.index._value_targets[self._current_scope.receiver_id] = [
                    ("instance", receiver) if positional[0].arg == "self" else receiver
                ]
        for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            if argument.annotation and self._resolve(argument.arg):
                self.index._value_targets.setdefault(self._resolve(argument.arg), []).append(
                    ("annotation", self._annotation_target(argument.annotation))
                )
        if node.returns:
            self.index._return_targets.setdefault(symbol.symbol_id, []).append(
                (
                    "annotation",
                    self._annotation_target(
                        node.returns.slice
                        if symbol.symbol_id in self.index._fixtures
                        and isinstance(node.returns, ast.Subscript)
                        else node.returns
                    ),
                )
            )
        for statement in node.body:
            self.visit(statement)
        self._record_scope(node)
        self._pop_scope()
        if scoped:
            self._pop_type_parameters(node)

    def _visit_function_outer_expressions(self, node, *, annotations=True):
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        if annotations:
            self._visit_function_annotations(node)

    def _visit_function_annotations(self, node):
        for argument in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
            *([node.args.vararg] if node.args.vararg else []),
            *([node.args.kwarg] if node.args.kwarg else []),
        ]:
            if argument.annotation is not None:
                self._visit_annotation(argument.annotation)
        if node.returns is not None:
            self._visit_annotation(node.returns)

    def _visit_annotation(self, node: ast.AST) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            self._record_string_annotation(node)
            return
        self._annotation_depth += 1
        try:
            self.visit(node)
        finally:
            self._annotation_depth -= 1
        self._record_annotation_strings(node)

    def _record_annotation_strings(self, node: ast.AST) -> None:
        for constant in self._annotation_strings(node):
            self._record_string_annotation(constant)

    def _annotation_strings(self, node: ast.AST):
        """Yield string literals used as forward references in an annotation."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node
            return
        if isinstance(node, ast.Subscript):
            qualified = self._qualified_expression_name(node.value)
            arguments = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            if qualified in {"typing.Literal", "typing_extensions.Literal"}:
                return
            if qualified in {"typing.Annotated", "typing_extensions.Annotated"}:
                if arguments:
                    yield from self._annotation_strings(arguments[0])
                return
            for argument in arguments:
                yield from self._annotation_strings(argument)
            return
        if isinstance(node, (ast.Tuple, ast.List)):
            for item in node.elts:
                yield from self._annotation_strings(item)
            return
        for child in ast.iter_child_nodes(node):
            yield from self._annotation_strings(child)

    def _record_string_annotation(self, node: ast.Constant) -> None:
        """Record identifiers referenced by a string annotation.

        ``"Widget"`` and ``Optional["Widget"]`` are source-visible references:
        navigation and rename must treat them like the equivalent expression.
        Escaped or concatenated literals are replaced as a whole.
        """
        value = node.value
        if not isinstance(value, str) or "\n" in value:
            return
        try:
            expression = ast.parse(value, mode="eval").body
        except (SyntaxError, ValueError, RecursionError):
            return
        segment = ast.get_source_segment(self.source, node)
        if segment is None:
            return
        line_no = node.lineno - 1
        line = self.lines[line_no] if line_no < len(self.lines) else ""
        node_start = _byte_col_to_char(line, node.col_offset)
        node_end = _byte_col_to_char(line, node.end_col_offset)
        literal = line[node_start:node_end]
        escaped = _literal_payload(literal) != value
        inner = 1
        seen: set[tuple[int, int]] = set()
        for child in ast.walk(expression):
            if isinstance(child, ast.Name):
                name = child.id
                end_in_value = _byte_col_to_char(value, child.end_col_offset)
                start_in_value = _byte_col_to_char(value, child.col_offset)
            elif isinstance(child, ast.Attribute):
                name = child.attr
                end_in_value = _byte_col_to_char(value, child.end_col_offset)
                start_in_value = end_in_value - len(name)
            else:
                continue
            if not name.isidentifier():
                continue
            if escaped:
                start_char, end_char = node_start, node_end
            else:
                start_char = node_start + inner + start_in_value
                end_char = node_start + inner + end_in_value
                if line[start_char:end_char] != name:
                    continue
                if (start_char, end_char) in seen:
                    continue
                seen.add((start_char, end_char))
            location = SourceRange(
                self.uri,
                line_no,
                offset_to_lsp_character(line, start_char),
                line_no,
                offset_to_lsp_character(line, end_char),
            )
            self.index._reference_targets[location] = self._target(child)
            self.index.references.append(
                SourceReference(
                    name,
                    location,
                    self._current_function(),
                    string_literal=escaped,
                )
            )

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
            function_lsp_kind=(6 if self._current_scope.kind is _ScopeKind.CLASS else 12),
            alias_range=self._alias_range,
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
                binding.node,
                binding.name,
                binding.identity_kind,
                binding.lsp_kind,
                aliased=binding.aliased,
                selection_range=binding.selection_range,
            )
            self._current_scope.predeclared.add(symbol.symbol_id)

    def _predeclare_expression_bindings(
        self, expression: ast.expr, *, arguments: list[ast.arg]
    ) -> None:
        collector = _ScopeBindingCollector(function_lsp_kind=12, alias_range=self._alias_range)
        for argument in arguments:
            collector.visit(argument)
        collector.visit(expression)
        for binding in collector.bindings:
            symbol = self._add_local_definition(
                binding.node, binding.name, binding.identity_kind, binding.lsp_kind
            )
            self._current_scope.predeclared.add(symbol.symbol_id)

    def visit_ClassDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        existing = self._current_scope.bindings.get(node.name)
        if existing is not None and existing in self._current_scope.predeclared:
            symbol = self.index._symbols_by_id[existing]
        else:
            symbol = self._add_definition(node, node.name, 5, SymbolKind.CLASS)
        generated = any(
            self._qualified_expression_name(base)
            in {
                "typing.NamedTuple",
                "typing_extensions.NamedTuple",
                "typing.TypedDict",
                "typing_extensions.TypedDict",
                "pydantic.BaseModel",
                "pydantic.main.BaseModel",
                "pydantic.v1.BaseModel",
                "pydantic.v1.main.BaseModel",
            }
            for base in node.bases
        )
        for decorator in node.decorator_list:
            head = decorator.func if isinstance(decorator, ast.Call) else decorator
            if self._qualified_expression_name(head) in {
                "dataclasses.dataclass",
                "pydantic.dataclasses.dataclass",
                "attrs.define",
                "attrs.frozen",
                "attrs.mutable",
                "attr.s",
                "attr.attrs",
                "attr.dataclass",
                "attr.frozen",
            }:
                options = decorator.keywords if isinstance(decorator, ast.Call) else ()
                generated = not any(
                    item.arg == "init"
                    and not (isinstance(item.value, ast.Constant) and item.value.value is True)
                    for item in options
                )
        fields = []
        if generated:
            for item in node.body:
                if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                    continue
                annotation = (
                    item.annotation.value
                    if isinstance(item.annotation, ast.Subscript)
                    else item.annotation
                )
                if self._qualified_expression_name(annotation) in {
                    "typing.ClassVar",
                    "typing_extensions.ClassVar",
                    "dataclasses.KW_ONLY",
                }:
                    continue
                if (
                    isinstance(item.value, ast.Call)
                    and self._qualified_expression_name(item.value.func) == "dataclasses.field"
                    and any(
                        kw.arg == "init"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is False
                        for kw in item.value.keywords
                    )
                ):
                    continue
                fields.append(item.target.id)
        if generated or symbol.constructor_fields is not None:
            symbol = replace(symbol, constructor_fields=tuple(fields) if generated else None)
            self.index._symbols_by_id[symbol.symbol_id] = symbol
            self.index.symbols = [
                symbol if item.symbol_id == symbol.symbol_id else item
                for item in self.index.symbols
            ]
        scoped = self._push_type_parameters(node, symbol)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self.index._class_bases[symbol.qualified_name] = tuple(
            self._target(base) for base in node.bases
        )
        self._push_scope(node.name, kind=_ScopeKind.CLASS, class_symbol=symbol.symbol_id)
        for statement in node.body:
            self.visit(statement)
        self._record_scope(node)
        self._pop_scope()
        if scoped:
            self._pop_type_parameters(node)

    def _qualified_expression_name(self, node):
        name = _call_name(node) or ""
        head, separator, tail = name.partition(".")
        return self.index._import_targets.get(self._resolve(head), head) + (
            separator + tail if separator else ""
        )

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
            symbol = self._add_local_definition(
                alias,
                name,
                SymbolKind.IMPORT,
                aliased=bool(alias.asname),
                selection_range=(self._alias_range(alias, alias.asname) if alias.asname else None),
            )
            self.index._import_targets[symbol.symbol_id] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )
            components = alias.name.split(".")
            prefix = ""
            for component in components:
                column = alias.col_offset + len(prefix.encode("utf-8"))
                token = ast.Name(
                    id=component,
                    lineno=alias.lineno,
                    col_offset=column,
                    end_lineno=alias.lineno,
                    end_col_offset=column + len(component.encode("utf-8")),
                )
                location = self._range(token)
                prefix += component
                self.index._reference_targets[location] = ("external", prefix)
                self.index.references.append(
                    SourceReference(component, location, self._current_function())
                )
                prefix += "."

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
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
        self._record_import_module_reference(node, module)
        for alias in node.names:
            if alias.name != "*":
                symbol = self._add_local_definition(
                    alias,
                    alias.asname or alias.name,
                    SymbolKind.IMPORT,
                    aliased=bool(alias.asname),
                    selection_range=(
                        self._alias_range(alias, alias.asname) if alias.asname else None
                    ),
                )
                self.index._import_targets[symbol.symbol_id] = f"{module}.{alias.name}".lstrip(".")
                self.index.references.append(
                    SourceReference(
                        alias.name,
                        self._range(alias, name=alias.name),
                        self._current_function(),
                        symbol.symbol_id,
                        import_name=True,
                    )
                )

    def _record_import_module_reference(self, node: ast.ImportFrom, module: str) -> None:
        """Expose the module path of ``from pkg.mod import name`` for navigation."""
        if not node.module or not module:
            return
        line_no = node.lineno - 1
        line = self.lines[line_no] if line_no < len(self.lines) else ""
        start = _byte_col_to_char(line, node.col_offset)
        found = line.find(node.module, start)
        if found < 0:
            return
        textual = node.module.split(".")
        absolute = module.split(".")
        base = len(absolute) - len(textual)
        offset = 0
        for index, component in enumerate(textual):
            column = found + offset
            location = SourceRange(
                self.uri,
                line_no,
                offset_to_lsp_character(line, column),
                line_no,
                offset_to_lsp_character(line, column + len(component)),
            )
            prefix = ".".join(absolute[: base + index + 1])
            self.index._reference_targets[location] = ("external", prefix)
            self.index.references.append(
                SourceReference(component, location, self._current_function())
            )
            offset += len(component) + 1

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
        for name in node.names:
            self.index.references.append(
                SourceReference(
                    name,
                    self._range(node, name=name),
                    self._current_function(),
                    self._resolve(name),
                )
            )

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self._current_scope.nonlocal_names.update(node.names)
        for name in node.names:
            self.index.references.append(
                SourceReference(
                    name,
                    self._range(node, name=name),
                    self._current_function(),
                    self._resolve(name),
                )
            )

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self._add_local_definition(node, node.name, SymbolKind.VARIABLE)
        self.generic_visit(node)

    def visit_MatchClass(self, node):
        import io
        import tokenize

        self.visit(node.cls)
        owner = self._target(node.cls)
        if not hasattr(self, "_pattern_tokens"):
            self._pattern_tokens = [
                token
                for token in tokenize.generate_tokens(io.StringIO(self.source).readline)
                if token.type
                not in {
                    tokenize.NL,
                    tokenize.NEWLINE,
                    tokenize.COMMENT,
                    tokenize.INDENT,
                    tokenize.DEDENT,
                }
            ]
        start = (node.lineno, _byte_col_to_char(self.lines[node.lineno - 1], node.col_offset))
        for name, pattern in zip(node.kwd_attrs, node.kwd_patterns):
            stop = (
                pattern.lineno,
                _byte_col_to_char(self.lines[pattern.lineno - 1], pattern.col_offset),
            )
            candidates = [
                token
                for position, token in enumerate(self._pattern_tokens[:-1])
                if token.type == tokenize.NAME
                and token.string == name
                and start <= token.start < stop
                and self._pattern_tokens[position + 1].string == "="
            ]
            if candidates:
                token = candidates[-1]
                text = self.lines[token.start[0] - 1]
                location = SourceRange(
                    self.uri,
                    token.start[0] - 1,
                    offset_to_lsp_character(text, token.start[1]),
                    token.end[0] - 1,
                    offset_to_lsp_character(text, token.end[1]),
                )
                self.index._reference_targets[location] = ("member", owner, name, "read")
                self.index.references.append(
                    SourceReference(name, location, self._current_function())
                )
            self.visit(pattern)
            if isinstance(pattern, ast.MatchAs) and pattern.name:
                self._bind_value(ast.Name(id=pattern.name), ("member", owner, name, "read"))
        for position, pattern in enumerate(node.patterns):
            self.visit(pattern)
            if isinstance(pattern, ast.MatchAs) and pattern.name:
                self._bind_value(ast.Name(id=pattern.name), ("match-position", owner, position))

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

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.generic_visit(node)
        if self._annotation_depth:
            return
        key = node.slice
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            return
        name = key.value
        if not name.isidentifier():
            return
        escaped = _literal_payload(ast.get_source_segment(self.source, key)) != name
        location = self._range(key) if escaped else self._range(key, name=name)
        self.index._reference_targets[location] = ("member", self._target(node.value), name, "read")
        self.index.references.append(
            SourceReference(
                name,
                location,
                self._current_function(),
                string_literal=escaped,
            )
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
            if self._target(node)[0] == "super":
                self.index._reference_targets[self._range(node.func)] = self._target(node)
            self.index.calls.append(
                SourceCall(
                    self._current_function(),
                    callee,
                    self._range(node.func),
                    self._current_scope.function_id,
                    self._resolve_call(node.func),
                )
            )
        for keyword in node.keywords:
            if keyword.arg is not None:
                location = self._range(keyword, name=keyword.arg)
                self.index.references.append(
                    SourceReference(keyword.arg, location, self._current_function())
                )
                self.index._keyword_targets[location] = (self._target(node.func), keyword.arg)
        if (
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and self._qualified_expression_name(node.func)
            in {"typing.cast", "typing_extensions.cast"}
        ):
            # ``cast("Widget", value)`` uses the same forward-reference syntax
            # as an annotation string.
            self._record_string_annotation(node.args[0])
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
    aliased: bool = False
    selection_range: Optional[SourceRange] = None


class _ScopeBindingCollector(ast.NodeVisitor):
    """Collect scope-local bindings without descending into child scopes."""

    def __init__(self, *, function_lsp_kind: int = 6, alias_range=None) -> None:
        self.bindings: list[_FunctionBinding] = []
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()
        self._function_lsp_kind = function_lsp_kind
        self._alias_range = alias_range

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

    def _import_binding(self, alias: ast.alias, name: str) -> _FunctionBinding:
        selection = None
        if alias.asname and self._alias_range is not None:
            selection = self._alias_range(alias, alias.asname)
        return _FunctionBinding(
            alias,
            name,
            SymbolKind.IMPORT,
            aliased=bool(alias.asname),
            selection_range=selection,
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.bindings.append(
                self._import_binding(alias, alias.asname or alias.name.split(".", 1)[0])
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.bindings.append(self._import_binding(alias, alias.asname or alias.name))

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

    def visit_TypeAlias(self, node):
        self.bindings.append(_FunctionBinding(node, node.name.id, SymbolKind.TYPE_ALIAS))

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
