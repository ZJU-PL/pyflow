"""Shared Workspace and SourceStore infrastructure.

Centralizes project file discovery, canonical ignored-directory policies,
PEP 263 encoding-aware source loading, content hashing, inode/symlink
deduplication, bounded read-only AST caching, and monorepo import-root
discovery so ``frontend``, ``typeinfo``, ``callgraph``, and CLI tools operate
on a single consistent view of the workspace without re-parsing files.
"""

from __future__ import annotations

import ast
from collections import OrderedDict, defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import threading
import tokenize
from typing import TYPE_CHECKING

from pyflow.language.environment import AnalysisEnvironment
from pyflow.language.modules.project_resolution import ProjectContext, default_import_root
from pyflow.language.modules.type_stubs import StubResolver
from pyflow.language.source_compat import parse_python_source

if TYPE_CHECKING:
    from pyflow.language.modules.module_graph import ModuleGraph


DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "node_modules",
        "build",
        "dist",
        "site-packages",
        "dist-packages",
    }
)

_STMT_CONTAINER_ATTRS = ("body", "orelse", "finalbody")

_GLOBAL_AST_CACHE_MAX = 64
_GLOBAL_AST_CACHE: OrderedDict[tuple[bytes, int, str], ast.Module] = OrderedDict()
_GLOBAL_AST_CACHE_LOCK = threading.RLock()


def read_python_source(path: str | Path) -> str:
    """Read a Python source file using its PEP 263 encoding cookie (or UTF-8 BOM)."""
    with tokenize.open(path) as stream:
        return stream.read()


def content_hash_text(source: str) -> str:
    """Return a fast, stable BLAKE2b-128 hex digest for source text."""
    return hashlib.blake2b(
        source.encode("utf-8", errors="surrogatepass"),
        digest_size=16,
    ).hexdigest()


def parse_source_cached(source: str, filename: str = "<string>") -> ast.Module:
    """Parse Python source using a bounded digest-keyed process LRU cache.

    Keys by ``(blake2b_16_digest, len(source), filename)`` so full source
    strings are never pinned in global memory.  Callers MUST treat the returned
    ``ast.Module`` as read-only.
    """
    digest = hashlib.blake2b(
        source.encode("utf-8", errors="surrogatepass"),
        digest_size=16,
    ).digest()
    key = (digest, len(source), filename)
    with _GLOBAL_AST_CACHE_LOCK:
        cached = _GLOBAL_AST_CACHE.get(key)
        if cached is not None:
            _GLOBAL_AST_CACHE.move_to_end(key)
            return cached
    tree = parse_python_source(source, filename=filename)
    with _GLOBAL_AST_CACHE_LOCK:
        _GLOBAL_AST_CACHE[key] = tree
        _GLOBAL_AST_CACHE.move_to_end(key)
        while len(_GLOBAL_AST_CACHE) > _GLOBAL_AST_CACHE_MAX:
            _GLOBAL_AST_CACHE.popitem(last=False)
    return tree


def clear_global_ast_cache() -> None:
    """Clear the process-wide read-only AST cache."""
    with _GLOBAL_AST_CACHE_LOCK:
        _GLOBAL_AST_CACHE.clear()


def iter_all_import_nodes(tree: ast.Module) -> Iterator[ast.Import | ast.ImportFrom]:
    """Yield every ``Import``/``ImportFrom`` statement in *tree* without walking expressions."""
    stack: list[list[ast.stmt]] = [tree.body]
    while stack:
        block = stack.pop()
        for stmt in block:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                yield stmt
                continue
            for attr in _STMT_CONTAINER_ATTRS:
                nested = getattr(stmt, attr, None)
                if nested:
                    stack.append(nested)
            handlers = getattr(stmt, "handlers", None)
            if handlers:
                for handler in handlers:
                    if handler.body:
                        stack.append(handler.body)
            cases = getattr(stmt, "cases", None)
            if cases:
                for case in cases:
                    if case.body:
                        stack.append(case.body)


def discover_source_roots(
    import_root: str | Path,
    sources: Mapping[str, str],
    *,
    entry_path: str | Path | None = None,
    entry_source: str | None = None,
    parse_fn: Callable[[str, str], ast.Module] | None = None,
) -> tuple[str, ...]:
    """Infer additional non-package component roots in monorepo layouts.

    Detects non-package ``src/`` and non-identifier directories (e.g.
    ``pkg-core/``) as well as uniquely matched top-level import roots
    (e.g. ``libs/core/`` when code imports ``mypkg`` living at
    ``libs/core/mypkg/``).  Never cuts inside a regular package or guesses
    between ambiguous duplicate packages.
    """
    root = os.path.realpath(str(import_root))
    root_prefix = root if root.endswith(os.sep) else root + os.sep
    normalized_sources: dict[str, str] = {
        os.path.realpath(path): source for path, source in sources.items()
    }
    if entry_path is not None and entry_source is not None:
        normalized_sources.setdefault(os.path.realpath(str(entry_path)), entry_source)

    parser = parse_fn or parse_source_cached
    roots: set[str] = set()
    imports: defaultdict[str, set[tuple[str, ...]]] = defaultdict(set)
    module_paths: list[list[str]] = []
    visited: set[str] = {root}
    package_dirs: dict[str, bool] = {}

    def within_root(candidate_path: str) -> bool:
        return candidate_path == root or candidate_path.startswith(root_prefix)

    def is_package(directory: str) -> bool:
        if directory not in package_dirs:
            package_dirs[directory] = any(
                os.path.join(directory, name) in normalized_sources
                or os.path.isfile(os.path.join(directory, name))
                for name in ("__init__.py", "__init__.pyi")
            )
        return package_dirs[directory]

    for path, source in normalized_sources.items():
        if not within_root(path):
            continue
        parts = os.path.relpath(path, root).split(os.sep)
        parts[-1] = os.path.splitext(parts[-1])[0]
        if parts[-1] == "__init__":
            parts.pop()
        module_paths.append(parts)
        parent = os.path.dirname(path)
        while parent not in visited and within_root(parent):
            visited.add(parent)
            component = os.path.basename(parent)
            if (not component.isidentifier() or component == "src") and not is_package(parent):
                roots.add(parent)
                break
            parent = os.path.dirname(parent)
        try:
            tree = parser(source, path)
        except SyntaxError:
            continue
        for node in iter_all_import_nodes(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                imported = tuple(name.split("."))
                imports[imported[0]].add(imported)

    candidates: defaultdict[tuple[str, ...], set[str]] = defaultdict(set)
    for parts in module_paths:
        for offset, part in enumerate(parts):
            for imported in imports.get(part, ()):
                if tuple(parts[offset : offset + len(imported)]) != imported:
                    continue
                candidate = os.path.join(root, *parts[:offset])
                if not is_package(candidate):
                    candidates[imported].add(candidate)
    for matches in candidates.values():
        if len(matches) == 1:
            roots.update(matches)
    roots.discard(root)
    return tuple(sorted(roots))


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """Normalized immutable source entry stored in a :class:`SourceStore`."""

    path: str
    real_path: str
    text: str
    content_hash: str
    byte_length: int
    inode: tuple[int, int] | None = None


class SourceStore:
    """Workspace-scoped source reader, content hasher, inode deduper, and AST cache."""

    def __init__(
        self,
        in_memory_sources: Mapping[str, str] | None = None,
        *,
        max_ast_cache: int = 256,
    ) -> None:
        self._records: dict[str, SourceRecord] = {}
        self._by_real_path: dict[str, str] = {}
        self._by_inode: dict[tuple[int, int], str] = {}
        self._ast_cache: OrderedDict[tuple[str, int, str], ast.Module | SyntaxError] = OrderedDict()
        self._max_ast_cache = max(1, max_ast_cache)
        if in_memory_sources:
            for path, text in in_memory_sources.items():
                self.put(path, text)

    def _stat_inode(self, path: str) -> tuple[int, int] | None:
        try:
            st = os.stat(path)
            return (st.st_dev, st.st_ino)
        except OSError:
            return None

    def put(self, path: str | Path, text: str) -> SourceRecord:
        """Register or update an in-memory source file."""
        logical = str(path)
        real_path = (
            os.path.realpath(logical) if logical and not logical.startswith("<") else logical
        )
        inode = self._stat_inode(real_path) if real_path and not real_path.startswith("<") else None
        digest = content_hash_text(text)
        record = SourceRecord(
            path=logical,
            real_path=real_path,
            text=text,
            content_hash=digest,
            byte_length=len(text),
            inode=inode,
        )
        self._records[logical] = record
        self._records[real_path] = record
        self._by_real_path.setdefault(real_path, logical)
        if inode is not None:
            self._by_inode.setdefault(inode, real_path)
        return record

    def get(self, path: str | Path) -> SourceRecord | None:
        """Return a previously loaded :class:`SourceRecord`, if cached."""
        logical = str(path)
        record = self._records.get(logical)
        if record is not None:
            return record
        if logical and not logical.startswith("<"):
            return self._records.get(os.path.realpath(logical))
        return None

    def load(self, path: str | Path) -> SourceRecord:
        """Return the :class:`SourceRecord` for *path*, reading from disk if needed."""
        existing = self.get(path)
        if existing is not None:
            return existing
        text = read_python_source(path)
        return self.put(path, text)

    def canonical_path(self, path: str | Path) -> str:
        """Return the canonical path for *path*, collapsing symlink/hardlink aliases."""
        logical = str(path)
        if not logical or logical.startswith("<"):
            return logical
        real_path = os.path.realpath(logical)
        inode = self._stat_inode(real_path)
        if inode is not None and inode in self._by_inode:
            return self._by_inode[inode]
        return real_path

    def parse_ast(
        self,
        path: str | Path,
        source: str | None = None,
    ) -> ast.Module:
        """Parse *path* (or *source*) and cache the resulting read-only ``ast.Module``."""
        if source is None:
            record = self.load(path)
            text = record.text
            digest = record.content_hash
            filename = record.real_path
        else:
            text = source
            filename = str(path)
            existing = self.get(path)
            if existing is not None and existing.text == text:
                digest = existing.content_hash
                filename = existing.real_path
            else:
                digest = content_hash_text(text)

        cache_key = (digest, len(text), filename)
        cached = self._ast_cache.get(cache_key)
        if cached is not None:
            self._ast_cache.move_to_end(cache_key)
            if isinstance(cached, SyntaxError):
                raise cached
            return cached

        try:
            tree = parse_source_cached(text, filename=filename)
        except SyntaxError as exc:
            # Strip traceback frames before caching.
            clean_exc = type(exc)(*exc.args)
            self._ast_cache[cache_key] = clean_exc
            self._trim_ast_cache()
            raise clean_exc from None

        self._ast_cache[cache_key] = tree
        self._trim_ast_cache()
        return tree

    def _trim_ast_cache(self) -> None:
        while len(self._ast_cache) > self._max_ast_cache:
            self._ast_cache.popitem(last=False)

    def all_sources(self) -> dict[str, str]:
        """Return a mapping of canonical real paths to loaded source text."""
        out: dict[str, str] = {}
        for record in self._records.values():
            out[record.real_path] = record.text
        return out

    def content_hashes(self) -> dict[str, str]:
        """Return a mapping of canonical real paths to BLAKE2b content hashes."""
        out: dict[str, str] = {}
        for record in self._records.values():
            out[record.real_path] = record.content_hash
        return out


class Workspace:
    """Shared project workspace bridging discovery, resolution, ASTs, and graphs."""

    def __init__(
        self,
        root: str | Path,
        *,
        environment: AnalysisEnvironment | None = None,
        source_store: SourceStore | None = None,
        in_memory_sources: Mapping[str, str] | None = None,
        added_sys_path: Iterable[str | Path] = (),
        smart_sys_path: bool = True,
        discover_roots: bool = False,
        typeshed_roots: list[str | Path] | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.import_root = default_import_root(self.root)
        self.environment = environment or AnalysisEnvironment.current()
        self.source_store = source_store or SourceStore(in_memory_sources)
        if source_store is not None and in_memory_sources:
            for path, text in in_memory_sources.items():
                self.source_store.put(path, text)

        extra_roots: list[str] = [str(p) for p in added_sys_path]
        if discover_roots:
            sources_for_roots = self.source_store.all_sources()
            if not sources_for_roots and self.root.is_dir():
                for py_path in self.discover_files():
                    try:
                        rec = self.source_store.load(py_path)
                        sources_for_roots[rec.real_path] = rec.text
                    except (OSError, UnicodeError, SyntaxError):
                        continue
            for discovered in discover_source_roots(
                self.import_root,
                sources_for_roots,
                parse_fn=lambda src, fn: self.source_store.parse_ast(fn, src),
            ):
                if discovered not in extra_roots:
                    extra_roots.append(discovered)

        self.project_context = ProjectContext(
            self.import_root,
            added_sys_path=extra_roots,
            smart_sys_path=smart_sys_path,
            source_files=self.source_store.all_sources(),
        )
        self._typeshed_roots = typeshed_roots
        self._stub_resolver: StubResolver | None = None
        self._module_graph: ModuleGraph | None = None

    def discover_files(
        self,
        *,
        recursive: bool = True,
        ignored_dirs: Iterable[str] = DEFAULT_IGNORED_DIRS,
        follow_symlinks: bool = False,
    ) -> list[Path]:
        """Discover ``.py`` files under :attr:`root` in deterministic sorted order."""
        ignored = frozenset(ignored_dirs)
        if self.root.is_file():
            return [self.root] if self.root.suffix == ".py" else []

        files: list[Path] = []
        ancestor_reals: dict[str, frozenset[str]] = {}
        for current, directories, filenames in os.walk(self.root, followlinks=follow_symlinks):
            if follow_symlinks:
                parent = os.path.dirname(current)
                chain = ancestor_reals.get(parent, frozenset())
                real = os.path.realpath(current)
                if real in chain:
                    directories[:] = []
                    continue
                ancestor_reals[current] = chain | {real}
            directories[:] = (
                sorted(
                    name for name in directories if name not in ignored and not name.startswith(".")
                )
                if recursive
                else []
            )
            for filename in sorted(filenames):
                if not filename.endswith(".py") or filename.startswith("."):
                    continue
                files.append(Path(current, filename))
        return files

    def iter_modules(
        self,
        *,
        recursive: bool = True,
        ignored_dirs: Iterable[str] = DEFAULT_IGNORED_DIRS,
        require_valid_identifiers: bool = True,
    ) -> list[tuple[str, Path]]:
        """Return ``(module_name, path)`` pairs for importable Python modules."""
        modules: list[tuple[str, Path]] = []
        seen_names: set[str] = set()
        for path in self.discover_files(recursive=recursive, ignored_dirs=ignored_dirs):
            module_name = self.project_context.module_name_from_path(
                path, allow_absolute_fallback=False
            )
            if not module_name:
                continue
            if module_name == "main" and path.stem != "main":
                continue
            if require_valid_identifiers and not all(
                part.isidentifier() for part in module_name.split(".")
            ):
                continue
            if module_name in seen_names:
                continue
            seen_names.add(module_name)
            modules.append((module_name, path))
        return modules

    def load_sources(
        self,
        paths: Iterable[str | Path] | None = None,
    ) -> dict[str, str]:
        """Load *paths* (or all discovered files) into :attr:`source_store` and sync context."""
        target_paths = list(paths) if paths is not None else self.discover_files()
        loaded: dict[str, str] = {}
        for path in target_paths:
            try:
                record = self.source_store.load(path)
            except (OSError, UnicodeError, SyntaxError):
                continue
            loaded[record.real_path] = record.text
            self.project_context.source_files[record.real_path] = record.text
        return loaded

    def stub_resolver(self) -> StubResolver:
        """Return a lazily initialized :class:`StubResolver` bound to this workspace."""
        if self._stub_resolver is None:
            self._stub_resolver = StubResolver(
                self.project_context,
                typeshed_roots=self._typeshed_roots,
                python_version=self.environment.python_version,
            )
        return self._stub_resolver

    def module_graph(
        self,
        *,
        environment: AnalysisEnvironment | None = None,
        refresh: bool = False,
    ) -> "ModuleGraph":
        """Build (or return cached) IR-independent :class:`ModuleGraph` for this workspace."""
        from pyflow.language.modules.module_graph import ModuleGraph

        if (
            self._module_graph is None
            or refresh
            or (environment is not None and environment != self._module_graph.environment)
        ):
            self._module_graph = ModuleGraph.from_workspace(
                self, environment=environment or self.environment
            )
        return self._module_graph


__all__ = [
    "DEFAULT_IGNORED_DIRS",
    "SourceRecord",
    "SourceStore",
    "Workspace",
    "clear_global_ast_cache",
    "content_hash_text",
    "discover_source_roots",
    "iter_all_import_nodes",
    "parse_source_cached",
    "read_python_source",
]
