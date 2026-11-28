"""IR-independent static module dependency graph and export/re-export tables.

Extracts module-level imports, relative imports, ``__all__`` declarations
(including ``__all__ += [...]``, ``__all__.extend(...)``, ``__all__.append(...)``),
star imports, and re-export chains directly from Python ASTs under an
:class:`AnalysisEnvironment`.  Provides iterative Tarjan SCC ordering
(dependencies before importers) and Merkle transitive dependency fingerprinting
for incremental caching.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import os
from typing import Any

from pyflow.language.diagnostics import SourceSpan
from pyflow.language.environment import (
    AnalysisEnvironment,
    evaluate_static_condition,
)
from pyflow.language.modules.imports import literal_string_list
from pyflow.language.modules.workspace import (
    SourceStore,
    Workspace,
    content_hash_text,
    parse_source_cached,
)

MODULE_EXPORT_SCHEMA_VERSION = "module_exports.v1"


def resolve_relative_module(
    current_module: str,
    imported_module: str | None,
    level: int,
    *,
    is_package: bool = False,
) -> str:
    """Resolve an ``ImportFrom`` target relative to *current_module*.

    Follows Python's PEP 328 package semantics:
    - ``level == 0`` returns ``imported_module or ""``.
    - For a package (``__init__.py``), ``level == 1`` refers to ``current_module`` itself.
    - For a regular module ``pkg.sub.mod``, ``level == 1`` refers to ``pkg.sub``.
    """
    if level <= 0:
        return imported_module or ""

    parts = [part for part in current_module.split(".") if part]
    if is_package:
        # level=1 stays in `current_module`, level=2 pops 1 segment, ...
        pops = level - 1
    else:
        # level=1 pops the module leaf to reach its enclosing package, level=2 pops 2, ...
        pops = level

    if pops >= len(parts):
        base_parts: list[str] = []
    elif pops <= 0:
        base_parts = parts
    else:
        base_parts = parts[:-pops]

    if imported_module:
        return ".".join([*base_parts, imported_module]) if base_parts else imported_module
    return ".".join(base_parts)


@dataclass(frozen=True, slots=True)
class ImportEdge:
    """One resolved static import statement binding inside a module."""

    importer: str
    imported_module: str
    imported_name: str | None  # None for `import m`, "*" for star import, else attr name
    local_name: str
    level: int = 0
    is_from: bool = False
    is_type_checking_only: bool = False
    span: SourceSpan | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "importer": self.importer,
            "imported_module": self.imported_module,
            "imported_name": self.imported_name,
            "local_name": self.local_name,
            "level": self.level,
            "is_from": self.is_from,
            "is_type_checking_only": self.is_type_checking_only,
            "span": self.span.to_dict() if self.span is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ImportEdge":
        raw_span = data.get("span")
        span = (
            SourceSpan(
                lineno=int(raw_span["lineno"]),
                col_offset=int(raw_span["col_offset"]),
                end_lineno=raw_span.get("end_lineno"),
                end_col_offset=raw_span.get("end_col_offset"),
            )
            if isinstance(raw_span, Mapping)
            else None
        )
        return cls(
            importer=str(data["importer"]),
            imported_module=str(data["imported_module"]),
            imported_name=data.get("imported_name"),
            local_name=str(data["local_name"]),
            level=int(data.get("level", 0)),
            is_from=bool(data.get("is_from", False)),
            is_type_checking_only=bool(data.get("is_type_checking_only", False)),
            span=span,
        )


@dataclass(frozen=True, slots=True)
class ExportBinding:
    """A module-level symbol definition or imported re-export."""

    local_name: str
    kind: str  # "function" | "class" | "variable" | "import" | "module"
    target_module: str
    target_name: str | None  # None when binding refers to an imported module object
    is_public: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "local_name": self.local_name,
            "kind": self.kind,
            "target_module": self.target_module,
            "target_name": self.target_name,
            "is_public": self.is_public,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExportBinding":
        return cls(
            local_name=str(data["local_name"]),
            kind=str(data["kind"]),
            target_module=str(data["target_module"]),
            target_name=data.get("target_name"),
            is_public=bool(data.get("is_public", True)),
        )


@dataclass
class ModuleExportTable:
    """Static symbol export and import metadata for one Python module."""

    module_name: str
    path: str | None = None
    is_package: bool = False
    explicit_all: tuple[str, ...] | None = None
    bindings: dict[str, ExportBinding] = field(default_factory=dict)
    imports: tuple[ImportEdge, ...] = ()
    star_imports: tuple[str, ...] = ()
    content_hash: str = ""

    def public_names(self) -> frozenset[str]:
        """Return names exported by this module (honoring explicit ``__all__``)."""
        if self.explicit_all is not None:
            return frozenset(self.explicit_all)
        return frozenset(name for name, binding in self.bindings.items() if binding.is_public)

    def imported_modules(self, *, include_type_checking: bool = True) -> frozenset[str]:
        """Return the set of target module names imported by this module."""
        out: set[str] = set()
        for edge in self.imports:
            if not include_type_checking and edge.is_type_checking_only:
                continue
            if edge.imported_module:
                out.add(edge.imported_module)
            if edge.is_from and edge.imported_name and edge.imported_name != "*":
                # ``from pkg import submod`` may refer to either a submodule or an attribute.
                if edge.imported_module:
                    out.add(f"{edge.imported_module}.{edge.imported_name}")
        return frozenset(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": MODULE_EXPORT_SCHEMA_VERSION,
            "module_name": self.module_name,
            "path": self.path,
            "is_package": self.is_package,
            "explicit_all": list(self.explicit_all) if self.explicit_all is not None else None,
            "bindings": {name: b.to_dict() for name, b in self.bindings.items()},
            "imports": [edge.to_dict() for edge in self.imports],
            "star_imports": list(self.star_imports),
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ModuleExportTable":
        raw_all = data.get("explicit_all")
        return cls(
            module_name=str(data["module_name"]),
            path=data.get("path"),
            is_package=bool(data.get("is_package", False)),
            explicit_all=tuple(str(x) for x in raw_all) if raw_all is not None else None,
            bindings={
                str(name): ExportBinding.from_dict(item)
                for name, item in (data.get("bindings") or {}).items()
            },
            imports=tuple(ImportEdge.from_dict(item) for item in (data.get("imports") or ())),
            star_imports=tuple(str(x) for x in (data.get("star_imports") or ())),
            content_hash=str(data.get("content_hash", "")),
        )


def _is_package_path(path: str | None) -> bool:
    if not path:
        return False
    return os.path.basename(path) in {"__init__.py", "__init__.pyi"}


def _extract_string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_type_checking_guard(test: ast.AST, aliases: Mapping[str, str]) -> bool:
    runtime_env = AnalysisEnvironment.current(type_checking=False)
    tc_env = AnalysisEnvironment.current(type_checking=True)
    return (
        evaluate_static_condition(test, runtime_env, aliases=aliases) is False
        and evaluate_static_condition(test, tc_env, aliases=aliases) is True
    )


def extract_module_export_table(
    module_name: str,
    tree: ast.Module,
    *,
    path: str | None = None,
    is_package: bool | None = None,
    environment: AnalysisEnvironment | None = None,
    content_hash: str = "",
) -> ModuleExportTable:
    """Extract a :class:`ModuleExportTable` from a parsed Python ``ast.Module``."""
    env = environment or AnalysisEnvironment.current()
    pkg = _is_package_path(path) if is_package is None else is_package

    bindings: dict[str, ExportBinding] = {}
    imports: list[ImportEdge] = []
    star_imports: list[str] = []
    explicit_all: list[str] | None = None
    explicit_all_dynamic = False

    # Collect initial module-scope aliases for static condition evaluation.
    aliases: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name if alias.asname else alias.name.split(".", 1)[0]
        elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module:
            for alias in stmt.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{stmt.module}.{alias.name}"

    def _visit_statements(stmts: list[ast.stmt], *, in_type_checking: bool) -> None:
        nonlocal explicit_all, explicit_all_dynamic
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                is_tc_only = in_type_checking or _is_type_checking_guard(stmt.test, aliases)
                decision = evaluate_static_condition(stmt.test, env, aliases=aliases)
                if decision is True:
                    _visit_statements(stmt.body, in_type_checking=is_tc_only)
                elif decision is False:
                    _visit_statements(stmt.orelse, in_type_checking=in_type_checking)
                else:
                    _visit_statements(stmt.body, in_type_checking=is_tc_only)
                    _visit_statements(stmt.orelse, in_type_checking=in_type_checking)
                continue

            if isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
                _visit_statements(
                    list(getattr(stmt, "body", ()) or ()), in_type_checking=in_type_checking
                )
                for handler in getattr(stmt, "handlers", ()) or ():
                    _visit_statements(
                        list(getattr(handler, "body", ()) or ()),
                        in_type_checking=in_type_checking,
                    )
                _visit_statements(
                    list(getattr(stmt, "orelse", ()) or ()), in_type_checking=in_type_checking
                )
                _visit_statements(
                    list(getattr(stmt, "finalbody", ()) or ()), in_type_checking=in_type_checking
                )
                continue

            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                _visit_statements(
                    list(getattr(stmt, "body", ()) or ()), in_type_checking=in_type_checking
                )
                _visit_statements(
                    list(getattr(stmt, "orelse", ()) or ()), in_type_checking=in_type_checking
                )
                continue

            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                bindings[stmt.name] = ExportBinding(
                    local_name=stmt.name,
                    kind="function",
                    target_module=module_name,
                    target_name=stmt.name,
                    is_public=not stmt.name.startswith("_"),
                )
                continue

            if isinstance(stmt, ast.ClassDef):
                bindings[stmt.name] = ExportBinding(
                    local_name=stmt.name,
                    kind="class",
                    target_module=module_name,
                    target_name=stmt.name,
                    is_public=not stmt.name.startswith("_"),
                )
                continue

            if isinstance(stmt, ast.Import):
                span = SourceSpan.from_ast(stmt)
                for alias in stmt.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    target_mod = alias.name if alias.asname else alias.name.split(".", 1)[0]
                    imports.append(
                        ImportEdge(
                            importer=module_name,
                            imported_module=alias.name,
                            imported_name=None,
                            local_name=local,
                            level=0,
                            is_from=False,
                            is_type_checking_only=in_type_checking,
                            span=span,
                        )
                    )
                    if not in_type_checking or local not in bindings:
                        bindings[local] = ExportBinding(
                            local_name=local,
                            kind="module",
                            target_module=target_mod,
                            target_name=None,
                            is_public=not local.startswith("_"),
                        )
                continue

            if isinstance(stmt, ast.ImportFrom):
                span = SourceSpan.from_ast(stmt)
                resolved_mod = resolve_relative_module(
                    module_name,
                    stmt.module,
                    int(stmt.level or 0),
                    is_package=pkg,
                )
                for alias in stmt.names:
                    if alias.name == "*":
                        imports.append(
                            ImportEdge(
                                importer=module_name,
                                imported_module=resolved_mod,
                                imported_name="*",
                                local_name="*",
                                level=int(stmt.level or 0),
                                is_from=True,
                                is_type_checking_only=in_type_checking,
                                span=span,
                            )
                        )
                        if resolved_mod and resolved_mod not in star_imports:
                            star_imports.append(resolved_mod)
                        continue
                    local = alias.asname or alias.name
                    imports.append(
                        ImportEdge(
                            importer=module_name,
                            imported_module=resolved_mod,
                            imported_name=alias.name,
                            local_name=local,
                            level=int(stmt.level or 0),
                            is_from=True,
                            is_type_checking_only=in_type_checking,
                            span=span,
                        )
                    )
                    if not in_type_checking or local not in bindings:
                        bindings[local] = ExportBinding(
                            local_name=local,
                            kind="import",
                            target_module=resolved_mod,
                            target_name=alias.name,
                            is_public=not local.startswith("_"),
                        )
                continue

            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if target.id == "__all__":
                        values = literal_string_list(stmt.value)
                        if values is not None:
                            explicit_all = list(values)
                            explicit_all_dynamic = False
                        else:
                            explicit_all_dynamic = True
                    else:
                        bindings[target.id] = ExportBinding(
                            local_name=target.id,
                            kind="variable",
                            target_module=module_name,
                            target_name=target.id,
                            is_public=not target.id.startswith("_"),
                        )
                continue

            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                if stmt.target.id == "__all__" and stmt.value is not None:
                    values = literal_string_list(stmt.value)
                    if values is not None:
                        explicit_all = list(values)
                        explicit_all_dynamic = False
                    else:
                        explicit_all_dynamic = True
                elif stmt.target.id != "__all__":
                    bindings[stmt.target.id] = ExportBinding(
                        local_name=stmt.target.id,
                        kind="variable",
                        target_module=module_name,
                        target_name=stmt.target.id,
                        is_public=not stmt.target.id.startswith("_"),
                    )
                continue

            if (
                isinstance(stmt, ast.AugAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id == "__all__"
                and isinstance(stmt.op, ast.Add)
            ):
                added = literal_string_list(stmt.value)
                if added is not None and explicit_all is not None and not explicit_all_dynamic:
                    explicit_all.extend(added)
                else:
                    explicit_all_dynamic = True
                continue

            if (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Attribute)
                and isinstance(stmt.value.func.value, ast.Name)
                and stmt.value.func.value.id == "__all__"
            ):
                method = stmt.value.func.attr
                if method == "append" and len(stmt.value.args) == 1:
                    item = _extract_string_literal(stmt.value.args[0])
                    if item is not None and explicit_all is not None and not explicit_all_dynamic:
                        explicit_all.append(item)
                    else:
                        explicit_all_dynamic = True
                elif method == "extend" and len(stmt.value.args) == 1:
                    added = literal_string_list(stmt.value.args[0])
                    if added is not None and explicit_all is not None and not explicit_all_dynamic:
                        explicit_all.extend(added)
                    else:
                        explicit_all_dynamic = True

    _visit_statements(list(tree.body), in_type_checking=False)

    final_all: tuple[str, ...] | None = None
    if explicit_all is not None and not explicit_all_dynamic:
        final_all = tuple(dict.fromkeys(explicit_all))

    return ModuleExportTable(
        module_name=module_name,
        path=path,
        is_package=pkg,
        explicit_all=final_all,
        bindings=bindings,
        imports=tuple(imports),
        star_imports=tuple(star_imports),
        content_hash=content_hash,
    )


class ModuleGraph:
    """Whole-project static import dependency graph and re-export resolver."""

    def __init__(
        self,
        tables: Mapping[str, ModuleExportTable],
        *,
        environment: AnalysisEnvironment | None = None,
    ) -> None:
        self.environment = environment or AnalysisEnvironment.current()
        self.modules: dict[str, ModuleExportTable] = dict(tables)
        self._deps: dict[str, frozenset[str]] = {}
        self._rdeps: dict[str, set[str]] = defaultdict(set)
        self._sccs_cache: tuple[tuple[str, ...], ...] | None = None
        self._build_edges()

    def _build_edges(self) -> None:
        known = set(self.modules)
        for mod_name, table in self.modules.items():
            resolved_deps: set[str] = set()
            for candidate in table.imported_modules(
                include_type_checking=self.environment.type_checking is not False
            ):
                if candidate == mod_name:
                    continue
                if candidate in known:
                    resolved_deps.add(candidate)
                else:
                    # Walk enclosing package prefixes if a submodule isn't loaded directly.
                    prefix = candidate
                    while "." in prefix:
                        prefix = prefix.rpartition(".")[0]
                        if prefix in known and prefix != mod_name:
                            resolved_deps.add(prefix)
                            break
            self._deps[mod_name] = frozenset(resolved_deps)
            for dep in resolved_deps:
                self._rdeps[dep].add(mod_name)

    @classmethod
    def from_sources(
        cls,
        module_sources: Mapping[str, tuple[str, str | None]],
        *,
        environment: AnalysisEnvironment | None = None,
        source_store: SourceStore | None = None,
        summary_cache: Any = None,
    ) -> "ModuleGraph":
        """Build a :class:`ModuleGraph` from ``{module_name: (source_text, path)}``."""
        env = environment or AnalysisEnvironment.current()
        env_fp = env.fingerprint()
        tables: dict[str, ModuleExportTable] = {}
        for module_name, (source, path) in module_sources.items():
            digest = content_hash_text(source)
            if summary_cache is not None:
                cached = summary_cache.get_module_export_table(
                    module_name, file_hash=digest, env_fingerprint=env_fp
                )
                if cached is not None:
                    tables[module_name] = cached
                    continue
            filename = path or f"<{module_name}>"
            try:
                tree = (
                    source_store.parse_ast(filename, source)
                    if source_store is not None
                    else parse_source_cached(source, filename=filename)
                )
            except SyntaxError:
                continue
            table = extract_module_export_table(
                module_name,
                tree,
                path=path,
                environment=env,
                content_hash=digest,
            )
            tables[module_name] = table
            if summary_cache is not None:
                summary_cache.put_module_export_table(
                    table, file_hash=digest, env_fingerprint=env_fp
                )
        return cls(tables, environment=env)

    @classmethod
    def from_workspace(
        cls,
        workspace: Workspace,
        *,
        environment: AnalysisEnvironment | None = None,
        summary_cache: Any = None,
    ) -> "ModuleGraph":
        """Build a :class:`ModuleGraph` from all modules discovered in *workspace*."""
        env = environment or workspace.environment
        module_sources: dict[str, tuple[str, str | None]] = {}
        for module_name, path in workspace.iter_modules():
            try:
                rec = workspace.source_store.load(path)
            except (OSError, UnicodeError, SyntaxError):
                continue
            module_sources[module_name] = (rec.text, rec.real_path)
        # Also include any in-memory-only sources not on disk.
        for path_str, text in workspace.source_store.all_sources().items():
            mod = workspace.project_context.module_name_from_path(
                path_str, allow_absolute_fallback=False
            )
            if mod and mod not in module_sources:
                module_sources[mod] = (text, path_str)
        return cls.from_sources(
            module_sources,
            environment=env,
            source_store=workspace.source_store,
            summary_cache=summary_cache,
        )

    def dependencies(self, module_name: str) -> frozenset[str]:
        """Direct in-project dependencies of *module_name*."""
        return self._deps.get(module_name, frozenset())

    def dependents(self, module_name: str) -> frozenset[str]:
        """Direct in-project modules that import *module_name*."""
        return frozenset(self._rdeps.get(module_name, ()))

    def transitive_dependencies(self, module_name: str) -> frozenset[str]:
        """All modules transitively imported by *module_name* (excluding itself)."""
        visited: set[str] = set()
        stack = list(self.dependencies(module_name))
        while stack:
            current = stack.pop()
            if current in visited or current == module_name:
                continue
            visited.add(current)
            stack.extend(self.dependencies(current))
        return frozenset(visited)

    def transitive_dependents(self, module_name: str) -> frozenset[str]:
        """All modules transitively affected when *module_name* changes."""
        visited: set[str] = set()
        stack = list(self.dependents(module_name))
        while stack:
            current = stack.pop()
            if current in visited or current == module_name:
                continue
            visited.add(current)
            stack.extend(self.dependents(current))
        return frozenset(visited)

    def sccs(self) -> tuple[tuple[str, ...], ...]:
        """Return strongly connected components in bottom-up dependency order.

        Uses an iterative Tarjan algorithm so arbitrarily deep import chains
        never hit Python's recursion limit.  Dependencies appear before their
        importers; nodes inside each SCC are sorted deterministically.
        """
        if self._sccs_cache is not None:
            return self._sccs_cache

        index_counter = 0
        index: dict[str, int] = {}
        lowlink: dict[str, int] = {}
        on_stack: set[str] = set()
        tarjan_stack: list[str] = []
        result: list[tuple[str, ...]] = []

        for root in sorted(self.modules):
            if root in index:
                continue
            call_stack: list[tuple[str, list[str], int]] = [
                (root, sorted(self._deps.get(root, ())), 0)
            ]
            index[root] = lowlink[root] = index_counter
            index_counter += 1
            tarjan_stack.append(root)
            on_stack.add(root)

            while call_stack:
                node, neighbors, pos = call_stack[-1]
                if pos < len(neighbors):
                    call_stack[-1] = (node, neighbors, pos + 1)
                    nxt = neighbors[pos]
                    if nxt not in index:
                        index[nxt] = lowlink[nxt] = index_counter
                        index_counter += 1
                        tarjan_stack.append(nxt)
                        on_stack.add(nxt)
                        call_stack.append((nxt, sorted(self._deps.get(nxt, ())), 0))
                    elif nxt in on_stack:
                        if index[nxt] < lowlink[node]:
                            lowlink[node] = index[nxt]
                else:
                    call_stack.pop()
                    if call_stack:
                        parent = call_stack[-1][0]
                        if lowlink[node] < lowlink[parent]:
                            lowlink[parent] = lowlink[node]
                    if lowlink[node] == index[node]:
                        comp: list[str] = []
                        while True:
                            member = tarjan_stack.pop()
                            on_stack.discard(member)
                            comp.append(member)
                            if member == node:
                                break
                        result.append(tuple(sorted(comp)))

        self._sccs_cache = tuple(result)
        return self._sccs_cache

    def topological_order(self) -> tuple[str, ...]:
        """Flatten :meth:`sccs` into a deterministic bottom-up module order."""
        return tuple(mod for comp in self.sccs() for mod in comp)

    def resolve_reexport(
        self,
        module_name: str,
        symbol_name: str,
        *,
        max_depth: int = 16,
    ) -> tuple[str, str | None] | None:
        """Follow re-export and star-import chains to the defining ``(module, symbol)``."""
        visited: set[tuple[str, str]] = set()
        current_mod = module_name
        current_sym = symbol_name

        for _ in range(max_depth):
            key = (current_mod, current_sym)
            if key in visited:
                return None
            visited.add(key)

            table = self.modules.get(current_mod)
            if table is None:
                return (current_mod, current_sym)

            binding = table.bindings.get(current_sym)
            if binding is not None:
                if binding.kind in {"function", "class", "variable"}:
                    return (current_mod, current_sym)
                if binding.kind == "module":
                    return (binding.target_module, None)
                if binding.kind == "import":
                    if not binding.target_module:
                        return None
                    # Check if `from pkg import submod` refers to a known submodule.
                    submod = (
                        f"{binding.target_module}.{binding.target_name}"
                        if binding.target_name
                        else binding.target_module
                    )
                    if submod in self.modules:
                        return (submod, None)
                    if binding.target_name is None:
                        return (binding.target_module, None)
                    current_mod = binding.target_module
                    current_sym = binding.target_name
                    continue

            # Check star imports in declaration order.
            found_star: tuple[str, str | None] | None = None
            for star_mod in table.star_imports:
                star_table = self.modules.get(star_mod)
                if star_table is None:
                    continue
                if current_sym in star_table.public_names():
                    found_star = self.resolve_reexport(
                        star_mod, current_sym, max_depth=max_depth - len(visited)
                    )
                    if found_star is not None:
                        return found_star
            if found_star is not None:
                return found_star

            # Check if `current_mod.current_sym` is itself a known submodule.
            submod = f"{current_mod}.{current_sym}"
            if submod in self.modules:
                return (submod, None)
            return None
        return None

    def expanded_exports(self, module_name: str) -> dict[str, tuple[str, str | None]]:
        """Return ``{exported_name: (defining_module, defining_symbol)}`` for *module_name*."""
        table = self.modules.get(module_name)
        if table is None:
            return {}

        names: set[str] = set(table.public_names())
        if table.explicit_all is None:
            seen_stars: set[str] = {module_name}
            stack = list(table.star_imports)
            while stack:
                star_mod = stack.pop()
                if star_mod in seen_stars:
                    continue
                seen_stars.add(star_mod)
                star_table = self.modules.get(star_mod)
                if star_table is None:
                    continue
                names.update(star_table.public_names())
                if star_table.explicit_all is None:
                    stack.extend(star_table.star_imports)

        resolved: dict[str, tuple[str, str | None]] = {}
        for name in sorted(names):
            target = self.resolve_reexport(module_name, name)
            if target is not None:
                resolved[name] = target
        return resolved

    def dependency_fingerprint(
        self,
        module_name: str,
        content_hashes: Mapping[str, str] | None = None,
    ) -> str:
        """Return a stable Merkle digest over *module_name* and its transitive dependencies."""
        hashes = content_hashes or {
            name: table.content_hash for name, table in self.modules.items()
        }
        closure = sorted(self.transitive_dependencies(module_name) | {module_name})
        hasher = hashlib.blake2b(digest_size=16)
        hasher.update(self.environment.fingerprint().encode("utf-8"))
        for mod in closure:
            hasher.update(b"\0")
            hasher.update(mod.encode("utf-8"))
            hasher.update(b"=")
            hasher.update(hashes.get(mod, "").encode("utf-8"))
        return hasher.hexdigest()


__all__ = [
    "ExportBinding",
    "ImportEdge",
    "MODULE_EXPORT_SCHEMA_VERSION",
    "ModuleExportTable",
    "ModuleGraph",
    "extract_module_export_table",
    "resolve_relative_module",
]
