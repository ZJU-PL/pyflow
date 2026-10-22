"""Module discovery, import resolution, and import binding."""

from __future__ import annotations

import ast
import os
import tokenize
from collections import defaultdict, deque
from typing import Dict, Iterable, Mapping, Optional, Set

from pyflow.language.source_compat import normalize_legacy_python_syntax

from .model import (
    AbstractValue,
    CLASS_KIND,
    MODULE_KIND,
    ModuleInfo,
    make_class,
    make_func,
    make_module,
)


def _is_stdlib_path(path: str) -> bool:
    """Check whether *path* lives inside the Python standard library."""
    stdlib_dir = os.path.dirname(os.__file__)
    try:
        common = os.path.commonpath([os.path.abspath(path), os.path.abspath(stdlib_dir)])
    except ValueError:
        return False
    return common == stdlib_dir


def _is_within_path(path: str, root: str) -> bool:
    """Return whether *path* is located within *root*."""
    try:
        return os.path.commonpath(
            [os.path.realpath(path), os.path.realpath(root)]
        ) == os.path.realpath(root)
    except ValueError:
        return False


class _ModuleAnalysisMixin:
    """Load modules and model import bindings."""

    def _parse_module_source(self, source: str, path: Optional[str]) -> ast.Module:
        """Reuse the AST inspected for import-root discovery during loading."""
        key = os.path.realpath(path) if path else "<string>"
        if key not in self._source_trees:
            try:
                self._source_trees[key] = ast.parse(
                    normalize_legacy_python_syntax(source), filename=key
                )
            except SyntaxError as exc:
                # Do not retain discovery/loading frames in cached tracebacks.
                self._source_trees[key] = type(exc)(*exc.args)
        tree = self._source_trees[key]
        if isinstance(tree, SyntaxError):
            raise type(tree)(*tree.args)
        return tree

    def _discover_source_roots(self, import_root: str) -> tuple[str, ...]:
        """Infer shared search/identity roots from project-local import evidence.

        Matching ``mypkg.mod`` against ``libs/core/mypkg/mod.py`` establishes
        ``libs/core`` as a root regardless of the container directory names.
        Do not cut inside a regular package or guess between duplicate packages.
        """
        root = os.path.realpath(import_root)
        sources = {
            os.path.realpath(path): source for path, source in self.additional_sources.items()
        }
        if self.entry_path:
            sources[os.path.realpath(self.entry_path)] = self.source_code
        imports = defaultdict(set)
        module_paths = []
        roots = set()
        visited = {root}
        package_dirs = {}

        def is_package(directory):
            if directory not in package_dirs:
                package_dirs[directory] = any(
                    os.path.join(directory, name) in sources
                    or os.path.isfile(os.path.join(directory, name))
                    for name in ("__init__.py", "__init__.pyi")
                )
            return package_dirs[directory]

        for path, source in sources.items():
            if not _is_within_path(path, root):
                continue
            parts = os.path.relpath(path, root).split(os.sep)
            parts[-1] = os.path.splitext(parts[-1])[0]
            if parts[-1] == "__init__":
                parts.pop()
            module_paths.append(parts)
            parent = os.path.dirname(path)
            while parent not in visited and _is_within_path(parent, root):
                visited.add(parent)
                component = os.path.basename(parent)
                if (not component.isidentifier() or component == "src") and not is_package(parent):
                    roots.add(parent)
                    break
                parent = os.path.dirname(parent)
            try:
                tree = self._parse_module_source(source, path)
            except SyntaxError:
                continue  # The loader reports syntax diagnostics.
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    imported = tuple(name.split("."))
                    imports[imported[0]].add(imported)

        candidates = defaultdict(set)
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

    def _distinct_source_module_names(self, import_root: str) -> Dict[str, str]:
        """Keep colliding companion namespaces (e.g. scripts/) project-qualified.

        Two components can each have scripts/check_imports.py. Adding both
        components as import roots must not silently discard one of those files.
        """
        paths = {os.path.realpath(path) for path in self.additional_sources}
        if self.entry_path:
            paths.add(os.path.realpath(self.entry_path))
        names = {path: self.project_context.module_name_from_path(path) for path in sorted(paths)}
        by_name = defaultdict(list)
        for path, name in names.items():
            by_name[name].append(path)
        conflicting_heads = {
            name.split(".")[0] for name, files in by_name.items() if len(files) > 1
        }
        overrides = {}
        for path, name in names.items():
            if name.split(".")[0] not in conflicting_heads or not _is_within_path(
                path, import_root
            ):
                continue
            parts = os.path.relpath(path, os.path.realpath(import_root)).split(os.sep)
            parts[-1] = os.path.splitext(parts[-1])[0]
            if parts[-1] == "__init__":
                parts.pop()
            overrides[path] = ".".join(parts)
        return overrides

    def _load_modules(self) -> None:
        """
        BFS-load import-reachable modules rooted at the entry module.

        Parsing/IO failures are treated conservatively by skipping the module
        (analysis continues with whatever symbols were available).
        """
        main_tree = self._parse_module_source(self.source_code, self.entry_path)
        entry_name = self.entry_module_name
        self.modules[entry_name] = ModuleInfo(entry_name, main_tree, self.entry_path)

        if not self.entry_path:
            return

        entry_path = os.path.realpath(self.entry_path)
        modules_by_path = {entry_path: entry_name}
        for source_path, source in sorted(self.additional_sources.items()):
            normalized_path = os.path.realpath(source_path)
            if normalized_path in modules_by_path:
                continue
            module_name = self.project_context.module_name_from_path(normalized_path)
            if module_name in self.modules:
                continue
            try:
                tree = self._parse_module_source(source, normalized_path)
            except SyntaxError as exc:
                self.diagnostics.append(f"Skipped {normalized_path}: {exc}")
                continue
            self.modules[module_name] = ModuleInfo(module_name, tree, normalized_path)
            modules_by_path[normalized_path] = module_name

        queue: deque[str] = deque(self.modules)
        visited: Set[str] = set()

        while queue:
            module_name = queue.popleft()
            if module_name in visited:
                continue
            visited.add(module_name)

            module_info = self.modules.get(module_name)
            if not module_info:
                continue

            for imported in self._iter_imported_modules(module_info):
                if imported in self.modules or imported in self.module_aliases:
                    continue
                resolution = self.project_context.find_module(
                    imported,
                    script_path=module_info.path,
                )
                if resolution is None or resolution.path is None:
                    imported_path = self.stub_resolver.resolve_path(
                        imported,
                        script_path=module_info.path,
                    )
                    if imported_path is None:
                        continue
                else:
                    imported_path = resolution.path
                    if not str(imported_path).endswith(".pyi"):
                        stub_path = self.stub_resolver.resolve_path(
                            imported,
                            script_path=module_info.path,
                        )
                        if stub_path is not None:
                            imported_path = stub_path
                if self.options.skip_stdlib_modules and _is_stdlib_path(str(imported_path)):
                    continue
                if self.options.skip_external_modules and not _is_within_path(
                    str(imported_path), self.project_root
                ):
                    continue
                normalized_path = os.path.realpath(imported_path)
                if normalized_path in modules_by_path:
                    self.module_aliases[imported] = modules_by_path[normalized_path]
                    continue
                try:
                    with tokenize.open(imported_path) as handle:
                        src = handle.read()
                except (OSError, UnicodeError, SyntaxError) as exc:
                    self.diagnostics.append(f"Skipped {normalized_path}: {exc}")
                    continue
                try:
                    tree = self._parse_module_source(src, normalized_path)
                except SyntaxError as exc:
                    self.diagnostics.append(f"Skipped {normalized_path}: {exc}")
                    continue

                self.modules[imported] = ModuleInfo(imported, tree, imported_path)
                modules_by_path[normalized_path] = imported
                queue.append(imported)

    def _iter_imported_modules(self, module_info: ModuleInfo) -> Iterable[str]:
        """Yield imported module names referenced anywhere in the module AST."""
        yield from self.project_context.iter_imported_modules(
            module_info.tree,
            current_module=module_info.name,
            current_path=module_info.path,
        )

    def _resolve_import_module_name(
        self, current_module: str, imported_module: Optional[str], level: int
    ) -> Optional[str]:
        """
        Resolve relative import targets to absolute module names when possible.

        The logic mirrors Python package semantics approximately and intentionally
        falls back conservatively when package/module boundaries are ambiguous.
        """
        module_info = self.modules.get(current_module)
        current_path = module_info.path if module_info else None
        resolved = self.project_context.resolve_import_name(
            current_module,
            imported_module,
            level,
            current_path=current_path,
        )
        return self.module_aliases.get(resolved, resolved)

    def _resolve_module_file(self, module_name: str) -> Optional[str]:
        """Map module name to a `.py` or package `__init__.py` under project root."""
        if not module_name:
            return None

        stub_path = self.stub_resolver.resolve_path(module_name)
        if stub_path is not None:
            return stub_path

        resolution = self.project_context.find_module(module_name)
        if resolution is None:
            return None
        return resolution.path

    def _eval_expr_static(
        self, expr: ast.expr, env: Mapping[str, Set[AbstractValue]]
    ) -> Set[AbstractValue]:
        if isinstance(expr, ast.Name):
            return set(env.get(expr.id, set()))
        if isinstance(expr, ast.Attribute):
            base_values = self._eval_expr_static(expr.value, env)
            out: Set[AbstractValue] = set()
            for base_value in base_values:
                if base_value.kind == MODULE_KIND:
                    module_bindings = self.module_bindings.get(base_value.name, {})
                    out.update(module_bindings.get(expr.attr, set()))
                    nested_module = f"{base_value.name}.{expr.attr}"
                    if nested_module in self.modules:
                        out.add(make_module(nested_module))
                elif base_value.kind == CLASS_KIND:
                    out.update(self.class_fields.get(base_value.name, {}).get(expr.attr, set()))
                    nested_class = f"{base_value.name}.{expr.attr}"
                    if nested_class in self.classes:
                        out.add(make_class(nested_class))
            return out
        return set()

    def _register_imported_module_chain(self, module_name: str) -> None:
        if not module_name:
            return
        self.module_bindings.setdefault(module_name, {})
        parts = module_name.split(".")
        for idx in range(1, len(parts)):
            parent = ".".join(parts[:idx])
            parent = self.module_aliases.get(parent, parent)
            child = ".".join(parts[: idx + 1])
            attr = parts[idx]
            parent_bindings = self.module_bindings.setdefault(parent, {})
            self._merge_value_set(
                parent_bindings.setdefault(attr, set()),
                {make_module(self.module_aliases.get(child, child))},
            )

    def _bind_import_alias(
        self,
        imported_name: str,
        local_name: str,
        env: Dict[str, Set[AbstractValue]],
        explicit_alias: bool = False,
    ) -> None:
        if not imported_name:
            return
        root_name = imported_name.split(".")[0]
        if not explicit_alias and "." in imported_name and local_name == root_name:
            imported_value = make_module(self.module_aliases.get(root_name, root_name))
        else:
            imported_value = make_module(self.module_aliases.get(imported_name, imported_name))
        self._merge_value_set(
            env.setdefault(local_name, set()),
            {imported_value},
            preserve_callables=True,
        )
        self._register_imported_module_chain(imported_name)

    def _bind_import(
        self, stmt: ast.Import, module_name: str, env: Dict[str, Set[AbstractValue]]
    ) -> None:
        for alias in stmt.names:
            imported_name = alias.name
            as_name = alias.asname or imported_name.split(".")[0]
            self._bind_import_alias(
                imported_name,
                as_name,
                env,
                explicit_alias=alias.asname is not None,
            )

    def _bind_import_from(
        self, stmt: ast.ImportFrom, module_name: str, env: Dict[str, Set[AbstractValue]]
    ) -> None:
        source_module = self._resolve_import_module_name(module_name, stmt.module, stmt.level)
        if not source_module:
            return

        source_exports = self.module_bindings.get(source_module, {})
        self._register_module_dependency(source_module)
        for alias in stmt.names:
            if alias.name == "*":
                for exported_name, exported_values in source_exports.items():
                    self._merge_value_set(
                        env.setdefault(exported_name, set()),
                        set(exported_values),
                        preserve_callables=True,
                    )
                continue

            local_name = alias.asname or alias.name
            if alias.name in source_exports:
                self._merge_value_set(
                    env.setdefault(local_name, set()),
                    set(source_exports[alias.name]),
                    preserve_callables=True,
                )
            else:
                candidate_module = f"{source_module}.{alias.name}"
                candidate_module = self.module_aliases.get(candidate_module, candidate_module)
                if candidate_module in self.modules or self._resolve_module_file(candidate_module):
                    self._merge_value_set(
                        env.setdefault(local_name, set()),
                        {make_module(candidate_module)},
                        preserve_callables=True,
                    )
                    self._register_imported_module_chain(candidate_module)
                    self._merge_value_set(
                        self.module_bindings.setdefault(source_module, {}).setdefault(
                            alias.name, set()
                        ),
                        {make_module(candidate_module)},
                    )
                elif source_module not in self.modules:
                    self._merge_value_set(
                        env.setdefault(local_name, set()),
                        {make_func(f"{source_module}.{alias.name}")},
                        preserve_callables=True,
                    )
                else:
                    # A loaded module's export may still be propagating (or
                    # require executing its assignments). Do not invent an
                    # external callable at the re-exporting package's name.
                    env.setdefault(local_name, set())

    def _merge_bindings(
        self,
        target: Dict[str, Set[AbstractValue]],
        source: Mapping[str, Set[AbstractValue]],
    ) -> bool:
        changed = False
        for name, values in source.items():
            current = target.setdefault(name, set())
            changed = (
                self._merge_value_set(current, set(values), preserve_callables=True) or changed
            )
        return changed
