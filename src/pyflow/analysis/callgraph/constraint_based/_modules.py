"""Module discovery, import resolution, and import binding."""

from __future__ import annotations

import ast
import os
from collections import deque
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
        common = os.path.commonpath(
            [os.path.abspath(path), os.path.abspath(stdlib_dir)]
        )
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

    def _load_modules(self) -> None:
        """
        BFS-load import-reachable modules rooted at the entry module.

        Parsing/IO failures are treated conservatively by skipping the module
        (analysis continues with whatever symbols were available).
        """
        main_tree = ast.parse(normalize_legacy_python_syntax(self.source_code))
        self.modules["main"] = ModuleInfo("main", main_tree, self.entry_path)

        if not self.entry_path:
            return

        entry_path = os.path.realpath(self.entry_path)
        for source_path, source in sorted(self.additional_sources.items()):
            normalized_path = os.path.realpath(source_path)
            if normalized_path == entry_path:
                continue
            module_name = self.project_context.module_name_from_path(normalized_path)
            if module_name in self.modules:
                continue
            try:
                tree = ast.parse(normalize_legacy_python_syntax(source))
            except SyntaxError:
                continue
            self.modules[module_name] = ModuleInfo(
                module_name, tree, normalized_path
            )

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
                if imported in self.modules:
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
                if self.options.skip_stdlib_modules and _is_stdlib_path(
                    str(imported_path)
                ):
                    continue
                if self.options.skip_external_modules and not _is_within_path(
                    str(imported_path), self.project_root
                ):
                    continue
                try:
                    with open(
                        imported_path,
                        "r",
                        encoding="utf-8",
                        errors="replace",
                    ) as handle:
                        src = handle.read()
                except OSError:
                    continue
                try:
                    tree = ast.parse(normalize_legacy_python_syntax(src))
                except SyntaxError:
                    continue

                self.modules[imported] = ModuleInfo(imported, tree, imported_path)
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
        return self.project_context.resolve_import_name(
            current_module,
            imported_module,
            level,
            current_path=current_path,
        )

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
                    out.update(
                        self.class_fields.get(base_value.name, {}).get(expr.attr, set())
                    )
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
            child = ".".join(parts[: idx + 1])
            attr = parts[idx]
            parent_bindings = self.module_bindings.setdefault(parent, {})
            self._merge_value_set(
                parent_bindings.setdefault(attr, set()),
                {make_module(child)},
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
            imported_value = make_module(root_name)
        else:
            imported_value = make_module(imported_name)
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
        source_module = self._resolve_import_module_name(
            module_name, stmt.module, stmt.level
        )
        if not source_module:
            return

        source_exports = self.module_bindings.get(source_module, {})
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
                if candidate_module in self.modules or self._resolve_module_file(
                    candidate_module
                ):
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
                else:
                    self._merge_value_set(
                        env.setdefault(local_name, set()),
                        {make_func(f"{source_module}.{alias.name}")},
                        preserve_callables=True,
                    )

    def _merge_bindings(
        self,
        target: Dict[str, Set[AbstractValue]],
        source: Mapping[str, Set[AbstractValue]],
    ) -> bool:
        changed = False
        for name, values in source.items():
            current = target.setdefault(name, set())
            changed = (
                self._merge_value_set(current, set(values), preserve_callables=True)
                or changed
            )
        return changed
