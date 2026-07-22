"""Module loading and import resolution for constraint-based call graph analysis."""

from __future__ import annotations

import ast
import os
import sys
from collections import deque
from typing import Iterable, Optional, Set

from .model import ModuleInfo


def _is_stdlib_path(path: str) -> bool:
    """Check whether *path* lives inside the Python standard library."""
    stdlib_dir = os.path.dirname(os.__file__)
    try:
        common = os.path.commonpath([os.path.abspath(path), os.path.abspath(stdlib_dir)])
    except ValueError:
        return False
    return common == stdlib_dir


class _LoaderMixin:
    """Handles loading Python source modules and resolving import paths."""

    def _load_modules(self) -> None:
        """
        BFS-load import-reachable modules rooted at the entry module.

        Parsing/IO failures are treated conservatively by skipping the module
        (analysis continues with whatever symbols were available).
        """
        main_tree = ast.parse(self.source_code)
        self.modules["main"] = ModuleInfo("main", main_tree, self.entry_path)

        if not self.entry_path:
            return

        queue: deque[str] = deque(["main"])
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
                if (
                    self.options.skip_stdlib_modules
                    and _is_stdlib_path(str(imported_path))
                ):
                    continue
                try:
                    with open(imported_path, "r", encoding="utf-8") as handle:
                        src = handle.read()
                except OSError:
                    continue
                try:
                    tree = ast.parse(src)
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
