"""Module loading and import resolution for constraint-based call graph analysis."""

from __future__ import annotations

import ast
import os
from collections import deque
from typing import Iterable, Optional, Set

from .model import make_module, ModuleInfo


class _LoaderMixin:
    """Handles loading Python source modules and resolving import paths."""

    def _load_modules(self) -> None:
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
                imported_path = self._resolve_module_file(imported)
                if not imported_path:
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
        for node in ast.walk(module_info.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield alias.name
            elif isinstance(node, ast.ImportFrom):
                resolved = self._resolve_import_module_name(
                    module_info.name, node.module, node.level
                )
                if resolved:
                    yield resolved

    def _resolve_import_module_name(
        self, current_module: str, imported_module: Optional[str], level: int
    ) -> Optional[str]:
        if level <= 0:
            return imported_module

        package_parts = current_module.split(".")
        if package_parts and package_parts[-1] == "__init__":
            package_parts = package_parts[:-1]
            is_package_module = True
        else:
            module_info = self.modules.get(current_module)
            is_package_module = bool(
                module_info
                and module_info.path
                and os.path.basename(module_info.path) == "__init__.py"
            )
            if not is_package_module and "." not in current_module and current_module != "main":
                # Without a loaded module path we cannot always distinguish
                # package modules from top-level .py modules.
                # Prefer package anchoring for non-entry single-segment names.
                is_package_module = True
        if package_parts and not is_package_module:
            package_parts = package_parts[:-1]

        ascents = level - 1
        if ascents > len(package_parts):
            return imported_module
        prefix = ".".join(package_parts[: len(package_parts) - ascents])

        if imported_module:
            return f"{prefix}.{imported_module}" if prefix else imported_module
        return prefix or imported_module

    def _resolve_module_file(self, module_name: str) -> Optional[str]:
        if not module_name:
            return None

        relative_path = module_name.replace(".", os.sep)
        direct = os.path.join(self.project_root, f"{relative_path}.py")
        init_path = os.path.join(self.project_root, relative_path, "__init__.py")

        if os.path.isfile(direct):
            return os.path.abspath(direct)
        if os.path.isfile(init_path):
            return os.path.abspath(init_path)
        return None
