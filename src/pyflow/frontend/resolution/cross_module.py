"""Cross-module name resolution built on the class hierarchy."""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from .hierarchy import ClassHierarchy, ClassInfo


class CrossModuleResolver:
    """Resolve class and function references across registered modules."""

    def __init__(
        self,
        hierarchy: Optional[ClassHierarchy] = None,
        verbose: bool = False,
    ):
        self.hierarchy = hierarchy or ClassHierarchy(verbose=verbose)
        self.modules: Dict[str, Dict] = {}
        self.imports: Dict[str, Dict[str, str]] = {}
        self.verbose = verbose

    def register_module(
        self,
        module_name: str,
        classes: Optional[Dict[str, ClassInfo]] = None,
        functions: Optional[Dict[str, object]] = None,
        imports: Optional[Dict[str, str]] = None,
    ) -> None:
        self.modules[module_name] = {
            "classes": classes or {},
            "functions": functions or {},
        }
        if imports:
            self.imports[module_name] = imports
        if classes:
            for class_info in classes.values():
                self.hierarchy.register_class(
                    name=class_info.name,
                    bases=class_info.bases,
                    module=module_name,
                    methods=class_info.methods,
                    attributes=class_info.attributes,
                    ast_node=class_info.ast_node,
                    code=class_info.code,
                )

    def resolve_name(
        self,
        name: str,
        from_module: str,
    ) -> Optional[Tuple[str, str]]:
        module_imports = self.imports.get(from_module, {})
        if name in module_imports:
            qualified = module_imports[name]
            if qualified in self.hierarchy.classes:
                return qualified, "class"
            return qualified, "function"

        qualified = f"{from_module}.{name}"
        if qualified in self.hierarchy.classes:
            return qualified, "class"
        if from_module in self.modules:
            if name in self.modules[from_module].get("functions", {}):
                return qualified, "function"

        builtin_qualified = f"builtins.{name}"
        if builtin_qualified in self.hierarchy.classes:
            return builtin_qualified, "class"
        return None

    def get_class_code(self, qualified_name: str) -> Optional[object]:
        class_info = self.hierarchy.get_class_info(qualified_name)
        return class_info.code if class_info else None

    def get_method_code(
        self,
        qualified_name: str,
        method_name: str,
    ) -> Optional[object]:
        defining_class = self.hierarchy.resolve_method(qualified_name, method_name)
        if defining_class:
            class_info = self.hierarchy.get_class_info(defining_class)
            if class_info and class_info.code:
                return class_info.code
        return None


__all__ = ["CrossModuleResolver"]
