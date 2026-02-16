"""
Class Hierarchy and MRO Resolution for Cross-Module Analysis.

This module provides class hierarchy tracking and Method Resolution Order (MRO)
computation for Python static analysis, enabling cross-module inheritance resolution.

Key Features:
- C3 Linearization: Standard Python MRO algorithm
- Cross-module class registration and lookup
- Method resolution along inheritance hierarchy
- Support for built-in types as base classes

Usage:
    hierarchy = ClassHierarchy()
    
    # Register classes from multiple modules
    hierarchy.register_class("MyClass", bases=["BaseClass"], module="mymodule")
    hierarchy.register_class("BaseClass", bases=["object"], module="basemodule")
    
    # Resolve MRO
    mro = hierarchy.get_mro("MyClass")  # ["MyClass", "BaseClass", "object"]
    
    # Resolve method
    defining_class = hierarchy.resolve_method("MyClass", "some_method")
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import deque


@dataclass
class ClassInfo:
    """Information about a registered class.
    
    Attributes:
        name: Simple class name (e.g., "MyClass")
        qualified_name: Fully qualified name (e.g., "mymodule.MyClass")
        module: Module where the class is defined
        bases: List of base class names (as they appear in source)
        resolved_bases: List of resolved base class qualified names
        methods: Set of method names defined in this class
        attributes: Set of class attribute names
        ast_node: Reference to the AST node (if available)
        code: Reference to PyFlow Code object (if converted)
    """
    name: str
    qualified_name: str
    module: str
    bases: List[str] = field(default_factory=list)
    resolved_bases: List[str] = field(default_factory=list)
    methods: Set[str] = field(default_factory=set)
    attributes: Set[str] = field(default_factory=set)
    ast_node: Optional[object] = None
    code: Optional[object] = None


class MROError(Exception):
    """Raised when MRO cannot be computed (e.g., inconsistent hierarchy)."""
    pass


class ClassHierarchy:
    """Manages class hierarchy and MRO resolution for cross-module analysis.
    
    This class tracks class definitions across multiple modules and provides
    method resolution order (MRO) computation using Python's C3 linearization
    algorithm.
    
    Attributes:
        classes: Dictionary mapping qualified names to ClassInfo
        name_to_qualified: Mapping from simple names to qualified names (per module)
        builtin_types: Set of built-in type names
        _mro_cache: Cache of computed MROs
        
    Example:
        >>> hierarchy = ClassHierarchy()
        >>> hierarchy.register_class("A", [], "mod1", methods={"foo"})
        >>> hierarchy.register_class("B", ["A"], "mod2", methods={"bar"})
        >>> hierarchy.get_mro("mod2.B")
        ['mod2.B', 'mod1.A', 'object']
    """
    
    BUILTIN_TYPES = {
        "object", "type", "int", "float", "str", "bool", "list", "dict",
        "set", "tuple", "frozenset", "bytes", "bytearray", "complex",
        "NoneType", "ellipsis", "range", "slice", "Exception", "BaseException",
    }
    
    def __init__(self, verbose: bool = False):
        self.classes: Dict[str, ClassInfo] = {}
        self.name_to_qualified: Dict[str, Dict[str, str]] = {}  # module -> {name -> qualified}
        self._mro_cache: Dict[str, List[str]] = {}
        self._method_cache: Dict[Tuple[str, str], Optional[str]] = {}
        self.verbose = verbose
        
        self._register_builtins()
    
    def _register_builtins(self):
        """Register built-in types with their standard MRO."""
        for builtin in self.BUILTIN_TYPES:
            qualified = f"builtins.{builtin}"
            self.classes[qualified] = ClassInfo(
                name=builtin,
                qualified_name=qualified,
                module="builtins",
                bases=["object"] if builtin != "object" else [],
                resolved_bases=["builtins.object"] if builtin != "object" else [],
                methods=set(),
                attributes=set(),
            )
        
        self.classes["builtins.object"] = ClassInfo(
            name="object",
            qualified_name="builtins.object",
            module="builtins",
            bases=[],
            resolved_bases=[],
            methods={"__init__", "__repr__", "__str__", "__eq__", "__hash__"},
            attributes=set(),
        )
    
    def register_class(
        self,
        name: str,
        bases: List[str],
        module: str,
        methods: Optional[Set[str]] = None,
        attributes: Optional[Set[str]] = None,
        ast_node: Optional[object] = None,
        code: Optional[object] = None,
    ) -> str:
        """Register a class definition.
        
        Args:
            name: Class name
            bases: List of base class names (as they appear in source)
            module: Module where the class is defined
            methods: Set of method names defined in this class
            attributes: Set of class attribute names
            ast_node: Reference to the AST node
            code: Reference to PyFlow Code object
            
        Returns:
            The qualified name of the registered class
        """
        qualified_name = f"{module}.{name}"
        
        if qualified_name in self.classes:
            if self.verbose:
                print(f"DEBUG: Updating existing class {qualified_name}")
            existing = self.classes[qualified_name]
            existing.bases = bases
            if methods:
                existing.methods.update(methods)
            if attributes:
                existing.attributes.update(attributes)
            existing.ast_node = ast_node
            existing.code = code
        else:
            self.classes[qualified_name] = ClassInfo(
                name=name,
                qualified_name=qualified_name,
                module=module,
                bases=bases,
                methods=methods or set(),
                attributes=attributes or set(),
                ast_node=ast_node,
                code=code,
            )
        
        if module not in self.name_to_qualified:
            self.name_to_qualified[module] = {}
        self.name_to_qualified[module][name] = qualified_name
        
        self._invalidate_cache(qualified_name)
        
        return qualified_name
    
    def resolve_base_class(
        self,
        base_name: str,
        current_module: str,
        imported_names: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """Resolve a base class name to its qualified name.
        
        Args:
            base_name: The base class name as it appears in the source
            current_module: The module where the reference occurs
            imported_names: Mapping of imported names to their qualified names
            
        Returns:
            The qualified name of the base class, or None if not found
        """
        if imported_names and base_name in imported_names:
            return imported_names[base_name]
        
        if "." in base_name:
            if base_name in self.classes:
                return base_name
            return None
        
        if current_module in self.name_to_qualified:
            if base_name in self.name_to_qualified[current_module]:
                return self.name_to_qualified[current_module][base_name]
        
        builtin_qualified = f"builtins.{base_name}"
        if builtin_qualified in self.classes:
            return builtin_qualified
        
        for mod_name, name_map in self.name_to_qualified.items():
            if base_name in name_map:
                return name_map[base_name]
        
        return None
    
    def resolve_bases(
        self,
        bases: List[str],
        module: str,
        imported_names: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Resolve all base classes to their qualified names.
        
        Args:
            bases: List of base class names
            module: Current module
            imported_names: Mapping of imported names
            
        Returns:
            List of resolved qualified names
        """
        resolved = []
        for base in bases:
            resolved_name = self.resolve_base_class(base, module, imported_names)
            if resolved_name:
                resolved.append(resolved_name)
            elif self.verbose:
                print(f"DEBUG: Could not resolve base class '{base}' in module '{module}'")
        return resolved
    
    def _invalidate_cache(self, qualified_name: str):
        """Invalidate MRO cache for a class and its subclasses."""
        to_remove = [qualified_name]
        
        for qname in list(self._mro_cache.keys()):
            if qualified_name in self._mro_cache.get(qname, []):
                to_remove.append(qname)
        
        for qname in to_remove:
            self._mro_cache.pop(qname, None)
            
            for (cls, method), _ in list(self._method_cache.items()):
                if cls == qname:
                    del self._method_cache[(cls, method)]
    
    def get_class_info(self, qualified_name: str) -> Optional[ClassInfo]:
        """Get class information by qualified name."""
        return self.classes.get(qualified_name)
    
    def get_mro(self, qualified_name: str) -> List[str]:
        """Compute the Method Resolution Order (MRO) for a class.
        
        Uses C3 linearization algorithm, the same algorithm used by Python.
        
        Args:
            qualified_name: The qualified name of the class
            
        Returns:
            List of qualified class names in MRO order
            
        Raises:
            MROError: If the hierarchy is inconsistent
        """
        if qualified_name in self._mro_cache:
            return list(self._mro_cache[qualified_name])
        
        if qualified_name not in self.classes:
            return [qualified_name]
        
        visited = set()
        return self._compute_mro(qualified_name, visited)
    
    def _compute_mro(self, qualified_name: str, visited: Set[str]) -> List[str]:
        """Recursively compute MRO using C3 linearization."""
        if qualified_name in visited:
            raise MROError(f"Cyclic inheritance detected involving {qualified_name}")
        
        visited.add(qualified_name)
        
        if qualified_name in self._mro_cache:
            visited.remove(qualified_name)
            return list(self._mro_cache[qualified_name])
        
        cls_info = self.classes.get(qualified_name)
        if cls_info is None:
            result = [qualified_name]
            self._mro_cache[qualified_name] = result
            visited.remove(qualified_name)
            return result
        
        if not cls_info.resolved_bases:
            result = [qualified_name, "builtins.object"]
            self._mro_cache[qualified_name] = result
            visited.remove(qualified_name)
            return result
        
        base_mros = []
        for base in cls_info.resolved_bases:
            base_mro = self._compute_mro(base, visited.copy())
            base_mros.append(base_mro)
        
        base_mros.append([b for b in cls_info.resolved_bases])
        
        result = self._c3_merge(qualified_name, base_mros)
        
        self._mro_cache[qualified_name] = result
        visited.remove(qualified_name)
        return result
    
    def _c3_merge(self, class_name: str, mro_lists: List[List[str]]) -> List[str]:
        """Perform C3 merge of MRO lists.
        
        The C3 algorithm:
        1. Take the head of the first list
        2. If the head is not in the tail of any other list, add it to the result
        3. Remove the head from all lists and repeat
        4. If no valid head is found, the hierarchy is inconsistent
        """
        result = [class_name]
        lists = [list(lst) for lst in mro_lists]
        
        while True:
            non_empty = [lst for lst in lists if lst]
            if not non_empty:
                break
            
            candidate = None
            for lst in non_empty:
                head = lst[0]
                
                is_in_tail = any(
                    head in tail_lst[1:]
                    for tail_lst in non_empty
                    if len(tail_lst) > 1
                )
                
                if not is_in_tail:
                    candidate = head
                    break
            
            if candidate is None:
                raise MROError(
                    f"Cannot create consistent MRO for {class_name}. "
                    f"Inconsistent hierarchy with bases: {lists}"
                )
            
            result.append(candidate)
            
            for lst in lists:
                if lst and lst[0] == candidate:
                    lst.pop(0)
        
        if result[-1] != "builtins.object" and "builtins.object" not in result:
            result.append("builtins.object")
        
        return result
    
    def resolve_method(self, qualified_name: str, method_name: str) -> Optional[str]:
        """Resolve which class in the hierarchy defines a method.
        
        Args:
            qualified_name: The class to start resolution from
            method_name: The method name to resolve
            
        Returns:
            The qualified name of the class that defines the method, or None
        """
        cache_key = (qualified_name, method_name)
        if cache_key in self._method_cache:
            return self._method_cache[cache_key]
        
        mro = self.get_mro(qualified_name)
        
        for cls_name in mro:
            cls_info = self.classes.get(cls_name)
            if cls_info and method_name in cls_info.methods:
                self._method_cache[cache_key] = cls_name
                return cls_name
        
        self._method_cache[cache_key] = None
        return None
    
    def resolve_attribute(self, qualified_name: str, attr_name: str) -> Optional[str]:
        """Resolve which class in the hierarchy defines an attribute.
        
        Args:
            qualified_name: The class to start resolution from
            attr_name: The attribute name to resolve
            
        Returns:
            The qualified name of the class that defines the attribute, or None
        """
        mro = self.get_mro(qualified_name)
        
        for cls_name in mro:
            cls_info = self.classes.get(cls_name)
            if cls_info and attr_name in cls_info.attributes:
                return cls_name
            
        for cls_name in mro:
            cls_info = self.classes.get(cls_name)
            if cls_info and attr_name in cls_info.methods:
                return cls_name
        
        return None
    
    def get_all_subclasses(self, qualified_name: str) -> Set[str]:
        """Get all subclasses of a class (transitive closure).
        
        Args:
            qualified_name: The class to find subclasses for
            
        Returns:
            Set of qualified names of all subclasses
        """
        subclasses = set()
        
        for cls_qname, cls_info in self.classes.items():
            if qualified_name in cls_info.resolved_bases:
                subclasses.add(cls_qname)
                subclasses.update(self.get_all_subclasses(cls_qname))
        
        return subclasses
    
    def get_direct_subclasses(self, qualified_name: str) -> Set[str]:
        """Get direct subclasses of a class.
        
        Args:
            qualified_name: The class to find direct subclasses for
            
        Returns:
            Set of qualified names of direct subclasses
        """
        subclasses = set()
        
        for cls_qname, cls_info in self.classes.items():
            if qualified_name in cls_info.resolved_bases:
                subclasses.add(cls_qname)
        
        return subclasses
    
    def get_all_methods(self, qualified_name: str) -> Dict[str, str]:
        """Get all methods available on a class, with their defining class.
        
        Args:
            qualified_name: The class to get methods for
            
        Returns:
            Dict mapping method names to the class that defines them
        """
        methods = {}
        mro = self.get_mro(qualified_name)
        
        for cls_name in reversed(mro):
            cls_info = self.classes.get(cls_name)
            if cls_info:
                for method in cls_info.methods:
                    methods[method] = cls_name
        
        return methods
    
    def is_subclass(self, child: str, parent: str) -> bool:
        """Check if one class is a subclass of another.
        
        Args:
            child: Potential subclass qualified name
            parent: Potential parent class qualified name
            
        Returns:
            True if child is a subclass of parent
        """
        mro = self.get_mro(child)
        return parent in mro
    
    def common_ancestor(self, *classes: str) -> Optional[str]:
        """Find the most derived common ancestor of multiple classes.
        
        Args:
            classes: Class qualified names
            
        Returns:
            Qualified name of the most derived common ancestor, or None
        """
        if not classes:
            return None
        
        mros = [set(self.get_mro(cls)) for cls in classes]
        
        common = mros[0].intersection(*mros[1:]) if len(mros) > 1 else mros[0]
        
        if not common:
            return None
        
        first_mro = self.get_mro(classes[0])
        for cls in first_mro:
            if cls in common:
                return cls
        
        return None


class CrossModuleResolver:
    """Resolves class and function references across multiple modules.
    
    This class coordinates with the ClassHierarchy to resolve imports
    and provide cross-module class lookup.
    
    Attributes:
        hierarchy: The ClassHierarchy instance
        modules: Dict mapping module names to module info
        imports: Dict mapping module names to their import mappings
    """
    
    def __init__(self, hierarchy: Optional[ClassHierarchy] = None, verbose: bool = False):
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
    ):
        """Register a module with its classes, functions, and imports.
        
        Args:
            module_name: Name of the module
            classes: Dict mapping class names to ClassInfo
            functions: Dict mapping function names to function objects
            imports: Dict mapping imported names to their qualified names
        """
        self.modules[module_name] = {
            "classes": classes or {},
            "functions": functions or {},
        }
        
        if imports:
            self.imports[module_name] = imports
        
        if classes:
            for cls_name, cls_info in classes.items():
                self.hierarchy.register_class(
                    name=cls_info.name,
                    bases=cls_info.bases,
                    module=module_name,
                    methods=cls_info.methods,
                    attributes=cls_info.attributes,
                    ast_node=cls_info.ast_node,
                    code=cls_info.code,
                )
    
    def resolve_name(
        self,
        name: str,
        from_module: str,
    ) -> Optional[Tuple[str, str]]:
        """Resolve a name to its definition location.
        
        Args:
            name: The name to resolve
            from_module: The module where the reference occurs
            
        Returns:
            Tuple of (qualified_name, kind) where kind is "class" or "function",
            or None if not found
        """
        module_imports = self.imports.get(from_module, {})
        
        if name in module_imports:
            qualified = module_imports[name]
            if qualified in self.hierarchy.classes:
                return (qualified, "class")
            return (qualified, "function")
        
        qualified = f"{from_module}.{name}"
        if qualified in self.hierarchy.classes:
            return (qualified, "class")
        
        if from_module in self.modules:
            if name in self.modules[from_module].get("functions", {}):
                return (qualified, "function")
        
        builtin_qualified = f"builtins.{name}"
        if builtin_qualified in self.hierarchy.classes:
            return (builtin_qualified, "class")
        
        return None
    
    def get_class_code(self, qualified_name: str) -> Optional[object]:
        """Get the PyFlow Code object for a class.
        
        Args:
            qualified_name: The qualified class name
            
        Returns:
            The Code object or None
        """
        cls_info = self.hierarchy.get_class_info(qualified_name)
        if cls_info:
            return cls_info.code
        return None
    
    def get_method_code(
        self,
        qualified_name: str,
        method_name: str,
    ) -> Optional[object]:
        """Get the PyFlow Code object for a method.
        
        Args:
            qualified_name: The class qualified name
            method_name: The method name
            
        Returns:
            The Code object for the method, or None
        """
        defining_class = self.hierarchy.resolve_method(qualified_name, method_name)
        if defining_class:
            cls_info = self.hierarchy.get_class_info(defining_class)
            if cls_info and cls_info.code:
                return cls_info.code
        return None