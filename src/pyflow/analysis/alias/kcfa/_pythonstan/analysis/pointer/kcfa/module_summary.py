"""
Module summaries for modular pointer analysis.

Summaries capture cross-module analysis information including exports,
functions, classes, and context mappings for compositional analysis.
"""

from dataclasses import dataclass, field
from typing import Dict, List, FrozenSet, Tuple, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .state import PointsToSet
    from .object import AllocSite

__all__ = ["FunctionSummary", "ClassSummary", "ModuleSummary"]


@dataclass(frozen=True)
class FunctionSummary:
    """Function summary for cross-module analysis.
    
    Captures parameter/return flow and side effects for context-sensitive
    inter-procedural analysis across module boundaries.
    
    Attributes:
        name: Function name
        params: Parameter names in order
        context_returns: Maps calling context to return points-to set
        param_effects: Side effects on parameters (reference parameters)
    """
    
    name: str
    params: Tuple[str, ...] = field(default_factory=tuple)
    context_returns: Dict[str, 'PointsToSet'] = field(default_factory=dict)
    param_effects: Dict[str, 'PointsToSet'] = field(default_factory=dict)
    
    def merge(self, other: 'FunctionSummary') -> 'FunctionSummary':
        """Merge with another summary for same function."""
        if self.name != other.name:
            raise ValueError(f"Cannot merge summaries for different functions: {self.name} vs {other.name}")
        
        from .state import PointsToSet
        
        merged_ctx_returns = dict(self.context_returns)
        for ctx, pts in other.context_returns.items():
            if ctx in merged_ctx_returns:
                merged_ctx_returns[ctx] = merged_ctx_returns[ctx].union(pts)
            else:
                merged_ctx_returns[ctx] = pts
        
        merged_param_effects = dict(self.param_effects)
        for param, pts in other.param_effects.items():
            if param in merged_param_effects:
                merged_param_effects[param] = merged_param_effects[param].union(pts)
            else:
                merged_param_effects[param] = pts
        
        return FunctionSummary(
            name=self.name,
            params=self.params,
            context_returns=merged_ctx_returns,
            param_effects=merged_param_effects
        )


@dataclass(frozen=True)
class ClassSummary:
    """Class summary for inheritance and attribute resolution.
    
    Attributes:
        name: Class name
        alloc_site: Allocation site for class object
        bases: Base class names
        methods: Method summaries
        attributes: Class attribute points-to sets
    """
    
    name: str
    alloc_site: 'AllocSite'
    bases: Tuple[str, ...] = field(default_factory=tuple)
    methods: Dict[str, FunctionSummary] = field(default_factory=dict)
    attributes: Dict[str, 'PointsToSet'] = field(default_factory=dict)
    
    def merge(self, other: 'ClassSummary') -> 'ClassSummary':
        """Merge with another summary for same class."""
        if self.name != other.name:
            raise ValueError(f"Cannot merge summaries for different classes: {self.name} vs {other.name}")
        
        from .state import PointsToSet
        
        merged_methods = dict(self.methods)
        for method_name, method_summary in other.methods.items():
            if method_name in merged_methods:
                merged_methods[method_name] = merged_methods[method_name].merge(method_summary)
            else:
                merged_methods[method_name] = method_summary
        
        merged_attributes = dict(self.attributes)
        for attr_name, pts in other.attributes.items():
            if attr_name in merged_attributes:
                merged_attributes[attr_name] = merged_attributes[attr_name].union(pts)
            else:
                merged_attributes[attr_name] = pts
        
        return ClassSummary(
            name=self.name,
            alloc_site=self.alloc_site,
            bases=self.bases,
            methods=merged_methods,
            attributes=merged_attributes
        )


@dataclass(frozen=True)
class ModuleSummary:
    """Complete module analysis summary.
    
    Captures all cross-module visible information: exports, functions,
    classes, and context mappings for compositional analysis.
    
    Attributes:
        module_name: Fully qualified module name
        exports: Module-level exported variable points-to sets
        functions: Exported function summaries
        classes: Exported class summaries
        context_map: External-to-internal context mapping
        visible_allocs: Allocation sites visible to importers
        external_calls: Cross-module call edges
    """
    
    module_name: str
    exports: Dict[str, 'PointsToSet'] = field(default_factory=dict)
    functions: Dict[str, FunctionSummary] = field(default_factory=dict)
    classes: Dict[str, ClassSummary] = field(default_factory=dict)
    context_map: Dict[str, str] = field(default_factory=dict)
    visible_allocs: FrozenSet['AllocSite'] = field(default_factory=frozenset)
    external_calls: FrozenSet[Tuple[str, str]] = field(default_factory=frozenset)
    
    @staticmethod
    def empty(module_name: str) -> 'ModuleSummary':
        """Create empty summary for module."""
        return ModuleSummary(module_name=module_name)
    
    def merge(self, other: 'ModuleSummary') -> 'ModuleSummary':
        """Merge with another summary for same module."""
        if self.module_name != other.module_name:
            raise ValueError(f"Cannot merge summaries for different modules: {self.module_name} vs {other.module_name}")
        
        from .state import PointsToSet
        
        merged_exports = dict(self.exports)
        for var_name, pts in other.exports.items():
            if var_name in merged_exports:
                merged_exports[var_name] = merged_exports[var_name].union(pts)
            else:
                merged_exports[var_name] = pts
        
        merged_functions = dict(self.functions)
        for func_name, func_summary in other.functions.items():
            if func_name in merged_functions:
                merged_functions[func_name] = merged_functions[func_name].merge(func_summary)
            else:
                merged_functions[func_name] = func_summary
        
        merged_classes = dict(self.classes)
        for class_name, class_summary in other.classes.items():
            if class_name in merged_classes:
                merged_classes[class_name] = merged_classes[class_name].merge(class_summary)
            else:
                merged_classes[class_name] = class_summary
        
        merged_context_map = {**self.context_map, **other.context_map}
        merged_visible_allocs = self.visible_allocs | other.visible_allocs
        merged_external_calls = self.external_calls | other.external_calls
        
        return ModuleSummary(
            module_name=self.module_name,
            exports=merged_exports,
            functions=merged_functions,
            classes=merged_classes,
            context_map=merged_context_map,
            visible_allocs=merged_visible_allocs,
            external_calls=merged_external_calls
        )
    
    def get_export_names(self) -> Set[str]:
        """Get all exported names."""
        names = set(self.exports.keys())
        names.update(self.functions.keys())
        names.update(self.classes.keys())
        return names
