"""Single-module analyzer for modular pointer analysis.

Analyzes individual modules with imported module summaries,
producing module summaries for compositional analysis.
"""

import logging
from typing import Dict, Set, Any, Optional, TYPE_CHECKING

from .config import Config
from .module_summary import ModuleSummary, FunctionSummary, ClassSummary
from .state import PointerAnalysisState
from .solver import PointerSolver
from .variable import Variable, VariableKind
from .context import Scope
from .ir_translator import IRTranslator
from .context_selector import ContextSelector, parse_policy
from .class_hierarchy import ClassHierarchyManager
from .builtin_api_handler import BuiltinSummaryManager
from .module_summary import ModuleSummary

logger = logging.getLogger(__name__)

__all__ = ["ModuleAnalyzer"]


class ModuleAnalyzer:
    """Analyzes single module with imported summaries.
    
    Creates fresh solver for module, applies import summaries,
    solves to fixpoint, and extracts module summary.
    """
    
    def __init__(self, config: 'Config'):
        """Initialize module analyzer.
        
        Args:
            config: Analysis configuration
        """
        self.config = config
    
    def analyze_module(
        self,
        module_ir: Any,
        import_summaries: Dict[str, 'ModuleSummary']
    ) -> 'ModuleSummary':
        """Analyze single module with imported module summaries.
        
        Args:
            module_ir: IR for this module
            import_summaries: Summaries of modules this one imports
            
        Returns:
            Module summary
        """
        
        module_name = self._get_module_name(module_ir)
        logger.info(f"Analyzing module: {module_name}")
        
        state = PointerAnalysisState()
        
        policy = parse_policy(self.config.context_policy)
        context_selector = ContextSelector(policy=policy)
        
        class_hierarchy = None
        if self.config.build_class_hierarchy:
            class_hierarchy = ClassHierarchyManager()
        
        builtin_manager = BuiltinSummaryManager(context_selector.empty_context())
        
        translator = IRTranslator(self.config)
        
        solver = PointerSolver(
            state=state,
            config=self.config,
            ir_translator=translator,
            context_selector=context_selector,
            function_registry={},
            class_hierarchy=class_hierarchy,
            builtin_manager=builtin_manager
        )
        
        for import_name, summary in import_summaries.items():
            self._apply_import_summary(summary, import_name, state, context_selector)
        
        empty_context = context_selector.empty_context()
        
        constraints, _ = translator.translate_module(module_ir, empty_context)
        
        for constraint in constraints:
            solver.add_constraint(constraint)
        
        solver.solve_to_fixpoint()
        
        summary = self._extract_summary(module_name, module_ir, state, translator)
        
        logger.info(f"Module {module_name}: {len(summary.exports)} exports, "
                   f"{len(summary.functions)} functions, {len(summary.classes)} classes")
        
        return summary
    
    def _apply_import_summary(
        self,
        summary: 'ModuleSummary',
        local_name: str,
        state: 'PointerAnalysisState',
        context_selector: Any
    ) -> None:
        """Apply imported module summary to current state.
        
        Args:
            summary: Module summary to import
            local_name: Local name for module
            state: Current analysis state
            context_selector: Context selector for creating variables
        """
        from .object import AbstractObject, AllocSite, AllocKind
        
        empty_context = context_selector.empty_context()
        module_scope = Scope(name=local_name, kind="module")
        
        for var_name, pts in summary.exports.items():
            var = Variable(
                name=var_name,
                scope=module_scope,
                context=empty_context,
                kind=VariableKind.GLOBAL
            )
            
            current_pts = state.get_points_to(var)
            if not current_pts.is_empty():
                new_pts = current_pts.union(pts)
                state.set_points_to(var, new_pts)
            else:
                state.set_points_to(var, pts)
    
    def _extract_summary(
        self,
        module_name: str,
        module_ir: Any,
        state: 'PointerAnalysisState',
        translator: Any
    ) -> 'ModuleSummary':
        """Extract module summary from solved state.
        
        Args:
            module_name: Module name
            module_ir: Module IR
            state: Solved analysis state
            translator: IR translator
            
        Returns:
            Module summary
        """
        from .module_summary import ModuleSummary, FunctionSummary, ClassSummary
        from .object import AllocKind
        
        exported_names = self._get_exported_names(module_ir)
        
        exports = {}
        functions = {}
        classes = {}
        visible_allocs = set()
        
        for var, pts in state._env.items():
            if var.name in exported_names:
                exports[var.name] = pts
                
                for obj in pts.objects:
                    visible_allocs.add(obj.alloc_site)
                    
                    if obj.alloc_site.kind == AllocKind.FUNCTION:
                        if var.name not in functions:
                            functions[var.name] = self._extract_function_summary(
                                var.name, obj, state
                            )
                    elif obj.alloc_site.kind == AllocKind.CLASS:
                        if var.name not in classes:
                            classes[var.name] = self._extract_class_summary(
                                var.name, obj, state
                            )
        
        return ModuleSummary(
            module_name=module_name,
            exports=exports,
            functions=functions,
            classes=classes,
            context_map={},
            visible_allocs=frozenset(visible_allocs),
            external_calls=frozenset()
        )
    
    def _extract_function_summary(
        self,
        name: str,
        func_obj: Any,
        state: 'PointerAnalysisState'
    ) -> 'FunctionSummary':
        from .module_summary import FunctionSummary
        
        return FunctionSummary(
            name=name,
            params=(),
            context_returns={},
            param_effects={}
        )
    
    def _extract_class_summary(
        self,
        name: str,
        class_obj: Any,
        state: 'PointerAnalysisState'
    ) -> 'ClassSummary':
        from .module_summary import ClassSummary        
        return ClassSummary(
            name=name,
            alloc_site=class_obj.alloc_site,
            bases=(),
            methods={},
            attributes={}
        )
    
    def _get_module_name(self, module_ir: Any) -> str:
        if hasattr(module_ir, 'name'):
            return module_ir.name
        elif hasattr(module_ir, '__name__'):
            return module_ir.__name__
        elif hasattr(module_ir, 'module_name'):
            return module_ir.module_name
        else:
            return "<unknown>"
    
    def _get_exported_names(self, module_ir: Any) -> Set[str]:
        """Get exported names from module."""
        exported = set()
        
        if hasattr(module_ir, '__all__'):
            exported.update(module_ir.__all__)
        
        if hasattr(module_ir, 'get_functions'):
            for func in module_ir.get_functions():
                if hasattr(func, 'name'):
                    exported.add(func.name)
        elif hasattr(module_ir, 'functions'):
            for func in module_ir.functions:
                if hasattr(func, 'name'):
                    exported.add(func.name)
        
        if hasattr(module_ir, 'get_classes'):
            for cls in module_ir.get_classes():
                if hasattr(cls, 'name'):
                    exported.add(cls.name)
        elif hasattr(module_ir, 'classes'):
            for cls in module_ir.classes:
                if hasattr(cls, 'name'):
                    exported.add(cls.name)
        
        if hasattr(module_ir, 'body') and hasattr(module_ir.body, '__iter__'):
            import ast
            for stmt in module_ir.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if not stmt.name.startswith('_'):
                        exported.add(stmt.name)
                elif isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and not target.id.startswith('_'):
                            exported.add(target.id)
        
        return exported if exported else {'*'}
