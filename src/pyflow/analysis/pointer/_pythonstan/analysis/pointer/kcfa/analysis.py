"""Main k-CFA pointer analysis driver.

This module provides the main entry point for running pointer analysis.
"""

import ast
import logging
from typing import Optional, List, Any, TYPE_CHECKING, Dict
from pyflow.analysis.pointer._pythonstan.analysis import AnalysisDriver, AnalysisConfig
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.object import AllocKind, AllocSite
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.points_to_set import reset_object_table
from pyflow.analysis.pointer._pythonstan.ir import IRScope
from pyflow.analysis.pointer._pythonstan.ir.ir_statements import IRCall
from .processor import *

if TYPE_CHECKING:
    from .config import Config
    from .solver_interface import ISolverQuery
    from .context import Scope, AbstractContext

__all__ = ["PointerAnalysis", "AnalysisResult"]

logger = logging.getLogger(__name__)


class PointerAnalysis(AnalysisDriver):
    """Main entry point for k-CFA pointer analysis.
    """
    
    def __init__(self, analysis_config: AnalysisConfig):
        """Initialize pointer analysis.
        
        Args:
            config: Analysis configuration. If None, uses default.
        """
        from .config import Config        
        from .state import PointerAnalysisState
        from .solver import PointerSolver
        from .ir_translator import IRTranslator
        from .context_selector import ContextSelector, parse_policy
        from .class_hierarchy import ClassHierarchyManager
        from .builtin_api_handler import BuiltinSummaryManager        
        from pyflow.analysis.pointer._pythonstan.world import World
        from .debug_monitor import DebugMonitor
        
        self.config = analysis_config
        if not hasattr(self.config, 'options'):
            print(f"Analysis config {self.config} has no options")
        self.kcfa_config = Config.from_dict(self.config.options)        
        self._setup_logging()
        self._result: Optional['AnalysisResult'] = None
        self.world = World()
        
        # Initialize debug monitor if enabled
        self.debug_monitor = None
        if self.kcfa_config.enable_debug_monitor:
            self.debug_monitor = DebugMonitor(
                output_dir=self.kcfa_config.debug_output_dir,
                log_interval=self.kcfa_config.debug_log_interval,
                track_events=True,
                track_object_flow=self.kcfa_config.track_object_flow,
                track_pfg=self.kcfa_config.track_pfg_activation,
                enabled=True
            )
            logger.info(f"Debug monitoring enabled, output to: {self.kcfa_config.debug_output_dir}")
        
        self.state = PointerAnalysisState(debug_monitor=self.debug_monitor)
        
        # Initialize PFG with debug monitor
        from .pointer_flow_graph import PointerFlowGraph
        self.state._pointer_flow_graph = PointerFlowGraph(debug_monitor=self.debug_monitor)
        
        policy = parse_policy(self.kcfa_config.context_policy)
        self.context_selector = ContextSelector(policy=policy)
        self.translator = IRTranslator(self.kcfa_config)
        self.class_hierarchy = ClassHierarchyManager()
        self.builtin_manager = BuiltinSummaryManager(self.kcfa_config)
        
        self.solver = PointerSolver(
            state=self.state,
            config=self.kcfa_config,
            ir_translator=self.translator,
            context_selector=self.context_selector,
            class_hierarchy=self.class_hierarchy,
            builtin_manager=self.builtin_manager,
            debug_monitor=self.debug_monitor,
            processor=ComposeProcessor([
                GeneratorProcessor(),
                AttributeSemanticsProcessor(),
                NormalCallProcessor(),
                ContainerProcessor(index_sensitive=self.kcfa_config.index_sensitive),
                SuperResolveProcessor(),
            ])
        )

    def analyze(
        self,
        entry_scope: IRScope,
        prev_results: Dict[str, Any]
    ) -> 'AnalysisResult':
        """Run pointer analysis on module.
        
        Args:
            entry_scope: Scope to analyze
            prev_results: Results of previous analyses
        
        Returns:
            AnalysisResult containing points-to information and call graph
        """
        # Reset object ID table for clean state each analysis run
        reset_object_table()
        
        logger.info("Starting pointer analysis")

        # Get empty context for module-level analysis
        empty_context = self.context_selector.empty_context()
        
        from .object import ModuleObject
        from .context import Scope

        # Translate ALL scopes to constraints (not just entry module)
        logger.info("Translating all scopes to constraints...")
        
        constraints = []
        
        scope = self.world.get_entry_module()
        
        # Make scope with context
        alloc_site = AllocSite.from_ir_node(scope, AllocKind.MODULE)
        module_obj = ModuleObject(empty_context, alloc_site, entry_scope)
        ctx_scope = Scope(scope, None, empty_context, None, None)
        self.state.set_internal_scope(module_obj, ctx_scope)
        
        # Generate constraints
        try:
            scope_name = scope.get_qualname()
            logger.debug(f"Translating module: {scope_name}")                    
            c = self.translator.translate_module(scope)
            constraints.extend(c)
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            logger.warning(f"Error translating scope {scope.get_qualname()}: {e}")        
        logger.info(f"Total constraints generated: {len(constraints)}")
        
        # Add all constraints to solver
        for constraint in constraints:
            self.solver.add_constraint(ctx_scope, empty_context, constraint)
        
        # Initialize builtin functions (iter, next, len, etc.)
        logger.info("Initializing builtin functions...")
        self._initialize_builtins(ctx_scope, empty_context)
        
        # Create synthetic method contexts to enable method-to-method call resolution
        logger.info("Creating synthetic method contexts...")
        self._create_synthetic_method_contexts(ctx_scope, empty_context)
        
        # Solve to fixpoint
        self.solver.solve_to_fixpoint()
        
        # Export debug data if enabled
        if self.debug_monitor and self.kcfa_config.export_debug_data:
            logger.info("Exporting debug data...")
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            project_name = self.kcfa_config.project_path.split('/')[-1] if self.kcfa_config.project_path else "unknown"
            policy_name = self.kcfa_config.context_policy.replace("-", "_")
            
            # Compute final statistics
            self.debug_monitor.compute_points_to_statistics(self.state)
            self.debug_monitor.compute_pfg_statistics(self.state.pointer_flow_graph)
            
            # Export to files
            self.debug_monitor.export_to_json(f"{project_name}_{policy_name}_{timestamp}_debug.json")
            self.debug_monitor.generate_summary_report(f"{project_name}_{policy_name}_{timestamp}_summary.md")
            
            logger.info("Debug data exported")
        
        # Create and return result
        solver_query = self.solver.query()
        result = AnalysisResult(solver_query)
        self.results = result
        
        logger.info("Analysis complete")
        return result
    
    def _create_synthetic_method_contexts(self, module_scope: 'Scope', empty_context: 'AbstractContext') -> None:
        """Create synthetic contexts for analyzing method bodies.
        
        This enables method-to-method call resolution by:
        1. Creating synthetic 'self' instances for each method
        2. Binding 'self' in method-specific contexts
        3. Processing method bodies with bound 'self'
        
        Args:
            module_scope: The module scope
            empty_context: The empty context for module level
        """
        from .context import Scope, CallSite, CallStringContext
        from .object import InstanceObject, AllocSite, AllocKind, ClassObject
        from .variable import Variable, VariableKind
        from pyflow.analysis.pointer._pythonstan.ir import IRClass, IRFunc
        
        # Get all scopes from the scope manager
        scope_manager = self.world.scope_manager
        
        method_count = 0
        class_count = 0
        
        # Iterate through all scopes to find classes and their methods
        for scope_ir in scope_manager.scopes:
            if isinstance(scope_ir, IRClass):
                class_count += 1
                class_qualname = scope_ir.get_qualname()
                
                # Get subscopes (methods) of this class
                methods = scope_manager.subscopes.get(scope_ir, [])
                
                for method_ir in methods:
                    if not isinstance(method_ir, IRFunc):
                        continue
                    
                    # Only process instance methods (not static or class methods)
                    if not method_ir.is_instance_method:
                        continue
                    
                    method_count += 1
                    method_qualname = method_ir.get_qualname()
                    
                    # Create a method-specific synthetic context
                    # Use a special marker to distinguish from regular call contexts
                    synthetic_stmt = IRCall(ast.parse("synthetic_method()").body[0].value)
                    synthetic_call_site = CallSite(
                        statement=synthetic_stmt,
                        scope_name=f"synthetic_method:{method_qualname}",
                        index=0
                    )
                    
                    # Get k value from empty context
                    if isinstance(empty_context, CallStringContext):
                        k_value = empty_context.k
                    else:
                        k_value = 2  # Default to 2-CFA
                    
                    method_context = CallStringContext(
                        call_sites=(synthetic_call_site,),
                        k=k_value
                    )
                    
                    # Map this instance to its class for method lookup
                    # Find the class object allocation
                    class_alloc_site = AllocSite.from_ir_node(scope_ir, AllocKind.CLASS)
                    
                    # ClassObject needs container_scope and ir parameters
                    # We use module_scope as container since that's where the class is defined
                    class_obj = ClassObject(
                        context=empty_context,
                        alloc_site=class_alloc_site,
                        container_scope=module_scope,
                        ir=scope_ir
                    )
                    
                    # Create and register internal scope for the class
                    # This is needed for field access resolution on instances
                    class_internal_scope = Scope.new(
                        obj=class_obj,
                        module=module_scope,
                        context=empty_context,
                        stmt=scope_ir,
                        parent=module_scope
                    )
                    self.state.set_internal_scope(class_obj, class_internal_scope)
                    
                    # Create a synthetic InstanceObject for 'self'
                    cls_name = scope_ir.get_qualname().split(".")[-1]
                    synthetic_alloc_site = AllocSite(
                        stmt=IRCall(ast.parse(f"{cls_name}()").body[0].value),
                        kind=AllocKind.INSTANCE
                    )
                    
                    # Create the synthetic instance object with the class object
                    # The class_obj is stored in the InstanceObject itself
                    self_instance = InstanceObject(
                        context=method_context,
                        alloc_site=synthetic_alloc_site,
                        class_obj=class_obj
                    )
                    
                    # Create a scope for this method analysis
                    method_scope = Scope.new(
                        obj=self_instance,  # Use the instance as the scope object
                        module=module_scope,
                        context=method_context,
                        stmt=method_ir,
                        parent=module_scope
                    )
                    self.state.set_internal_scope(self_instance, method_scope)
                    
                    # Bind 'self' variable to point to the synthetic instance
                    self_var = self.solver.variable_factory.make_variable('self', VariableKind.LOCAL)
                    from .points_to_set import PointsToSet
                    from .pointer_flow_graph import NormalNode
                    self_pts = PointsToSet.singleton(self_instance)
                    
                    # Get contextualized variable and add to worklist for propagation
                    ctx_self_var = self.state.get_variable(method_scope, method_context, self_var)
                    self.state._worklist.add((method_scope, NormalNode(ctx_self_var), self_pts))
                    
                    # Translate the method body and add constraints
                    try:
                        method_constraints = self.translator.translate_function(method_ir)
                        for constraint in method_constraints:
                            self.solver.add_constraint(method_scope, method_context, constraint)
                    except Exception as e:
                        logger.warning(f"Error translating method {method_qualname}: {e}")
        
        logger.info(f"Created synthetic contexts for {method_count} methods in {class_count} classes")
    
    def _initialize_builtins(self, module_scope: 'Scope', context: 'AbstractContext') -> None:
        """Initialize common builtin functions in the global scope.
        
        Creates builtin function objects for commonly used Python builtins like
        iter, next, len, etc., so they're available when referenced in code.
        
        Args:
            module_scope: The module scope
            context: The context to use for builtin allocations
        """
        self.solver.initialize_builtins(module_scope, context)
        logger.debug(f"Initialized {len(self.solver.BUILTIN_FUNCTIONS)} builtin functions")
    
    def query(self) -> 'ISolverQuery':
        """Get query interface for last analysis.
        
        Returns:
            Query interface for retrieving analysis results
        
        Raises:
            RuntimeError: If analyze() hasn't been called yet
        """
        if self.results is None:
            raise RuntimeError("Must call analyze() before query()")
        
        return self.results.query()
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.kcfa_config.log_level),
            format='%(levelname)s: %(message)s'
        )


class AnalysisResult:
    """Container for analysis results.
    
    Provides access to points-to information, call graph, and statistics.
    """
    
    def __init__(self, solver_query: 'ISolverQuery'):
        """Initialize analysis result.
        
        Args:
            solver_query: Query interface from solver
        """
        self._query = solver_query
    
    def query(self) -> 'ISolverQuery':
        """Get query interface.
        
        Returns:
            Query interface for this result
        """
        return self._query
    
    def get_statistics(self):
        """Get analysis statistics.
        
        Returns:
            Dictionary with analysis statistics
        """
        return self._query.get_statistics()
