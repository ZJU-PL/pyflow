from ast import stmt
from typing import Set, Iterator

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRScope, IRStatement, IRFunc, IRModule, IRClass
from pyflow.analysis.alias.kcfa._pythonstan.graph.cfg import ControlFlowGraph
from pyflow.analysis.alias.kcfa._pythonstan.utils.toposort import topo_edges
from pyflow.analysis.alias.kcfa._pythonstan.utils.var_collector import VarCollector
from .analysis import AnalysisConfig, AnalysisDriver
from .dataflow.driver import DataflowAnalysisDriver

__all__ = ["ClosureAnalysis"]


class ClosureAnalysis(AnalysisDriver):
    compute_stores: bool
    compute_loads: bool

    def __init__(self, config: AnalysisConfig):
        live_config = AnalysisConfig(
            name="liveness-analysis",
            id="LivenessAnalysis",
            options={"type": "dataflow analysis"})
        self.liveness_analysis = DataflowAnalysisDriver[Set[stmt]](live_config)

        from pyflow.analysis.alias.kcfa._pythonstan.world import World
        self.world = World()

        super().__init__(config)
    
    def analyze(self, scope: IRScope, prev_results):
        scope_manager = self.world.scope_manager
        hier = self.world.class_hierarchy
        m_edges = [(u, v) for (u, _), v in scope_manager.get_module_graph().succ_module_index.items()]
        for module in topo_edges(m_edges):
            for cls in scope_manager.get_subscopes(module):
                if isinstance(cls, IRClass):
                    for base in cls.get_bases():
                        base_name = base.id
                        ...




        scopes = scope_manager.get_scopes()
        parent_scope = {}
        subscopes = {}
        

        from queue import Queue
        q = Queue()

        for scope in scopes:
            subscopes[scope] = set()
            for subscope in scope_manager.get_subscopes(scope):
                parent_scope[subscope] = scope
                subscopes[scope].add(subscope)
            if len(subscopes[scope]) == 0:
                q.put(scope)
        
        while not q.empty():
            scope = q.get()

            cfg = scope_manager.get_ir(scope, "cfg")

            if cfg:
                self.liveness_analysis.analyze(scope, cfg)

                # set cell vars for each scope
                entry = cfg.get_entry()
                cell_vars = self.liveness_analysis.results["out"][entry]
                if isinstance(scope, IRFunc):
                    arguments = scope.get_arg_names()
                    cell_vars.difference_update(arguments)
                if not isinstance(scope, IRModule):
                    scope.cell_vars = cell_vars

            parent = parent_scope.get(scope, None)
            if parent:
                subscopes[parent].remove(scope)
                if len(subscopes[parent]) == 0:
                    q.put(parent)
        
        self.results = None
