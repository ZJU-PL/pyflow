from ast import stmt
from typing import Set

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRFunc, IRModule, IRScope
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
        # Analyze only the requested module's lexical tree.  Pipeline invokes
        # this driver once per lowered module; walking every scope registered
        # so far made project construction quadratic in the number of imports.
        postorder = []
        pending = [(scope, False)]
        while pending:
            current, expanded = pending.pop()
            if expanded:
                postorder.append(current)
                continue
            pending.append((current, True))
            pending.extend(
                (subscope, False)
                for subscope in scope_manager.get_subscopes(current)
            )

        for current in postorder:
            cfg = scope_manager.get_ir(current, "cfg")

            if cfg:
                self.liveness_analysis.analyze(current, cfg)

                # set cell vars for each scope
                entry = cfg.get_entry()
                cell_vars = self.liveness_analysis.results["out"][entry]
                if isinstance(current, IRFunc):
                    arguments = current.get_arg_names()
                    cell_vars.difference_update(arguments)
                if not isinstance(current, IRModule):
                    current.cell_vars = cell_vars

        self.results = None
