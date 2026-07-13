from typing import TypeVar, Generic, Dict, Type

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRScope
from ..analysis import Analysis, AnalysisDriver, AnalysisConfig
from .analysis import DataflowAnalysis
from .solver import Solver, WorklistSolver

Fact = TypeVar('Fact')


class DataflowAnalysisDriver(Generic[Fact], AnalysisDriver):
    analysis: Type[DataflowAnalysis]
    solver: Solver
    results: Dict

    def __init__(self, config: AnalysisConfig):
        super().__init__(config)
        self.analysis = DataflowAnalysis.get_analysis(config.id)
        if 'solver' in config.options:
            self.solver = Solver.get_solver(config.options['solver'])[Fact]
        else:
            self.solver = WorklistSolver[Fact]
        self.results = {}

    def analyze(self, scope: IRScope, prev_results):
        from pyflow.analysis.alias.kcfa._pythonstan.world import World
        ir_name = self.config.options.get("ir", "cfg")
        cfg = World().scope_manager.get_ir(scope, ir_name)

        analyzer = self.analysis(scope, cfg, self.config)
        for prev in self.config.prev_analysis:
            if prev in prev_results:
                analyzer.set_input(prev, prev_results[prev][scope])

        facts_in, facts_out = self.solver.solve(analyzer)

        self.results = {'in': facts_in,
                        'out': facts_out}
