from ast import stmt
from typing import Set, Iterator

from pyflow.analysis.pointer._pythonstan.ir import IRScope, IRStatement
from .analysis import AnalysisConfig, AnalysisDriver
from .dataflow.driver import DataflowAnalysisDriver


class DefUseAnalysis(AnalysisDriver):
    compute_stores: bool
    compute_loads: bool

    def __init__(self, config: AnalysisConfig):
        self.compute_stores = config.options.get('compute-stores',
                                                 default=True)
        self.compute_loads = config.options.get('compute-loads',
                                                default=True)
        rd_config = AnalysisConfig(name="reaching-definition",
                                   id="ReachingDefinitionAnalysis")
        self.rd_analysis = DataflowAnalysisDriver[Set[stmt]](rd_config)

        from pyflow.analysis.pointer._pythonstan.world import World
        self.world = World()

        super().__init__(config)
    
    def analyze(self, scope: IRScope):
        rd_result = self.rd_analysis.analyze(scope)
        stores, loads = {}, {}
        ir: Iterator[IRStatement] = self.world.scope_manager.get_ir(scope, "ir")

        for cur_stmt in ir:
            reaching_defs = rd_result['in'][cur_stmt]
            for load_id in cur_stmt.get_nostores():
                for reaching_def in reaching_defs:
                    for store_id in reaching_def.get_stores():
                        if load_id == store_id:
                            if self.compute_stores:
                                if (cur_stmt, load_id) not in stores:
                                    stores[(cur_stmt, load_id)] = {*()}
                                stores[(cur_stmt, load_id)].add(reaching_def)
                            if self.compute_loads:
                                if reaching_def not in loads:
                                    loads[reaching_def] = {*()}
                                loads[reaching_def].add(cur_stmt)
        return stores, loads
