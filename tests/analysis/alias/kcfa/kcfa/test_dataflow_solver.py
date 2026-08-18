from pyflow.analysis.alias.kcfa._pythonstan.analysis import AnalysisConfig
from pyflow.analysis.alias.kcfa._pythonstan.analysis.dataflow.liveness import (
    LivenessAnalysis,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.dataflow.solver import (
    WorklistSolver,
)
from pyflow.analysis.alias.kcfa._pythonstan.graph.cfg import (
    BaseBlock,
    ControlFlowGraph,
    NormalEdge,
)


class LoadStatement:
    def __init__(self, name):
        self.name = name

    def get_stores(self):
        return set()

    def get_nostores(self):
        return {self.name}


class CountingLiveness(LivenessAnalysis):
    def __init__(self, scope, cfg, config):
        super().__init__(scope, cfg, config)
        self.transfer_count = 0

    def transfer_node(self, node, fact):
        self.transfer_count += 1
        return super().transfer_node(node, fact)


def test_backward_solver_uses_cfg_postorder_for_linear_graph():
    entry = BaseBlock(0)
    cfg = ControlFlowGraph(entry)
    cfg.add_blk(entry)
    previous = entry
    block_count = 100
    for index in range(1, block_count + 1):
        block = BaseBlock(index, [LoadStatement(f"value_{index}")])
        cfg.add_blk(block)
        cfg.add_edge(NormalEdge(previous, block))
        previous = block
    cfg.add_exit(previous)
    cfg.add_super_exit_blk(BaseBlock(block_count + 1))

    analysis = CountingLiveness(
        None,
        cfg,
        AnalysisConfig(
            name="liveness",
            id="LivenessAnalysis",
            options={"type": "dataflow analysis"},
        ),
    )

    WorklistSolver.solve(analysis)

    assert analysis.transfer_count == block_count + 1
