import copy
from typing import List, Dict, Optional

from ..analysis import AnalysisConfig
from .transform import Transform
from pyflow.analysis.alias.kcfa._pythonstan.graph.cfg import *
from pyflow.analysis.alias.kcfa._pythonstan.world import World
from pyflow.analysis.alias.kcfa._pythonstan.ir import *

__all__ = ["CFG"]


class CFG(Transform):
    transformer: 'CFGTransformer'

    def __init__(self, config: AnalysisConfig):
        super().__init__(config)
        self.transformer = CFGTransformer()

    def transform(self, module: IRModule):
        block_cfg = World().scope_manager.get_ir(module, "block cfg")
        self.transformer.trans(module, block_cfg)
        self.results = None


class CFGTransformer:
    scope: IRScope
    cfg: ControlFlowGraph

    # map a bblock in source cfg to the head block in the target cfg
    head_map: Dict[BaseBlock, BaseBlock]
    next_idx: int

    def trans(self, scope: IRScope, block_cfg: ControlFlowGraph):
        self.scope = scope
        self.cfg = ControlFlowGraph()
        entry = self.cfg.get_entry()
        self.head_map = {block_cfg.entry_blk: self.cfg.entry_blk}
        self.next_idx = 1
        self._trans(block_cfg, block_cfg.get_entry(), entry)
        super_exit = self.new_blk()
        self.cfg.add_super_exit_blk(super_exit)

        World().scope_manager.set_ir(scope, "cfg", self.cfg)
        for subscope in World().scope_manager.get_subscopes(scope):
            sub_transformer = CFGTransformer()
            sub_block_cfg = World().scope_manager.get_ir(subscope, "block cfg")
            # print(f"Subscope: {subscope.qualname} {sub_block_cfg}")
            # print(World().scope_manager.scope_ir.keys())
            sub_transformer.trans(subscope, sub_block_cfg)

    def new_blk(self, statement: Optional[IRStatement] = None):
        if statement is not None:
            stmts = [statement]
        else:
            stmts = []
        blk = BaseBlock(self.next_idx, stmts)
        self.next_idx += 1
        return blk

    def _trans(self, cfg: ControlFlowGraph, entry: BaseBlock, stmt_entry: BaseBlock):
        tgt_cfg = self.cfg
        if entry in cfg.exit_blks:
            tgt_cfg.add_exit(stmt_entry)
        for e in cfg.out_edges_of(entry):
            if e.tgt == cfg.super_exit_blk:
                continue
            stmt_e = copy.deepcopy(e)
            stmt_e.src = stmt_entry
            if e.tgt in self.head_map:
                stmt_e.tgt = self.head_map[e.tgt]
                tgt_cfg.add_edge(stmt_e)
            else:
                head_blk = stmt_entry
                tail_blk = stmt_entry
                if e.tgt.n_stmt() > 0:
                    for idx, cur_stmt in enumerate(e.tgt.stmts):
                        blk = self.new_blk(cur_stmt)
                        tgt_cfg.add_blk(blk)
                        if idx == 0:
                            head_blk = blk
                        else:
                            tgt_cfg.add_edge(NormalEdge(tail_blk, blk))
                        tail_blk = blk
                else:
                    blk = self.new_blk()
                    tgt_cfg.add_blk(blk)
                    head_blk = blk
                    tail_blk = blk
                self.head_map[e.tgt] = head_blk
                if e.tgt in cfg.blk2label:
                    tgt_cfg.add_label(cfg.blk2label[e.tgt], head_blk)
                stmt_e.tgt = head_blk
                tgt_cfg.add_edge(stmt_e)
                self._trans(cfg, e.tgt, tail_blk)
