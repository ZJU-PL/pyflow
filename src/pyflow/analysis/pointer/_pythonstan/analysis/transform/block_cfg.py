from typing import List, Dict, Optional, Tuple, Any
from queue import Queue

from ..analysis import AnalysisConfig
from .transform import Transform
from pyflow.analysis.pointer._pythonstan.graph.cfg import *
from pyflow.analysis.pointer._pythonstan.world import World
from pyflow.analysis.pointer._pythonstan.ir import *


__all__ = ['STAGE_NAME', 'BlockCFG', 'BlockCFGBuilder']
STAGE_NAME = 'block cfg'


class BlockCFG(Transform):
    transformer: 'BlockCFGBuilder'

    def __init__(self, config: AnalysisConfig):
        super().__init__(config)

    def transform(self, module: IRModule):
        module_ir: List[IRStatement] = World().scope_manager.get_ir(module, "ir")
        q = Queue()
        q.put((module, module_ir))
        while not q.empty():
            cur_scope, cur_ir = q.get()
            transformer = BlockCFGBuilder(cur_scope)
            transformer.build_graph(cur_ir)
            World().scope_manager.set_ir(cur_scope, STAGE_NAME, transformer.cfg)
            for subscope in World().scope_manager.get_subscopes(cur_scope):
                if World().scope_manager.get_ir(subscope, STAGE_NAME) is None:
                    subscope_ir = World().scope_manager.get_ir(subscope, "ir")
                    q.put((subscope, subscope_ir))


class BaseBlockHelper:
    @staticmethod
    def get_goto_stmts(blk: BaseBlock) -> List[IRStatement]:
        return [s for s in blk.get_stmts() if isinstance(s, (Goto, JumpIfTrue, JumpIfFalse, IRCatchException))]

    @staticmethod
    def will_directly_jump(blk: BaseBlock) -> bool:
        stmts = blk.get_stmts()
        return len(stmts) > 0 and isinstance(stmts[-1], (Goto, IRReturn, IRRaise))

    @staticmethod
    def will_return(blk: BaseBlock) -> bool:
        stmts = blk.get_stmts()
        return len(stmts) > 0 and any([s for s in stmts if isinstance(s, IRReturn)])

    @staticmethod
    def retrive_label(blk: BaseBlock) -> Optional[Label]:
        stmts = blk.get_stmts()
        for stmt in stmts:
            if isinstance(stmt, Label):
                return stmt
        return None


class BlockCFGBuilder:
    cfg: ControlFlowGraph
    scope: IRScope
    lab2blk: Dict[Label, BaseBlock]
    blk_count: int

    def __init__(self, scope: IRScope):
        self.scope = scope
        self.lab2blk = {}
        self.blk_count = 0

    def split_stmts(self, stmts: List[IRStatement]) -> List[List[IRStatement]]:
        cur_blk = []
        ret_blks = [cur_blk]
        for stmt in stmts:
            if isinstance(stmt, Label):
                cur_blk = [stmt]
                ret_blks.append(cur_blk)
            elif isinstance(stmt, (Goto, JumpIfTrue, JumpIfFalse,
                                   IRCatchException, IRReturn, IRRaise)):
                cur_blk.append(stmt)
                cur_blk = []
                ret_blks.append(cur_blk)
            else:
                cur_blk.append(stmt)
        return ret_blks

    def build_graph(self, stmts: List[IRStatement]):
        entry_blk = self.new_blk([])
        self.cfg = ControlFlowGraph(entry_blk)
        stmts_list = self.split_stmts(stmts)
        blk_list = []
        for cur_stmts in stmts_list:
            blk = self.new_blk(cur_stmts)
            blk_label = BaseBlockHelper.retrive_label(blk)
            if blk_label is not None:
                self.lab2blk[blk_label] = blk
                # Populate CFG label map so downstream analyses can resolve jumps
                self.cfg.add_label(blk_label, blk)
            blk_list.append(blk)
        for blk in blk_list:
            self.cfg.add_blk(blk)
            if blk.idx == 1:
                self.cfg.add_edge(NormalEdge(entry_blk, blk))
        for blk, next_blk in zip(blk_list, blk_list[1:]):
            if not BaseBlockHelper.will_directly_jump(blk):
                self.cfg.add_edge(NormalEdge(blk, next_blk))
            for stmt in BaseBlockHelper.get_goto_stmts(blk):
                if isinstance(stmt, Goto):
                    tgt_blk = self.lab2blk.get(stmt.label, None)
                    if tgt_blk is not None:
                        self.cfg.add_edge(NormalEdge(blk, tgt_blk))
                if isinstance(stmt, JumpIfTrue):
                    tgt_blk = self.lab2blk.get(stmt.label, None)
                    if tgt_blk is not None:
                        self.cfg.add_edge(IfEdge(blk, tgt_blk, stmt.test, True))
                if isinstance(stmt, JumpIfFalse):
                    tgt_blk = self.lab2blk.get(stmt.label, None)
                    if tgt_blk is not None:
                        self.cfg.add_edge(IfEdge(blk, tgt_blk, stmt.test, False))
                elif isinstance(stmt, IRCatchException):
                    tgt_blk = self.lab2blk.get(stmt.goto_label, None)
                    if tgt_blk is not None:
                        self.cfg.add_edge(ExceptionEdge(blk, tgt_blk, stmt.exception))
        for blk in blk_list:
            if BaseBlockHelper.will_return(blk):
                self.cfg.add_exit(blk)
        self.cfg.add_exit(blk_list[-1])
        self.cfg.add_super_exit_blk(self.new_blk([]))

    def new_blk(self, stmts) -> BaseBlock:
        blk = BaseBlock(self.blk_count, stmts)
        self.blk_count += 1
        return blk
