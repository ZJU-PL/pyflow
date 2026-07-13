from typing import Dict, List
from queue import Queue

from .base import ICFGTransformBase, IR
from pyflow.analysis.pointer._pythonstan.ir import *
from pyflow.analysis.pointer._pythonstan.graph.cfg import ControlFlowGraph, BaseBlock, IfEdge
from pyflow.analysis.pointer._pythonstan.world import World
from pyflow.analysis.pointer._pythonstan.utils.persistent_rb_tree import PersistentMap


class ICFGPreTransform(ICFGTransformBase):
    def analysis_module(self, module: IRModule, env: PersistentMap):
        visited = {*()}
        cfg: ControlFlowGraph = World().scope_manager.get_ir(module, IR)
        q: Queue[BaseBlock] = Queue()
        q.put(cfg.get_entry())
        while not q.empty():
            cur_blk = q.get()
            visited.add(cur_blk)
            cond_assigns = {}
            for stmt in cur_blk.get_stmts():
                if isinstance(stmt, IRAstStmt):
                    self.analysis_stmt(stmt.get_ast(), env)
                elif isinstance(stmt, IRClass):
                    ...
                elif isinstance(stmt, IRFunc):
                    ...
                elif isinstance(stmt, IRImport):
                    ...
                elif isinstance(stmt, IRCall):
                    ...
                elif isinstance(stmt, IRReturn):
                    ...
                elif isinstance(stmt, IRYield):
                    ...
                elif isinstance(stmt, Phi):
                    ...
                elif isinstance(stmt, JumpIfTrue):
                    if stmt.label in cfg.label2blk:
                        tgt_blk = cfg.label2blk[stmt.label]
                        cond_assigns[tgt_blk] = [(t, [self._const(True)])
                                                 for t in self.resolve_node(env, stmt.test)]
                elif isinstance(stmt, JumpIfFalse):
                    if stmt.label in cfg.label2blk:
                        tgt_blk = cfg.label2blk[stmt.label]
                        cond_assigns[tgt_blk] = [(t, [self._const(False)])
                                                 for t in self.resolve_node(env, stmt.test)]
            for succ in cfg.succs_of(cur_blk):
                new_env = PersistentMap(env.backup())
                if succ in cond_assigns:
                    for k, v in cond_assigns[succ]:
                        new_env[k] = v



    def analysis_cls(self, cls: IRClass, env: PersistentMap):
        if cls.keywords is not None:
            for kw in cls.keywords:
                if kw.arg == "metaclass":
                    for v in self.resolve_node(env, kw.value):
                        if self.resolve_attribute():
                            ...
        ...

    def analysis_func(self, func: IRFunc, env: PersistentMap):
        ...


#self.analysis_stmt(env, stmt.get_ast())