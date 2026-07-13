from typing import List, Set, Dict

from ..cfg import ControlFlowGraph, BaseBlock, NormalEdge, CallEdge, ReturnEdge
from pyflow.analysis.pointer._pythonstan.ir import *

__all__ = ["InterControlFlowGraph"]


class InterControlFlowGraph(ControlFlowGraph):
    super_entry_blk: BaseBlock
    entry_scopes: Set[IRScope]
    scope2cfg: Dict[IRScope, ControlFlowGraph]
    call_sites: Set[BaseBlock]
    callees: Dict[BaseBlock, Set[IRScope]]
    callers: Dict[IRScope, Set[BaseBlock]]
    blk2scope: Dict[BaseBlock, IRScope]

    def __init__(self):
        super().__init__()
        self.super_entry_blk = BaseBlock()
        self.add_blk(self.super_entry_blk)
        self.entry_scopes = {*()}
        self.scope2cfg = {}
        self.call_sites = {*()}
        self.callees = {}
        self.callers = {}
        self.blk2scope = {}

    def add_entry_scope(self, scope: IRScope):
        assert scope in self.scope2cfg, f"Scope {scope} not in current icfg!"
        self.entry_scopes.add(scope)
        scope_cfg = self.get_cfg(scope)
        entry_edge = NormalEdge(self.super_entry_blk, scope_cfg.get_entry())
        self.add_edge(entry_edge)

    def add_scope(self, scope: IRScope, cfg: ControlFlowGraph):
        self.scope2cfg[scope] = cfg

        self.in_edges |= cfg.in_edges
        self.out_edges |= cfg.out_edges
        self.blks |= cfg.blks
        self.stmts |= cfg.stmts
        self.label2blk |= cfg.label2blk
        self.blk2label |= cfg.blk2label
        for blk in cfg.get_nodes():
            self.blk2scope[blk] = scope

    def add_invoke(self, call_site: BaseBlock, callee: IRScope):
        self.call_sites.add(call_site)
        if call_site not in self.callees:
            self.callees[call_site] = {*()}
        self.callees[call_site].add(callee)
        if callee not in self.callers:
            self.callers[callee] = {*()}
        self.callers[callee].add(call_site)
        callee_cfg = self.get_cfg(callee)
        call_edge = CallEdge(call_site, callee_cfg.get_entry(), callee)
        self.add_edge(call_edge)
        ret_vals = {stmt.get_ast() for blk in callee_cfg.exit_blks
                    for stmt in blk.stmts if isinstance(stmt, IRReturn)}
        for ret_site in self.return_sites_of(call_site):
            ret_edge = ReturnEdge(callee_cfg.get_entry(), ret_site, call_site, ret_vals)
            self.add_edge(ret_edge)

    def get_entry_scopes(self) -> Set[IRScope]:
        return self.entry_scopes

    def get_scopes(self) -> Set[IRScope]:
        return set(self.scope2cfg.keys())

    def get_scope_from_base_block(self, blk: BaseBlock) -> IRScope:
        assert blk in self.blk2scope, "Block not in ICFG!"
        return self.blk2scope[blk]

    def get_cfg(self, scope: IRScope) -> ControlFlowGraph:
        return self.scope2cfg[scope]

    def callees_of(self, call_site: BaseBlock) -> Set[IRScope]:
        return self.callees[call_site]

    def return_sites_of(self, call_site: BaseBlock) -> Set[BaseBlock]:
        assert call_site in self.call_sites, f"block {call_site} is not a call_site of current icfg!"
        return set(self.scope2cfg[self.blk2scope[call_site]].succs_of(call_site))

    def entry_of(self, scope: IRScope) -> BaseBlock:
        return self.scope2cfg[scope].get_entry()

    def exit_of(self, scope: IRScope) -> BaseBlock:
        return self.scope2cfg[scope].get_exit()

    def caller_of(self, scope: IRScope) -> Set[BaseBlock]:
        return self.callers[scope]

    def scope_of(self, blk: BaseBlock) -> IRScope:
        return self.blk2scope[blk]

    def is_call_site(self, blk: BaseBlock) -> bool:
        return blk in self.call_sites
