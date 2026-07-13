from typing import *

from ..graph import Edge, Node, Graph

from .base_block import BaseBlock
from .edges import NormalEdge
from pyflow.analysis.alias.kcfa._pythonstan.ir import *
from pyflow.analysis.alias.kcfa._pythonstan.utils.var_collector import VarCollector

__all__ = ["ControlFlowGraph"]


class ControlFlowGraph(Graph):
    entry_blk: BaseBlock
    exit_blks: Set[BaseBlock]
    super_exit_blk: Optional[BaseBlock]
    in_edges: Dict[BaseBlock, List[Edge]]
    out_edges: Dict[BaseBlock, List[Edge]]
    blks: Set[BaseBlock]
    stmts: Set[IRStatement]
    label2blk: Dict[Label, BaseBlock]
    blk2label: Dict[BaseBlock, Label]

    def __init__(self, entry_blk=None):
        self.blks = {*()}
        self.stmts = {*()}
        self.in_edges = {}
        self.out_edges = {}
        self.entry_blk = entry_blk if entry_blk is not None else BaseBlock(0)
        self.exit_blks = {*()}
        self.super_exit_blk = None
        self.var_collector = VarCollector()
        self.label2blk = {}
        self.blk2label = {}

    def preds_of(self, node: Node) -> List[BaseBlock]:
        preds = []
        for e in self.in_edges_of(node):
            pred = e.get_src()
            if isinstance(pred, BaseBlock):
                preds.append(pred)
            else:
                raise ValueError(
                    "The type of Node in the current CFG can only be BaseBlock!")
        return preds

    def succs_of(self, node: Node) -> List[BaseBlock]:
        succs = []
        for e in self.out_edges_of(node):
            succ = e.get_tgt()
            if isinstance(succ, BaseBlock):
                succs.append(succ)
            else:
                raise ValueError(
                    "The type of Node in the current CFG can only be BaseBlock!")
        return succs

    def in_edges_of(self, node: Node):
        if isinstance(node, BaseBlock):
            return self.in_edges[node]
        else:
            raise ValueError(
                "The type of Node in the current CFG can only be BaseBlock!")

    def out_edges_of(self, node: Node):
        if isinstance(node, BaseBlock):
            return self.out_edges[node]
        else:
            raise ValueError(
                "The type of Node in the current CFG can only be BaseBlock!")

    def in_degree_of(self, node: Node) -> int:
        if isinstance(node, BaseBlock):
            return len(self.in_edges_of(node))
        else:
            raise ValueError(
                "The type of Node in the current CFG can only be BaseBlock!")

    def out_degree_of(self, node: Node) -> int:
        if isinstance(node, BaseBlock):
            return len(self.out_edges_of(node))
        else:
            raise ValueError(
                "The type of Node in the current CFG can only be BaseBlock!")

    def get_entry(self) -> BaseBlock:
        return self.entry_blk

    def get_exit(self) -> BaseBlock:
        if self.super_exit_blk is None:
            raise ValueError(
                "Super Exit Block in current CFG does not exists!")
        return self.super_exit_blk

    def add_node(self, node: Node):
        if isinstance(node, BaseBlock):
            self.add_blk(node)
        else:
            raise ValueError(
                "The type of Node in the current CFG can only be BaseBlock!")

    def add_blk(self, blk: BaseBlock):
        if blk not in self.blks:
            self.blks.add(blk)
            for stmt in blk.stmts:
                self.stmts.add(stmt)
            self.in_edges[blk] = []
            self.out_edges[blk] = []

    def add_stmt(self, blk: BaseBlock, stmt: IRStatement):
        blk.add(stmt)
        self.stmts.add(stmt)

    def add_edge(self, edge: Edge):
        src = edge.get_src()
        tgt = edge.get_tgt()
        if isinstance(src, BaseBlock) and isinstance(tgt, BaseBlock):
            if src not in self.blks:
                self.add_node(src)
            if tgt not in self.blks:
                self.add_node(tgt)
            self.in_edges[tgt].append(edge)
            self.out_edges[src].append(edge)
        else:
            raise ValueError(
                "The type of Node in the current CFG can only be BaseBlock!")

    def add_exit(self, blk: BaseBlock):
        self.exit_blks.add(blk)

    def find_var(self, var):
        return self.var_collector.find(var)

    def get_var_map(self):
        return self.var_collector.get_vars()

    def get_var_num(self):
        return self.var_collector.size()

    def add_super_exit_blk(self, blk):
        self.delete_invalid_blk()
        for cur_blk in self.exit_blks:
            if self.out_degree_of(cur_blk) == 0:
                self.exit_blks.add(cur_blk)
        self.add_blk(blk)
        self.super_exit_blk = blk
        for exit_blk in self.exit_blks:
            self.add_edge(NormalEdge(exit_blk, blk))

    def delete_node(self, node: Node):
        if isinstance(node, BaseBlock):
            self.delete_block(node)
        else:
            raise ValueError(
                "The type of Node in the current CFG can only be BaseBlock!")

    def delete_block(self, blk: BaseBlock):
        if blk in self.exit_blks:
            self.exit_blks.remove(blk)
        for e in self.out_edges_of(blk):
            self.delete_edge(e)
        for e in self.in_edges_of(blk):
            self.delete_edge(e)
        self.in_edges.pop(blk)
        self.out_edges.pop(blk)
        for stmt in blk.stmts:
            if not isinstance(stmt, Label):
                self.stmts.remove(stmt)
        self.blks.remove(blk)

    def delete_edge(self, e: Edge):
        self.out_edges_of(e.get_src()).remove(e)
        self.in_edges_of(e.get_tgt()).remove(e)

    def delete_invalid_blk(self):
        q = {blk for blk in self.blks
             if blk != self.entry_blk and self.in_degree_of(blk) == 0}
        while len(q) > 0:
            cur = q.pop()
            out_list = self.succs_of(cur)
            self.delete_block(cur)
            for blk in out_list:
                if self.in_degree_of(blk) == 0:
                    q.add(blk)

    def get_nodes(self) -> Set[BaseBlock]:
        return self.blks

    def retrive_label(self, label: Label) -> Optional[BaseBlock]:
        if label in self.label2blk:
            return self.label2blk[label]
        else:
            return None

    def add_label(self, label: Label, block: BaseBlock):
        self.label2blk[label] = block
        self.blk2label[block] = label

    def get_stmts(self) -> Set[IRStatement]:
        return self.stmts
