from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Dict, Any

from pyflow.analysis.pointer._pythonstan.graph.cfg import CFGEdge, BaseBlock, ControlFlowGraph
from pyflow.analysis.pointer._pythonstan.ir import *
from ..analysis import Analysis, AnalysisConfig

Fact = TypeVar('Fact')


class DataflowAnalysis(Generic[Fact], Analysis):
    is_forward: bool
    scope: IRScope
    inputs: Dict[str, Any]
    cfg: ControlFlowGraph
    inter_procedure: bool

    @abstractmethod
    def __init__(self, scope: IRScope, cfg: ControlFlowGraph, config: AnalysisConfig):
        super(Analysis, self.__class__).__init__(config)
        self.cfg = cfg
        self.scope = scope
        self.inputs = {}

    @abstractmethod
    def new_boundary_fact(self) -> Fact:
        pass

    @abstractmethod
    def new_init_fact(self) -> Fact:
        pass

    @abstractmethod
    def meet(self, fact_1: Fact, fact_2: Fact) -> Fact:
        pass

    @abstractmethod
    def transfer_node(self, node: BaseBlock, fact: Fact) -> Fact:
        pass

    @abstractmethod
    def need_transfer_edge(self, edge: CFGEdge) -> bool:
        return False

    def transfer_edge(self, edge: CFGEdge, node_fact: Fact) -> Fact:
        return node_fact

    def get_scope(self) -> IRScope:
        return self.scope

    def get_cfg(self) -> ControlFlowGraph:
        return self.cfg

    def set_input(self, item: str, value: Any):
        self.inputs[item] = value

    def get_input(self, item) -> Any:
        return self.inputs[item]
