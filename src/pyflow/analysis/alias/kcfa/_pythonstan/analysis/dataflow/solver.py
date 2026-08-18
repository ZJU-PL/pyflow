from typing import Generic, TypeVar, Tuple, Dict, Type
from abc import ABC, abstractmethod
from collections import deque

from .analysis import DataflowAnalysis
from pyflow.analysis.alias.kcfa._pythonstan.graph.cfg import BaseBlock


Fact = TypeVar("Fact")


class Solver(Generic[Fact], ABC):
    solver_dict: Dict[str, 'Type[Solver[Fact]]'] = {}

    def __init_subclass__(cls) -> None:
        cls.solver_dict[cls.__name__] = cls

    @classmethod
    def get_solver(cls, id):
        return cls.solver_dict[id]

    @classmethod
    def init(cls, analysis: DataflowAnalysis[Fact]
             ) -> Tuple[Dict[BaseBlock, Fact], Dict[BaseBlock, Fact]]:
        if analysis.is_forward:
            in_facts, out_facts = cls.init_forward(analysis)
        else:
            in_facts, out_facts = cls.init_backward(analysis)
        return in_facts, out_facts

    @classmethod
    def init_forward(cls, analysis: DataflowAnalysis[Fact]
                     ) -> Tuple[Dict[BaseBlock, Fact], Dict[BaseBlock, Fact]]:
        in_facts, out_facts = {}, {}
        cfg = analysis.get_cfg()
        for node in cfg.blks:
            if node == cfg.entry_blk:
                in_facts[node] = analysis.new_boundary_fact()
                out_facts[node] = analysis.new_boundary_fact()
            else:
                in_facts[node] = analysis.new_init_fact()
                out_facts[node] = analysis.new_init_fact()
        return in_facts, out_facts

    @classmethod
    def init_backward(cls, analysis: DataflowAnalysis[Fact]
                      ) -> Tuple[Dict[BaseBlock, Fact], Dict[BaseBlock, Fact]]:
        in_facts, out_facts = {}, {}
        cfg = analysis.cfg
        for node in cfg.blks:
            if node == cfg.super_exit_blk:
                in_facts[node] = analysis.new_boundary_fact()
                out_facts[node] = analysis.new_boundary_fact()
            else:
                in_facts[node] = analysis.new_init_fact()
                out_facts[node] = analysis.new_init_fact()
        return in_facts, out_facts

    @classmethod
    def solve(cls, analysis: DataflowAnalysis[Fact]):
        in_facts, out_facts = cls.init(analysis)
        if analysis.is_forward:
            cls.solve_forward(analysis, in_facts, out_facts)
        else:
            cls.solve_backward(analysis, in_facts, out_facts)
        return in_facts, out_facts

    @classmethod
    @abstractmethod
    def solve_forward(cls, analysis: DataflowAnalysis[Fact],
                      in_facts: Dict[BaseBlock, Fact],
                      out_facts: Dict[BaseBlock, Fact]):
        pass

    @classmethod
    @abstractmethod
    def solve_backward(cls, analysis: DataflowAnalysis[Fact],
                       in_facts: Dict[BaseBlock, Fact],
                       out_facts: Dict[BaseBlock, Fact]):
        pass


class WorklistSolver(Generic[Fact], Solver[Fact]):
    @classmethod
    def _cfg_postorder(cls, cfg) -> list[BaseBlock]:
        """Return a successor DFS postorder covering every CFG block."""
        postorder = []
        visited = set()

        def visit(root):
            visited.add(root)
            stack = [(root, iter(cfg.succs_of(root)))]
            while stack:
                node, successors = stack[-1]
                try:
                    successor = next(successors)
                except StopIteration:
                    postorder.append(node)
                    stack.pop()
                    continue
                if successor not in visited:
                    visited.add(successor)
                    stack.append((successor, iter(cfg.succs_of(successor))))

        visit(cfg.entry_blk)
        for block in cfg.blks:
            if block not in visited:
                visit(block)
        return postorder

    @classmethod
    def init_forward(cls, analysis: DataflowAnalysis[Fact]
                     ) -> Tuple[Dict[BaseBlock, Fact], Dict[BaseBlock, Fact]]:
        in_facts, out_facts = {}, {}
        cfg = analysis.get_cfg()
        for node in cfg.blks:
            if node == cfg.entry_blk:
                in_facts[node] = analysis.new_boundary_fact()
                out_facts[node] = analysis.new_boundary_fact()
            else:
                if cfg.in_degree_of(node) == 1:
                    e = cfg.in_edges_of(node)[0]
                    if not analysis.need_transfer_edge(e):
                        src = e.src
                        if src not in out_facts:
                            out_facts[src] = analysis.new_init_fact()
                        in_facts[node] = out_facts[src]
                else:
                    in_facts[node] = analysis.new_init_fact()
                if node not in out_facts:
                    out_facts[node] = analysis.new_init_fact()
        return in_facts, out_facts

    @classmethod
    def solve_forward(cls, analysis: DataflowAnalysis[Fact],
                      in_facts: Dict[BaseBlock, Fact],
                      out_facts: Dict[BaseBlock, Fact]):
        cfg = analysis.get_cfg()
        postorder = cls._cfg_postorder(cfg)
        work_list = deque(
            blk for blk in reversed(postorder) if blk != cfg.entry_blk
        )
        queued = set(work_list)
        while work_list:
            cur = work_list.popleft()
            queued.remove(cur)
            fact_in = in_facts[cur]
            if cfg.in_degree_of(cur) > 0:
                for e in cfg.in_edges_of(cur):
                    fact = out_facts[e.src]
                    if analysis.need_transfer_edge(e):
                        fact = analysis.transfer_edge(e, fact)
                    fact_in = analysis.meet(fact, fact_in)
            in_facts[cur] = fact_in
            fact_out = analysis.transfer_node(cur, fact_in)
            if fact_out != out_facts[cur]:
                out_facts[cur] = fact_out
                for succ in cfg.succs_of(cur):
                    if succ not in queued:
                        queued.add(succ)
                        work_list.append(succ)

    @classmethod
    def init_backward(cls, analysis: DataflowAnalysis[Fact]
                      ) -> Tuple[Dict[BaseBlock, Fact], Dict[BaseBlock, Fact]]:
        in_facts, out_facts = {}, {}
        cfg = analysis.get_cfg()
        for node in cfg.blks:
            if node == cfg.super_exit_blk:
                in_facts[node] = analysis.new_boundary_fact()
                out_facts[node] = analysis.new_boundary_fact()
            else:
                if cfg.out_degree_of(node) == 1:
                    e = cfg.out_edges_of(node)[0]
                    if not analysis.need_transfer_edge(e):
                        tgt = e.get_tgt()
                        if tgt not in in_facts:
                            in_facts[tgt] = analysis.new_init_fact()
                        out_facts[node] = in_facts[tgt]
                else:
                    out_facts[node] = analysis.new_init_fact()
                if node not in in_facts:
                    in_facts[node] = analysis.new_init_fact()
        return in_facts, out_facts

    @classmethod
    def solve_backward(cls, analysis: DataflowAnalysis[Fact],
                       in_facts: Dict[BaseBlock, Fact],
                       out_facts: Dict[BaseBlock, Fact]):
        cfg = analysis.get_cfg()
        postorder = cls._cfg_postorder(cfg)
        work_list = deque(
            blk for blk in postorder if blk != cfg.super_exit_blk
        )
        queued = set(work_list)
        while work_list:
            cur = work_list.popleft()
            queued.remove(cur)
            fact_out = out_facts[cur]
            if cfg.out_degree_of(cur) > 0:
                for e in cfg.out_edges_of(cur):
                    fact = in_facts[e.tgt]
                    if analysis.need_transfer_edge(e):
                        fact = analysis.transfer_edge(e, fact)
                    fact_out = analysis.meet(fact, fact_out)
            out_facts[cur] = fact_out
            fact_in = analysis.transfer_node(cur, fact_out)
            if fact_in != in_facts[cur]:
                in_facts[cur] = fact_in
                for pred in cfg.preds_of(cur):
                    if pred not in queued:
                        queued.add(pred)
                        work_list.append(pred)
