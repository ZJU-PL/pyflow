from typing import Dict, List, Collection, Set

from .graph import Graph, Node


class DominatorTree:
    graph: Graph
    is_post: bool
    dfn: Dict[Node, int]
    idom: Dict[Node, Node]
    sdom: Dict[Node, Node]
    father: Dict[Node, Node]
    nodes: List[Node]
    f: Dict[Node, Node]
    ran: Dict[Node, Node]
    df: Dict[Node, Set[Node]]

    def __init__(self, graph: Graph, is_post: bool = False):
        self.graph = graph
        self.is_post = is_post

        self.reset()
        self.lengauer_tarjan()
        self.gen_df()

    def reset(self):
        self.idom = {}
        self.df = {}

        self.dfn = {}
        self.father = {}
        self.nodes = []
        start = self.get_entry()
        self.dfs(start)

        self.sdom = {}
        self.f = {}
        self.ran = {}
        for u in self.nodes:
            self.sdom[u] = self.f[u] = self.ran[u] = u
            self.df[u] = {*()}

    def get_entry(self) -> Node:
        if not self.is_post:
            return self.graph.get_entry()
        else:
            return self.graph.get_exit()

    def succs_of(self, node: Node) -> Collection[Node]:
        if self.is_post:
            return self.graph.preds_of(node)
        else:
            return self.graph.succs_of(node)

    def preds_of(self, node: Node) -> Collection[Node]:
        if self.is_post:
            return self.graph.succs_of(node)
        else:
            return self.graph.preds_of(node)

    def dfs(self, u: Node):
        self.dfn[u] = len(self.nodes)
        self.nodes.append(u)
        for v in self.succs_of(u):
            if v not in self.dfn:
                self.father[v] = u
                self.dfs(v)

    def sdom_min(self, u: Node, v: Node) -> Node:
        u_idx = self.dfn[self.sdom[u]]
        v_idx = self.dfn[self.sdom[v]]
        return u if u_idx <= v_idx else v

    def merge(self, u: Node):
        if self.f[u] == u:
            return u
        res = self.merge(self.f[u])
        self.ran[u] = self.sdom_min(self.ran[u], self.ran[self.f[u]])
        self.f[u] = res
        return res

    def lengauer_tarjan(self):
        tr = {}
        for u in self.nodes[::-1]:
            if u != self.get_entry():
                for v in self.preds_of(u):
                    if v in self.dfn:
                        self.merge(v)
                        self.sdom[u] = self.sdom[self.sdom_min(u, self.ran[v])]

                self.f[u] = self.father[u]
                if self.sdom[u] in tr:
                    tr[self.sdom[u]].append(u)
                else:
                    tr[self.sdom[u]] = [u]
                fa = self.father[u]
                if fa in tr:
                    for v in tr[fa]:
                        self.merge(v)
                        if fa == self.sdom[self.ran[v]]:
                            self.idom[v] = fa
                        else:
                            self.idom[v] = self.ran[v]
                tr[fa] = []

        for u in self.nodes[1::]:
            if self.idom[u] != self.sdom[u]:
                self.idom[u] = self.idom[self.idom[u]]

    def gen_df(self):
        entry = self.get_entry()
        for u in self.nodes:
            if u == entry:
                continue
            if len(self.preds_of(u)) > 1:
                for pred in self.preds_of(u):
                    runner = pred
                    while runner != self.idom[u]:
                        self.df[runner].add(u)
                        runner = self.idom[runner]

    def intermediate_dominator(self, u: Node) -> Node:
        return self.idom[u]

    def dominance_frontier(self, u: Node) -> Collection[Node]:
        return self.df[u]
