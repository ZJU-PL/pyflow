from typing import List, Optional, Set

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRStatement, Label
from ..graph import Node

__all__ = ["BaseBlock"]


class BaseBlock(Node):
    idx: int
    only_pass: bool
    stmts: List[IRStatement]

    def __init__(self, idx: int, stmts: Optional[List[IRStatement]] = None):
        self.idx = idx
        if stmts is None:
            self.stmts = []
        else:
            self.stmts = stmts

    def get_stmts(self):
        return self.stmts

    def get_idx(self):
        return self.idx

    def get_name(self) -> str:
        return f"[{self.idx}]"

    def add(self, stmt: IRStatement):
        self.stmts.append(stmt)

    def add_front(self, stmt: IRStatement):
        if self.n_stmt() > 0 and isinstance(self.stmts[0], Label):
            self.stmts.insert(1, stmt)
        else:
            self.stmts.insert(0, stmt)

    def n_stmt(self) -> int:
        return len(self.stmts)

    def get_stores(self) -> Set[str]:
        stores = {*()}
        for stmt in self.stmts:
            stores.update(stmt.get_stores())
        return stores

    def get_loads(self) -> Set[str]:
        loads = {*()}
        for stmt in self.stmts:
            loads.update(stmt.get_loads())
        return loads

    def get_dels(self) -> Set[str]:
        dels = {*()}
        for stmt in self.stmts:
            dels.update(stmt.get_dels())
        return dels

    def __str__(self):
        head = self.get_name()
        stmts_str = '\\n'.join([str(s) for s in self.stmts])
        return '\\n'.join([head, stmts_str])

    def __repr__(self):
        head = self.get_name()
        stmts_str = '\\n'.join([str(s) for s in self.stmts])
        return '\\n'.join([head, stmts_str])

    def gen_label(self) -> Label:
        if self.n_stmt() > 0 and isinstance(self.stmts[0], Label):
            return self.stmts[0]
        else:
            label = Label(self.get_idx())
            self.add_front(label)
            return label

    def __lt__(self, other: 'BaseBlock') -> bool:
        if self.n_stmt() == 0:
            return True
        if other.n_stmt() == 0:
            return False
        return self.stmts[0] < other.stmts[0]
