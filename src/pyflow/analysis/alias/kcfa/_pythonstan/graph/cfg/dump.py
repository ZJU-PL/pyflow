"""Flatten reachable CFG blocks into breadth-first statement order."""

import ast
from queue import Queue

from . import ControlFlowGraph, BaseBlock

def dump(cfg: ControlFlowGraph):
    """Return statements from blocks reachable from ``cfg``'s entry."""
    entry = cfg.get_entry()
    stmts = []
    visited = {*()}
    q = Queue()
    q.put(entry)
    while not q.empty():
        cur = q.get()
        for stmt in cur.stmts:
            stmts.append(stmt)
        for v in cfg.succs_of(cur):
            if v not in visited:
                visited.add(v)
                q.put(v)
    return stmts
