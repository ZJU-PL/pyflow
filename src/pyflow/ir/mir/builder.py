"""Small CFG construction utilities for the Python-to-MIR frontend.

The builder is deliberately separate from the core language: branching is an
edge to two ``Assume`` nodes, and a return is a binding followed by an exit edge.
"""

from __future__ import annotations

from typing import Iterable

from .model import (
    Alloc,
    Assume,
    Attr,
    Bind,
    Call,
    CFG,
    DictExpr,
    Lambda,
    ListExpr,
    Literal,
    Node,
    Not,
    Program,
    Skip,
    Var,
)


def field(base, key):
    return Attr(base, Literal(key) if isinstance(key, (str, int, bool)) else key)


class Builder:
    """Build one-instruction-per-node MIR with explicit successors."""

    def __init__(self, program: Program, name: str, filename="", synthetic=False):
        self.program = program
        self.cfg = CFG(
            name=name, nodes={}, entry=0, exit=1, is_synthetic=synthetic, filename=filename
        )
        self.cfg.nodes[0] = Node(0, Skip(), ())
        self.cfg.nodes[1] = Node(1, Skip(), ())
        self.program.cfgs[name] = self.cfg
        self.tails = {0}
        self.counter = 0
        self.lineno = None

    @property
    def name(self):
        return self.cfg.name

    def temp(self, hint="tmp"):
        self.counter += 1
        return f"${hint}{self.counter}"

    def node(self, instruction=None):
        index = len(self.cfg.nodes)
        self.cfg.nodes[index] = Node(index, instruction or Skip(), (), self.lineno)
        return index

    def connect(self, sources: Iterable[int], target: int):
        for source in sources:
            node = self.cfg.nodes[source]
            node.successors = tuple(dict.fromkeys((*node.successors, target)))

    def emit(self, instruction):
        node = self.node(instruction)
        self.connect(self.tails, node)
        self.tails = {node}
        return node

    def alloc(self, value, hint="tmp"):
        name = self.temp(hint)
        self.emit(Alloc(name, value))
        return Var(name)

    def bind(self, value, hint="alias"):
        name = self.temp(hint)
        self.emit(Bind(Var(name), value))
        return Var(name)

    def assign(self, target, value):
        self.emit(Bind(target if not isinstance(target, str) else Var(target), value))

    def branch(self, condition):
        yes = self.node(Assume(condition))
        no = self.node(Assume(Not(condition)))
        self.connect(self.tails, yes)
        self.connect(self.tails, no)
        self.tails = set()
        return {yes}, {no}

    def use(self, tails):
        self.tails = set(tails)

    def jump(self, target):
        self.connect(self.tails, target)
        self.tails = set()

    def join(self, *tails):
        self.tails = set().union(*tails)

    def call(self, function, args, kwargs):
        target = self.temp("call")
        self.emit(Call(target, function, args, kwargs))
        return Var(target)

    def invoke(self, body: str, args=(), kwargs=None):
        closure = self.alloc(Lambda("$args", "$kwargs", "$parent", body, "$return"), "closure")
        positional = self.alloc(ListExpr(tuple(args)), "args")
        keywords = kwargs if kwargs is not None else self.alloc(DictExpr(()), "kwargs")
        return self.call(closure, positional, keywords)

    def ret(self, value):
        self.assign("$return", value)
        self.jump(self.cfg.exit)

    def finish(self):
        self.connect(self.tails, self.cfg.exit)
        self.tails = set()
        return self.cfg
