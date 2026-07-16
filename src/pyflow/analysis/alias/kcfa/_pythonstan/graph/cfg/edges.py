import ast
from abc import ABC, abstractmethod
from typing import Set

from pyflow.analysis.alias.kcfa._pythonstan.ir import IRScope
from ..graph import Edge, Node
from .base_block import BaseBlock

__all__ = ["CFGEdge", "NormalEdge", "IfEdge",
           "WhileEdge", "WhileElseEdge",
           "WithEdge", "WithEndEdge",
           "ExceptionEdge", "ExceptionEndEdge",
           "FinallyEdge", "FinallyEndEdge",
           "CallEdge", "ReturnEdge", "CallToReturnEdge"]


class CFGEdge(Edge):
    src: BaseBlock
    tgt: BaseBlock

    @abstractmethod
    def __init__(self, src, tgt):
        self.src = src
        self.tgt = tgt

    def set_src(self, node: Node):
        assert isinstance(node, BaseBlock)
        self.src = node

    def set_tgt(self, node: Node):
        assert isinstance(node, BaseBlock)
        self.tgt = node

    def get_src(self) -> BaseBlock:
        return self.src

    def get_tgt(self) -> BaseBlock:
        return self.tgt

    def get_name(self) -> str:
        return ""


class NormalEdge(CFGEdge):
    def __init__(self, src, tgt):
        super().__init__(src, tgt)


class IfEdge(CFGEdge):
    test: str
    value: bool

    def __init__(self, src, tgt, test_expr, value):
        assert isinstance(test_expr, ast.Name), f"The test variable of IfEdge should be ast.Name! {ast.dump(test_expr)}:{type(test_expr)} got"
        super().__init__(src, tgt)
        self.test = test_expr.id
        self.value = value

    def get_name(self) -> str:
        return f"if_{self.test}_is_{self.value}"


class CallEdge(CFGEdge):
    scope: IRScope

    def __init__(self, src, tgt, scope: IRScope):
        super().__init__(src, tgt)
        self.scope = scope

    def get_callee(self) -> IRScope:
        return self.scope


class ReturnEdge(CFGEdge):
    call_site: BaseBlock
    ret_vars: Set[ast.Expr]

    def __init__(self, src, tgt, call_site: BaseBlock, ret_vars: Set[ast.Expr]):
        super().__init__(src, tgt)
        self.call_site = call_site
        self.ret_vars = ret_vars

    def get_ret_vars(self) -> Set[ast.Expr]:
        return self.ret_vars

    def get_call_site(self) -> BaseBlock:
        return self.call_site


class CallToReturnEdge(CFGEdge):
    def __init__(self, src, tgt):
        super().__init__(src, tgt)


class WhileEdge(CFGEdge):
    def __init__(self, start, end):
        super().__init__(start, end)

    def get_name(self) -> str:
        return "while"


class WhileElseEdge(CFGEdge):
    def __init__(self, start, end):
        super().__init__(start, end)

    def get_name(self) -> str:
        return "while_else"


class WithEdge(CFGEdge):
    def __init__(self, start, end, var):
        super().__init__(start, end)
        self.var = var

    def get_name(self) -> str:
        return "with"


class WithEndEdge(CFGEdge):
    def __init__(self, start, end, var):
        super().__init__(start, end)
        self.var = var

    def get_name(self) -> str:
        return "with_end"


class ExceptionEdge(CFGEdge):
    def __init__(self, start, end, e):
        super().__init__(start, end)
        self.e = e

    def get_name(self) -> str:
        return ast.unparse(self.e)


class ExceptionEndEdge(CFGEdge):
    def __init__(self, start, end, e):
        super().__init__(start, end)
        self.e = e

    def get_name(self) -> str:
        return "end: " + ast.unparse(self.e)


class FinallyEdge(CFGEdge):
    def __init__(self, start, end, stmt):
        super().__init__(start, end)
        self.stmt = stmt

    def get_name(self) -> str:
        return "finally"


class FinallyEndEdge(CFGEdge):
    def __init__(self, start, end, stmt):
        super().__init__(start, end)
        self.stmt = stmt

    def get_name(self) -> str:
        return "finally_end"
