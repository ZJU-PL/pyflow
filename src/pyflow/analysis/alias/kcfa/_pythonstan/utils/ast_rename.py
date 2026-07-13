import copy
from typing import Tuple
import ast
from ast import NodeTransformer

__all__ = ["RenameTransformer"]


class RenameTransformer(NodeTransformer):
    old_name: str
    new_name: str
    ctxs: Tuple

    def __init__(self, old_name, new_name, ctxs):
        self.old_name = old_name
        self.new_name = new_name
        self.ctxs = ctxs

    def visit_Name(self, node: ast.Name):
        name = node
        if isinstance(node.ctx, self.ctxs) and name.id == self.old_name:
            name = copy.deepcopy(node)
            name.id = self.new_name
        return name

    def visit_alias(self, node):
        alias = node
        if isinstance(ast.Store(), self.ctxs):
            if alias.asname == self.old_name:
                alias = copy.deepcopy(node)
                alias.asname = self.new_name
            elif alias.asname is None and alias.name == self.old_name:
                alias = copy.deepcopy(node)
                alias.asname = self.new_name
        return alias
