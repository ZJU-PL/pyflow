"""
AST Converter for converting Python AST to PyFlow AST.

This module handles the conversion of Python Abstract Syntax Trees
to PyFlow's internal AST representation for static analysis.
"""

import ast as python_ast
from typing import Any, List, Optional

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.program import Object
from pyflow.language.python.pythonbase import PythonASTNode


class ASTConverter:
    """Converts Python AST nodes to PyFlow AST nodes."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def convert_python_ast_to_pyflow(self, python_nodes: List[python_ast.AST]) -> pyflow_ast.Suite:
        """Convert Python AST nodes to pyflow AST nodes."""
        if not python_nodes:
            return pyflow_ast.Suite([])

        blocks = []
        for i, node in enumerate(python_nodes):
            converted = self._convert_node(node)
            if converted is not None:
                blocks.append(converted)

        return pyflow_ast.Suite(blocks)

    def _convert_node(self, node: python_ast.AST) -> Optional[PythonASTNode]:
        """Convert a single Python AST node to pyflow AST."""
        if isinstance(node, python_ast.Return):
            if node.value:
                expr = self._convert_expression(node.value)
                return pyflow_ast.Return([expr])
            else:
                return pyflow_ast.Return([])
        
        elif isinstance(node, python_ast.Assign):
            # Handle assignment: target = value
            targets = []
            for target in node.targets:
                if isinstance(target, python_ast.Name):
                    targets.append(pyflow_ast.Local(target.id))
                else:
                    # For more complex targets, create a generic local
                    targets.append(pyflow_ast.Local(f"target_{id(target)}"))
            
            value = self._convert_expression_safe(node.value)
            return pyflow_ast.Assign(value, targets)
        
        elif isinstance(node, python_ast.If):
            # Handle if statements
            condition = self._convert_expression_safe(node.test)
            
            then_body = self.convert_python_ast_to_pyflow(node.body)
            else_body = self.convert_python_ast_to_pyflow(node.orelse)
            
            # Create a Switch node for the condition
            return pyflow_ast.Switch(
                condition=pyflow_ast.Condition(pyflow_ast.Suite([]), condition),
                t=then_body,
                f=else_body
            )
        
        elif isinstance(node, python_ast.Expr):
            # Handle expression statements (like function calls)
            return pyflow_ast.Discard(self._convert_expression_safe(node.value))
        
        elif isinstance(node, python_ast.Pass):
            # Handle pass statements
            return pyflow_ast.Suite([])
        
        else:
            # For unhandled node types, create a generic discard
            if hasattr(node, 'value'):
                return pyflow_ast.Discard(self._convert_expression(node.value))
            else:
                return pyflow_ast.Suite([])

    def _convert_expression(self, node: python_ast.AST) -> PythonASTNode:
        """Convert Python AST expressions to pyflow AST expressions."""
        if isinstance(node, python_ast.Name):
            return pyflow_ast.Local(node.id)
        
        elif isinstance(node, python_ast.Constant):
            return pyflow_ast.Existing(Object(node.value))
        
        elif isinstance(node, python_ast.Num):  # Python < 3.8
            return pyflow_ast.Existing(Object(node.n))
        
        elif isinstance(node, python_ast.Str):  # Python < 3.8
            return pyflow_ast.Existing(Object(node.s))
        
        elif isinstance(node, python_ast.NameConstant):  # Python < 3.8
            return pyflow_ast.Existing(Object(node.value))
        
        elif isinstance(node, python_ast.Call):
            # Handle function calls
            func = self._convert_expression_safe(node.func)
            args = [self._convert_expression_safe(arg) for arg in node.args]
            keywords = []
            if node.keywords:
                for kw in node.keywords:
                    if kw.arg is not None:  # Skip **kwargs
                        converted_value = self._convert_expression_safe(kw.value)
                        keywords.append((kw.arg, converted_value))
            
            return pyflow_ast.Call(func, args, keywords, None, None)
        
        elif isinstance(node, python_ast.Compare):
            # Handle comparisons (==, !=, <, >, etc.)
            left = self._convert_expression(node.left)
            if len(node.ops) == 1 and len(node.comparators) == 1:
                op = node.ops[0]
                right = self._convert_expression(node.comparators[0])
                
                # Map Python comparison operators to pyflow operators
                op_map = {
                    python_ast.Eq: 'interpreter__eq__',
                    python_ast.NotEq: 'interpreter__ne__',
                    python_ast.Lt: 'interpreter__lt__',
                    python_ast.LtE: 'interpreter__le__',
                    python_ast.Gt: 'interpreter__gt__',
                    python_ast.GtE: 'interpreter__ge__',
                    python_ast.Is: 'interpreter__is__',
                    python_ast.IsNot: 'interpreter__is_not__',
                }
                
                if type(op) in op_map:
                    op_name = op_map[type(op)]
                    return pyflow_ast.Call(
                        pyflow_ast.Existing(Object(op_name)),
                        [left, right], [], None, None
                    )
            
            # Fallback for complex comparisons
            return pyflow_ast.Existing(Object(None))
        
        elif isinstance(node, python_ast.BinOp):
            # Handle binary operations (+, -, *, /, etc.)
            left = self._convert_expression(node.left)
            right = self._convert_expression(node.right)
            
            op_map = {
                python_ast.Add: 'interpreter__add__',
                python_ast.Sub: 'interpreter__sub__',
                python_ast.Mult: 'interpreter__mul__',
                python_ast.Div: 'interpreter__truediv__',
                python_ast.FloorDiv: 'interpreter__floordiv__',
                python_ast.Mod: 'interpreter__mod__',
                python_ast.Pow: 'interpreter__pow__',
            }
            
            if type(node.op) in op_map:
                op_name = op_map[type(node.op)]
                return pyflow_ast.Call(
                    pyflow_ast.Existing(Object(op_name)),
                    [left, right], [], None, None
                )
            
            # Fallback
            return pyflow_ast.Existing(Object(None))
        
        elif isinstance(node, python_ast.Subscript):
            # Handle array/list indexing: arr[index]
            value = self._convert_expression(node.value)
            if isinstance(node.slice, python_ast.Index):  # Python < 3.9
                index = self._convert_expression(node.slice.value)
            else:
                index = self._convert_expression(node.slice)
            
            return pyflow_ast.Call(
                pyflow_ast.Existing(Object('interpreter__getitem__')),
                [value, index], [], None, None
            )
        
        else:
            # Fallback for unhandled expressions
            return pyflow_ast.Existing(Object(None))
    
    def _convert_expression_safe(self, node: python_ast.AST) -> PythonASTNode:
        """Convert Python AST expressions to pyflow AST expressions with None protection."""
        result = self._convert_expression(node)
        if result is None:
            return pyflow_ast.Existing(Object(None))
        return result
