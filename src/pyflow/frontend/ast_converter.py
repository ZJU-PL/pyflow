"""
AST Converter for converting Python AST to PyFlow AST.

This module handles the conversion of Python Abstract Syntax Trees
to PyFlow's internal AST representation for static analysis.
"""

import ast as python_ast
from typing import Any, List, Optional, Tuple

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.program import Object
from pyflow.language.python.pythonbase import PythonASTNode
from pyflow.language.python.annotations import CodeAnnotation


class ASTConverter:
    """Converts Python AST nodes to PyFlow AST nodes."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def convert_python_ast_to_pyflow(
        self, python_nodes: List[python_ast.AST]
    ) -> pyflow_ast.Suite:
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
        if isinstance(node, python_ast.FunctionDef):
            # Handle function definitions
            return self._convert_function_def(node)

        elif isinstance(node, python_ast.ClassDef):
            # Handle class definitions
            return self._convert_class_def(node)

        elif isinstance(node, python_ast.Return):
            if node.value:
                expr = self._convert_expression(node.value)
                return pyflow_ast.Return([expr])
            else:
                return pyflow_ast.Return([])

        elif isinstance(node, python_ast.Assign):
            # Handle assignment: target = value
            targets = []
            for target in node.targets:
                targets.append(self._convert_assignment_target(target))

            value = self._convert_expression_safe(node.value)
            return pyflow_ast.Assign(value, targets)

        elif isinstance(node, python_ast.AugAssign):
            # Handle augmented assignment: target += value
            target = self._convert_assignment_target(node.target)
            value = self._convert_expression_safe(node.value)

            # Convert augmented assignment to regular assignment
            # This is a simplification - in a full implementation, we'd create SetAttr/SetSubscript nodes
            return pyflow_ast.Assign(value, [target])

        elif isinstance(node, python_ast.If):
            # Handle if statements
            condition = self._convert_expression_safe(node.test)

            then_body = self.convert_python_ast_to_pyflow(node.body)
            else_body = self.convert_python_ast_to_pyflow(node.orelse)

            # Create a Switch node for the condition
            return pyflow_ast.Switch(
                condition=pyflow_ast.Condition(pyflow_ast.Suite([]), condition),
                t=then_body,
                f=else_body,
            )

        elif isinstance(node, python_ast.Import):
            # Handle import statements
            return self._convert_import(node)

        elif isinstance(node, python_ast.ImportFrom):
            # Handle from ... import statements
            return self._convert_import_from(node)

        elif isinstance(node, python_ast.For):
            # Handle for loops
            return self._convert_for_loop(node)

        elif isinstance(node, python_ast.While):
            # Handle while loops
            return self._convert_while_loop(node)

        elif isinstance(node, python_ast.Break):
            # Handle break statements
            return pyflow_ast.Break()

        elif isinstance(node, python_ast.Continue):
            # Handle continue statements
            return pyflow_ast.Continue()

        elif isinstance(node, python_ast.Try):
            # Handle try-except-finally blocks
            return self._convert_try_except_finally(node)

        elif isinstance(node, python_ast.Raise):
            # Handle raise statements
            return self._convert_raise(node)

        elif isinstance(node, python_ast.Global):
            # Handle global statements
            return self._convert_global(node)

        elif isinstance(node, python_ast.Nonlocal):
            # Handle nonlocal statements
            return self._convert_nonlocal(node)

        elif isinstance(node, python_ast.Assert):
            # Handle assert statements
            return self._convert_assert(node)

        elif isinstance(node, python_ast.With):
            # Handle with statements (context managers)
            return self._convert_with(node)

        elif isinstance(node, python_ast.Expr):
            # Handle expression statements (like function calls)
            return pyflow_ast.Discard(self._convert_expression_safe(node.value))

        elif isinstance(node, python_ast.Pass):
            # Handle pass statements
            return pyflow_ast.Suite([])

        else:
            # For unhandled node types, create a generic discard
            if hasattr(node, "value"):
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
                    python_ast.Eq: "interpreter__eq__",
                    python_ast.NotEq: "interpreter__ne__",
                    python_ast.Lt: "interpreter__lt__",
                    python_ast.LtE: "interpreter__le__",
                    python_ast.Gt: "interpreter__gt__",
                    python_ast.GtE: "interpreter__ge__",
                    python_ast.Is: "interpreter__is__",
                    python_ast.IsNot: "interpreter__is_not__",
                }

                if type(op) in op_map:
                    op_name = op_map[type(op)]
                    return pyflow_ast.Call(
                        pyflow_ast.Existing(Object(op_name)),
                        [left, right],
                        [],
                        None,
                        None,
                    )

            # Fallback for complex comparisons
            return pyflow_ast.Existing(Object(None))

        elif isinstance(node, python_ast.BinOp):
            # Handle binary operations (+, -, *, /, etc.)
            left = self._convert_expression(node.left)
            right = self._convert_expression(node.right)

            op_map = {
                python_ast.Add: "interpreter__add__",
                python_ast.Sub: "interpreter__sub__",
                python_ast.Mult: "interpreter__mul__",
                python_ast.Div: "interpreter__truediv__",
                python_ast.FloorDiv: "interpreter__floordiv__",
                python_ast.Mod: "interpreter__mod__",
                python_ast.Pow: "interpreter__pow__",
            }

            if type(node.op) in op_map:
                op_name = op_map[type(node.op)]
                return pyflow_ast.Call(
                    pyflow_ast.Existing(Object(op_name)), [left, right], [], None, None
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
                pyflow_ast.Existing(Object("interpreter__getitem__")),
                [value, index],
                [],
                None,
                None,
            )

        elif isinstance(node, python_ast.Tuple):
            # Handle tuple creation: (a, b, c)
            elts = [self._convert_expression(elt) for elt in node.elts]
            return pyflow_ast.BuildTuple(elts)

        elif isinstance(node, python_ast.List):
            # Handle list creation: [a, b, c]
            elts = [self._convert_expression(elt) for elt in node.elts]
            return pyflow_ast.BuildList(elts)

        elif isinstance(node, python_ast.Dict):
            # Handle dict creation: {k1: v1, k2: v2}
            # BuildMap doesn't take arguments, so we'll use a generic approach
            return pyflow_ast.BuildMap()

        elif isinstance(node, python_ast.Set):
            # Handle set creation: {a, b, c}
            elts = [self._convert_expression(elt) for elt in node.elts]
            return pyflow_ast.BuildList(elts)  # Using BuildList as fallback for sets

        elif isinstance(node, python_ast.Attribute):
            # Handle attribute access: obj.attr
            value = self._convert_expression(node.value)
            # Create an Existing object for the attribute name
            attr_name = pyflow_ast.Existing(Object(node.attr))
            return pyflow_ast.GetAttr(value, attr_name)

        elif isinstance(node, python_ast.Lambda):
            # Handle lambda expressions
            args = self._convert_function_args(node.args)
            body = self._convert_expression(node.body)
            return pyflow_ast.MakeFunction(defaults=[], cells=[], code=body)

        else:
            # Fallback for unhandled expressions
            return pyflow_ast.Existing(Object(None))

    def _convert_expression_safe(self, node: python_ast.AST) -> PythonASTNode:
        """Convert Python AST expressions to pyflow AST expressions with None protection."""
        result = self._convert_expression(node)
        if result is None:
            return pyflow_ast.Existing(Object(None))
        return result

    def _convert_function_def(
        self, node: python_ast.FunctionDef
    ) -> Optional[PythonASTNode]:
        """Convert Python AST FunctionDef to pyflow AST."""
        # Convert function arguments
        codeparams = self._convert_function_args(node.args)

        # Convert function body
        body = self.convert_python_ast_to_pyflow(node.body)

        # Create Code object
        code = pyflow_ast.Code(node.name, codeparams, body)

        # Initialize annotation
        code.annotation = CodeAnnotation(
            contexts=None,
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=[f"converted_function({node.name})"],
            live=None,
            killed=None,
            codeReads=None,
            codeModifies=None,
            codeAllocates=None,
            lowered=False,
            runtime=False,
            interpreter=False,
        )

        # Wrap in FunctionDef node
        return pyflow_ast.FunctionDef(
            node.name,
            code,
            [
                self._convert_expression_safe(decorator)
                for decorator in node.decorator_list
            ],
        )

    def _convert_class_def(self, node: python_ast.ClassDef) -> Optional[PythonASTNode]:
        """Convert Python AST ClassDef to pyflow AST."""
        # Convert base classes
        bases = [self._convert_expression_safe(base) for base in node.bases]

        # Convert class body
        body = self.convert_python_ast_to_pyflow(node.body)

        # Wrap in ClassDef node
        return pyflow_ast.ClassDef(
            node.name,
            bases,
            body,
            [
                self._convert_expression_safe(decorator)
                for decorator in node.decorator_list
            ],
        )

    def _convert_function_args(
        self, args_node: python_ast.arguments
    ) -> pyflow_ast.CodeParameters:
        """Convert Python AST arguments to pyflow AST CodeParameters."""
        # Get default values
        defaults = []
        if args_node.defaults:
            for default in args_node.defaults:
                defaults.append(self._convert_expression_safe(default))

        # Get parameter names
        param_names = [arg.arg for arg in args_node.args]

        # Create Local objects for parameters
        params = [pyflow_ast.Local(name) for name in param_names]

        # Handle *args and **kwargs
        vararg = None
        if args_node.vararg:
            vararg = pyflow_ast.Local(args_node.vararg.arg)

        kwarg = None
        if args_node.kwarg:
            kwarg = pyflow_ast.Local(args_node.kwarg.arg)

        # Create CodeParameters object
        return pyflow_ast.CodeParameters(
            selfparam=None,
            params=params,
            paramnames=param_names,
            defaults=defaults,
            vparam=vararg,
            kparam=kwarg,
            returnparams=[],
        )

    def _convert_import(self, node: python_ast.Import) -> Optional[PythonASTNode]:
        """Convert Python AST Import to pyflow AST."""
        # For now, create a discard node as imports are typically handled at module level
        # In a full implementation, this would create Import nodes or affect module resolution
        return pyflow_ast.Discard(
            pyflow_ast.Existing(Object(f"import_{len(node.names)}"))
        )

    def _convert_import_from(
        self, node: python_ast.ImportFrom
    ) -> Optional[PythonASTNode]:
        """Convert Python AST ImportFrom to pyflow AST."""
        # For now, create a discard node as imports are typically handled at module level
        # In a full implementation, this would create Import nodes or affect module resolution
        return pyflow_ast.Discard(
            pyflow_ast.Existing(
                Object(f"from_import_{len(node.names) if node.names else 0}")
            )
        )

    def _convert_for_loop(self, node: python_ast.For) -> Optional[PythonASTNode]:
        """Convert Python AST For loop to pyflow AST."""
        # Convert target (what we're iterating over)
        # Handle tuple unpacking in for loops (e.g., for x, y in items)
        if isinstance(node.target, python_ast.Tuple):
            # For tuple unpacking, use the first element as index for now
            # In a full implementation, we'd need to handle multiple indices
            target = self._convert_expression(node.target.elts[0])
        else:
            target = self._convert_expression(node.target)

        # Convert iterator
        iter_expr = self._convert_expression(node.iter)

        # Convert loop body
        body = self.convert_python_ast_to_pyflow(node.body)

        # Convert else clause
        else_body = self.convert_python_ast_to_pyflow(node.orelse)

        # Create For loop node
        return pyflow_ast.For(
            iterator=iter_expr,
            index=target,
            loopPreamble=pyflow_ast.Suite([]),
            bodyPreamble=pyflow_ast.Suite([]),
            body=body,
            else_=else_body,
        )

    def _convert_while_loop(self, node: python_ast.While) -> Optional[PythonASTNode]:
        """Convert Python AST While loop to pyflow AST."""
        # Convert condition
        condition = self._convert_expression(node.test)

        # Convert loop body
        body = self.convert_python_ast_to_pyflow(node.body)

        # Convert else clause
        else_body = self.convert_python_ast_to_pyflow(node.orelse)

        # Create While loop node
        return pyflow_ast.While(
            condition=pyflow_ast.Condition(pyflow_ast.Suite([]), condition),
            body=body,
            else_=else_body,
        )

    def _convert_try_except_finally(
        self, node: python_ast.Try
    ) -> Optional[PythonASTNode]:
        """Convert Python AST Try block to pyflow AST."""
        # Convert try body
        try_body = self.convert_python_ast_to_pyflow(node.body)

        # Convert except handlers
        handlers = []
        for handler in node.handlers:
            if handler.type:
                # Convert exception type
                exc_type = self._convert_expression(handler.type)
            else:
                exc_type = None

            if handler.name:
                # Convert exception variable name
                exc_name = pyflow_ast.Local(handler.name)
            else:
                exc_name = None

            # Convert handler body
            handler_body = self.convert_python_ast_to_pyflow(handler.body)

            # Create exception handler
            exc_handler = pyflow_ast.ExceptionHandler(
                preamble=pyflow_ast.Suite([]),
                type=exc_type,
                value=exc_name,
                body=handler_body,
            )
            handlers.append(exc_handler)

        # Convert else clause
        else_body = self.convert_python_ast_to_pyflow(node.orelse)

        # Convert finally clause
        finally_body = self.convert_python_ast_to_pyflow(node.finalbody)

        # Create TryExceptFinally node
        return pyflow_ast.TryExceptFinally(
            body=try_body,
            handlers=handlers,
            defaultHandler=None,
            else_=else_body,
            finally_=finally_body,
        )

    def _convert_raise(self, node: python_ast.Raise) -> Optional[PythonASTNode]:
        """Convert Python AST Raise to pyflow AST."""
        exc = None
        if node.exc:
            exc = self._convert_expression(node.exc)

        cause = None
        if node.cause:
            cause = self._convert_expression(node.cause)

        return pyflow_ast.Raise(exception=exc, parameter=None, traceback=cause)

    def _convert_global(self, node: python_ast.Global) -> Optional[PythonASTNode]:
        """Convert Python AST Global to pyflow AST."""
        # For now, create a discard node as global statements are typically handled at module level
        return pyflow_ast.Discard(
            pyflow_ast.Existing(Object(f"global_{'_'.join(node.names)}"))
        )

    def _convert_nonlocal(self, node: python_ast.Nonlocal) -> Optional[PythonASTNode]:
        """Convert Python AST Nonlocal to pyflow AST."""
        # For now, create a discard node as nonlocal statements are typically handled at module level
        return pyflow_ast.Discard(
            pyflow_ast.Existing(Object(f"nonlocal_{'_'.join(node.names)}"))
        )

    def _convert_assert(self, node: python_ast.Assert) -> Optional[PythonASTNode]:
        """Convert Python AST Assert to pyflow AST."""
        test_expr = self._convert_expression(node.test)
        msg_expr = None
        if node.msg:
            msg_expr = self._convert_expression(node.msg)

        return pyflow_ast.Assert(test_expr, msg_expr)

    def _convert_with(self, node: python_ast.With) -> Optional[PythonASTNode]:
        """Convert Python AST With to pyflow AST."""
        # Convert context managers
        items = []
        for item in node.items:
            context_expr = self._convert_expression(item.context_expr)
            optional_vars = None
            if item.optional_vars:
                optional_vars = self._convert_expression(item.optional_vars)
            items.append((context_expr, optional_vars))

        # Convert with body
        body = self.convert_python_ast_to_pyflow(node.body)

        # For now, treat as a regular suite since pyflow may not have specific With support
        return body

    def _convert_assignment_target(self, target: python_ast.AST) -> PythonASTNode:
        """Convert Python AST assignment target to pyflow AST."""
        if isinstance(target, python_ast.Name):
            return pyflow_ast.Local(target.id)
        elif isinstance(target, python_ast.Attribute):
            # Handle obj.attr assignments
            obj = self._convert_expression(target.value)
            return pyflow_ast.Local(
                f"attr_{id(target)}"
            )  # Simplified - should use SetAttr
        elif isinstance(target, python_ast.Subscript):
            # Handle obj[key] assignments
            obj = self._convert_expression(target.value)
            if isinstance(target.slice, python_ast.Index):  # Python < 3.9
                index = self._convert_expression(target.slice.value)
            else:
                index = self._convert_expression(target.slice)
            return pyflow_ast.Local(
                f"subscript_{id(target)}"
            )  # Simplified - should use SetSubscript
        else:
            # For other complex targets, create a generic local
            return pyflow_ast.Local(f"target_{id(target)}")
