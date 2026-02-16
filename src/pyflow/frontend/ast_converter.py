"""
AST Converter for converting Python AST to PyFlow AST.

This module handles the conversion of Python Abstract Syntax Trees
to PyFlow's internal AST representation for static analysis.

Supported Python features:
- Python 3.7+ core syntax
- Async/await (Python 3.5+)
- Walrus operator / NamedExpr (Python 3.8+)
- Pattern matching / match-case (Python 3.10+)
- Type annotations (AnnAssign)
"""

import ast as python_ast
import sys
from typing import Any, List, Optional, Set, Tuple

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.program import Object
from pyflow.language.python.pythonbase import PythonASTNode
from pyflow.language.python.annotations import CodeAnnotation


HAS_MATCH = sys.version_info >= (3, 10)
HAS_NAMED_EXPR = sys.version_info >= (3, 8)
HAS_EXCEPTION_GROUP = sys.version_info >= (3, 11)


class ASTConverter:
    """Converts Python AST nodes to PyFlow AST nodes."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def _tmp_local(self, hint: str, node: python_ast.AST) -> pyflow_ast.Local:
        return pyflow_ast.Local(f"__pyflow_tmp_{hint}_{id(node)}")

    def _call_named(
        self,
        name: str,
        args: List[PythonASTNode],
        *,
        kwds: Optional[list] = None,
        vargs: Optional[PythonASTNode] = None,
        kargs: Optional[PythonASTNode] = None,
    ) -> pyflow_ast.Call:
        return pyflow_ast.Call(
            pyflow_ast.Existing(Object(name)),
            args,
            kwds or [],
            vargs,
            kargs,
        )

    def _convert_subscript_index(self, slice_node: python_ast.AST) -> PythonASTNode:
        sl = slice_node
        if isinstance(sl, python_ast.Index):  # Python < 3.9
            sl = sl.value
        if isinstance(sl, python_ast.Slice):
            start = self._convert_expression_safe(sl.lower) if sl.lower else None
            stop = self._convert_expression_safe(sl.upper) if sl.upper else None
            step = self._convert_expression_safe(sl.step) if sl.step else None
            return pyflow_ast.BuildSlice(start, stop, step)
        return self._convert_expression_safe(sl)

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
        if isinstance(node, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
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
            return self._convert_assign(node)

        elif isinstance(node, python_ast.AugAssign):
            return self._convert_augassign(node)

        elif isinstance(node, python_ast.AnnAssign):
            # Handle annotated assignment: x: int = 5 or x: int
            return self._convert_annassign(node)
        
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
        
        elif hasattr(python_ast, "AsyncFor") and isinstance(node, python_ast.AsyncFor):
            # Handle async for loops
            return self._convert_async_for(node)

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
        
        elif hasattr(python_ast, "AsyncWith") and isinstance(node, python_ast.AsyncWith):
            # Handle async with statements
            return self._convert_async_with(node)

        elif isinstance(node, python_ast.Expr):
            # Handle expression statements (like function calls)
            return pyflow_ast.Discard(self._convert_expression_safe(node.value))

        elif isinstance(node, python_ast.Delete):
            # Handle deletes (locals vs. attributes/subscripts).
            suite = pyflow_ast.Suite([])
            for target in node.targets:
                stmt = self._convert_delete_target(target)
                if stmt is not None:
                    suite.append(stmt)
            return suite
        
        elif hasattr(python_ast, "Match") and isinstance(node, python_ast.Match):
            # Handle pattern matching (Python 3.10+)
            return self._convert_match(node)
        
        elif hasattr(python_ast, "TryStar") and isinstance(node, python_ast.TryStar):
            # Handle exception groups (Python 3.11+)
            return self._convert_try_star(node)

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
            args: List[PythonASTNode] = []
            vargs: Optional[PythonASTNode] = None
            for arg in node.args:
                if isinstance(arg, python_ast.Starred):
                    star = self._convert_expression_safe(arg.value)
                    if vargs is None:
                        vargs = star
                    else:
                        # Approximate multiple *args by packing them into a list.
                        vargs = pyflow_ast.BuildList([vargs, star])
                else:
                    args.append(self._convert_expression_safe(arg))

            keywords = []
            kargs: Optional[PythonASTNode] = None
            if node.keywords:
                for kw in node.keywords:
                    converted_value = self._convert_expression_safe(kw.value)
                    if kw.arg is None:
                        # **kwargs
                        if kargs is None:
                            kargs = converted_value
                        else:
                            # Multiple **kwargs: conservative approximation.
                            kargs = pyflow_ast.BuildMap()
                    else:
                        keywords.append((kw.arg, converted_value))

            return pyflow_ast.Call(func, args, keywords, vargs, kargs)

        elif isinstance(node, python_ast.Starred):
            # Starred expressions are only valid in certain contexts (call args, unpacking).
            # When encountered directly, approximate by returning the underlying value.
            return self._convert_expression_safe(node.value)

        elif isinstance(node, python_ast.UnaryOp):
            operand = self._convert_expression_safe(node.operand)
            if isinstance(node.op, python_ast.Not):
                return pyflow_ast.Not(operand)
            # Represent unary ops using the same "interpreter_*" call convention as BinOp/Compare,
            # because downstream analyses don't universally handle UnaryPrefixOp nodes.
            if isinstance(node.op, python_ast.UAdd):
                return pyflow_ast.Call(
                    pyflow_ast.Existing(Object("interpreter__pos__")),
                    [operand],
                    [],
                    None,
                    None,
                )
            if isinstance(node.op, python_ast.USub):
                return pyflow_ast.Call(
                    pyflow_ast.Existing(Object("interpreter__neg__")),
                    [operand],
                    [],
                    None,
                    None,
                )
            if isinstance(node.op, python_ast.Invert):
                return pyflow_ast.Call(
                    pyflow_ast.Existing(Object("interpreter__invert__")),
                    [operand],
                    [],
                    None,
                    None,
                )
            return pyflow_ast.Existing(Object(None))

        elif isinstance(node, python_ast.Compare):
            # Handle comparisons (==, !=, <, >, etc.)
            left = self._convert_expression_safe(node.left)
            if len(node.ops) != len(node.comparators) or not node.ops:
                return pyflow_ast.Existing(Object(None))

            def single(
                op: python_ast.AST, a: PythonASTNode, b: PythonASTNode
            ) -> PythonASTNode:
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
                    return self._call_named(op_map[type(op)], [a, b])
                if isinstance(op, python_ast.In):
                    return self._call_named("interpreter__contains__", [b, a])
                if isinstance(op, python_ast.NotIn):
                    return pyflow_ast.Not(
                        self._call_named("interpreter__contains__", [b, a])
                    )
                return pyflow_ast.Existing(Object(None))

            comps: List[PythonASTNode] = []
            cur_left = left
            for op, right_node in zip(node.ops, node.comparators):
                right = self._convert_expression_safe(right_node)
                comps.append(single(op, cur_left, right))
                cur_left = right

            if len(comps) == 1:
                return comps[0]

            # Chained comparisons: approximate by conjunction of each comparison.
            expr = comps[0]
            for c in comps[1:]:
                expr = self._call_named("interpreter_booland", [expr, c])
            return expr

        elif isinstance(node, python_ast.BinOp):
            # Handle binary operations (+, -, *, /, etc.)
            left = self._convert_expression(node.left)
            right = self._convert_expression(node.right)

            op_map = {
                python_ast.Add: "interpreter__add__",
                python_ast.Sub: "interpreter__sub__",
                python_ast.Mult: "interpreter__mul__",
                python_ast.Div: "interpreter__div__",
                python_ast.FloorDiv: "interpreter__floordiv__",
                python_ast.Mod: "interpreter__mod__",
                python_ast.Pow: "interpreter__pow__",
                python_ast.BitAnd: "interpreter__and__",
                python_ast.BitOr: "interpreter__or__",
                python_ast.BitXor: "interpreter__xor__",
                python_ast.LShift: "interpreter__lshift__",
                python_ast.RShift: "interpreter__rshift__",
            }

            if type(node.op) in op_map:
                op_name = op_map[type(node.op)]
                return self._call_named(op_name, [left, right])

            # Fallback
            return pyflow_ast.Existing(Object(None))

        elif isinstance(node, python_ast.Subscript):
            value = self._convert_expression(node.value)
            index = self._convert_subscript_index(node.slice)
            return self._call_named("interpreter_getitem", [value, index])

        elif isinstance(node, python_ast.Tuple):
            # Handle tuple creation: (a, b, c)
            elts = [self._convert_expression(elt) for elt in node.elts]
            return pyflow_ast.BuildTuple(elts)

        elif isinstance(node, python_ast.List):
            # Handle list creation: [a, b, c]
            elts = [self._convert_expression(elt) for elt in node.elts]
            return pyflow_ast.BuildList(elts)

        elif isinstance(node, python_ast.Dict):
            # Prefer literal evaluation when possible to keep constant dicts precise.
            try:
                value = python_ast.literal_eval(node)
                return pyflow_ast.Existing(Object(value))
            except Exception:
                return pyflow_ast.BuildMap()

        elif isinstance(node, python_ast.Set):
            # Handle set creation: {a, b, c}
            try:
                value = python_ast.literal_eval(node)
                return pyflow_ast.Existing(Object(value))
            except Exception:
                elts = [self._convert_expression(elt) for elt in node.elts]
                return pyflow_ast.BuildList(elts)  # Fallback approximation

        elif isinstance(node, python_ast.Attribute):
            # Handle attribute access: obj.attr
            value = self._convert_expression(node.value)
            # Create an Existing object for the attribute name
            attr_name = pyflow_ast.Existing(Object(node.attr))
            return pyflow_ast.GetAttr(value, attr_name)

        elif isinstance(node, python_ast.BoolOp):
            # Approximate boolean ops using helper stubs (no short-circuit).
            values = [self._convert_expression_safe(v) for v in node.values]
            if not values:
                return pyflow_ast.Existing(Object(None))
            if isinstance(node.op, python_ast.And):
                op_name = "interpreter_booland"
            elif isinstance(node.op, python_ast.Or):
                op_name = "interpreter_boolor"
            else:
                return pyflow_ast.Existing(Object(None))
            expr: PythonASTNode = values[0]
            for v in values[1:]:
                expr = self._call_named(op_name, [expr, v])
            return expr

        elif isinstance(node, python_ast.IfExp):
            # Ternary expression: a if cond else b (approximate via helper stub).
            test = self._convert_expression_safe(node.test)
            body = self._convert_expression_safe(node.body)
            orelse = self._convert_expression_safe(node.orelse)
            return self._call_named("interpreter_ifexp", [test, body, orelse])

        elif isinstance(node, python_ast.JoinedStr):
            # f-strings: try to constant-evaluate, otherwise approximate.
            try:
                value = python_ast.literal_eval(node)
                return pyflow_ast.Existing(Object(value))
            except Exception:
                return pyflow_ast.Existing(Object(None))

        elif isinstance(node, python_ast.FormattedValue):
            return self._convert_expression_safe(node.value)

        elif isinstance(node, python_ast.Yield):
            expr = (
                self._convert_expression_safe(node.value)
                if node.value
                else pyflow_ast.Existing(Object(None))
            )
            return pyflow_ast.Yield(expr)

        elif isinstance(node, python_ast.YieldFrom):
            expr = self._convert_expression_safe(node.value)
            return pyflow_ast.Yield(expr)

        elif isinstance(node, python_ast.ListComp):
            # Approximate comprehensions as a singleton list of the element.
            return pyflow_ast.BuildList([self._convert_expression_safe(node.elt)])

        elif isinstance(node, python_ast.SetComp):
            try:
                value = python_ast.literal_eval(node)
                return pyflow_ast.Existing(Object(value))
            except Exception:
                return pyflow_ast.BuildList([self._convert_expression_safe(node.elt)])

        elif isinstance(node, python_ast.DictComp):
            try:
                value = python_ast.literal_eval(node)
                return pyflow_ast.Existing(Object(value))
            except Exception:
                return pyflow_ast.BuildMap()

        elif isinstance(node, python_ast.GeneratorExp):
            return pyflow_ast.Existing(Object(None))

        elif hasattr(python_ast, "NamedExpr") and isinstance(node, python_ast.NamedExpr):
            # Handle walrus operator (:=) - Python 3.8+
            return self._convert_named_expr(node)
        
        elif hasattr(python_ast, "Await") and isinstance(node, python_ast.Await):
            # Handle await expression - Python 3.5+
            return self._convert_await(node)

        elif isinstance(node, python_ast.Lambda):
            # Handle lambda expressions
            codeparams = self._convert_function_args(node.args, ensure_return=True)
            body_expr = self._convert_expression_safe(node.body)
            suite = pyflow_ast.Suite([pyflow_ast.Return([body_expr])])
            code = pyflow_ast.Code(f"<lambda_{id(node)}>", codeparams, suite)
            code.annotation = CodeAnnotation(
                contexts=None,
                descriptive=False,
                primitive=False,
                staticFold=False,
                dynamicFold=False,
                origin=[f"converted_lambda({id(node)})"],
                live=None,
                killed=None,
                codeReads=None,
                codeModifies=None,
                codeAllocates=None,
                lowered=False,
                runtime=False,
                interpreter=False,
            )
            return pyflow_ast.MakeFunction(defaults=[], cells=[], code=code)

        else:
            # Fallback for unhandled expressions
            return pyflow_ast.Existing(Object(None))

    def _convert_expression_safe(self, node: Optional[python_ast.AST]) -> PythonASTNode:
        """Convert Python AST expressions to pyflow AST expressions with None protection."""
        if node is None:
            return pyflow_ast.Existing(Object(None))
        result = self._convert_expression(node)
        if result is None:
            return pyflow_ast.Existing(Object(None))
        return result

    def _convert_function_def(self, node: python_ast.AST) -> Optional[PythonASTNode]:
        """Convert Python AST FunctionDef to pyflow AST."""
        # Convert function arguments
        codeparams = self._convert_function_args(node.args, ensure_return=True)

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
        self, args_node: python_ast.arguments, *, ensure_return: bool = False
    ) -> pyflow_ast.CodeParameters:
        """Convert Python AST arguments to pyflow AST CodeParameters."""
        posonly = [a.arg for a in getattr(args_node, "posonlyargs", [])]
        regular = [a.arg for a in getattr(args_node, "args", [])]
        kwonly = [a.arg for a in getattr(args_node, "kwonlyargs", [])]
        param_names = [*posonly, *regular, *kwonly]
        params = [pyflow_ast.Local(name) for name in param_names]

        # Per-parameter default list (may include None holes).
        per_param_defaults: List[Optional[pyflow_ast.Existing]] = [None] * len(
            param_names
        )

        # Positional defaults apply to the last N of (posonly + regular).
        positional_names = [*posonly, *regular]
        pos_defaults = list(getattr(args_node, "defaults", []) or [])
        if pos_defaults:
            start = len(positional_names) - len(pos_defaults)
            for i, default_node in enumerate(pos_defaults):
                idx = start + i
                try:
                    value = python_ast.literal_eval(default_node)
                    per_param_defaults[idx] = pyflow_ast.Existing(Object(value))
                except Exception:
                    per_param_defaults[idx] = pyflow_ast.Existing(Object(None))

        # Keyword-only defaults align with kwonlyargs (can contain None holes).
        kw_defaults = list(getattr(args_node, "kw_defaults", []) or [])
        if kwonly and kw_defaults:
            base = len(positional_names)
            for i, default_node in enumerate(kw_defaults):
                if default_node is None:
                    continue
                try:
                    value = python_ast.literal_eval(default_node)
                    per_param_defaults[base + i] = pyflow_ast.Existing(Object(value))
                except Exception:
                    per_param_defaults[base + i] = pyflow_ast.Existing(Object(None))

        # Collapse to trailing-contiguous defaults as required by CalleeParams.
        first_default = next(
            (i for i, d in enumerate(per_param_defaults) if d is not None), None
        )
        defaults: List[pyflow_ast.Existing] = []
        if first_default is not None:
            for d in per_param_defaults[first_default:]:
                defaults.append(
                    d if d is not None else pyflow_ast.Existing(Object(None))
                )

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
            returnparams=[pyflow_ast.Local("ret0")] if ensure_return else [],
        )

    def _convert_import(self, node: python_ast.Import) -> Optional[PythonASTNode]:
        """Convert Python AST Import to pyflow AST."""
        suite = pyflow_ast.Suite([])
        for alias in node.names:
            target = alias.asname or alias.name.split(".")[0]
            suite.append(
                pyflow_ast.Assign(
                    pyflow_ast.Import(alias.name, [], 0),
                    [pyflow_ast.Local(target)],
                )
            )
        return suite

    def _convert_import_from(
        self, node: python_ast.ImportFrom
    ) -> Optional[PythonASTNode]:
        """Convert Python AST ImportFrom to pyflow AST."""
        module = node.module or ""
        level = int(getattr(node, "level", 0) or 0)
        fromlist = [
            a.name
            for a in (node.names or [])
            if getattr(a, "name", None) not in (None, "*")
        ]

        tmp = self._tmp_local("importfrom", node)
        suite = pyflow_ast.Suite(
            [
                pyflow_ast.Assign(
                    pyflow_ast.Import(module, fromlist, level),
                    [tmp],
                )
            ]
        )

        for alias in node.names or []:
            if alias.name == "*":
                continue
            target = alias.asname or alias.name
            suite.append(
                pyflow_ast.Assign(
                    pyflow_ast.GetAttr(tmp, pyflow_ast.Existing(Object(alias.name))),
                    [pyflow_ast.Local(target)],
                )
            )

        return suite

    def _convert_for_loop(self, node: python_ast.For) -> Optional[PythonASTNode]:
        """Convert Python AST For loop to pyflow AST."""
        # The PyFlow For node requires a Local index.
        body_preamble = pyflow_ast.Suite([])
        if isinstance(node.target, python_ast.Name):
            index = pyflow_ast.Local(node.target.id)
        else:
            index = self._tmp_local("for_index", node)
            store = self._convert_store(node.target, index)
            body_preamble.append(store)

        # Convert iterator
        iter_expr = self._convert_expression_safe(node.iter)

        # Convert loop body
        body = self.convert_python_ast_to_pyflow(node.body)

        # Convert else clause
        else_body = self.convert_python_ast_to_pyflow(node.orelse)

        # Create For loop node
        return pyflow_ast.For(
            iterator=iter_expr,
            index=index,
            loopPreamble=pyflow_ast.Suite([]),
            bodyPreamble=body_preamble,
            body=body,
            else_=else_body,
        )

    def _convert_while_loop(self, node: python_ast.While) -> Optional[PythonASTNode]:
        """Convert Python AST While loop to pyflow AST."""
        # Convert condition
        condition = self._convert_expression_safe(node.test)

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
        pre = pyflow_ast.Suite([])
        for item in node.items:
            ctx = self._convert_expression_safe(item.context_expr)
            if item.optional_vars is not None:
                tmp = self._tmp_local("with", item)
                pre.append(pyflow_ast.Assign(ctx, [tmp]))
                pre.append(self._convert_store(item.optional_vars, tmp))
            else:
                pre.append(pyflow_ast.Discard(ctx))

        body = self.convert_python_ast_to_pyflow(node.body)
        return pyflow_ast.Suite([pre, body])

    def _binary_op_name(self, op: python_ast.AST) -> Optional[str]:
        op_map = {
            python_ast.Add: "interpreter__add__",
            python_ast.Sub: "interpreter__sub__",
            python_ast.Mult: "interpreter__mul__",
            python_ast.Div: "interpreter__truediv__",
            python_ast.FloorDiv: "interpreter__floordiv__",
            python_ast.Mod: "interpreter__mod__",
            python_ast.Pow: "interpreter__pow__",
            python_ast.BitAnd: "interpreter__and__",
            python_ast.BitOr: "interpreter__or__",
            python_ast.BitXor: "interpreter__xor__",
            python_ast.LShift: "interpreter__lshift__",
            python_ast.RShift: "interpreter__rshift__",
        }
        return op_map.get(type(op))

    def _convert_delete_target(self, target: python_ast.AST) -> Optional[PythonASTNode]:
        if isinstance(target, python_ast.Name):
            return pyflow_ast.Delete(pyflow_ast.Local(target.id))
        if isinstance(target, python_ast.Attribute):
            obj = self._convert_expression_safe(target.value)
            name = pyflow_ast.Existing(Object(target.attr))
            return pyflow_ast.DeleteAttr(obj, name)
        if isinstance(target, python_ast.Subscript):
            obj = self._convert_expression_safe(target.value)
            sub = self._convert_subscript_index(target.slice)
            return pyflow_ast.Discard(
                self._call_named("interpreter_delitem", [obj, sub])
            )
        return None

    def _convert_store(
        self, target: python_ast.AST, value: PythonASTNode
    ) -> PythonASTNode:
        if isinstance(target, python_ast.Name):
            return pyflow_ast.Assign(value, [pyflow_ast.Local(target.id)])
        if isinstance(target, python_ast.Attribute):
            obj = self._convert_expression_safe(target.value)
            name = pyflow_ast.Existing(Object(target.attr))
            return pyflow_ast.SetAttr(value, obj, name)
        if isinstance(target, python_ast.Subscript):
            obj = self._convert_expression_safe(target.value)
            sub = self._convert_subscript_index(target.slice)
            return pyflow_ast.Discard(
                pyflow_ast.Call(
                    pyflow_ast.Existing(Object("interpreter_setitem")),
                    [obj, sub, value],
                    [],
                    None,
                    None,
                )
            )
        if isinstance(target, (python_ast.Tuple, python_ast.List)):
            # Model simple unpacking without introducing UnpackSequence (not handled by all analyses).
            suite = pyflow_ast.Suite([])
            for i, elt in enumerate(target.elts):
                if not isinstance(elt, python_ast.Name):
                    return pyflow_ast.Discard(value)
                idx = pyflow_ast.Existing(Object(i))
                rhs = pyflow_ast.Call(
                    pyflow_ast.Existing(Object("interpreter_getitem")),
                    [value, idx],
                    [],
                    None,
                    None,
                )
                suite.append(pyflow_ast.Assign(rhs, [pyflow_ast.Local(elt.id)]))
            return suite
        return pyflow_ast.Discard(value)

    def _convert_assign(self, node: python_ast.Assign) -> PythonASTNode:
        rhs = self._convert_expression_safe(node.value)

        # Fast path for pure-local assignment(s).
        if all(isinstance(t, python_ast.Name) for t in node.targets):
            locals_ = [pyflow_ast.Local(t.id) for t in node.targets]  # type: ignore[attr-defined]
            return pyflow_ast.Assign(rhs, locals_)

        # General path: evaluate RHS once then store into each target.
        tmp = self._tmp_local("assign", node)
        suite = pyflow_ast.Suite([pyflow_ast.Assign(rhs, [tmp])])
        for target in node.targets:
            suite.append(self._convert_store(target, tmp))
        return suite

    def _convert_augassign(self, node: python_ast.AugAssign) -> PythonASTNode:
        rhs = self._convert_expression_safe(node.value)
        op_name = self._binary_op_name(node.op)
        if op_name is None:
            # Unknown op: fall back to assignment of RHS (conservative/approximate).
            return self._convert_store(node.target, rhs)

        op = pyflow_ast.Existing(Object(op_name))

        # Load current value from target.
        if isinstance(node.target, python_ast.Name):
            cur = pyflow_ast.Local(node.target.id)
            new_val = pyflow_ast.Call(op, [cur, rhs], [], None, None)
            return pyflow_ast.Assign(new_val, [pyflow_ast.Local(node.target.id)])

        if isinstance(node.target, python_ast.Attribute):
            obj = self._convert_expression_safe(node.target.value)
            name = pyflow_ast.Existing(Object(node.target.attr))
            cur = pyflow_ast.GetAttr(obj, name)
            new_val = pyflow_ast.Call(op, [cur, rhs], [], None, None)
            return pyflow_ast.SetAttr(new_val, obj, name)

        if isinstance(node.target, python_ast.Subscript):
            obj = self._convert_expression_safe(node.target.value)
            sub = self._convert_subscript_index(node.target.slice)
            cur = pyflow_ast.Call(
                pyflow_ast.Existing(Object("interpreter_getitem")),
                [obj, sub],
                [],
                None,
                None,
            )
            new_val = pyflow_ast.Call(op, [cur, rhs], [], None, None)
            return pyflow_ast.Discard(
                pyflow_ast.Call(
                    pyflow_ast.Existing(Object("interpreter_setitem")),
                    [obj, sub, new_val],
                    [],
                    None,
                    None,
                )
            )

        # Fallback for other targets.
        return self._convert_store(node.target, rhs)

    def _convert_async_for(self, node) -> Optional[PythonASTNode]:
        """Convert Python AST AsyncFor to pyflow AST.
        
        Async for loops are modeled similarly to regular for loops,
        with an annotation to indicate async iteration.
        """
        body_preamble = pyflow_ast.Suite([])
        if isinstance(node.target, python_ast.Name):
            index = pyflow_ast.Local(node.target.id)
        else:
            index = self._tmp_local("async_for_index", node)
            store = self._convert_store(node.target, index)
            body_preamble.append(store)

        iter_expr = self._convert_expression_safe(node.iter)
        iter_expr = self._call_named("interpreter_aiter", [iter_expr])

        body = self.convert_python_ast_to_pyflow(node.body)
        else_body = self.convert_python_ast_to_pyflow(node.orelse)

        return pyflow_ast.For(
            iterator=iter_expr,
            index=index,
            loopPreamble=pyflow_ast.Suite([]),
            bodyPreamble=body_preamble,
            body=body,
            else_=else_body,
        )

    def _convert_async_with(self, node) -> Optional[PythonASTNode]:
        """Convert Python AST AsyncWith to pyflow AST.
        
        Async context managers are modeled with async enter/exit semantics.
        """
        pre = pyflow_ast.Suite([])
        for item in node.items:
            ctx = self._convert_expression_safe(item.context_expr)
            ctx = self._call_named("interpreter_async_with", [ctx])
            if item.optional_vars is not None:
                tmp = self._tmp_local("async_with", item)
                pre.append(pyflow_ast.Assign(ctx, [tmp]))
                pre.append(self._convert_store(item.optional_vars, tmp))
            else:
                pre.append(pyflow_ast.Discard(ctx))

        body = self.convert_python_ast_to_pyflow(node.body)
        return pyflow_ast.Suite([pre, body])

    def _convert_match(self, node) -> Optional[PythonASTNode]:
        """Convert Python AST Match (pattern matching, Python 3.10+) to pyflow AST.
        
        Pattern matching is converted to a series of conditional checks
        (similar to a chain of if-elif-else statements).
        """
        subject = self._convert_expression_safe(node.subject)
        tmp_subject = self._tmp_local("match_subject", node)
        
        suite = pyflow_ast.Suite([
            pyflow_ast.Assign(subject, [tmp_subject])
        ])
        
        cases = []
        for i, case in enumerate(node.cases):
            case_body = self.convert_python_ast_to_pyflow(case.body)
            
            if hasattr(case, 'pattern'):
                condition = self._convert_pattern(case.pattern, tmp_subject)
                if case.guard:
                    guard = self._convert_expression_safe(case.guard)
                    condition = self._call_named("interpreter_booland", [condition, guard])
                cases.append((condition, case_body))
            else:
                cases.append((None, case_body))
        
        if not cases:
            return suite
        
        result = cases[-1][1]
        for condition, body in reversed(cases[:-1]):
            if condition is None:
                result = body
            else:
                result = pyflow_ast.Switch(
                    condition=pyflow_ast.Condition(pyflow_ast.Suite([]), condition),
                    t=body,
                    f=result,
                )
        
        suite.append(result)
        return suite

    def _convert_pattern(self, pattern, subject: PythonASTNode) -> PythonASTNode:
        """Convert a match pattern to a condition check.
        
        Returns a condition expression that evaluates to True if the pattern matches.
        """
        if hasattr(python_ast, "MatchValue") and isinstance(pattern, python_ast.MatchValue):
            value = self._convert_expression_safe(pattern.value)
            return self._call_named("interpreter__eq__", [subject, value])
        
        elif hasattr(python_ast, "MatchSingleton") and isinstance(pattern, python_ast.MatchSingleton):
            return self._call_named("interpreter__eq__", [
                subject, 
                pyflow_ast.Existing(Object(pattern.value))
            ])
        
        elif hasattr(python_ast, "MatchSequence") and isinstance(pattern, python_ast.MatchSequence):
            length_check = self._call_named("interpreter_match_sequence", [subject])
            if not pattern.patterns:
                return length_check
            result = length_check
            for i, sub_pattern in enumerate(pattern.patterns):
                idx = pyflow_ast.Existing(Object(i))
                elem = self._call_named("interpreter_getitem", [subject, idx])
                sub_condition = self._convert_pattern(sub_pattern, elem)
                result = self._call_named("interpreter_booland", [result, sub_condition])
            return result
        
        elif hasattr(python_ast, "MatchMapping") and isinstance(pattern, python_ast.MatchMapping):
            result = self._call_named("interpreter_match_mapping", [subject])
            for key, sub_pattern in zip(pattern.keys, pattern.patterns):
                key_expr = self._convert_expression_safe(key)
                value = self._call_named("interpreter_getitem", [subject, key_expr])
                sub_condition = self._convert_pattern(sub_pattern, value)
                result = self._call_named("interpreter_booland", [result, sub_condition])
            return result
        
        elif hasattr(python_ast, "MatchClass") and isinstance(pattern, python_ast.MatchClass):
            cls = self._convert_expression_safe(pattern.cls)
            result = self._call_named("interpreter_match_class", [subject, cls])
            for i, sub_pattern in enumerate(pattern.patterns):
                idx = pyflow_ast.Existing(Object(i))
                elem = self._call_named("interpreter_getattr", [subject, idx])
                sub_condition = self._convert_pattern(sub_pattern, elem)
                result = self._call_named("interpreter_booland", [result, sub_condition])
            for attr_name, sub_pattern in zip(pattern.kwd_attrs, pattern.kwd_patterns):
                attr = self._call_named("interpreter_getattr", [
                    subject, 
                    pyflow_ast.Existing(Object(attr_name))
                ])
                sub_condition = self._convert_pattern(sub_pattern, attr)
                result = self._call_named("interpreter_booland", [result, sub_condition])
            return result
        
        elif hasattr(python_ast, "MatchStar") and isinstance(pattern, python_ast.MatchStar):
            if pattern.name:
                return pyflow_ast.Existing(Object(True))
            return pyflow_ast.Existing(Object(True))
        
        elif hasattr(python_ast, "MatchAs") and isinstance(pattern, python_ast.MatchAs):
            if pattern.pattern is None:
                return pyflow_ast.Existing(Object(True))
            sub_condition = self._convert_pattern(pattern.pattern, subject)
            return sub_condition
        
        elif hasattr(python_ast, "MatchOr") and isinstance(pattern, python_ast.MatchOr):
            if not pattern.patterns:
                return pyflow_ast.Existing(Object(False))
            result = self._convert_pattern(pattern.patterns[0], subject)
            for sub_pattern in pattern.patterns[1:]:
                sub_condition = self._convert_pattern(sub_pattern, subject)
                result = self._call_named("interpreter_boolor", [result, sub_condition])
            return result
        
        return pyflow_ast.Existing(Object(True))

    def _convert_try_star(self, node) -> Optional[PythonASTNode]:
        """Convert Python AST TryStar (exception groups, Python 3.11+) to pyflow AST.
        
        Exception groups are handled similarly to regular try-except,
        with special handling for exception group matching.
        """
        try_body = self.convert_python_ast_to_pyflow(node.body)

        handlers = []
        for handler in node.handlers:
            if handler.type:
                exc_type = self._convert_expression(handler.type)
            else:
                exc_type = None

            if handler.name:
                exc_name = pyflow_ast.Local(handler.name)
            else:
                exc_name = None

            handler_body = self.convert_python_ast_to_pyflow(handler.body)

            exc_handler = pyflow_ast.ExceptionHandler(
                preamble=pyflow_ast.Suite([]),
                type=exc_type,
                value=exc_name,
                body=handler_body,
            )
            handlers.append(exc_handler)

        else_body = self.convert_python_ast_to_pyflow(node.orelse)
        finally_body = self.convert_python_ast_to_pyflow(node.finalbody)

        return pyflow_ast.TryExceptFinally(
            body=try_body,
            handlers=handlers,
            defaultHandler=None,
            else_=else_body,
            finally_=finally_body,
        )

    def _convert_global(self, node: python_ast.Global) -> Optional[PythonASTNode]:
        """Convert Python AST Global to pyflow AST with proper scope tracking."""
        suite = pyflow_ast.Suite([])
        for name in node.names:
            suite.append(pyflow_ast.GlobalDecl(pyflow_ast.Local(name)))
        return suite

    def _convert_nonlocal(self, node: python_ast.Nonlocal) -> Optional[PythonASTNode]:
        """Convert Python AST Nonlocal to pyflow AST with proper closure tracking."""
        suite = pyflow_ast.Suite([])
        for name in node.names:
            suite.append(pyflow_ast.NonlocalDecl(pyflow_ast.Local(name)))
        return suite

    def _convert_annassign(self, node: python_ast.AnnAssign) -> Optional[PythonASTNode]:
        """Convert annotated assignment to pyflow AST.
        
        Handles both `x: int = 5` and `x: int` (annotation-only).
        Annotations are preserved in the AST for type inference.
        """
        annotation = self._convert_expression_safe(node.annotation)
        
        if node.value is None:
            if isinstance(node.target, python_ast.Name):
                return pyflow_ast.AnnAssign(
                    pyflow_ast.Local(node.target.id),
                    annotation,
                    None
                )
            return pyflow_ast.Suite([])
        
        value = self._convert_expression_safe(node.value)
        
        if isinstance(node.target, python_ast.Name):
            return pyflow_ast.AnnAssign(
                pyflow_ast.Local(node.target.id),
                annotation,
                value
            )
        elif isinstance(node.target, python_ast.Attribute):
            obj = self._convert_expression_safe(node.target.value)
            name = pyflow_ast.Existing(Object(node.target.attr))
            suite = pyflow_ast.Suite([
                pyflow_ast.SetAttr(value, obj, name)
            ])
            return suite
        elif isinstance(node.target, python_ast.Subscript):
            obj = self._convert_expression_safe(node.target.value)
            sub = self._convert_subscript_index(node.target.slice)
            return pyflow_ast.Discard(
                pyflow_ast.Call(
                    pyflow_ast.Existing(Object("interpreter_setitem")),
                    [obj, sub, value],
                    [],
                    None,
                    None,
                )
            )
        
        return pyflow_ast.Suite([])

    def _convert_named_expr(self, node) -> PythonASTNode:
        """Convert walrus operator (:=) to pyflow AST.
        
        The walrus operator both assigns and returns a value.
        We model this by returning the target local after assignment.
        """
        target = node.target
        value = self._convert_expression_safe(node.value)
        
        if isinstance(target, python_ast.Name):
            local = pyflow_ast.Local(target.id)
            return pyflow_ast.NamedExpr(local, value)
        
        return value

    def _convert_await(self, node) -> PythonASTNode:
        """Convert await expression to pyflow AST."""
        value = self._convert_expression_safe(node.value)
        return pyflow_ast.Await(value)

    def _convert_comprehension(self, node, result_type: str) -> PythonASTNode:
        """Convert list/set/dict comprehensions and generator expressions.
        
        Comprehensions are modeled as nested loops with append operations.
        This preserves the iteration semantics better than a simple singleton.
        """
        generators = node.generators
        
        if result_type == "dict":
            key_expr = self._convert_expression_safe(node.key)
            value_expr = self._convert_expression_safe(node.value)
            result = pyflow_ast.BuildMap()
        else:
            element = self._convert_expression_safe(node.elt)
            if result_type == "list":
                result = pyflow_ast.BuildList([])
            elif result_type == "set":
                result = pyflow_ast.BuildList([])
            else:
                result = pyflow_ast.Existing(Object(None))
        
        if not generators:
            if result_type == "list":
                return pyflow_ast.BuildList([element])
            return result
        
        result_local = self._tmp_local("comp_result", node)
        suite = pyflow_ast.Suite([
            pyflow_ast.Assign(result, [result_local])
        ])
        
        inner_body = pyflow_ast.Suite([])
        
        for i, gen in enumerate(reversed(generators)):
            iter_expr = self._convert_expression_safe(gen.iter)
            
            if isinstance(gen.target, python_ast.Name):
                index = pyflow_ast.Local(gen.target.id)
            else:
                index = self._tmp_local("comp_idx", gen)
            
            if i == 0:
                if result_type == "dict":
                    inner_body.append(pyflow_ast.Discard(
                        self._call_named("interpreter_setitem", [
                            result_local, key_expr, value_expr
                        ])
                    ))
                elif result_type == "list":
                    inner_body.append(pyflow_ast.Discard(
                        self._call_named("interpreter_list_append", [result_local, element])
                    ))
            else:
                inner_body = pyflow_ast.For(
                    iterator=iter_expr,
                    index=index,
                    loopPreamble=pyflow_ast.Suite([]),
                    bodyPreamble=pyflow_ast.Suite([]),
                    body=inner_body,
                    else_=pyflow_ast.Suite([]),
                )
        
        suite.append(inner_body)
        suite.append(pyflow_ast.Discard(result_local))
        
        return result

    def _convert_list_comp(self, node) -> PythonASTNode:
        """Convert list comprehension with proper iteration modeling."""
        return self._convert_comprehension(node, "list")

    def _convert_set_comp(self, node) -> PythonASTNode:
        """Convert set comprehension with proper iteration modeling."""
        return self._convert_comprehension(node, "set")

    def _convert_dict_comp(self, node) -> PythonASTNode:
        """Convert dict comprehension with proper iteration modeling."""
        return self._convert_comprehension(node, "dict")

    def _convert_gen_exp(self, node) -> PythonASTNode:
        """Convert generator expression.
        
        Generator expressions are lazy and don't materialize all values.
        We model them as creating a generator object.
        """
        return self._call_named("interpreter_make_generator", [
            pyflow_ast.Existing(Object("<generator>"))
        ])
