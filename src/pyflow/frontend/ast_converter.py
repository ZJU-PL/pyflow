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
from typing import Any, Dict, List, Optional, Set, Tuple

from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python.default_markers import MISSING_DEFAULT
from pyflow.language.python.program import Object
from pyflow.language.python.pythonbase import PythonASTNode
from pyflow.language.python.annotations import CodeAnnotation
from pyflow.language.asttools.origin import SourceOrigin
from pyflow.analysis.ir_utils import (
    register_call_argument_metadata,
    register_class_cell,
    register_code_definition_metadata,
)

HAS_MATCH = sys.version_info >= (3, 10)
HAS_NAMED_EXPR = sys.version_info >= (3, 8)
HAS_EXCEPTION_GROUP = sys.version_info >= (3, 11)
_KWONLY_PARAM_PREFIX = "kwonly:"


class ASTConverter:
    """Converts Python AST nodes to PyFlow AST nodes."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        # Collected approximation notes for debugging and tests.
        self.approximation_warnings: List[str] = []
        self._telemetry: Dict[str, int] = {
            "unsupported_expr": 0,
            "unsupported_stmt": 0,
            "unknown_augassign": 0,
            "merged_varargs": 0,
            "merged_kwargs": 0,
        }
        self._scope_stack: List[Dict[str, Any]] = []
        self._future_annotations = False
        self.current_filename: str | None = None

    def _with_source_origin(
        self, converted: Optional[PythonASTNode], source: python_ast.AST
    ) -> Optional[PythonASTNode]:
        if converted is None or not hasattr(converted, "rewriteAnnotation"):
            return converted
        annotation = getattr(converted, "annotation", None)
        if annotation is None or not hasattr(annotation, "origin"):
            return converted
        filename = self.current_filename or getattr(source, "filename", None)
        origin = SourceOrigin(
            None,
            filename,
            getattr(source, "lineno", None),
            getattr(source, "col_offset", None),
            getattr(source, "end_lineno", None),
            getattr(source, "end_col_offset", None),
        )
        converted.rewriteAnnotation(origin=(origin,))
        return converted

    def _tmp_local(self, hint: str, node: python_ast.AST) -> pyflow_ast.Local:
        return pyflow_ast.Local(f"__pyflow_tmp_{hint}_{id(node)}")

    def _warn_approx(self, node: python_ast.AST, detail: str) -> None:
        line = getattr(node, "lineno", "?")
        msg = f"{type(node).__name__}@{line}: {detail}"
        self.approximation_warnings.append(msg)
        if self.verbose:
            print(f"WARN: {msg}")

    def _unsupported_expr(self, node: python_ast.AST, detail: str) -> PythonASTNode:
        self._telemetry["unsupported_expr"] += 1
        self._warn_approx(node, detail)
        return self._call_named(
            "interpreter_unsupported_expr",
            [
                pyflow_ast.Existing(Object(type(node).__name__)),
                pyflow_ast.Existing(Object(detail)),
            ],
        )

    def _unsupported_stmt(self, node: python_ast.AST, detail: str) -> PythonASTNode:
        self._telemetry["unsupported_stmt"] += 1
        self._warn_approx(node, detail)
        return pyflow_ast.Discard(
            self._call_named(
                "interpreter_unsupported_stmt",
                [
                    pyflow_ast.Existing(Object(type(node).__name__)),
                    pyflow_ast.Existing(Object(detail)),
                ],
            )
        )

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

    def reset_telemetry(self) -> None:
        self.approximation_warnings = []
        for key in self._telemetry:
            self._telemetry[key] = 0

    def get_telemetry(self) -> Dict[str, Any]:
        out: Dict[str, Any] = dict(self._telemetry)
        out["approximation_warnings"] = len(self.approximation_warnings)
        return out

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

    def _push_scope(
        self,
        kind: str,
        *,
        global_names: Optional[Set[str]] = None,
        nonlocal_names: Optional[Set[str]] = None,
        cell_names: Optional[Set[str]] = None,
        global_hints: Optional[Set[str]] = None,
        bound_names: Optional[Set[str]] = None,
    ) -> None:
        self._scope_stack.append(
            {
                "kind": kind,
                "global_names": set(global_names or ()),
                "nonlocal_names": set(nonlocal_names or ()),
                "cell_names": set(cell_names or ()),
                "global_hints": set(global_hints or ()),
                "bound_names": set(bound_names or ()),
                "cells": {},
            }
        )

    def _pop_scope(self) -> None:
        self._scope_stack.pop()

    def _current_scope(self) -> Optional[Dict[str, Any]]:
        if not self._scope_stack:
            return None
        return self._scope_stack[-1]

    def _collect_direct_scope_directives(
        self, body_nodes: List[python_ast.AST]
    ) -> Tuple[Set[str], Set[str]]:
        global_names: Set[str] = set()
        nonlocal_names: Set[str] = set()

        class DirectiveVisitor(python_ast.NodeVisitor):
            def visit_Global(self, node: python_ast.Global) -> None:
                global_names.update(node.names)

            def visit_Nonlocal(self, node: python_ast.Nonlocal) -> None:
                nonlocal_names.update(node.names)

            def visit_FunctionDef(self, node: python_ast.FunctionDef) -> None:
                return

            def visit_AsyncFunctionDef(self, node: python_ast.AsyncFunctionDef) -> None:
                return

            def visit_ClassDef(self, node: python_ast.ClassDef) -> None:
                return

        visitor = DirectiveVisitor()
        for stmt in body_nodes:
            visitor.visit(stmt)
        return global_names, nonlocal_names

    def _collect_scope_names(
        self,
        body_nodes: List[python_ast.AST],
    ) -> Tuple[Set[str], Set[str]]:
        """Collect names bound and loaded directly in one lexical scope."""
        bound: Set[str] = set()
        loaded: Set[str] = set()

        class ScopeVisitor(python_ast.NodeVisitor):
            def visit_Name(self, node: python_ast.Name) -> None:
                if isinstance(node.ctx, (python_ast.Store, python_ast.Del)):
                    bound.add(node.id)
                else:
                    loaded.add(node.id)

            def visit_FunctionDef(self, node: python_ast.FunctionDef) -> None:
                bound.add(node.name)
                for decorator in node.decorator_list:
                    self.visit(decorator)
                for default in (*node.args.defaults, *node.args.kw_defaults):
                    if default is not None:
                        self.visit(default)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node: python_ast.ClassDef) -> None:
                bound.add(node.name)
                for base in node.bases:
                    self.visit(base)
                for keyword in node.keywords:
                    self.visit(keyword.value)
                for decorator in node.decorator_list:
                    self.visit(decorator)

            def visit_Lambda(self, node: python_ast.Lambda) -> None:
                return

            def visit_Import(self, node: python_ast.Import) -> None:
                for alias in node.names:
                    bound.add(alias.asname or alias.name.split(".")[0])

            def visit_ImportFrom(self, node: python_ast.ImportFrom) -> None:
                for alias in node.names:
                    if alias.name != "*":
                        bound.add(alias.asname or alias.name)

        visitor = ScopeVisitor()
        for statement in body_nodes:
            visitor.visit(statement)
        return bound, loaded

    def _enclosing_cell_names(
        self,
        candidates: Set[str],
    ) -> Set[str]:
        captured: Set[str] = set()
        for name in candidates:
            for scope in reversed(self._scope_stack):
                if scope.get("kind") == "module":
                    break
                if name in scope.get("bound_names", ()) or name in scope.get(
                    "cell_names", ()
                ):
                    scope["cell_names"].add(name)
                    cells = scope["cells"]
                    cells.setdefault(name, pyflow_ast.Cell(name))
                    captured.add(name)
                    break
        return captured

    def _direct_child_captures(
        self,
        body_nodes: List[python_ast.AST],
        parent_bound: Set[str],
    ) -> Set[str]:
        captures: Set[str] = set()

        class ChildVisitor(python_ast.NodeVisitor):
            def _visit_function(self, node) -> None:
                child_bound, child_loaded = self_outer._collect_scope_names(
                    list(node.body)
                )
                child_globals, child_nonlocals = (
                    self_outer._collect_direct_scope_directives(list(node.body))
                )
                child_bound.update(
                    argument.arg
                    for argument in (
                        *getattr(node.args, "posonlyargs", ()),
                        *getattr(node.args, "args", ()),
                        *getattr(node.args, "kwonlyargs", ()),
                    )
                )
                if getattr(node.args, "vararg", None) is not None:
                    child_bound.add(node.args.vararg.arg)
                if getattr(node.args, "kwarg", None) is not None:
                    child_bound.add(node.args.kwarg.arg)
                candidates = (
                    child_loaded - child_bound - child_globals
                ) | child_nonlocals
                captures.update(candidates & parent_bound)

            def visit_FunctionDef(self, node: python_ast.FunctionDef) -> None:
                self._visit_function(node)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Lambda(self, node: python_ast.Lambda) -> None:
                return

            def visit_ClassDef(self, node: python_ast.ClassDef) -> None:
                return

        self_outer = self
        visitor = ChildVisitor()
        for statement in body_nodes:
            visitor.visit(statement)
        return captures

    def _collect_descendant_scope_directives(
        self, body_nodes: List[python_ast.AST]
    ) -> Tuple[Set[str], Set[str]]:
        global_names: Set[str] = set()
        nonlocal_names: Set[str] = set()

        def walk(nodes: List[python_ast.AST]) -> None:
            for stmt in nodes:
                if isinstance(
                    stmt, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)
                ):
                    direct_global, direct_nonlocal = (
                        self._collect_direct_scope_directives(list(stmt.body))
                    )
                    global_names.update(direct_global)
                    nonlocal_names.update(direct_nonlocal)
                    walk(list(stmt.body))
                    continue

                if isinstance(
                    stmt,
                    (
                        python_ast.If,
                        python_ast.For,
                        python_ast.AsyncFor,
                        python_ast.While,
                        python_ast.With,
                        python_ast.AsyncWith,
                    ),
                ):
                    walk(list(getattr(stmt, "body", []) or []))
                    walk(list(getattr(stmt, "orelse", []) or []))
                    continue

                if isinstance(stmt, python_ast.Try):
                    walk(list(getattr(stmt, "body", []) or []))
                    for handler in getattr(stmt, "handlers", []) or []:
                        walk(list(getattr(handler, "body", []) or []))
                    walk(list(getattr(stmt, "orelse", []) or []))
                    walk(list(getattr(stmt, "finalbody", []) or []))
                    continue

                if hasattr(python_ast, "TryStar") and isinstance(
                    stmt, python_ast.TryStar
                ):
                    walk(list(getattr(stmt, "body", []) or []))
                    for handler in getattr(stmt, "handlers", []) or []:
                        walk(list(getattr(handler, "body", []) or []))
                    walk(list(getattr(stmt, "orelse", []) or []))
                    walk(list(getattr(stmt, "finalbody", []) or []))
                    continue

                if hasattr(python_ast, "Match") and isinstance(stmt, python_ast.Match):
                    for case in getattr(stmt, "cases", []) or []:
                        walk(list(getattr(case, "body", []) or []))

        walk(body_nodes)
        return global_names, nonlocal_names

    def _name_constant(self, name: str) -> pyflow_ast.Existing:
        return pyflow_ast.Existing(Object(name))

    def _get_local_cell(self, name: str) -> pyflow_ast.Cell:
        scope = self._current_scope()
        if scope is None:
            return pyflow_ast.Cell(name)
        cells = scope["cells"]
        if name not in cells:
            cells[name] = pyflow_ast.Cell(name)
        return cells[name]

    def _resolve_nonlocal_cell(self, name: str) -> pyflow_ast.Cell:
        for scope in reversed(self._scope_stack[:-1]):
            if scope.get("kind") == "module":
                continue
            if name in scope["cell_names"] or name in scope["cells"]:
                cells = scope["cells"]
                if name not in cells:
                    cells[name] = pyflow_ast.Cell(name)
                return cells[name]
        return self._get_local_cell(name)

    def _name_expr(self, name: str) -> PythonASTNode:
        scope = self._current_scope()
        if scope is None:
            return pyflow_ast.Local(name)
        if scope["kind"] == "module" and name in scope["global_hints"]:
            return pyflow_ast.GetGlobal(self._name_constant(name))
        if name in scope["global_names"]:
            return pyflow_ast.GetGlobal(self._name_constant(name))
        if name in scope["nonlocal_names"]:
            return pyflow_ast.GetCellDeref(self._resolve_nonlocal_cell(name))
        if name in scope["cell_names"]:
            return pyflow_ast.GetCellDeref(self._get_local_cell(name))
        return pyflow_ast.Local(name)

    def _name_store(self, name: str, value: PythonASTNode) -> PythonASTNode:
        scope = self._current_scope()
        if scope is None:
            return pyflow_ast.Assign(value, [pyflow_ast.Local(name)])
        if scope["kind"] == "module" and name in scope["global_hints"]:
            return pyflow_ast.SetGlobal(self._name_constant(name), value)
        if name in scope["global_names"]:
            return pyflow_ast.SetGlobal(self._name_constant(name), value)
        if name in scope["nonlocal_names"]:
            return pyflow_ast.SetCellDeref(value, self._resolve_nonlocal_cell(name))
        if name in scope["cell_names"]:
            return pyflow_ast.SetCellDeref(value, self._get_local_cell(name))
        return pyflow_ast.Assign(value, [pyflow_ast.Local(name)])

    def _name_delete(self, name: str) -> PythonASTNode:
        scope = self._current_scope()
        if scope is None:
            return pyflow_ast.Delete(pyflow_ast.Local(name))
        if scope["kind"] == "module" and name in scope["global_hints"]:
            return pyflow_ast.DeleteGlobal(self._name_constant(name))
        if name in scope["global_names"]:
            return pyflow_ast.DeleteGlobal(self._name_constant(name))
        if name in scope["nonlocal_names"] or name in scope["cell_names"]:
            return pyflow_ast.Discard(
                self._call_named(
                    "interpreter_unsupported_stmt",
                    [
                        pyflow_ast.Existing(Object("Delete")),
                        pyflow_ast.Existing(Object(f"delete shared name {name}")),
                    ],
                )
            )
        return pyflow_ast.Delete(pyflow_ast.Local(name))

    def _name_uses_plain_local(self, name: str) -> bool:
        scope = self._current_scope()
        if scope is None:
            return True
        if scope["kind"] == "module" and name in scope["global_hints"]:
            return False
        return (
            name not in scope["global_names"]
            and name not in scope["nonlocal_names"]
            and name not in scope["cell_names"]
        )

    def convert_python_ast_to_pyflow(
        self, python_nodes: List[python_ast.AST]
    ) -> pyflow_ast.Suite:
        """Convert Python AST nodes to pyflow AST nodes."""
        if not python_nodes:
            return pyflow_ast.Suite([])

        pushed_module_scope = False
        previous_future_annotations = self._future_annotations
        if not self._scope_stack:
            self._future_annotations = any(
                isinstance(node, python_ast.ImportFrom)
                and node.module == "__future__"
                and any(alias.name == "annotations" for alias in node.names)
                for node in python_nodes
            )
            descendant_global, _descendant_nonlocal = (
                self._collect_descendant_scope_directives(python_nodes)
            )
            module_bound, _module_loaded = self._collect_scope_names(python_nodes)
            self._push_scope(
                "module",
                global_hints=descendant_global,
                bound_names=module_bound,
            )
            pushed_module_scope = True

        try:
            blocks = []
            for node in python_nodes:
                converted = self._convert_node(node)
                if converted is not None:
                    if isinstance(node, python_ast.AugAssign):
                        suite = pyflow_ast.Suite([converted])
                        suite._origin_tag = "AugAssign"
                        converted = suite
                    blocks.append(converted)
            return pyflow_ast.Suite(blocks)
        finally:
            if pushed_module_scope:
                self._pop_scope()
                self._future_annotations = previous_future_annotations

    def _convert_node(self, node: python_ast.AST) -> Optional[PythonASTNode]:
        return self._with_source_origin(self._convert_node_impl(node), node)

    def _convert_node_impl(self, node: python_ast.AST) -> Optional[PythonASTNode]:
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

        elif hasattr(python_ast, "TypeAlias") and isinstance(
            node, python_ast.TypeAlias
        ):
            # Handle Python 3.12+ type alias declarations.
            return self._convert_type_alias(node)

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

        elif hasattr(python_ast, "AsyncWith") and isinstance(
            node, python_ast.AsyncWith
        ):
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
            return self._unsupported_stmt(node, "unhandled statement node")

    def _convert_expression(self, node: python_ast.AST) -> PythonASTNode:
        return self._with_source_origin(self._convert_expression_impl(node), node)

    def _convert_expression_impl(self, node: python_ast.AST) -> PythonASTNode:
        """Convert Python AST expressions to pyflow AST expressions."""
        if isinstance(node, python_ast.Name):
            return self._name_expr(node.id)

        elif isinstance(node, python_ast.Constant):
            return pyflow_ast.Existing(Object(node.value))

        elif isinstance(node, python_ast.Call):
            # Handle function calls
            func = self._convert_expression_safe(node.func)
            args: List[PythonASTNode] = []
            vargs: Optional[PythonASTNode] = None
            positional_spreads: List[PythonASTNode] = []
            positional_items: List[Tuple[bool, PythonASTNode]] = []
            ordered_arguments: List[Tuple[int, int, int, PythonASTNode]] = []
            order_index = 0
            for arg in node.args:
                if isinstance(arg, python_ast.Starred):
                    star = self._convert_expression_safe(arg.value)
                    positional_spreads.append(star)
                    positional_items.append((True, star))
                    ordered_arguments.append(
                        (
                            int(getattr(arg, "lineno", 0) or 0),
                            int(getattr(arg, "col_offset", 0) or 0),
                            order_index,
                            star,
                        )
                    )
                    if vargs is None:
                        vargs = star
                    else:
                        # Preserve intent of repeated unpacking with a merge helper.
                        self._telemetry["merged_varargs"] += 1
                        vargs = self._call_named(
                            "interpreter_merge_varargs", [vargs, star]
                        )
                else:
                    converted_arg = self._convert_expression_safe(arg)
                    args.append(converted_arg)
                    positional_items.append((False, converted_arg))
                    ordered_arguments.append(
                        (
                            int(getattr(arg, "lineno", 0) or 0),
                            int(getattr(arg, "col_offset", 0) or 0),
                            order_index,
                            converted_arg,
                        )
                    )
                order_index += 1

            keywords = []
            kargs: Optional[PythonASTNode] = None
            keyword_spreads: List[PythonASTNode] = []
            if node.keywords:
                for kw in node.keywords:
                    converted_value = self._convert_expression_safe(kw.value)
                    ordered_arguments.append(
                        (
                            int(getattr(kw.value, "lineno", 0) or 0),
                            int(getattr(kw.value, "col_offset", 0) or 0),
                            order_index,
                            converted_value,
                        )
                    )
                    order_index += 1
                    if kw.arg is None:
                        # **kwargs
                        keyword_spreads.append(converted_value)
                        if kargs is None:
                            kargs = converted_value
                        else:
                            # Preserve chained unpacking with an explicit merge helper.
                            self._telemetry["merged_kwargs"] += 1
                            kargs = self._call_named(
                                "interpreter_merge_kwargs", [kargs, converted_value]
                            )
                    else:
                        keywords.append((kw.arg, converted_value))

            call = pyflow_ast.Call(func, args, keywords, vargs, kargs)
            register_call_argument_metadata(
                call,
                evaluation_order=tuple(
                    item[3] for item in sorted(ordered_arguments)
                ),
                positional_spreads=tuple(positional_spreads),
                keyword_spreads=tuple(keyword_spreads),
                positional_items=tuple(positional_items),
            )
            return call

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
            return self._unsupported_expr(node, "unknown unary operator")

        elif isinstance(node, python_ast.Compare):
            left = self._convert_expression_safe(node.left)
            if len(node.ops) != len(node.comparators) or not node.ops:
                return self._unsupported_expr(node, "malformed comparison")

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
                return self._unsupported_expr(node, "unsupported comparison operator")

            comps: List[PythonASTNode] = []
            cur_left = left
            for op, right_node in zip(node.ops, node.comparators):
                right = self._convert_expression_safe(right_node)
                comps.append(single(op, cur_left, right))
                cur_left = right

            if len(comps) == 1:
                return comps[0]

            expr: PythonASTNode = comps[0]
            for c in comps[1:]:
                expr = pyflow_ast.ShortCircutAnd([expr, c])
            return expr

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
                if any(key is None for key in node.keys):
                    explicit_entries = []
                    unpacked_mappings = []
                    for key, value in zip(node.keys, node.values):
                        value_expr = self._convert_expression_safe(value)
                        if key is None:
                            unpacked_mappings.append(value_expr)
                            continue
                        explicit_entries.append(
                            pyflow_ast.BuildTuple(
                                [
                                    self._convert_expression_safe(key),
                                    value_expr,
                                ]
                            )
                        )
                    return self._call_named(
                        "interpreter_build_map",
                        [
                            pyflow_ast.BuildList(explicit_entries),
                            pyflow_ast.BuildList(unpacked_mappings),
                        ],
                    )

                args: List[PythonASTNode] = []
                for key, value in zip(node.keys, node.values):
                    args.append(self._convert_expression_safe(key))
                    args.append(self._convert_expression_safe(value))
                return pyflow_ast.BuildMap(args)

        elif isinstance(node, python_ast.Set):
            # Handle set creation: {a, b, c}
            try:
                value = python_ast.literal_eval(node)
                return pyflow_ast.Existing(Object(value))
            except Exception:
                elts = [self._convert_expression(elt) for elt in node.elts]
                return pyflow_ast.BuildSet(elts)

        elif isinstance(node, python_ast.Attribute):
            # Handle attribute access: obj.attr
            value = self._convert_expression(node.value)
            # Create an Existing object for the attribute name
            attr_name = pyflow_ast.Existing(Object(node.attr))
            return pyflow_ast.GetAttr(value, attr_name)

        elif isinstance(node, python_ast.BoolOp):
            values = [self._convert_expression_safe(v) for v in node.values]
            if not values:
                return pyflow_ast.Existing(Object(None))
            if isinstance(node.op, python_ast.And):
                return pyflow_ast.ShortCircutAnd(values)
            elif isinstance(node.op, python_ast.Or):
                return pyflow_ast.ShortCircutOr(values)
            else:
                return self._unsupported_expr(node, "unsupported boolean operator")

        elif isinstance(node, python_ast.IfExp):
            test = self._convert_expression_safe(node.test)
            body = self._convert_expression_safe(node.body)
            orelse = self._convert_expression_safe(node.orelse)
            return pyflow_ast.ConditionalExpr(test, body, orelse)

        elif isinstance(node, python_ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, python_ast.Constant):
                    parts.append(pyflow_ast.Existing(Object(str(value.value))))
                elif hasattr(python_ast, "FormattedValue") and isinstance(
                    value, python_ast.FormattedValue
                ):
                    conv = value.conversion if hasattr(value, "conversion") else -1
                    format_spec = None
                    if hasattr(value, "format_spec") and value.format_spec:
                        format_spec = self._convert_expression_safe(value.format_spec)
                    expr = self._convert_expression_safe(value.value)
                    parts.append(
                        self._call_named(
                            "interpreter_format",
                            [
                                expr,
                                pyflow_ast.Existing(Object(conv)),
                                format_spec or pyflow_ast.Existing(Object(None)),
                            ],
                        )
                    )
                else:
                    parts.append(self._convert_expression_safe(value))
            return self._call_named(
                "interpreter_join_str", [pyflow_ast.BuildList(parts)]
            )

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
            return pyflow_ast.YieldFrom(expr)

        elif isinstance(node, python_ast.ListComp):
            return self._convert_list_comp(node)

        elif isinstance(node, python_ast.SetComp):
            return self._convert_set_comp(node)

        elif isinstance(node, python_ast.DictComp):
            return self._convert_dict_comp(node)

        elif isinstance(node, python_ast.GeneratorExp):
            return self._convert_gen_exp(node)

        elif hasattr(python_ast, "NamedExpr") and isinstance(
            node, python_ast.NamedExpr
        ):
            # Handle walrus operator (:=) - Python 3.8+
            return self._convert_named_expr(node)

        elif hasattr(python_ast, "Await") and isinstance(node, python_ast.Await):
            # Handle await expression - Python 3.5+
            return self._convert_await(node)

        elif isinstance(node, python_ast.Lambda):
            # Handle lambda expressions
            codeparams = self._convert_function_args(node.args, ensure_return=True)
            self._push_scope("function")
            try:
                body_expr = self._convert_expression_safe(node.body)
            finally:
                self._pop_scope()
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
            return self._unsupported_expr(node, "unhandled expression node")

    def _convert_expression_safe(self, node: Optional[python_ast.AST]) -> PythonASTNode:
        """Convert Python AST expressions to pyflow AST expressions with None protection."""
        if node is None:
            return pyflow_ast.Existing(Object(None))
        result = self._convert_expression(node)
        if result is None:
            return pyflow_ast.Existing(Object(None))
        return result

    def _convert_function_def(self, node: python_ast.AST) -> Optional[PythonASTNode]:
        """Convert Python AST FunctionDef to pyflow AST.

        Supports type parameters for generic functions (Python 3.12+).
        """
        type_params_node = getattr(node, "type_params", None)
        definition_annotations = [
            self._convert_annotation(argument.annotation)
            for argument in (
                *getattr(node.args, "posonlyargs", ()),
                *getattr(node.args, "args", ()),
                *getattr(node.args, "kwonlyargs", ()),
            )
            if getattr(argument, "annotation", None) is not None
        ]
        if getattr(node.args, "vararg", None) is not None and getattr(
            node.args.vararg, "annotation", None
        ) is not None:
            definition_annotations.append(
                self._convert_annotation(node.args.vararg.annotation)
            )
        if getattr(node.args, "kwarg", None) is not None and getattr(
            node.args.kwarg, "annotation", None
        ) is not None:
            definition_annotations.append(
                self._convert_annotation(node.args.kwarg.annotation)
            )
        if getattr(node, "returns", None) is not None:
            definition_annotations.append(
                self._convert_annotation(node.returns)
            )
        codeparams = self._convert_function_args(
            node.args, ensure_return=True, type_params_node=type_params_node
        )
        direct_global, direct_nonlocal = self._collect_direct_scope_directives(
            list(node.body)
        )
        body_bound, body_loaded = self._collect_scope_names(list(node.body))
        parameter_names = {
            argument.arg
            for argument in (
                *getattr(node.args, "posonlyargs", ()),
                *getattr(node.args, "args", ()),
                *getattr(node.args, "kwonlyargs", ()),
            )
        }
        if getattr(node.args, "vararg", None) is not None:
            parameter_names.add(node.args.vararg.arg)
        if getattr(node.args, "kwarg", None) is not None:
            parameter_names.add(node.args.kwarg.arg)
        bound_names = (body_bound | parameter_names) - direct_global - direct_nonlocal
        uses_zero_arg_super = any(
            isinstance(candidate, python_ast.Call)
            and isinstance(candidate.func, python_ast.Name)
            and candidate.func.id == "super"
            and not candidate.args
            and not candidate.keywords
            for statement in node.body
            for candidate in python_ast.walk(statement)
        )
        if uses_zero_arg_super:
            body_loaded.add("__class__")
        implicit_free = self._enclosing_cell_names(
            body_loaded - bound_names - direct_global
        )
        free_names = direct_nonlocal | implicit_free
        _descendant_global, descendant_nonlocal = (
            self._collect_descendant_scope_directives(list(node.body))
        )
        captured_by_children = self._direct_child_captures(
            list(node.body),
            bound_names,
        )
        self._push_scope(
            "function",
            global_names=direct_global,
            nonlocal_names=free_names,
            cell_names=descendant_nonlocal | captured_by_children,
            bound_names=bound_names,
        )
        try:
            body = self.convert_python_ast_to_pyflow(node.body)
            closure_cells = tuple(
                self._resolve_nonlocal_cell(name)
                for name in sorted(free_names)
            )
        finally:
            self._pop_scope()

        code = pyflow_ast.Code(node.name, codeparams, body)
        register_code_definition_metadata(
            code,
            annotations=tuple(definition_annotations),
            closure_cells=closure_cells,
        )

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

        type_params = None
        if type_params_node:
            type_params = self._convert_type_params(type_params_node)

        return pyflow_ast.FunctionDef(
            node.name,
            code,
            [
                self._convert_expression_safe(decorator)
                for decorator in node.decorator_list
            ],
            type_params,
        )

    def _convert_class_def(self, node: python_ast.ClassDef) -> Optional[PythonASTNode]:
        """Convert Python AST ClassDef to pyflow AST.

        Supports:
        - Metaclass keyword argument
        - __init_subclass__ keywords
        - Type parameters for generic classes (Python 3.12+)
        """
        bases = [self._convert_expression_safe(base) for base in node.bases]

        keywords = []
        for kw in getattr(node, "keywords", []):
            if kw.arg is not None:
                keywords.append((kw.arg, self._convert_expression_safe(kw.value)))

        class_bound, _class_loaded = self._collect_scope_names(list(node.body))
        class_bound.add("__class__")
        self._push_scope("class", bound_names=class_bound)
        class_scope = self._current_scope()
        class_scope["cells"]["__class__"] = pyflow_ast.Cell("__class__")
        try:
            body = self.convert_python_ast_to_pyflow(node.body)
            class_cell = class_scope["cells"].get("__class__")
        finally:
            self._pop_scope()

        type_params = None
        if hasattr(node, "type_params") and node.type_params:
            type_params = self._convert_type_params(node.type_params)

        class_definition = pyflow_ast.ClassDef(
            node.name,
            bases,
            keywords,
            body,
            [
                self._convert_expression_safe(decorator)
                for decorator in node.decorator_list
            ],
            type_params,
        )
        register_class_cell(class_definition, class_cell)
        return class_definition

    def _convert_function_args(
        self,
        args_node: python_ast.arguments,
        *,
        ensure_return: bool = False,
        type_params_node=None,
    ) -> pyflow_ast.CodeParameters:
        """Convert Python AST arguments to pyflow AST CodeParameters.

        Supports:
        - Positional-only parameters (Python 3.8+)
        - Keyword-only parameters
        - Type parameters for generics (Python 3.12+)
        """
        posonly = [a.arg for a in getattr(args_node, "posonlyargs", [])]
        posonly_params = [pyflow_ast.Local(name) for name in posonly]

        regular = [a.arg for a in getattr(args_node, "args", [])]
        regular_params = [pyflow_ast.Local(name) for name in regular]

        kwonly = [a.arg for a in getattr(args_node, "kwonlyargs", [])]
        kwonly_params = [pyflow_ast.Local(name) for name in kwonly]

        all_positional_names = [*posonly, *regular]
        params = [*regular_params, *kwonly_params]
        param_names = [
            *regular,
            *(f"{_KWONLY_PARAM_PREFIX}{name}" for name in kwonly),
        ]

        per_param_defaults: List[Optional[PythonASTNode]] = [None] * (
            len(all_positional_names) + len(kwonly)
        )

        pos_defaults = list(getattr(args_node, "defaults", []) or [])
        if pos_defaults:
            start = len(all_positional_names) - len(pos_defaults)
            for i, default_node in enumerate(pos_defaults):
                idx = start + i
                per_param_defaults[idx] = self._convert_default_value(default_node)

        kw_defaults = list(getattr(args_node, "kw_defaults", []) or [])
        if kwonly and kw_defaults:
            base = len(all_positional_names)
            for i, default_node in enumerate(kw_defaults):
                if default_node is None:
                    continue
                per_param_defaults[base + i] = self._convert_default_value(default_node)

        first_default = next(
            (i for i, d in enumerate(per_param_defaults) if d is not None), None
        )
        defaults: List[PythonASTNode] = []
        if first_default is not None:
            for d in per_param_defaults[first_default:]:
                defaults.append(
                    d if d is not None else pyflow_ast.Existing(Object(MISSING_DEFAULT))
                )

        vararg = None
        if args_node.vararg:
            vararg = pyflow_ast.Local(args_node.vararg.arg)

        kwarg = None
        if args_node.kwarg:
            kwarg = pyflow_ast.Local(args_node.kwarg.arg)

        type_params = None
        if type_params_node is not None:
            type_params = self._convert_type_params(type_params_node)

        return pyflow_ast.CodeParameters(
            selfparam=None,
            posonlyparams=posonly_params,
            posonlynames=posonly,
            params=params,
            paramnames=param_names,
            defaults=defaults,
            vparam=vararg,
            kparam=kwarg,
            returnparams=[pyflow_ast.Local("ret0")] if ensure_return else [],
            type_params=type_params,
        )

    def _convert_type_params(self, type_params_node) -> pyflow_ast.TypeParams:
        """Convert Python 3.12+ type parameters to pyflow AST."""
        params = []
        for tp in type_params_node:
            name = tp.name if hasattr(tp, "name") else str(tp)
            bound = None
            if hasattr(tp, "bound") and tp.bound:
                bound = self._convert_expression_safe(tp.bound)
            params.append(pyflow_ast.TypeParam(name, bound))
        return pyflow_ast.TypeParams(params)

    def _convert_default_value(self, node: python_ast.AST) -> PythonASTNode:
        """Preserve non-literal defaults as expressions instead of coercing to ``None``."""
        try:
            value = python_ast.literal_eval(node)
        except Exception:
            return self._convert_expression_safe(node)
        return pyflow_ast.Existing(Object(value))

    def _convert_annotation(self, node: python_ast.AST) -> PythonASTNode:
        if self._future_annotations:
            return pyflow_ast.Existing(Object(python_ast.unparse(node)))
        return self._convert_expression_safe(node)

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
        """Convert Python AST ImportFrom to pyflow AST.

        Star imports (``from mod import *``) are no longer silently dropped.
        Instead, the Import node is emitted with ``fromlist=["*"]`` so that
        downstream analyses can see that the module's entire namespace was
        pulled in.  The result is stored in a dedicated temporary so that
        alias-resolution passes can iterate over it.
        """
        module = node.module or ""
        level = int(getattr(node, "level", 0) or 0)

        # Separate regular names from the wildcard.
        has_star = any(getattr(a, "name", None) == "*" for a in (node.names or []))
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

        # Emit the star import as a separate Import node with fromlist=["*"].
        # Downstream analyses can recognise this pattern and widen the scope.
        if has_star:
            star_tmp = self._tmp_local("star_import", node)
            suite.append(
                pyflow_ast.Assign(
                    pyflow_ast.Import(module, ["*"], level),
                    [star_tmp],
                )
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

    def _convert_assert(self, node: python_ast.Assert) -> Optional[PythonASTNode]:
        """Convert Python AST Assert to pyflow AST."""
        test_expr = self._convert_expression(node.test)
        msg_expr = None
        if node.msg:
            msg_expr = self._convert_expression(node.msg)

        return pyflow_ast.Assert(test_expr, msg_expr)

    def _convert_with(self, node: python_ast.With) -> Optional[PythonASTNode]:
        """Convert Python AST With to pyflow AST with proper context manager semantics.

        Models the full context manager protocol:
        1. Evaluate context expression
        2. Call __enter__ on the context manager
        3. Assign result to optional_vars (if present)
        4. Execute body
        5. Call __exit__ on the context manager (guaranteed via try-finally)
        """
        body = self.convert_python_ast_to_pyflow(node.body)
        result = self._wrap_context_manager_items(node.items, body, is_async=False)
        result._origin_tag = "With"
        return result

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
            return self._name_delete(target.id)
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
            return self._name_store(target.id, value)
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
            suite = pyflow_ast.Suite([])
            elts = target.elts

            # Find starred element (e.g. a, *b, c = seq), if any.
            starred_idx = next(
                (i for i, e in enumerate(elts) if isinstance(e, python_ast.Starred)),
                None,
            )

            if starred_idx is None:
                # Simple element-wise unpacking: a, b, c = seq
                for i, elt in enumerate(elts):
                    idx = pyflow_ast.Existing(Object(i))
                    rhs = self._call_named("interpreter_getitem", [value, idx])
                    suite.append(self._convert_store(elt, rhs))
            else:
                # Starred unpacking: a, *b, c = seq
                n_after = len(elts) - starred_idx - 1

                # Elements before the starred target.
                for i in range(starred_idx):
                    idx = pyflow_ast.Existing(Object(i))
                    rhs = self._call_named("interpreter_getitem", [value, idx])
                    suite.append(self._convert_store(elts[i], rhs))

                # The starred target receives seq[starred_idx : -n_after or None].
                star_target = elts[starred_idx].value  # unwrap Starred node
                stop = (
                    pyflow_ast.Existing(Object(-n_after))
                    if n_after > 0
                    else pyflow_ast.Existing(Object(None))
                )
                slice_node = pyflow_ast.BuildSlice(
                    pyflow_ast.Existing(Object(starred_idx)), stop, None
                )
                # Extended unpacking always creates a fresh list.  Keep the
                # slice bounds as evaluated operands, while the dedicated
                # helper lets heap analysis copy the source elements without
                # aliasing the result container directly to those elements.
                star_rhs = self._call_named(
                    "interpreter_slice_copy",
                    [value, slice_node],
                )
                suite.append(self._convert_store(star_target, star_rhs))

                # Elements after the starred target (use negative indices).
                for j, elt in enumerate(elts[starred_idx + 1 :]):
                    idx = pyflow_ast.Existing(Object(-(n_after - j)))
                    rhs = self._call_named("interpreter_getitem", [value, idx])
                    suite.append(self._convert_store(elt, rhs))

            return suite
        return pyflow_ast.Discard(value)

    def _convert_assign(self, node: python_ast.Assign) -> PythonASTNode:
        rhs = self._convert_expression_safe(node.value)

        # Fast path for pure-local assignment(s).
        if all(
            isinstance(t, python_ast.Name) and self._name_uses_plain_local(t.id)
            for t in node.targets
        ):
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
            self._telemetry["unknown_augassign"] += 1
            self._warn_approx(node, "unknown augmented assignment operator")
            tagged_rhs = self._call_named(
                "interpreter_unknown_augassign",
                [pyflow_ast.Existing(Object(type(node.op).__name__)), rhs],
            )
            result = self._convert_store(node.target, tagged_rhs)
        else:
            op = pyflow_ast.Existing(Object(op_name))

            # Load current value from target.
            if isinstance(node.target, python_ast.Name):
                cur = self._name_expr(node.target.id)
                new_val = pyflow_ast.Call(op, [cur, rhs], [], None, None)
                result = self._name_store(node.target.id, new_val)

            elif isinstance(node.target, python_ast.Attribute):
                obj = self._convert_expression_safe(node.target.value)
                name = pyflow_ast.Existing(Object(node.target.attr))
                cur = pyflow_ast.GetAttr(obj, name)
                new_val = pyflow_ast.Call(op, [cur, rhs], [], None, None)
                result = pyflow_ast.SetAttr(new_val, obj, name)

            elif isinstance(node.target, python_ast.Subscript):
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
                result = pyflow_ast.Discard(
                    pyflow_ast.Call(
                        pyflow_ast.Existing(Object("interpreter_setitem")),
                        [obj, sub, new_val],
                        [],
                        None,
                        None,
                    )
                )
            else:
                result = self._unsupported_stmt(
                    node, f"unsupported AugAssign target {type(node.target).__name__}"
                )
        return result

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
        """Convert Python AST AsyncWith to pyflow AST with proper async context manager semantics.

        Models the full async context manager protocol:
        1. Evaluate context expression
        2. Call __aenter__ on the context manager
        3. Assign result to optional_vars (if present)
        4. Execute body
        5. Call __aexit__ on the context manager (guaranteed via try-finally)
        """
        body = self.convert_python_ast_to_pyflow(node.body)
        result = self._wrap_context_manager_items(node.items, body, is_async=True)
        result._origin_tag = "AsyncWith"
        return result

    def _ensure_suite(self, node_or_suite: PythonASTNode) -> pyflow_ast.Suite:
        """Ensure we have a Suite, wrapping a single statement when needed."""
        if isinstance(node_or_suite, pyflow_ast.Suite):
            return node_or_suite
        return pyflow_ast.Suite([node_or_suite])

    def _wrap_context_manager_items(
        self,
        items,
        body: PythonASTNode,
        *,
        is_async: bool,
    ) -> pyflow_ast.Suite:
        current = self._ensure_suite(body)
        for item in reversed(items):
            current = self._wrap_single_context_manager_item(
                item,
                current,
                is_async=is_async,
            )
        return current

    def _wrap_single_context_manager_item(
        self,
        item,
        body: pyflow_ast.Suite,
        *,
        is_async: bool,
    ) -> pyflow_ast.Suite:
        prefix = "async_" if is_async else ""
        ctx_expr = self._convert_expression_safe(item.context_expr)
        ctx_local = self._tmp_local(f"{prefix}ctx_mgr", item)
        active_local = self._tmp_local(f"{prefix}ctx_mgr_active", item)
        enter_local = self._tmp_local(f"{prefix}ctx_enter", item)
        exc_local = self._tmp_local(f"{prefix}ctx_exc", item)
        suppressed_local = self._tmp_local(f"{prefix}ctx_suppressed", item)

        preamble = pyflow_ast.Suite(
            [
                pyflow_ast.Assign(pyflow_ast.Existing(Object(False)), [active_local]),
                pyflow_ast.Assign(ctx_expr, [ctx_local]),
            ]
        )

        enter_call = self._call_named(
            "interpreter_aenter" if is_async else "interpreter_enter",
            [ctx_local],
        )
        if is_async:
            enter_value: PythonASTNode = pyflow_ast.Await(enter_call)
        else:
            enter_value = enter_call
        preamble.append(pyflow_ast.Assign(enter_value, [enter_local]))
        preamble.append(
            pyflow_ast.Assign(pyflow_ast.Existing(Object(True)), [active_local])
        )
        if item.optional_vars is not None:
            preamble.append(self._convert_store(item.optional_vars, enter_local))

        normal_exit_call = self._call_named(
            "interpreter_aexit" if is_async else "interpreter_exit",
            [
                ctx_local,
                pyflow_ast.Existing(Object(None)),
                pyflow_ast.Existing(Object(None)),
                pyflow_ast.Existing(Object(None)),
            ],
        )
        normal_exit_stmt: PythonASTNode
        if is_async:
            normal_exit_stmt = pyflow_ast.Discard(pyflow_ast.Await(normal_exit_call))
        else:
            normal_exit_stmt = pyflow_ast.Discard(normal_exit_call)

        exc_type = self._call_named("interpreter_exception_type", [exc_local])
        exc_tb = self._call_named(
            "interpreter_getattr",
            [exc_local, pyflow_ast.Existing(Object("__traceback__"))],
        )
        exceptional_exit_call = self._call_named(
            "interpreter_aexit" if is_async else "interpreter_exit",
            [ctx_local, exc_type, exc_local, exc_tb],
        )
        exceptional_exit_value: PythonASTNode
        if is_async:
            exceptional_exit_value = pyflow_ast.Await(exceptional_exit_call)
        else:
            exceptional_exit_value = exceptional_exit_call

        handler_body = pyflow_ast.Switch(
            condition=pyflow_ast.Condition(pyflow_ast.Suite([]), active_local),
            t=pyflow_ast.Suite(
                [
                    pyflow_ast.Assign(exceptional_exit_value, [suppressed_local]),
                    pyflow_ast.Switch(
                        condition=pyflow_ast.Condition(
                            pyflow_ast.Suite([]),
                            self._call_named(
                                "invertedConvertToBool", [suppressed_local]
                            ),
                        ),
                        t=pyflow_ast.Suite(
                            [
                                pyflow_ast.Raise(
                                    exception=exc_local,
                                    parameter=None,
                                    traceback=exc_tb,
                                )
                            ]
                        ),
                        f=pyflow_ast.Suite([]),
                    ),
                ]
            ),
            f=pyflow_ast.Suite(
                [
                    pyflow_ast.Raise(
                        exception=exc_local,
                        parameter=None,
                        traceback=pyflow_ast.Existing(Object(None)),
                    )
                ]
            ),
        )

        handler = pyflow_ast.ExceptionHandler(
            preamble=pyflow_ast.Suite([]),
            type=pyflow_ast.Existing(Object(BaseException)),
            value=exc_local,
            body=pyflow_ast.Suite([handler_body]),
        )

        try_body = pyflow_ast.Suite([*preamble.blocks, *body.blocks])
        wrapped = pyflow_ast.TryExceptFinally(
            body=try_body,
            handlers=[handler],
            defaultHandler=None,
            else_=pyflow_ast.Suite([normal_exit_stmt]),
            finally_=None,
        )
        return pyflow_ast.Suite([wrapped])

    def _convert_match(self, node) -> Optional[PythonASTNode]:
        """Convert Python AST Match (pattern matching, Python 3.10+) to pyflow AST.

        Pattern matching is converted with proper binding semantics:
        - Subject is evaluated once and stored in a temp variable
        - Each case is checked in order with proper pattern matching
        - Pattern bindings are properly captured
        """
        subject = self._convert_expression_safe(node.subject)
        tmp_subject = self._tmp_local("match_subject", node)

        suite = pyflow_ast.Suite([pyflow_ast.Assign(subject, [tmp_subject])])

        cases = []
        for i, case in enumerate(node.cases):
            bindings: List[PythonASTNode] = []
            case_body = self.convert_python_ast_to_pyflow(case.body)

            if hasattr(case, "pattern"):
                condition = self._convert_pattern_with_bindings(
                    case.pattern, tmp_subject, bindings
                )
                if case.guard:
                    guard = self._convert_expression_safe(case.guard)
                    condition = self._call_named(
                        "interpreter_booland", [condition, guard]
                    )
                cases.append((condition, bindings, case_body))
            else:
                cases.append((None, [], case_body))

        if not cases:
            return suite

        # Bug #14 fix: the original code accessed ``body.blocks`` which does
        # not exist on ``pyflow_ast.Suite``.  ``pyflow_ast.Suite`` stores its
        # statements in a list passed to its constructor; we should just use
        # the Suite object directly rather than trying to unwrap it.
        result: PythonASTNode = pyflow_ast.Suite([])
        for condition, bindings, body in reversed(cases):
            body_suite = self._ensure_suite(body)
            if bindings:
                full_body = pyflow_ast.Suite(list(bindings) + [body_suite])
            else:
                full_body = body_suite
            if condition is None:
                result = full_body
            else:
                result = pyflow_ast.Switch(
                    condition=pyflow_ast.Condition(pyflow_ast.Suite([]), condition),
                    t=full_body,
                    f=self._ensure_suite(result),
                )

        suite.append(result)
        suite._origin_tag = "Match"
        return suite

    def _convert_pattern_with_bindings(
        self, pattern, subject: PythonASTNode, bindings: List[PythonASTNode]
    ) -> PythonASTNode:
        """Convert a match pattern to a condition check, collecting bindings.

        Returns a condition expression that evaluates to True if the pattern matches.
        Bindings are appended to the bindings list as Assign statements.
        """
        if hasattr(python_ast, "MatchValue") and isinstance(
            pattern, python_ast.MatchValue
        ):
            value = self._convert_expression_safe(pattern.value)
            return self._call_named("interpreter__eq__", [subject, value])

        elif hasattr(python_ast, "MatchSingleton") and isinstance(
            pattern, python_ast.MatchSingleton
        ):
            return self._call_named(
                "interpreter__eq__",
                [subject, pyflow_ast.Existing(Object(pattern.value))],
            )

        elif hasattr(python_ast, "MatchSequence") and isinstance(
            pattern, python_ast.MatchSequence
        ):
            starred_idx = next(
                (
                    i
                    for i, sub_pattern in enumerate(pattern.patterns)
                    if hasattr(python_ast, "MatchStar")
                    and isinstance(sub_pattern, python_ast.MatchStar)
                ),
                None,
            )

            if starred_idx is None:
                length_check = self._call_named(
                    "interpreter_match_sequence_len",
                    [
                        subject,
                        pyflow_ast.Existing(Object(len(pattern.patterns))),
                    ],
                )
            else:
                length_check = self._call_named(
                    "interpreter_match_sequence_len_min",
                    [
                        subject,
                        pyflow_ast.Existing(Object(len(pattern.patterns) - 1)),
                    ],
                )

            if not pattern.patterns:
                return length_check

            result = length_check
            trailing_count = 0
            if starred_idx is not None:
                trailing_count = len(pattern.patterns) - starred_idx - 1

            for i, sub_pattern in enumerate(pattern.patterns):
                if starred_idx is not None and i == starred_idx:
                    stop = (
                        pyflow_ast.Existing(Object(-trailing_count))
                        if trailing_count > 0
                        else pyflow_ast.Existing(Object(None))
                    )
                    slice_node = pyflow_ast.BuildSlice(
                        pyflow_ast.Existing(Object(starred_idx)),
                        stop,
                        None,
                    )
                    elem = self._call_named(
                        "interpreter_getitem", [subject, slice_node]
                    )
                else:
                    if starred_idx is not None and i > starred_idx:
                        trailing_offset = i - starred_idx - 1
                        idx = pyflow_ast.Existing(
                            Object(-(trailing_count - trailing_offset))
                        )
                    else:
                        idx = pyflow_ast.Existing(Object(i))
                    elem = self._call_named("interpreter_getitem", [subject, idx])

                sub_condition = self._convert_pattern_with_bindings(
                    sub_pattern, elem, bindings
                )
                result = pyflow_ast.ShortCircutAnd([result, sub_condition])
            return result

        elif hasattr(python_ast, "MatchMapping") and isinstance(
            pattern, python_ast.MatchMapping
        ):
            result = self._call_named(
                "interpreter_match_mapping_len",
                [subject, pyflow_ast.Existing(Object(len(pattern.keys)))],
            )
            for key, sub_pattern in zip(pattern.keys, pattern.patterns):
                key_expr = self._convert_expression_safe(key)
                value = self._call_named("interpreter_getitem", [subject, key_expr])
                sub_condition = self._convert_pattern_with_bindings(
                    sub_pattern, value, bindings
                )
                result = pyflow_ast.ShortCircutAnd([result, sub_condition])
            if getattr(pattern, "rest", None):
                matched_keys = pyflow_ast.BuildList(
                    [self._convert_expression_safe(key) for key in pattern.keys]
                )
                rest = self._call_named(
                    "interpreter_match_mapping_rest", [subject, matched_keys]
                )
                bindings.append(
                    pyflow_ast.Assign(rest, [pyflow_ast.Local(pattern.rest)])
                )
            return result

        elif hasattr(python_ast, "MatchClass") and isinstance(
            pattern, python_ast.MatchClass
        ):
            cls = self._convert_expression_safe(pattern.cls)
            result = self._call_named("interpreter_match_class", [subject, cls])
            for i, sub_pattern in enumerate(pattern.patterns):
                idx = pyflow_ast.Existing(Object(i))
                elem = self._call_named(
                    "interpreter_match_class_arg", [subject, cls, idx]
                )
                sub_condition = self._convert_pattern_with_bindings(
                    sub_pattern, elem, bindings
                )
                result = pyflow_ast.ShortCircutAnd([result, sub_condition])
            for attr_name, sub_pattern in zip(pattern.kwd_attrs, pattern.kwd_patterns):
                attr = self._call_named(
                    "interpreter_getattr",
                    [subject, pyflow_ast.Existing(Object(attr_name))],
                )
                sub_condition = self._convert_pattern_with_bindings(
                    sub_pattern, attr, bindings
                )
                result = pyflow_ast.ShortCircutAnd([result, sub_condition])
            return result

        elif hasattr(python_ast, "MatchStar") and isinstance(
            pattern, python_ast.MatchStar
        ):
            if pattern.name:
                rest = self._call_named("interpreter_match_rest", [subject])
                bindings.append(
                    pyflow_ast.Assign(rest, [pyflow_ast.Local(pattern.name)])
                )
            return pyflow_ast.Existing(Object(True))

        elif hasattr(python_ast, "MatchAs") and isinstance(pattern, python_ast.MatchAs):
            if pattern.pattern is None:
                if pattern.name:
                    bindings.append(
                        pyflow_ast.Assign(subject, [pyflow_ast.Local(pattern.name)])
                    )
                return pyflow_ast.Existing(Object(True))
            sub_condition = self._convert_pattern_with_bindings(
                pattern.pattern, subject, bindings
            )
            if pattern.name:
                bindings.append(
                    pyflow_ast.Assign(subject, [pyflow_ast.Local(pattern.name)])
                )
            return sub_condition

        elif hasattr(python_ast, "MatchOr") and isinstance(pattern, python_ast.MatchOr):
            if not pattern.patterns:
                return pyflow_ast.Existing(Object(False))
            branch_conditions: List[PythonASTNode] = []
            branch_bindings: List[List[PythonASTNode]] = []
            for sub_pattern in pattern.patterns:
                sub_bindings: List[PythonASTNode] = []
                sub_condition = self._convert_pattern_with_bindings(
                    sub_pattern, subject, sub_bindings
                )
                branch_conditions.append(sub_condition)
                branch_bindings.append(sub_bindings)

            if any(branch_bindings):
                binding_switch: PythonASTNode = pyflow_ast.Suite([])
                for sub_condition, sub_bindings in reversed(
                    list(zip(branch_conditions, branch_bindings))
                ):
                    branch_body = self._ensure_suite(pyflow_ast.Suite(sub_bindings))
                    binding_switch = pyflow_ast.Switch(
                        condition=pyflow_ast.Condition(
                            pyflow_ast.Suite([]), sub_condition
                        ),
                        t=branch_body,
                        f=self._ensure_suite(binding_switch),
                    )
                bindings.append(binding_switch)

            result = branch_conditions[0]
            for sub_condition in branch_conditions[1:]:
                result = pyflow_ast.ShortCircutOr([result, sub_condition])
            return result

        return pyflow_ast.Existing(Object(True))

    def _convert_try_star(self, node) -> Optional[PythonASTNode]:
        """Convert Python AST TryStar (exception groups, Python 3.11+) to pyflow AST.

        Exception groups use except* syntax which can:
        - Match multiple exception types from a single exception group
        - Handle partial matches (some exceptions handled, others re-raised)
        - Use exception group specific matching
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

            original_group = pyflow_ast.Local("__exc_group__")
            handler_body = self.convert_python_ast_to_pyflow(handler.body)
            handler_body = self._ensure_suite(handler_body)
            # The transfer engine already preserves an unmatched exceptional
            # edge for typed handlers.  Unconditionally re-raising the original
            # group here incorrectly removed the fully-handled normal path.

            preamble = pyflow_ast.Suite([])
            if exc_name and exc_type:
                preamble.append(
                    pyflow_ast.Assign(
                        self._call_named(
                            "interpreter_exception_group_extract",
                            [original_group, exc_type],
                        ),
                        [exc_name],
                    )
                )

            exc_handler = pyflow_ast.ExceptionHandler(
                preamble=preamble,
                type=exc_type,
                value=original_group,
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
        """
        value = (
            self._convert_expression_safe(node.value)
            if node.value is not None
            else None
        )
        scope = self._current_scope()
        evaluates_annotation = scope is None or scope.get("kind") in {
            "module",
            "class",
        }
        annotation = (
            self._convert_annotation(node.annotation)
            if evaluates_annotation
            else None
        )

        if isinstance(node.target, python_ast.Name):
            if annotation is not None:
                return pyflow_ast.AnnAssign(
                    pyflow_ast.Local(node.target.id),
                    annotation,
                    value,
                )
            if value is not None:
                return self._name_store(node.target.id, value)
            return pyflow_ast.Suite([])

        # For non-local targets, keep the runtime-equivalent lowering.
        suite = pyflow_ast.Suite([])
        if value is None:
            if annotation is not None:
                suite.append(pyflow_ast.Discard(annotation))
            return suite

        if isinstance(node.target, python_ast.Attribute):
            obj = self._convert_expression_safe(node.target.value)
            name = pyflow_ast.Existing(Object(node.target.attr))
            suite.append(pyflow_ast.SetAttr(value, obj, name))
            if annotation is not None:
                suite.append(pyflow_ast.Discard(annotation))
            return suite
        if isinstance(node.target, python_ast.Subscript):
            obj = self._convert_expression_safe(node.target.value)
            sub = self._convert_subscript_index(node.target.slice)
            suite.append(
                pyflow_ast.Discard(
                    pyflow_ast.Call(
                        pyflow_ast.Existing(Object("interpreter_setitem")),
                        [obj, sub, value],
                        [],
                        None,
                        None,
                    )
                )
            )
            if annotation is not None:
                suite.append(pyflow_ast.Discard(annotation))
            return suite

        return self._unsupported_stmt(node, "annotated assignment target unsupported")

    def _convert_type_alias(self, node) -> PythonASTNode:
        """Convert Python 3.12+ ``type Alias = ...`` declarations.

        Preserve the alias declaration explicitly while also binding the alias name
        to the lowered value expression so downstream analyses can resolve later
        references conservatively.
        """
        value = self._convert_expression_safe(node.value)
        if isinstance(node.name, python_ast.Name):
            alias_name = node.name.id
        else:
            alias_name = getattr(node.name, "name", str(node.name))

        params_node = getattr(node, "type_params", None)
        params = []
        if params_node:
            params = list(self._convert_type_params(params_node).params)

        return pyflow_ast.Suite(
            [
                pyflow_ast.TypeAlias(alias_name, params, value),
                self._name_store(alias_name, value),
            ]
        )

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

        Comprehensions are modeled as nested loops with append operations,
        preserving iteration semantics and handling if-conditions.
        """
        generators = node.generators
        kind = result_type.lower()
        capture_names = self._comprehension_capture_names(node)
        capture_formals = [pyflow_ast.Local(name) for name in capture_names]
        capture_actuals = [self._name_expr(name) for name in capture_names]

        if kind == "dict":
            result_init = pyflow_ast.BuildMap([])

            def make_add_stmt(result_local: pyflow_ast.Local) -> PythonASTNode:
                key_expr = self._convert_expression_safe(node.key)
                value_expr = self._convert_expression_safe(node.value)
                return pyflow_ast.Discard(
                    self._call_named(
                        "interpreter_setitem", [result_local, key_expr, value_expr]
                    )
                )

        elif kind == "set":
            element = self._convert_expression_safe(node.elt)
            result_init = pyflow_ast.BuildSet([])

            def make_add_stmt(result_local: pyflow_ast.Local) -> PythonASTNode:
                return pyflow_ast.Discard(
                    self._call_named("interpreter_set_add", [result_local, element])
                )

        else:
            element = self._convert_expression_safe(node.elt)
            result_init = pyflow_ast.BuildList([])

            def make_add_stmt(result_local: pyflow_ast.Local) -> PythonASTNode:
                return pyflow_ast.Discard(
                    self._call_named("interpreter_list_append", [result_local, element])
                )

        if not generators:
            if kind == "list":
                return pyflow_ast.BuildList([element])
            if kind == "dict":
                return pyflow_ast.BuildMap(
                    [
                        self._convert_expression_safe(node.key),
                        self._convert_expression_safe(node.value),
                    ]
                )
            if kind == "set":
                return pyflow_ast.BuildSet([element])
            return result_init

        result_local = self._tmp_local("comp_result", node)
        inner_body: PythonASTNode = pyflow_ast.Suite([make_add_stmt(result_local)])

        for gen in reversed(generators):
            iter_expr = self._convert_expression_safe(gen.iter)
            body_preamble = pyflow_ast.Suite([])

            if isinstance(gen.target, python_ast.Name):
                index = pyflow_ast.Local(gen.target.id)
            else:
                index = self._tmp_local("comp_idx", gen)
                store = self._convert_store(gen.target, index)
                body_preamble.append(store)

            if gen.ifs:
                for if_cond in reversed(gen.ifs):
                    cond = self._convert_expression_safe(if_cond)
                    inner_body = pyflow_ast.Suite(
                        [
                            pyflow_ast.Switch(
                                condition=pyflow_ast.Condition(
                                    pyflow_ast.Suite([]), cond
                                ),
                                t=inner_body,
                                f=pyflow_ast.Suite([]),
                            )
                        ]
                    )

            inner_body = pyflow_ast.For(
                iterator=iter_expr,
                index=index,
                loopPreamble=pyflow_ast.Suite([]),
                bodyPreamble=body_preamble,
                body=inner_body,
                else_=pyflow_ast.Suite([]),
            )

        comp_body = pyflow_ast.Suite(
            [
                pyflow_ast.Assign(result_init, [result_local]),
                inner_body,
                pyflow_ast.Return([result_local]),
            ]
        )
        comp_params = pyflow_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=capture_formals,
            paramnames=capture_names,
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[pyflow_ast.Local("ret0")],
            type_params=None,
        )
        comp_code = pyflow_ast.Code(f"<{kind}comp>", comp_params, comp_body)
        comp_code.annotation = CodeAnnotation(
            contexts=None,
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=[f"converted_{kind}comp"],
            live=None,
            killed=None,
            codeReads=None,
            codeModifies=None,
            codeAllocates=None,
            lowered=False,
            runtime=False,
            interpreter=False,
        )
        return pyflow_ast.DirectCall(
            comp_code,
            None,
            capture_actuals,
            [],
            None,
            None,
        )

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

        Generator expressions are lazy. We model them by creating a
        generator function that yields values.
        """
        generators = node.generators
        element = self._convert_expression_safe(node.elt)
        capture_names = self._comprehension_capture_names(node)
        capture_formals = [pyflow_ast.Local(name) for name in capture_names]
        capture_actuals = [self._name_expr(name) for name in capture_names]

        if not generators:
            return self._call_named("interpreter_make_generator", [element])

        gen_func_codeparams = pyflow_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=capture_formals,
            paramnames=capture_names,
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=[pyflow_ast.Local("ret0")],
            type_params=None,
        )

        inner_body = pyflow_ast.Suite([pyflow_ast.Discard(pyflow_ast.Yield(element))])

        for gen in reversed(generators):
            iter_expr = self._convert_expression_safe(gen.iter)
            body_preamble = pyflow_ast.Suite([])

            if isinstance(gen.target, python_ast.Name):
                index = pyflow_ast.Local(gen.target.id)
            else:
                index = self._tmp_local("gen_idx", gen)
                store = self._convert_store(gen.target, index)
                body_preamble.append(store)

            if gen.ifs:
                for if_cond in reversed(gen.ifs):
                    cond = self._convert_expression_safe(if_cond)
                    inner_body = pyflow_ast.Suite(
                        [
                            pyflow_ast.Switch(
                                condition=pyflow_ast.Condition(
                                    pyflow_ast.Suite([]), cond
                                ),
                                t=inner_body,
                                f=pyflow_ast.Suite([]),
                            )
                        ]
                    )

            inner_body = pyflow_ast.For(
                iterator=iter_expr,
                index=index,
                loopPreamble=pyflow_ast.Suite([]),
                bodyPreamble=body_preamble,
                body=inner_body,
                else_=pyflow_ast.Suite([]),
            )

        code = pyflow_ast.Code(
            "<genexpr>", gen_func_codeparams, pyflow_ast.Suite([inner_body])
        )
        code.annotation = CodeAnnotation(
            contexts=None,
            descriptive=False,
            primitive=False,
            staticFold=False,
            dynamicFold=False,
            origin=["converted_genexpr"],
            live=None,
            killed=None,
            codeReads=None,
            codeModifies=None,
            codeAllocates=None,
            lowered=False,
            runtime=False,
            interpreter=False,
        )

        return pyflow_ast.DirectCall(
            code,
            None,
            capture_actuals,
            [],
            None,
            None,
        )

    @staticmethod
    def _comprehension_capture_names(node: python_ast.AST) -> List[str]:
        loaded: Set[str] = set()
        bound: Set[str] = set()

        class CaptureVisitor(python_ast.NodeVisitor):
            def visit_Name(self, current: python_ast.Name) -> None:
                if isinstance(current.ctx, python_ast.Load):
                    loaded.add(current.id)
                else:
                    bound.add(current.id)

            def visit_Lambda(self, current: python_ast.Lambda) -> None:
                return

        CaptureVisitor().visit(node)
        return sorted(loaded - bound)
