"""Control-flow and constant-evaluation helpers for local taint analysis."""

from __future__ import annotations

import ast
from typing import List, Optional, Tuple


class _ControlFlowMixin:
    def _visit_block(self, statements: List[ast.stmt]) -> None:
        """Visit statements in order, stopping after unconditional jumps."""
        for stmt in statements:
            self.visit(stmt)
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                break

    def _const_int(self, expr: ast.AST) -> Optional[int]:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, int):
            return expr.value
        if isinstance(expr, ast.Name):
            return self.int_values.get(expr.id)
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, (ast.UAdd, ast.USub)):
            value = self._const_int(expr.operand)
            if value is None:
                return None
            return value if isinstance(expr.op, ast.UAdd) else -value
        if isinstance(expr, ast.BinOp) and isinstance(
            expr.op, (ast.Add, ast.Sub, ast.Mult)
        ):
            left = self._const_int(expr.left)
            right = self._const_int(expr.right)
            if left is None or right is None:
                return None
            if isinstance(expr.op, ast.Add):
                return left + right
            if isinstance(expr.op, ast.Sub):
                return left - right
            return left * right
        if (
            isinstance(expr, ast.Call)
            and self._call_fullname(expr.func) == "len"
            and expr.args
        ):
            arg0 = expr.args[0]
            if isinstance(arg0, ast.Name) and arg0.id in self.list_lengths:
                return self.list_lengths[arg0.id]
        return None

    def _const_bool(self, expr: ast.AST) -> Optional[bool]:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, bool):
            return expr.value
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            inner = self._const_bool(expr.operand)
            return None if inner is None else (not inner)
        if isinstance(expr, ast.BoolOp):
            values = [self._const_bool(v) for v in expr.values]
            if any(v is None for v in values):
                return None
            if isinstance(expr.op, ast.And):
                return all(values)  # type: ignore[arg-type]
            if isinstance(expr.op, ast.Or):
                return any(values)  # type: ignore[arg-type]
        if (
            isinstance(expr, ast.Compare)
            and len(expr.ops) == 1
            and len(expr.comparators) == 1
        ):
            left = expr.left
            right = expr.comparators[0]
            left_int = self._const_int(left)
            right_int = self._const_int(right)
            if left_int is not None and right_int is not None:
                if isinstance(expr.ops[0], ast.Eq):
                    return left_int == right_int
                if isinstance(expr.ops[0], ast.NotEq):
                    return left_int != right_int
            if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
                if isinstance(expr.ops[0], ast.Eq):
                    return left.value == right.value
                if isinstance(expr.ops[0], ast.NotEq):
                    return left.value != right.value
        return None

    def _raise_is_tainted(self, stmt: ast.stmt) -> bool:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise) and node.exc is not None:
                if self._expr_is_tainted(node.exc):
                    return True
        return False

    def _expr_path(self, expr: ast.AST) -> Optional[Tuple[str, ...]]:
        """Return a constant key/index path for expressions like d['a'][0]."""
        if isinstance(expr, ast.Name):
            return (expr.id,)
        if isinstance(expr, ast.Attribute):
            base = self._expr_path(expr.value)
            if base is None:
                return None
            return base + (expr.attr,)
        if isinstance(expr, ast.Subscript):
            base = self._expr_path(expr.value)
            if base is None:
                return None
            key = self._subscript_key(expr.slice)
            if key is None:
                return None
            return base + (key,)
        return None

    def _clear_paths_for_root(self, root: str) -> None:
        paths = self.paths_by_root.pop(root, None)
        if not paths:
            return
        for path in paths:
            self.tainted_paths.discard(path)

    def _record_tainted_path(self, path: Tuple[str, ...]) -> None:
        if not path:
            return
        self.tainted_paths.add(path)
        self.paths_by_root.setdefault(path[0], set()).add(path)

    def _record_literal_taint_paths(
        self, prefix: Tuple[str, ...], expr: ast.AST
    ) -> None:
        """Record tainted leaf paths inside dict/list/tuple literals under prefix."""
        if isinstance(expr, ast.Dict):
            for k, v in zip(expr.keys, expr.values):
                if k is None:
                    # dict unpacking (**m): copy known paths when possible.
                    if isinstance(v, ast.Name):
                        src_root = v.id
                        for src_path in self.paths_by_root.get(src_root, set()):
                            self._record_tainted_path(prefix + src_path[1:])
                    continue
                key = self._subscript_key(k)
                if key is None:
                    continue
                if isinstance(v, (ast.Dict, ast.List, ast.Tuple)):
                    self._record_literal_taint_paths(prefix + (key,), v)
                elif self._expr_is_tainted(v):
                    self._record_tainted_path(prefix + (key,))
            return

        if isinstance(expr, (ast.List, ast.Tuple)):
            for idx, elt in enumerate(expr.elts):
                if isinstance(elt, ast.Starred):
                    # Precise modelling for starred expansions is handled elsewhere.
                    continue
                key = str(idx)
                if isinstance(elt, (ast.Dict, ast.List, ast.Tuple)):
                    self._record_literal_taint_paths(prefix + (key,), elt)
                elif self._expr_is_tainted(elt):
                    self._record_tainted_path(prefix + (key,))
            return
