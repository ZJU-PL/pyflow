"""Local expression, statement, alias, and sanitizer propagation."""

from __future__ import annotations
from typing import Any, FrozenSet, List, Optional
from pyflow.ir.pdg.graph import PDGNode
from pyflow.language.python import ast as py_ast
from .model import MemoryLayout, TaintState, _CLEAN
from .defaults import _DUNDER_PROPAGATE


class _TaintPropagationMixin:
    """Internal mixin composed by CPGTaintEngine."""

    def _propagate(
        self,
        tstate: TaintState,
        src_node: PDGNode,
        dst_node: PDGNode,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        ast_node = dst_node.ast_node
        if ast_node is None:
            return tstate

        src_label = src_node.label or ""
        if src_label.startswith("isinstance_guard:"):
            guarded_var = src_label.split(":", 1)[1]
            if guarded_var:
                mem.mark_tainted(guarded_var, _CLEAN)
                return None

        if self._isinstance_guard_strip(ast_node, mem):
            return None

        if isinstance(ast_node, py_ast.Call):
            return self._propagate_call(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.Assign):
            return self._propagate_assign(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.AnnAssign):
            return self._propagate_annassign(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.BinaryOp):
            return self._propagate_binary_op(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.GetSubscript):
            return self._propagate_subscript(ast_node, tstate, mem)
        if isinstance(ast_node, py_ast.Return):
            return tstate

        if isinstance(ast_node, py_ast.TryExceptFinally):
            return self._propagate_try(ast_node, tstate, dst_node, mem)

        label = dst_node.label or ""
        for san, san_cwes in self._sanitizers.items():
            if san in label:
                return self._apply_sanitizer(tstate, san, san_cwes)

        return tstate

    def _propagate_call(
        self,
        call_node: py_ast.Call,
        tstate: TaintState,
        mem: MemoryLayout,
        *,
        pending_sink_cwe: str = "",
    ) -> Optional[TaintState]:
        call_name = self._extract_call_name(call_node)

        if call_name and call_name in self._sanitizers:
            if call_name in ("re.match", "re.fullmatch", "re.search"):
                if self._is_validating_regex(call_node):
                    return self._apply_sanitizer(
                        tstate,
                        call_name,
                        self._sanitizers[call_name],
                        pending_sink_cwe,
                    )
                return tstate
            return self._apply_sanitizer(
                tstate, call_name, self._sanitizers[call_name], pending_sink_cwe
            )

        if call_name in ("int", "float", "bool", "str"):
            return tstate.sanitize(call_name)

        if call_name == "getattr":
            return self._handle_getattr(call_node, tstate, mem)

        if self._has_tainted_dict_unpack(call_node, mem):
            return tstate

        if call_name and call_name.split(".")[-1] in _DUNDER_PROPAGATE:
            return tstate

        if call_name and call_name.startswith("<lambda"):
            return self._handle_lambda_call(call_name, tstate, mem)

        if call_name:
            cache_key = (call_name, tuple(sorted(tstate.tags)))
            cached = self._summary_cache.get(cache_key)
            if cached is not None:
                return cached if cached.is_tainted() else None

        return tstate

    def _apply_sanitizer(
        self,
        tstate: TaintState,
        sanitizer_name: str,
        sanitizer_cwes: FrozenSet[str],
        pending_sink_cwe: str = "",
    ) -> TaintState:
        if not sanitizer_cwes:
            return tstate.sanitize(sanitizer_name)
        if not pending_sink_cwe or pending_sink_cwe in sanitizer_cwes:
            return tstate.sanitize(sanitizer_name)
        return tstate

    def _handle_lambda_call(
        self,
        lambda_name: str,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        lambda_entry = self._find_lambda_entry(lambda_name)
        if lambda_entry is None:
            return tstate
        lambda_meta = self._cpg.node_meta(lambda_entry)
        if not lambda_meta.get("lambda_name"):
            return tstate
        cache_key = (lambda_name, tuple(sorted(tstate.tags)))
        cached = self._summary_cache.get(cache_key)
        if cached is not None:
            return cached if cached.is_tainted() else None
        self._summary_cache[cache_key] = tstate
        return tstate

    def _find_lambda_entry(self, lambda_name: str) -> Optional[PDGNode]:
        for node in self._cpg.nodes():
            meta = self._cpg.node_meta(node)
            if meta.get("lambda_name") == lambda_name:
                return node
        return None

    def _propagate_assign(
        self,
        assign_node: py_ast.Assign,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        rhs = getattr(assign_node, "expr", None)
        if rhs is None:
            return tstate
        lcls = getattr(assign_node, "lcls", None)
        if lcls is None or len(lcls) != 1:
            return tstate
        target = lcls[0]
        if not isinstance(target, py_ast.Local):
            return tstate
        var_name = getattr(target, "name", "") or ""

        if isinstance(rhs, py_ast.Local):
            rhs_name = getattr(rhs, "name", "") or ""
            if rhs_name:
                mem.alias(var_name, rhs_name)
            return tstate

        if self._looks_like_subscript(rhs):
            base_name = self._first_local_name(rhs)
            if base_name and mem.is_tainted(base_name):
                mem.mark_tainted(var_name, tstate)
                return tstate

        if isinstance(rhs, py_ast.BinaryOp):
            op_type = (
                type(getattr(rhs, "op", None)).__name__ if hasattr(rhs, "op") else ""
            )
            if op_type == "Mod" or self._contains_tainted_local(rhs, mem):
                mem.mark_tainted(var_name, tstate)
                return tstate

        if isinstance(rhs, py_ast.Call):
            if tstate.is_tainted():
                mem.mark_tainted(var_name, tstate)
            return tstate

        rhs_type = type(rhs).__name__
        if rhs_type in ("List", "Tuple", "Set"):
            elts = getattr(rhs, "elts", None) or getattr(rhs, "elements", None)
            if elts:
                for elt in elts:
                    if isinstance(elt, py_ast.Local) and mem.is_tainted(
                        getattr(elt, "name", "")
                    ):
                        mem.mark_tainted(var_name, tstate)
                        return tstate

        if rhs_type == "Dict" and self._contains_tainted_local(rhs, mem):
            mem.mark_tainted(var_name, tstate)
            return tstate

        if self._looks_like_fstring(rhs) and self._contains_tainted_local(rhs, mem):
            mem.mark_tainted(var_name, tstate)
            return tstate

        return tstate

    def _propagate_annassign(
        self,
        ann_node: py_ast.AnnAssign,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        """Propagate taint through an annotated assignment (``x: int = val``).

        If the RHS value is tainted, or if the target is itself a tainted
        expression, taint flows through.  Annotation-only declarations
        (``x: int`` with no value) do not propagate.
        """
        value = getattr(ann_node, "value", None)
        if value is None:
            return tstate
        target = getattr(ann_node, "target", None)
        if not isinstance(target, py_ast.Local):
            return tstate
        var_name = getattr(target, "name", "") or ""

        if isinstance(value, py_ast.Local):
            rhs_name = getattr(value, "name", "") or ""
            if rhs_name and mem.is_tainted(rhs_name):
                mem.mark_tainted(var_name, tstate)
                return tstate

        if self._contains_tainted_local(value, mem):
            mem.mark_tainted(var_name, tstate)
            return tstate

        return tstate

    def _propagate_binary_op(
        self,
        binop_node: py_ast.BinaryOp,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        left = getattr(binop_node, "left", None)
        right = getattr(binop_node, "right", None)
        if (
            left
            and isinstance(left, py_ast.Local)
            and mem.is_tainted(getattr(left, "name", ""))
        ):
            return tstate
        if (
            right
            and isinstance(right, py_ast.Local)
            and mem.is_tainted(getattr(right, "name", ""))
        ):
            return tstate
        return tstate

    def _propagate_subscript(
        self,
        sub_node: py_ast.GetSubscript,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        """Propagate taint through a subscript read (``items[i]``).

        If the subscripted container or the index expression is tainted,
        the read result carries the taint.
        """
        container = getattr(sub_node, "expr", None) or getattr(sub_node, "value", None)
        if isinstance(container, py_ast.Local) and mem.is_tainted(
            getattr(container, "name", "") or ""
        ):
            return tstate
        subscript = getattr(sub_node, "subscript", None)
        if isinstance(subscript, py_ast.Local) and mem.is_tainted(
            getattr(subscript, "name", "") or ""
        ):
            return tstate
        return tstate

    @staticmethod
    def _iter_ast_children(node: Any) -> List[Any]:
        if node is None or isinstance(node, py_ast.leafTypes):
            return []
        children = getattr(node, "children", None)
        if children is None:
            return []
        result: List[Any] = []
        for child in children():
            if isinstance(child, (list, tuple)):
                result.extend(c for c in child if c is not None)
            elif child is not None:
                result.append(child)
        return result

    @classmethod
    def _first_local_name(cls, node: Any) -> str:
        if isinstance(node, py_ast.Local):
            return getattr(node, "name", "") or ""
        for child in cls._iter_ast_children(node):
            name = cls._first_local_name(child)
            if name:
                return name
        return ""

    @classmethod
    def _contains_tainted_local(cls, node: Any, mem: MemoryLayout) -> bool:
        if isinstance(node, py_ast.Local):
            return mem.is_tainted(getattr(node, "name", "") or "")
        return any(
            cls._contains_tainted_local(child, mem)
            for child in cls._iter_ast_children(node)
        )

    @staticmethod
    def _looks_like_subscript(node: Any) -> bool:
        node_type = type(node).__name__.lower()
        return node_type in {"subscript", "getitem"} or "subscript" in node_type

    @classmethod
    def _looks_like_fstring(cls, node: Any) -> bool:
        node_type = type(node).__name__
        if node_type in {"JoinedStr", "FormattedValue"}:
            return True
        text = ""
        if hasattr(node, "toStr"):
            try:
                text = node.toStr()
            except Exception:
                text = ""
        return text.startswith(("f'", 'f"', "F'", 'F"'))

    @classmethod
    def _literal_string(cls, node: Any) -> Optional[str]:
        value = cls._extract_constant_value(node)
        if value is not None:
            return value
        if hasattr(node, "toStr"):
            try:
                text = node.toStr()
            except Exception:
                return None
            if len(text) >= 2 and text[0] in "'\"" and text[-1] == text[0]:
                return text[1:-1]
            return text
        return None

    def _handle_getattr(
        self,
        call_node: py_ast.Call,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        args = getattr(call_node, "args", None) or []
        if len(args) >= 2:
            method_name = self._literal_string(args[1])
            if method_name:
                for sink_name in self._sinks:
                    if sink_name == method_name or sink_name.endswith(
                        "." + method_name
                    ):
                        return tstate
            if isinstance(args[1], py_ast.Local) and mem.is_tainted(
                getattr(args[1], "name", "") or ""
            ):
                return tstate
        return tstate

    def _has_tainted_dict_unpack(
        self, call_node: py_ast.Call, mem: MemoryLayout
    ) -> bool:
        kargs = getattr(call_node, "kargs", None)
        if isinstance(kargs, py_ast.Local) and mem.is_tainted(
            getattr(kargs, "name", "") or ""
        ):
            return True
        for keyword in getattr(call_node, "keywords", None) or []:
            key = getattr(keyword, "arg", None)
            value = getattr(keyword, "value", None)
            if key is None and isinstance(value, py_ast.Local):
                if mem.is_tainted(getattr(value, "name", "") or ""):
                    return True
        return False
