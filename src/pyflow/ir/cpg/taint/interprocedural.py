"""Loop, call, return, and interprocedural transfer helpers."""

from __future__ import annotations
from typing import Any, List, Optional, Tuple
from pyflow.ir.pdg.graph import PDGNode
from pyflow.ir.cpg.graph import CPGEdgeKind
from pyflow.language.python import ast as py_ast
from .model import MemoryLayout, TaintState, _CLEAN, _USER_CONTROLLED


class _TaintInterproceduralMixin:
    """Internal mixin composed by CPGTaintEngine."""

    def _is_loop_header(self, node: PDGNode) -> bool:
        """Check if a PDG node corresponds to a loop header Merge block."""
        meta = self._cpg.node_meta(node)
        return bool(meta.get("loop_header"))

    def _is_call_edge(self, src: PDGNode, dst: PDGNode) -> bool:
        self._cpg._ensure_built()
        for e in self._cpg._cpg_edges_out.get(src.node_id, ()):
            if e.target is dst and e.kind == CPGEdgeKind.CALL:
                return True
        return False

    def _is_return_edge(self, src: PDGNode, dst: PDGNode) -> bool:
        self._cpg._ensure_built()
        for e in self._cpg._cpg_edges_out.get(src.node_id, ()):
            if e.target is dst and e.kind == CPGEdgeKind.RETURN_EDGE:
                return True
        return False

    def _get_callee_param_names(self, func_name: str) -> List[str]:
        """Extract positional parameter names from a callee's ``Code`` object.

        ``ProgramDependenceGraph.cfg.code`` holds the ``py_ast.Code`` AST node,
        giving us direct access to ``Code.codeparameters``.  Returns an empty
        list when the function cannot be found or has no parameters.
        """
        pdg = self._cpg._pdgs.get(func_name)
        if pdg is None:
            return []
        code_ast = getattr(pdg.cfg, "code", None)
        if code_ast is None or not isinstance(code_ast, py_ast.Code):
            return []
        codeparams = getattr(code_ast, "codeparameters", None)
        if codeparams is None:
            return []
        posonly = getattr(codeparams, "posonlyparams", None) or []
        params = getattr(codeparams, "params", None) or []
        result: List[str] = []
        for p in posonly:
            if isinstance(p, py_ast.Local):
                result.append(getattr(p, "name", "") or "")
        for p in params:
            if isinstance(p, py_ast.Local):
                result.append(getattr(p, "name", "") or "")
        return result

    @staticmethod
    def _get_call_arg_exprs(call_node: Any) -> List[Any]:
        """Extract positional argument expressions from a ``Call`` AST node."""
        if not isinstance(call_node, py_ast.Call):
            return []
        return list(getattr(call_node, "args", None) or [])

    def _map_args_to_params(
        self,
        call_site: PDGNode,
        func_name: str,
        mem: MemoryLayout,
        new_mem: MemoryLayout,
    ) -> None:
        """Transfer taint from caller-side actual arguments to callee-side
        formal parameters in *new_mem*."""
        call_ast = call_site.ast_node
        if call_ast is None:
            return
        args = self._get_call_arg_exprs(call_ast)
        if not args:
            return
        param_names = self._get_callee_param_names(func_name)
        if not param_names:
            return
        for arg_expr, pname in zip(args, param_names):
            if isinstance(arg_expr, py_ast.Local):
                aname = getattr(arg_expr, "name", "") or ""
                if aname and mem.is_tainted(aname):
                    new_mem.mark_tainted(pname, mem.read(aname))

    def _propagate_return(
        self,
        tstate: TaintState,
        exit_node: PDGNode,
        call_site: PDGNode,
        mem: MemoryLayout,
    ) -> TaintState:
        """Propagate taint from a callee's ``Return`` value back to the
        caller's call-site result.

        When the callee exit carries a ``Return`` whose value references a
        variable that is tainted in *mem*, the return is marked as tainted.
        """
        exit_ast = exit_node.ast_node
        if not isinstance(exit_ast, py_ast.Return):
            return tstate
        # py_ast.Return uses "exprs" (a list; stdlib ast uses "value").
        ret_exprs = getattr(exit_ast, "exprs", None)
        if not ret_exprs:
            return tstate
        # The return value is either the sole expression or the first one.
        ret_value = ret_exprs[0] if len(ret_exprs) == 1 else ret_exprs[0]
        call_ast = call_site.ast_node
        if call_ast is None:
            return tstate

        # If the return value references a tainted variable, produce a
        # tainted state that flows back to the call site.  The caller's
        # DATA edges will then mark the LHS variable at the call site.
        if isinstance(ret_value, py_ast.Local):
            rname = getattr(ret_value, "name", "") or ""
            if rname and mem.is_tainted(rname):
                ret_taint = mem.read(rname)
                return tstate.merge(ret_taint)
        if self._contains_tainted_local(ret_value, mem):
            return tstate.merge(_USER_CONTROLLED)

        # Also propagate if the tstate at the exit is already tainted
        # (e.g. the return node itself was reached with tainted state).
        if tstate.is_tainted():
            return tstate

        return tstate

    def _propagate_for_loop_index(
        self,
        node: PDGNode,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> None:
        """If *node* is a loop header with for-loop variable metadata,
        mark loop index variables as tainted when their iterators are
        tainted in *mem*.
        """
        if not tstate.is_tainted():
            return
        meta = self._cpg.node_meta(node)
        for_loop_vars = meta.get("for_loop_vars", [])
        for iter_name, index_name in for_loop_vars:
            if mem.is_tainted(iter_name):
                mem.mark_tainted(index_name, tstate)

    def _propagate_try(
        self,
        try_node: py_ast.TryExceptFinally,
        tstate: TaintState,
        pdg_node: PDGNode,
        mem: MemoryLayout,
    ) -> TaintState:
        """Propagate taint through a TryExceptFinally node.

        If ``tstate`` is tainted, any handler with a caught variable
        ``except ... as e`` gets that variable marked as tainted in
        *mem* (modelling exception flow into the handler).
        """
        if not tstate.is_tainted():
            return tstate

        meta = self._cpg.node_meta(pdg_node)
        handlers = meta.get("handlers", [])
        for hinfo in handlers:
            caught_var = hinfo.get("caught_var")
            if caught_var:
                mem.mark_tainted(caught_var, tstate)
        return tstate

    def _interprocedural_transfer(
        self,
        tstate: TaintState,
        src: PDGNode,
        dst: PDGNode,
        mem: MemoryLayout,
        call_context: Tuple[int, ...] = (),
    ) -> Tuple[TaintState, MemoryLayout]:
        dst_meta = self._cpg.node_meta(dst)
        func_name = dst_meta.get("func_name", str(dst.node_id))
        cache_key = (func_name, tuple(sorted(tstate.tags)), call_context)
        cached = self._interprocedural_summary_cache.get(cache_key)
        if cached is not None:
            return cached, mem
        self._interprocedural_summary_cache[cache_key] = tstate
        new_mem = MemoryLayout()
        self._map_args_to_params(src, func_name, mem, new_mem)
        return tstate, new_mem

    def _isinstance_guard_strip(self, ast_node: Any, mem: MemoryLayout) -> bool:
        if not isinstance(ast_node, py_ast.Call):
            return False
        call_name = self._extract_call_name(ast_node)
        if call_name == "isinstance":
            args = getattr(ast_node, "args", None)
            if args is not None and len(args) >= 1:
                first_arg = args[0]
                if isinstance(first_arg, py_ast.Local):
                    var_name = getattr(first_arg, "name", "") or ""
                    if var_name:
                        mem.mark_tainted(var_name, _CLEAN)
                        return True
            return False
        return False

    def _is_validating_regex(self, call_node: py_ast.Call) -> bool:
        args = getattr(call_node, "args", None)
        if args is None or len(args) < 1:
            return False
        pattern_arg = args[0]
        pattern_str = self._extract_constant_value(pattern_arg)
        if pattern_str is None:
            return False
        return pattern_str.startswith("^") and pattern_str.endswith("$")

    @staticmethod
    def _extract_constant_value(node: Any) -> Optional[str]:
        node_type = type(node).__name__
        if node_type == "Str":
            return getattr(node, "s", None)
        if node_type == "Constant":
            val = getattr(node, "value", None)
            return str(val) if isinstance(val, str) else None
        if hasattr(node, "children"):
            parts = []
            for child in node.children():
                if isinstance(child, (list, tuple)):
                    continue
                v = _TaintInterproceduralMixin._extract_constant_value(child)
                if v is not None:
                    parts.append(v)
            return "".join(parts) if parts else None
        return None
