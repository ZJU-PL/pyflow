"""Source, sink, call-name, and local-flow matching."""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from pyflow.ir.pdg.graph import PDGNode
from pyflow.ir.cpg.graph import CPGEdgeKind
from pyflow.language.python import ast as py_ast
from .model import TaintFinding
from .defaults import _SQL_SINKS


class _TaintMatchingMixin:
    """Internal mixin composed by CPGTaintEngine."""

    def _detect_source(self, node: PDGNode) -> Optional[str]:
        ast_node = node.ast_node
        if ast_node is None:
            return None
        call_name = self._find_source_call(ast_node)
        if call_name and self._matches_source(call_name):
            return call_name
        label = node.label or ""
        for src in self._sources:
            if src in label:
                return src
        return None

    def _find_source_call(self, ast_node: Any) -> Optional[str]:
        call_name = self._extract_call_name(ast_node)
        if call_name and self._matches_source(call_name):
            return call_name
        for child in self._iter_ast_children(ast_node):
            found = self._find_source_call(child)
            if found:
                return found
        return None

    def _check_sink(self, node: PDGNode) -> Tuple[Optional[str], str]:
        ast_node = node.ast_node
        if ast_node is not None:
            call_name = self._extract_call_name(ast_node)
            if call_name:
                cwe = self._match_sink_cwe(call_name)
                if cwe and not self._is_parameterized_safe(ast_node, call_name):
                    return call_name, cwe
        label = node.label or ""
        for sink_name, cwe in self._sinks.items():
            if sink_name in label:
                return sink_name, cwe
        # Strategy 3: Match via DATA edges — if this node uses a sink-named variable
        cpg = self._cpg
        for edge in cpg._cpg_edges_in.get(node.node_id, ()):
            if edge.kind == CPGEdgeKind.DATA and edge.label:
                cwe = self._match_sink_cwe(edge.label)
                if cwe:
                    return edge.label, cwe
        return None, ""

    def _is_parameterized_safe(self, ast_node: Any, call_name: str) -> bool:
        sink_base = call_name.split(".")[-1]
        if sink_base not in _SQL_SINKS:
            return False
        args = getattr(ast_node, "args", None)
        if args is None or len(args) < 2:
            return False
        second = args[1]
        second_type = type(second).__name__
        return second_type in ("Tuple", "List", "Dict")

    def _extract_call_name(self, ast_node: Any) -> Optional[str]:
        if not isinstance(ast_node, py_ast.Call):
            return self._extract_call_from_assign(ast_node)
        expr = getattr(ast_node, "expr", None)
        if expr is None:
            return None
        return self._resolve_call_expr(expr)

    def _extract_call_from_assign(self, ast_node: Any) -> Optional[str]:
        expr = None
        if isinstance(ast_node, py_ast.Assign):
            expr = getattr(ast_node, "expr", None)
        elif isinstance(ast_node, py_ast.Discard):
            expr = getattr(ast_node, "expr", None)
        elif isinstance(ast_node, py_ast.Return):
            expr = getattr(ast_node, "expr", None)
        if expr is None:
            return None
        if isinstance(expr, py_ast.Call):
            return self._extract_call_name(expr)
        return None

    def _resolve_call_expr(self, expr: Any) -> Optional[str]:
        if isinstance(expr, py_ast.Local):
            n = getattr(expr, "name", None)
            if isinstance(n, str):
                return n
            return str(n) if n is not None else None
        if isinstance(expr, py_ast.Existing):
            try:
                value = expr.constantValue()
            except Exception:
                value = getattr(getattr(expr, "object", None), "pyobj", None)
            return value if isinstance(value, str) else None
        if isinstance(expr, py_ast.GetAttr):
            base = self._resolve_call_expr(getattr(expr, "expr", None))
            attr = self._resolve_call_expr(getattr(expr, "name", None))
            if base and attr:
                return f"{base}.{attr}"
            return attr or base
        if isinstance(expr, py_ast.MethodCall):
            base = self._resolve_call_expr(getattr(expr, "expr", None))
            method = self._resolve_call_expr(getattr(expr, "name", None))
            if base and method:
                return f"{base}.{method}"
            return method or base
        if hasattr(expr, "children"):
            parts: List[str] = []
            for child in expr.children():
                if isinstance(child, (list, tuple)) or child is None:
                    continue
                name = self._resolve_call_expr(child)
                if name:
                    parts.append(name)
            return ".".join(parts) if parts else None
        return None

    def _find_local_statement_flows(
        self, existing_findings: List[TaintFinding]
    ) -> List[TaintFinding]:
        """Find simple intra-function flows when CFG/PDG edges are sparse.

        Source-loaded CPGs sometimes lower rich Python constructs into PDG nodes
        without enough statement-to-statement edges for the graph worklist to
        connect nested sources to later sinks. This pass stays within the CPG
        abstraction but interprets each function's statement nodes in order,
        tracking local variables and object fields at a shallow level.
        """
        seen = {
            (id(f.source_node), id(f.sink_node), f.source_label, f.sink_label)
            for f in existing_findings
        }
        found: List[TaintFinding] = []

        for func_name in self._cpg.functions:
            tainted: Dict[str, Tuple[PDGNode, str]] = {}
            nodes = [
                node
                for node in self._cpg.nodes(func_name)
                if node.kind == "stmt" and node.ast_node is not None
            ]
            nodes.sort(key=lambda n: n.node_id)

            for node in nodes:
                ast_node = node.ast_node
                sink_name, cwe = self._check_sink(node)
                if sink_name:
                    source = self._source_for_sink_call(ast_node, tainted)
                    if source is not None:
                        source_node, source_label = source
                        key = (id(source_node), id(node), source_label, sink_name)
                        if key not in seen:
                            seen.add(key)
                            found.append(
                                TaintFinding(
                                    cwe=cwe,
                                    severity="high",
                                    source_label=source_label,
                                    sink_label=sink_name,
                                    source_node=source_node,
                                    sink_node=node,
                                    path_nodes=[source_node, node],
                                    tags=frozenset({source_label}),
                                )
                            )

                source_label = self._find_source_call(ast_node)
                source_info: Optional[Tuple[PDGNode, str]] = (
                    (node, f"from:{source_label}") if source_label else None
                )

                if isinstance(ast_node, py_ast.Assign):
                    value_source = source_info or self._source_for_expr(
                        getattr(ast_node, "expr", None), tainted
                    )
                    if value_source is not None:
                        for name in self._assigned_names(ast_node):
                            tainted[name] = value_source
                elif isinstance(ast_node, py_ast.SetAttr):
                    value_source = self._source_for_expr(
                        getattr(ast_node, "value", None), tainted
                    )
                    if value_source is not None:
                        attr_name = self._attribute_name(ast_node)
                        if attr_name:
                            tainted[attr_name] = value_source
                elif source_info is not None:
                    for name in self._expr_names(ast_node):
                        tainted.setdefault(name, source_info)

        return found

    def _source_for_sink_call(
        self,
        ast_node: Any,
        tainted: Dict[str, Tuple[PDGNode, str]],
    ) -> Optional[Tuple[PDGNode, str]]:
        call = self._call_expr(ast_node)
        if call is None:
            return self._source_for_expr(ast_node, tainted)
        for arg in getattr(call, "args", []) or []:
            source = self._source_for_expr(arg, tainted)
            if source is not None:
                return source
        return self._source_for_expr(call, tainted)

    def _source_for_expr(
        self,
        expr: Any,
        tainted: Dict[str, Tuple[PDGNode, str]],
    ) -> Optional[Tuple[PDGNode, str]]:
        for name in self._expr_names(expr):
            if name in tainted:
                return tainted[name]
        source_name = self._find_source_call(expr)
        if source_name:
            # The caller will replace this with the containing statement when
            # assigning. For direct sink arguments, use the sink node as source
            # evidence because the source call is nested inside that statement.
            return None
        for child in self._iter_ast_children(expr):
            source = self._source_for_expr(child, tainted)
            if source is not None:
                return source
        return None

    def _assigned_names(self, assign_node: Any) -> List[str]:
        names: List[str] = []
        for target in getattr(assign_node, "lcls", []) or []:
            if isinstance(target, py_ast.Local) and getattr(target, "name", None):
                names.append(target.name)
        return names

    def _expr_names(self, expr: Any) -> List[str]:
        if expr is None:
            return []
        if isinstance(expr, py_ast.Local):
            return [expr.name] if getattr(expr, "name", None) else []
        if isinstance(expr, py_ast.GetAttr):
            attr = self._resolve_call_expr(expr)
            names = [attr] if attr else []
            names.extend(self._expr_names(getattr(expr, "expr", None)))
            return names
        names: List[str] = []
        for child in self._iter_ast_children(expr):
            names.extend(self._expr_names(child))
        return names

    def _attribute_name(self, set_attr: Any) -> str:
        base = self._resolve_call_expr(getattr(set_attr, "expr", None))
        attr = self._resolve_call_expr(getattr(set_attr, "name", None))
        if base and attr:
            return f"{base}.{attr}"
        return attr or base or ""

    def _call_expr(self, ast_node: Any) -> Optional[Any]:
        if isinstance(ast_node, py_ast.Call):
            return ast_node
        if isinstance(ast_node, (py_ast.Assign, py_ast.Discard, py_ast.Return)):
            expr = getattr(ast_node, "expr", None)
            if isinstance(expr, py_ast.Call):
                return expr
        return None

    def _matches_source(self, name: str) -> bool:
        if not name:
            return False
        for src in self._sources:
            if name == src or name.endswith("." + src) or src.endswith("." + name):
                return True
        return False

    def _match_sink_cwe(self, name: str) -> str:
        if not name:
            return ""
        for sink, cwe in self._sinks.items():
            if name == sink or name.endswith("." + sink):
                return cwe
            if "." in name and sink.endswith("." + name):
                return cwe
        return ""
