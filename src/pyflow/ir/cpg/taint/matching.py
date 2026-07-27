"""Source, sink, call-name, and local-flow matching."""

from __future__ import annotations
from typing import Any, Dict, FrozenSet, List, Optional, Tuple
from pyflow.ir.pdg.graph import PDGNode
from pyflow.language.python import ast as py_ast
from .model import TaintFinding


class _TaintMatchingMixin:
    """Internal mixin composed by CPGTaintEngine."""

    def _detect_source(self, node: PDGNode) -> Optional[str]:
        ast_node = node.ast_node
        if ast_node is None:
            return None
        call_name = self._find_source_call(ast_node)
        if call_name and self._matches_source(call_name):
            return call_name
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
                sink_name = self._match_sink_name(call_name)
                if sink_name:
                    return sink_name, self._sinks[sink_name]
        return None, ""

    def _sink_has_tainted_argument(
        self,
        node: PDGNode,
        sink_name: str,
        mem,
        active_tags: FrozenSet[str],
    ) -> bool:
        """Require taint on a modeled sink port, not merely graph reachability."""
        call = self._call_expr(node.ast_node)
        if call is None:
            return False
        positions = self._sink_positions.get(sink_name, frozenset({0}))
        for index, argument in enumerate(getattr(call, "args", ()) or ()):
            if index not in positions:
                continue
            if self._expr_is_tainted(argument, mem, active_tags):
                return True
        for _name, value in getattr(call, "kwds", ()) or ():
            if self._expr_is_tainted(value, mem, active_tags):
                return True
        return False

    def _expr_is_tainted(self, expr: Any, mem, active_tags: FrozenSet[str]) -> bool:
        """Evaluate taint evidence for one expression, including heap fields."""
        if expr is None:
            return False
        if isinstance(expr, py_ast.Local):
            return mem.is_tainted(getattr(expr, "name", "") or "")
        if isinstance(expr, py_ast.GetAttr):
            base = self._first_local_name(getattr(expr, "expr", None))
            field = self._resolve_call_expr(getattr(expr, "name", None)) or ""
            if base and field and mem.read(base, field).is_tainted():
                return True
        if isinstance(expr, py_ast.Call):
            call_name = self._extract_call_name(expr)
            if call_name in self._sanitizers:
                sanitized = self._sanitizers[call_name]
                remaining = frozenset() if "*" in sanitized else active_tags - sanitized
                if not remaining:
                    return False
            if call_name and self._matches_source(call_name):
                return True
        return any(
            self._expr_is_tainted(child, mem, active_tags)
            for child in self._iter_ast_children(expr)
        )

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
        """Deprecated compatibility helper; never used by graph analysis.

        Kept temporarily for callers that imported this private method. The
        engine deliberately does not invoke it: incomplete CPGs are surfaced
        through diagnostics instead of silently switching analyses.
        """
        seen = {
            (
                id(f.source_node),
                id(f.sink_node),
                f.source_label,
                f.sink_label,
                f.effective_rule_id,
            )
            for f in existing_findings
        }
        found: List[TaintFinding] = []

        for func_name in self._cpg.functions:
            tainted: Dict[str, Tuple[PDGNode, str, FrozenSet[str]]] = {}
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
                    source = self._source_for_sink_call(
                        ast_node, tainted, sink_name=sink_name
                    )
                    if source is not None:
                        source_node, source_label, source_kinds = source
                        for rule in self._matching_rules(source_kinds, sink_name):
                            key = (
                                id(source_node),
                                id(node),
                                source_label,
                                sink_name,
                                rule.rule_id,
                            )
                            if key in seen:
                                continue
                            seen.add(key)
                            found.append(
                                TaintFinding(
                                    cwe=cwe or rule.cwe or "",
                                    severity=rule.severity,
                                    source_label=source_label,
                                    sink_label=sink_name,
                                    source_node=source_node,
                                    sink_node=node,
                                    path_nodes=[source_node, node],
                                    tags=source_kinds,
                                    rule_id=rule.rule_id,
                                    rule_title=rule.title,
                                    suggestion=rule.suggestion or "",
                                )
                            )

                source_label = self._find_source_call(ast_node)
                source_info: Optional[Tuple[PDGNode, str, FrozenSet[str]]] = (
                    (
                        node,
                        f"from:{source_label}",
                        self._source_kinds_for_name(source_label),
                    )
                    if source_label
                    else None
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
        tainted: Dict[str, Tuple[PDGNode, str, FrozenSet[str]]],
        *,
        sink_name: str,
    ) -> Optional[Tuple[PDGNode, str, FrozenSet[str]]]:
        call = self._call_expr(ast_node)
        if call is None:
            return self._source_for_expr(ast_node, tainted)
        positions = self._sink_positions.get(sink_name, frozenset({0}))
        for index, arg in enumerate(getattr(call, "args", []) or []):
            if index not in positions:
                continue
            source = self._source_for_expr(arg, tainted)
            if source is not None:
                return source
        return None

    def _source_for_expr(
        self,
        expr: Any,
        tainted: Dict[str, Tuple[PDGNode, str, FrozenSet[str]]],
    ) -> Optional[Tuple[PDGNode, str, FrozenSet[str]]]:
        call = self._call_expr(expr)
        if call is not None:
            call_name = self._extract_call_name(call)
            sanitizer_kinds = self._sanitizers.get(call_name or "")
            if sanitizer_kinds is not None:
                for arg in getattr(call, "args", []) or []:
                    source = self._source_for_expr(arg, tainted)
                    if source is None:
                        continue
                    source_node, source_label, source_kinds = source
                    remaining = (
                        frozenset()
                        if "*" in sanitizer_kinds
                        else source_kinds - sanitizer_kinds
                    )
                    if remaining:
                        return source_node, source_label, remaining
                return None
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
            if name == src:
                return True
            if "." not in src and name.rsplit(".", 1)[-1] == src:
                return True
        # Source-loaded ASTs may preserve an imported alias (``request``)
        # rather than its registry-qualified module (``flask.request``).
        suffix_matches = [src for src in self._sources if src.endswith("." + name)]
        return len(suffix_matches) == 1

    def _match_sink_name(self, name: str) -> str:
        if not name:
            return ""
        for sink in self._sinks:
            if name == sink:
                return sink
            if "." not in sink and name.rsplit(".", 1)[-1] == sink:
                return sink
        suffix_matches = [sink for sink in self._sinks if sink.endswith("." + name)]
        if len(suffix_matches) == 1:
            return suffix_matches[0]
        return ""
