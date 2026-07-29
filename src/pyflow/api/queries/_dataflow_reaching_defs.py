"""
Helpers for deriving reaching-definition style facts.
"""

from collections import deque
from typing import Any, Dict, List, Optional

from ._cfg_utils import get_block_statements, iter_successors
from ._models import ReachingDef


class ReachingDefsAnalyzer:
    """Compute lightweight reaching-definition summaries from SSA or def-use data."""

    def get_variable_uses(self, code, variable: str) -> List[str]:
        from pyflow.ir.core import SymbolId, ValueId, format_source

        catalog = code.ir_catalog
        procedure = catalog.procedure(code)
        symbols = {
            symbol.id
            for symbol in catalog.symbols
            if symbol.id.scope == procedure.root_scope and symbol.name == variable
        }
        uses = []
        for node_id, semantics in catalog.semantics.items():
            if node_id.code != procedure.code_id:
                continue
            if any(
                (identity in symbols)
                if isinstance(identity, SymbolId)
                else (
                    identity.symbol in symbols
                    if isinstance(identity, ValueId)
                    else False
                )
                for identity in semantics.uses
            ):
                uses.append(format_source(catalog.source_of(node_id)))
        return list(dict.fromkeys(uses))

    def from_defuse(self, code, get_var_name) -> Dict[str, List[ReachingDef]]:
        from pyflow.language.python.defuse import DefUseVisitor, DFS

        visitor = DefUseVisitor()
        dfs = DFS(visitor.visit)
        dfs.process(code)

        reaching_defs: Dict[str, List[ReachingDef]] = {}
        for lcl, def_locations in visitor.lcldef.items():
            var_name = get_var_name(lcl)
            if var_name:
                reaching_defs[var_name] = [
                    ReachingDef(variable=var_name, def_location=loc, is_call=False)
                    for loc in def_locations
                ]

        return reaching_defs

    def from_ssa(self, ssa_cfg, catalog, code) -> Dict[str, List[ReachingDef]]:
        entry = getattr(ssa_cfg, "entryTerminal", None)
        if entry is None:
            return {}
        return self._collect_defs_from_cfg(ssa_cfg, catalog, code)

    def _collect_defs_from_cfg(self, cfg, catalog, code) -> Dict[str, List[ReachingDef]]:
        from pyflow.ir.core import format_source
        from pyflow.language.python import ast

        reaching_defs: Dict[str, List[ReachingDef]] = {}
        visited = set()
        queue = deque([cfg.entryTerminal]) if hasattr(cfg, "entryTerminal") else deque()

        while queue:
            block = queue.popleft()
            if block in visited:
                continue
            visited.add(block)

            for stmt in get_block_statements(block):
                targets = getattr(stmt, "lcls", None)
                if targets is None:
                    targets = getattr(stmt, "targets", None)
                if targets is None and isinstance(stmt, ast.AnnAssign):
                    targets = (stmt.target,)
                if not targets:
                    continue
                for target in targets:
                    var_name = getattr(target, "name", None)
                    if not var_name:
                        continue
                    expression = getattr(stmt, "expr", getattr(stmt, "value", None))
                    reaching_defs.setdefault(var_name, []).append(
                        ReachingDef(
                            variable=var_name,
                            def_location=format_source(
                                catalog.source_of(stmt, code=code)
                            ),
                            def_value=(
                                self.describe_value(expression)
                                if expression is not None
                                else None
                            ),
                            is_call=isinstance(
                                expression,
                                (ast.Call, ast.DirectCall, ast.MethodCall),
                            ),
                        )
                    )

            for successor in iter_successors(block):
                if successor and successor not in visited:
                    queue.append(successor)

        return reaching_defs

    def describe_value(self, value) -> Optional[str]:
        if value is None:
            return None
        name = getattr(value, "name", None)
        if isinstance(name, str):
            return f"var:{name}"
        code = getattr(value, "code", None)
        if code is not None and hasattr(code, "codeName"):
            return f"call:{code.codeName()}"
        obj = getattr(value, "object", None)
        if obj is not None and hasattr(obj, "pyobj"):
            return f"constant:{obj.pyobj!r}"
        if hasattr(value, "s"):
            return f"str:{value.s}"
        if hasattr(value, "n"):
            return f"num:{value.n}"
        return str(type(value).__name__)
