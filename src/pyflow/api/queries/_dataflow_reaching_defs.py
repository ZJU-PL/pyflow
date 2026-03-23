"""
Helpers for deriving reaching-definition style facts.
"""

from collections import deque
from typing import Any, Dict, List, Optional

from ._cfg_utils import get_block_statements, iter_successors
from ._models import ReachingDef


class ReachingDefsAnalyzer:
    """Compute lightweight reaching-definition summaries from SSA or def-use data."""

    def get_variable_uses(self, code, variable: str, get_var_name) -> List[str]:
        from pyflow.language.python.defuse import DefUseVisitor, DFS

        visitor = DefUseVisitor()
        dfs = DFS(visitor.visit)
        dfs.process(code)

        uses: List[str] = []
        for lcl, use_locations in visitor.lcluse.items():
            if get_var_name(lcl) != variable:
                continue
            for loc in use_locations:
                lineno = getattr(loc, "lineno", None)
                uses.append(f"line {lineno}" if lineno is not None else str(loc))

        return uses

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

    def from_ssa(self, ssa_cfg) -> Dict[str, List[ReachingDef]]:
        entry = getattr(ssa_cfg, "entryTerminal", None)
        if entry is None:
            return {}
        return self._collect_defs_from_cfg(ssa_cfg)

    def _collect_defs_from_cfg(self, cfg) -> Dict[str, List[ReachingDef]]:
        reaching_defs: Dict[str, List[ReachingDef]] = {}
        visited = set()
        queue = deque([cfg.entryTerminal]) if hasattr(cfg, "entryTerminal") else deque()

        while queue:
            block = queue.popleft()
            if block in visited:
                continue
            visited.add(block)

            for stmt in get_block_statements(block):
                targets = getattr(stmt, "targets", None)
                if not targets:
                    continue
                for target in targets:
                    var_name = getattr(target, "id", None)
                    if not var_name:
                        continue
                    reaching_defs.setdefault(var_name, []).append(
                        ReachingDef(
                            variable=var_name,
                            def_location=getattr(stmt, "lineno", None),
                            def_value=(
                                self.describe_value(stmt.value)
                                if hasattr(stmt, "value")
                                else None
                            ),
                            is_call=hasattr(stmt, "value") and hasattr(stmt.value, "func"),
                        )
                    )

            for successor in iter_successors(block):
                if successor and successor not in visited:
                    queue.append(successor)

        return reaching_defs

    def describe_value(self, value) -> Optional[str]:
        if value is None:
            return None
        if hasattr(value, "id"):
            return f"var:{value.id}"
        if hasattr(value, "func") and hasattr(value.func, "id"):
            return f"call:{value.func.id}"
        if hasattr(value, "s"):
            return f"str:{value.s}"
        if hasattr(value, "n"):
            return f"num:{value.n}"
        return str(type(value).__name__)
