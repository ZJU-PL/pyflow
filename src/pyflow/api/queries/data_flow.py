"""
Data-flow query helpers for PyFlow.

These queries expose IPA/lifetime/store graph insights without forcing
consumers to interact with the raw analysis objects directly.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

from pyflow.application.errors import TemporaryLimitation

from .context import QueryContext


@dataclass(frozen=True)
class IpaFunctionSummary:
    """Container for IPA summaries per analyzed context."""

    name: str
    signature: object
    summary: object


@dataclass
class AliasInfo:
    """Information about variable aliases within a function."""

    variable: str
    aliases: Set[str] = field(default_factory=set)
    is_aliased: bool = False


@dataclass
class PointsToInfo:
    """Information about points-to relationships for a variable."""

    variable: str
    points_to: Set[str] = field(default_factory=set)
    may_be_null: bool = True


@dataclass
class ReachingDef:
    """A reaching definition for a variable use."""

    variable: str
    def_location: Any = None
    def_value: Optional[str] = None
    is_call: bool = False


class DataFlowQueries:
    """Encapsulates IPA-driven facts in a task-aware facade."""

    def __init__(self, context: QueryContext):
        self.context = context

    def get_reaching_defs(
        self, function: Union[str, object]
    ) -> Dict[str, List[ReachingDef]]:
        """Return reaching definitions for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as e:
            raise ValueError(f"Cannot resolve function: {e}")

        try:
            ssa_cfg = self.context.graph_engine.get_ssa(code)
        except Exception:
            return self._get_reaching_defs_from_defuse(code)

        return self._extract_reaching_defs_from_ssa(ssa_cfg, code)

    def _get_reaching_defs_from_defuse(self, code) -> Dict[str, List[ReachingDef]]:
        from pyflow.language.python.defuse import DefUseVisitor, DFS

        visitor = DefUseVisitor()
        dfs = DFS(visitor)
        dfs.process(code)

        reaching_defs: Dict[str, List[ReachingDef]] = {}

        for lcl, def_locations in visitor.lcldef.items():
            var_name = self._get_var_name(lcl)
            if var_name:
                reaching_defs[var_name] = [
                    ReachingDef(
                        variable=var_name,
                        def_location=loc,
                        is_call=False,
                    )
                    for loc in def_locations
                ]

        return reaching_defs

    def _extract_reaching_defs_from_ssa(
        self, ssa_cfg, code
    ) -> Dict[str, List[ReachingDef]]:
        reaching_defs: Dict[str, List[ReachingDef]] = {}

        try:
            entry = getattr(ssa_cfg, "entryTerminal", None)
            if entry:
                reaching_defs = self._collect_defs_from_cfg(ssa_cfg, code)
        except Exception:
            pass

        return reaching_defs

    def _collect_defs_from_cfg(self, cfg, code) -> Dict[str, List[ReachingDef]]:
        reaching_defs: Dict[str, List[ReachingDef]] = {}

        try:
            visited = set()
            queue = [cfg.entryTerminal] if hasattr(cfg, "entryTerminal") else []

            while queue:
                block = queue.pop(0)
                if block in visited:
                    continue
                visited.add(block)

                for stmt in self._get_block_statements(block):
                    if hasattr(stmt, "targets"):
                        for target in stmt.targets:
                            if hasattr(target, "id"):
                                var_name = target.id
                                if var_name not in reaching_defs:
                                    reaching_defs[var_name] = []
                                reaching_defs[var_name].append(
                                    ReachingDef(
                                        variable=var_name,
                                        def_location=getattr(stmt, "lineno", None),
                                        def_value=(
                                            self._describe_value(stmt.value)
                                            if hasattr(stmt, "value")
                                            else None
                                        ),
                                        is_call=hasattr(stmt, "value")
                                        and hasattr(stmt.value, "func"),
                                    )
                                )

                if hasattr(block, "next"):
                    for successor in (
                        block.next.values()
                        if isinstance(block.next, dict)
                        else [block.next]
                    ):
                        if successor and successor not in visited:
                            queue.append(successor)
        except Exception:
            pass

        return reaching_defs

    def _get_block_statements(self, block) -> List[Any]:
        try:
            if hasattr(block, "statements"):
                return block.statements
            elif hasattr(block, "ops"):
                return block.ops
            elif hasattr(block, "body"):
                return block.body
        except Exception:
            pass
        return []

    def _describe_value(self, value) -> Optional[str]:
        if value is None:
            return None
        if hasattr(value, "id"):
            return f"var:{value.id}"
        elif hasattr(value, "func") and hasattr(value.func, "id"):
            return f"call:{value.func.id}"
        elif hasattr(value, "s"):
            return f"str:{value.s}"
        elif hasattr(value, "n"):
            return f"num:{value.n}"
        else:
            return str(type(value).__name__)

    def _get_var_name(self, lcl) -> Optional[str]:
        if hasattr(lcl, "constantValue"):
            return lcl.constantValue()
        elif hasattr(lcl, "id"):
            return lcl.id
        elif hasattr(lcl, "name"):
            return lcl.name
        return None

    def get_aliases(self, function: Union[str, object]) -> Dict[str, AliasInfo]:
        """Return alias information for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as e:
            raise ValueError(f"Cannot resolve function: {e}")

        store_graph = self._get_store_graph_safe()
        if store_graph is None:
            return self._get_aliases_from_defuse(code)

        return self._get_aliases_from_storegraph(code, store_graph)

    def _get_store_graph_safe(self):
        store_graph = getattr(self.context.program, "storeGraph", None)
        if store_graph is None:
            return None
        return store_graph

    def _get_aliases_from_storegraph(self, code, store_graph) -> Dict[str, AliasInfo]:
        aliases: Dict[str, AliasInfo] = {}
        func_name = self.context.code_name(code)

        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue

            slot_str = str(slot_name)
            if func_name and func_name in slot_str:
                var_name = self._extract_var_from_slot(slot_name)
                if var_name:
                    canonical = slot.getForward()
                    if canonical:
                        all_aliases = self._find_all_aliases(slot, store_graph)
                        aliases[var_name] = AliasInfo(
                            variable=var_name,
                            aliases=all_aliases - {var_name},
                            is_aliased=len(all_aliases) > 1,
                        )

        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue
            if hasattr(slot_name, "isRoot") and not slot_name.isRoot():
                field_name = self._extract_field_from_slot(slot_name)
                if field_name:
                    obj_name = self._extract_obj_from_slot(slot_name)
                    if obj_name:
                        if obj_name not in aliases:
                            aliases[obj_name] = AliasInfo(variable=obj_name)
                        aliases[obj_name].aliases.add(f"{obj_name}.{field_name}")

        return aliases

    def _find_all_aliases(self, slot, store_graph) -> Set[str]:
        aliases: Set[str] = set()
        canonical = slot.getForward()

        for other_slot in store_graph:
            if other_slot.getForward() == canonical:
                var_name = self._extract_var_from_slot(other_slot.slotName)
                if var_name:
                    aliases.add(var_name)

        return aliases

    def _extract_var_from_slot(self, slot_name) -> Optional[str]:
        if slot_name is None:
            return None

        local = getattr(slot_name, "local", None)
        if local is not None:
            name = getattr(local, "name", None)
            if isinstance(name, str):
                if "/" in name:
                    return name.split("/")[0]
                return name

        obj = getattr(slot_name, "obj", None)
        if obj is not None:
            name = getattr(obj, "constantValue", None)
            if callable(name):
                return name()
            name = getattr(obj, "id", None)
            if isinstance(name, str):
                return name

        return None

    def _extract_obj_from_slot(self, slot_name) -> Optional[str]:
        if slot_name is None:
            return None
        if hasattr(slot_name, "name") and hasattr(slot_name.name, "obj"):
            obj = slot_name.name.obj
            if hasattr(obj, "constantValue"):
                return obj.constantValue()
            elif hasattr(obj, "id"):
                return obj.id
        return None

    def _extract_field_from_slot(self, slot_name) -> Optional[str]:
        if slot_name is None:
            return None
        if hasattr(slot_name, "name") and hasattr(slot_name.name, "field"):
            field = slot_name.name.field
            if hasattr(field, "constantValue"):
                return field.constantValue()
            elif hasattr(field, "id"):
                return field.id
        return None

    def _get_aliases_from_defuse(self, code) -> Dict[str, AliasInfo]:
        from pyflow.language.python.defuse import DefUseVisitor, DFS

        visitor = DefUseVisitor()
        dfs = DFS(visitor.visit)
        dfs.process(code)

        aliases: Dict[str, AliasInfo] = {}

        defined_vars = set(visitor.lcldef.keys())

        for var in defined_vars:
            var_name = self._get_var_name(var)
            if var_name:
                aliases[var_name] = AliasInfo(variable=var_name)

        return aliases

    def get_points_to(self, function: Union[str, object]) -> Dict[str, PointsToInfo]:
        """Return points-to information for all variables in a function."""
        try:
            code = self.context.resolve_function(function)
        except ValueError as e:
            raise ValueError(f"Cannot resolve function: {e}")

        store_graph = self._get_store_graph_safe()
        if store_graph is None:
            return {}

        return self._get_points_to_from_storegraph(code, store_graph)

    def _get_points_to_from_storegraph(
        self, code, store_graph
    ) -> Dict[str, PointsToInfo]:
        points_to: Dict[str, PointsToInfo] = {}
        func_name = self.context.code_name(code)

        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue

            slot_str = str(slot_name)
            if func_name and func_name in slot_str:
                var_name = self._extract_var_from_slot(slot_name)
                if var_name:
                    refs = getattr(slot, "refs", set())
                    point_set: Set[str] = set()
                    for ref in refs:
                        if hasattr(ref, "xtype"):
                            point_set.add(self._describe_xtype(ref.xtype))
                        elif hasattr(ref, "__class__"):
                            point_set.add(ref.__class__.__name__)

                    points_to[var_name] = PointsToInfo(
                        variable=var_name,
                        points_to=point_set,
                        may_be_null=getattr(slot, "null", True),
                    )

        return points_to

    def _describe_xtype(self, xtype) -> str:
        if xtype is None:
            return "unknown"
        if hasattr(xtype, "obj") and hasattr(xtype.obj, "__name__"):
            return xtype.obj.__name__
        elif hasattr(xtype, "base") and hasattr(xtype.base, "__name__"):
            return xtype.base.__name__
        else:
            return str(xtype)

    def get_lifetime(self):
        """Return lifetime analysis results if available."""
        if getattr(self.context.program, "lifetime_analysis", None) is None:
            raise TemporaryLimitation(
                "Lifetime analysis not available; run the lifetime pass first."
            )
        return self.context.program.lifetime_analysis

    def get_store_graph(self):
        """Return the store graph if available."""
        if getattr(self.context.program, "storeGraph", None) is None:
            raise TemporaryLimitation("Store graph not available; run IPA/CPA first.")
        return self.context.program.storeGraph

    def get_ipa_analysis(self):
        """Return IPA analysis results when available."""
        return self.context.require_ipa()

    def get_ipa_function_summaries(
        self, function: Optional[Union[str, object]] = None
    ) -> List[IpaFunctionSummary]:
        """Return IPA summaries for all contexts (or a single function)."""
        ipa = self.context.require_ipa()
        target = self.context.resolve_function_name(function) if function else None
        summaries: List[IpaFunctionSummary] = []
        for context in ipa.contexts.values():
            name = self.context.context_name(context)
            if not name:
                continue
            if target and name != target:
                continue
            summaries.append(
                IpaFunctionSummary(
                    name=name, signature=context.signature, summary=context.summary
                )
            )
        return summaries