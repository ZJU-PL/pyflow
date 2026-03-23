"""
Helpers for store-graph-backed alias and points-to queries.
"""

from typing import Dict, Optional, Set

from ._models import AliasInfo, PointsToInfo


class StoreGraphAnalyzer:
    """Extract alias and points-to facts from the program store graph."""

    def get_store_graph_safe(self, program):
        return getattr(program, "storeGraph", None)

    def aliases_from_storegraph(self, code, func_name: Optional[str], store_graph) -> Dict[str, AliasInfo]:
        aliases: Dict[str, AliasInfo] = {}

        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue

            slot_str = str(slot_name)
            if func_name and func_name in slot_str:
                var_name = self.extract_var_from_slot(slot_name)
                if var_name and slot.getForward():
                    all_aliases = self.find_all_aliases(slot, store_graph)
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
                field_name = self.extract_field_from_slot(slot_name)
                obj_name = self.extract_obj_from_slot(slot_name)
                if field_name and obj_name:
                    if obj_name not in aliases:
                        aliases[obj_name] = AliasInfo(variable=obj_name)
                    aliases[obj_name].aliases.add(f"{obj_name}.{field_name}")

        return aliases

    def aliases_from_defuse(self, code, get_var_name) -> Dict[str, AliasInfo]:
        from pyflow.language.python.defuse import DefUseVisitor, DFS

        visitor = DefUseVisitor()
        dfs = DFS(visitor.visit)
        dfs.process(code)

        aliases: Dict[str, AliasInfo] = {}
        for var in set(visitor.lcldef.keys()):
            var_name = get_var_name(var)
            if var_name:
                aliases[var_name] = AliasInfo(variable=var_name)
        return aliases

    def points_to_from_storegraph(self, func_name: Optional[str], store_graph) -> Dict[str, PointsToInfo]:
        points_to: Dict[str, PointsToInfo] = {}

        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue

            slot_str = str(slot_name)
            if func_name and func_name in slot_str:
                var_name = self.extract_var_from_slot(slot_name)
                if var_name:
                    point_set: Set[str] = set()
                    for ref in getattr(slot, "refs", set()):
                        if hasattr(ref, "xtype"):
                            point_set.add(self.describe_xtype(ref.xtype))
                        elif hasattr(ref, "__class__"):
                            point_set.add(ref.__class__.__name__)

                    points_to[var_name] = PointsToInfo(
                        variable=var_name,
                        points_to=point_set,
                        may_be_null=getattr(slot, "null", True),
                    )

        return points_to

    def find_all_aliases(self, slot, store_graph) -> Set[str]:
        aliases: Set[str] = set()
        canonical = slot.getForward()

        for other_slot in store_graph:
            if other_slot.getForward() == canonical:
                var_name = self.extract_var_from_slot(other_slot.slotName)
                if var_name:
                    aliases.add(var_name)

        return aliases

    def extract_var_from_slot(self, slot_name) -> Optional[str]:
        if slot_name is None:
            return None

        local = getattr(slot_name, "local", None)
        if local is not None:
            name = getattr(local, "name", None)
            if isinstance(name, str):
                return name.split("/")[0] if "/" in name else name

        obj = getattr(slot_name, "obj", None)
        if obj is not None:
            name = getattr(obj, "constantValue", None)
            if callable(name):
                return name()
            name = getattr(obj, "id", None)
            if isinstance(name, str):
                return name

        return None

    def extract_obj_from_slot(self, slot_name) -> Optional[str]:
        if slot_name is None:
            return None
        if hasattr(slot_name, "name") and hasattr(slot_name.name, "obj"):
            obj = slot_name.name.obj
            if hasattr(obj, "constantValue"):
                return obj.constantValue()
            if hasattr(obj, "id"):
                return obj.id
        return None

    def extract_field_from_slot(self, slot_name) -> Optional[str]:
        if slot_name is None:
            return None
        if hasattr(slot_name, "name") and hasattr(slot_name.name, "field"):
            field = slot_name.name.field
            if hasattr(field, "constantValue"):
                return field.constantValue()
            if hasattr(field, "id"):
                return field.id
        return None

    def describe_xtype(self, xtype) -> str:
        if xtype is None:
            return "unknown"
        if hasattr(xtype, "obj") and hasattr(xtype.obj, "__name__"):
            return xtype.obj.__name__
        if hasattr(xtype, "base") and hasattr(xtype.base, "__name__"):
            return xtype.base.__name__
        return str(xtype)
