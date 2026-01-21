"""
Data-flow helpers for coding agents.

These queries expose IPA/lifetime/store graph insights without forcing
consumers to interact with the raw analysis objects directly.

Query Categories:
- Alias analysis: Find variables that may alias (point to same object)
- Points-to analysis: Find what objects a variable may point to
- Reaching definitions: Find which assignments reach a use point
- Lifetime/effects: Find object lifetimes and escape behavior
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Union, Any, Tuple

from pyflow.application.errors import TemporaryLimitation

from ..core.context import QueryContext


@dataclass(frozen=True)
class IpaFunctionSummary:
    """Container for IPA summaries per analyzed context."""

    name: str
    signature: object
    summary: object


@dataclass
class AliasInfo:
    """Information about variable aliases within a function.

    Attributes:
        variable: The variable name
        aliases: Set of variable names that may alias with this variable
        is_aliased: Whether this variable has any aliases
    """

    variable: str
    aliases: Set[str] = field(default_factory=set)
    is_aliased: bool = False


@dataclass
class PointsToInfo:
    """Information about points-to relationships for a variable.

    Attributes:
        variable: The variable name
        points_to: Set of type descriptions or object identifiers this variable may point to
        may_be_null: Whether the variable may be None
    """

    variable: str
    points_to: Set[str] = field(default_factory=set)
    may_be_null: bool = True


@dataclass
class ReachingDef:
    """A reaching definition for a variable use.

    Attributes:
        variable: The variable name
        def_location: Location of the definition (e.g., line number, AST node)
        def_value: Description of the defined value (if available)
        is_call: Whether the definition comes from a function call
    """

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
        """Return reaching definitions for all variables in a function.

        This implementation uses the def-use analysis infrastructure to find
        definitions that may reach each use of a variable.

        Args:
            function: Function name or code object

        Returns:
            Dictionary mapping variable names to lists of ReachingDef objects

        Raises:
            ValueError: If function cannot be resolved
            TemporaryLimitation: If SSA analysis not available
        """
        try:
            code = self.context.resolve_function(function)
        except ValueError as e:
            raise ValueError(f"Cannot resolve function: {e}")

        # Try to get SSA form for reaching definitions
        try:
            ssa_cfg = self.context.graph_engine.get_ssa(code)
        except Exception:
            # Fall back to def-use analysis
            return self._get_reaching_defs_from_defuse(code)

        # Extract reaching definitions from SSA form
        # SSA encodes reaching definitions via versioned variables
        reaching_defs: Dict[str, List[ReachingDef]] = {}

        # Process the SSA CFG to find phi nodes and assignments
        # This is a simplified implementation
        return self._extract_reaching_defs_from_ssa(ssa_cfg, code)

    def _get_reaching_defs_from_defuse(
        self, code
    ) -> Dict[str, List[ReachingDef]]:
        """Extract reaching definitions using def-use analysis.

        Args:
            code: The code object to analyze

        Returns:
            Dictionary mapping variable names to ReachingDef lists
        """
        from pyflow.language.python.defuse import DefUseVisitor, DFS

        visitor = DefUseVisitor()
        dfs = DFS(visitor)  # Pass visitor to DFS
        dfs.process(code)

        reaching_defs: Dict[str, List[ReachingDef]] = {}

        # Process local definitions and uses
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
        """Extract reaching definitions from SSA form.

        Args:
            ssa_cfg: SSA-transformed CFG
            code: The code object

        Returns:
            Dictionary mapping variable names to ReachingDef lists
        """
        reaching_defs: Dict[str, List[ReachingDef]] = {}

        # In SSA, reaching definitions are encoded in phi nodes and versioned variables
        # This is a simplified extraction
        try:
            # Try to get the entry point and traverse
            entry = getattr(ssa_cfg, "entryTerminal", None)
            if entry:
                # Collect definitions from the CFG
                reaching_defs = self._collect_defs_from_cfg(ssa_cfg, code)
        except Exception:
            pass

        return reaching_defs

    def _collect_defs_from_cfg(
        self, cfg, code
    ) -> Dict[str, List[ReachingDef]]:
        """Collect definitions from CFG blocks.

        Args:
            cfg: The CFG to analyze
            code: The code object

        Returns:
            Dictionary mapping variable names to ReachingDef lists
        """
        reaching_defs: Dict[str, List[ReachingDef]] = {}

        # Traverse CFG blocks to find assignments
        try:
            visited = set()
            queue = [cfg.entryTerminal] if hasattr(cfg, "entryTerminal") else []

            while queue:
                block = queue.pop(0)
                if block in visited:
                    continue
                visited.add(block)

                # Extract statements from block
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
                                        def_value=self._describe_value(stmt.value) if hasattr(stmt, "value") else None,
                                        is_call=hasattr(stmt, "value") and hasattr(stmt.value, "func"),
                                    )
                                )

                # Add successors to queue
                if hasattr(block, "next"):
                    for successor in (block.next.values() if isinstance(block.next, dict) else [block.next]):
                        if successor and successor not in visited:
                            queue.append(successor)
        except Exception:
            pass

        return reaching_defs

    def _get_block_statements(self, block) -> List[Any]:
        """Extract statements from a CFG block.

        Args:
            block: The CFG block

        Returns:
            List of statements in the block
        """
        try:
            # Try different ways to get statements from a block
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
        """Describe a value for reachability information.

        Args:
            value: The value AST node

        Returns:
            String description of the value
        """
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
        """Extract variable name from a Local AST node.

        Args:
            lcl: The Local AST node

        Returns:
            Variable name string or None
        """
        if hasattr(lcl, "constantValue"):
            return lcl.constantValue()
        elif hasattr(lcl, "id"):
            return lcl.id
        elif hasattr(lcl, "name"):
            return lcl.name
        return None

    def get_aliases(self, function: Union[str, object]) -> Dict[str, AliasInfo]:
        """Return alias information for all variables in a function.

        This implementation uses the store graph and def-use analysis to find
        variables that may alias (point to the same object).

        Args:
            function: Function name or code object

        Returns:
            Dictionary mapping variable names to AliasInfo objects

        Raises:
            ValueError: If function cannot be resolved
            TemporaryLimitation: If store graph not available
        """
        try:
            code = self.context.resolve_function(function)
        except ValueError as e:
            raise ValueError(f"Cannot resolve function: {e}")

        # Get the store graph
        store_graph = self._get_store_graph_safe()
        if store_graph is None:
            # Fall back to def-use analysis
            return self._get_aliases_from_defuse(code)

        # Use store graph to find aliases
        return self._get_aliases_from_storegraph(code, store_graph)

    def _get_store_graph_safe(self):
        """Get store graph if available, else None."""
        store_graph = getattr(self.context.program, "storeGraph", None)
        if store_graph is None:
            return None
        return store_graph

    def _get_aliases_from_storegraph(
        self, code, store_graph
    ) -> Dict[str, AliasInfo]:
        """Extract alias information from store graph.

        Args:
            code: The code object
            store_graph: The store graph

        Returns:
            Dictionary mapping variable names to AliasInfo
        """
        aliases: Dict[str, AliasInfo] = {}

        # Get function name for slot lookup
        func_name = self.context.code_name(code)

        # Iterate through root slots in the store graph
        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue

            # Check if this slot belongs to our function
            slot_str = str(slot_name)
            if func_name and func_name in slot_str:
                var_name = self._extract_var_from_slot(slot_name)
                if var_name:
                    # Find aliases by looking at merged slots
                    canonical = slot.getForward()
                    if canonical:
                        # This slot has been merged with others (aliased)
                        all_aliases = self._find_all_aliases(slot, store_graph)
                        aliases[var_name] = AliasInfo(
                            variable=var_name,
                            aliases=all_aliases - {var_name},
                            is_aliased=len(all_aliases) > 1,
                        )

        # Also check for field aliases (obj.field patterns)
        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue
            # Look for field slots (non-root)
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
        """Find all variables that alias with the given slot.

        Args:
            slot: The slot node to check
            store_graph: The store graph

        Returns:
            Set of variable names that alias with this slot
        """
        aliases: Set[str] = set()

        # Get canonical representative
        canonical = slot.getForward()

        # Find all slots that point to the same canonical object
        for other_slot in store_graph:
            if other_slot.getForward() == canonical:
                var_name = self._extract_var_from_slot(other_slot.slotName)
                if var_name:
                    aliases.add(var_name)

        return aliases

    def _extract_var_from_slot(self, slot_name) -> Optional[str]:
        """Extract variable name from a slot name.

        Handles slot names like:
        - local(function_name, Local(var_name/memory_addr), region_id)
        - existing(function_name, Object('field_name'), region_id)

        Args:
            slot_name: The slot name object (LocalSlotName or ExistingSlotName)

        Returns:
            Variable name string or None
        """
        if slot_name is None:
            return None

        # Check for Local variable (has 'local' attribute with Local AST node)
        local = getattr(slot_name, "local", None)
        if local is not None:
            name = getattr(local, "name", None)
            if isinstance(name, str):
                # Remove memory address suffix if present (e.g., "a/4356266960")
                if "/" in name:
                    return name.split("/")[0]
                return name

        # Check for Existing slot (has 'obj' attribute)
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
        """Extract object name from a field slot name.

        Args:
            slot_name: The slot name object

        Returns:
            Object name string or None
        """
        if slot_name is None:
            return None
        # For field slots, try to get the object part
        if hasattr(slot_name, "name") and hasattr(slot_name.name, "obj"):
            obj = slot_name.name.obj
            if hasattr(obj, "constantValue"):
                return obj.constantValue()
            elif hasattr(obj, "id"):
                return obj.id
        return None

    def _extract_field_from_slot(self, slot_name) -> Optional[str]:
        """Extract field name from a slot name.

        Args:
            slot_name: The slot name object

        Returns:
            Field name string or None
        """
        if slot_name is None:
            return None
        # For field slots, try to get the field part
        if hasattr(slot_name, "name") and hasattr(slot_name.name, "field"):
            field = slot_name.name.field
            if hasattr(field, "constantValue"):
                return field.constantValue()
            elif hasattr(field, "id"):
                return field.id
        return None

    def _get_aliases_from_defuse(self, code) -> Dict[str, AliasInfo]:
        """Extract alias information from def-use analysis.

        This is a fallback when the store graph is not available.
        It uses simple heuristics based on assignment patterns.

        Args:
            code: The code object to analyze

        Returns:
            Dictionary mapping variable names to AliasInfo
        """
        from pyflow.language.python.defuse import DefUseVisitor, DFS

        visitor = DefUseVisitor()
        dfs = DFS(visitor.visit)
        dfs.process(code)

        aliases: Dict[str, AliasInfo] = {}

        # Variables that are defined and used
        defined_vars = set(visitor.lcldef.keys())
        used_vars = set(visitor.lcluse.keys())

        for var in defined_vars:
            var_name = self._get_var_name(var)
            if var_name:
                aliases[var_name] = AliasInfo(variable=var_name)

        # Simple alias detection: if a variable is assigned from another variable
        # This requires AST-level analysis which is more complex
        # For now, mark all defined variables as potentially aliased
        return aliases

    def get_points_to(
        self, function: Union[str, object]
    ) -> Dict[str, PointsToInfo]:
        """Return points-to information for all variables in a function.

        This tells you what objects each variable may point to during analysis.

        Args:
            function: Function name or code object

        Returns:
            Dictionary mapping variable names to PointsToInfo

        Raises:
            ValueError: If function cannot be resolved
            TemporaryLimitation: If store graph not available
        """
        try:
            code = self.context.resolve_function(function)
        except ValueError as e:
            raise ValueError(f"Cannot resolve function: {e}")

        # Get the store graph
        store_graph = self._get_store_graph_safe()
        if store_graph is None:
            return {}

        return self._get_points_to_from_storegraph(code, store_graph)

    def _get_points_to_from_storegraph(
        self, code, store_graph
    ) -> Dict[str, PointsToInfo]:
        """Extract points-to information from store graph.

        Args:
            code: The code object
            store_graph: The store graph

        Returns:
            Dictionary mapping variable names to PointsToInfo
        """
        points_to: Dict[str, PointsToInfo] = {}

        func_name = self.context.code_name(code)

        for slot in store_graph:
            slot_name = getattr(slot, "slotName", None)
            if slot_name is None:
                continue

            # Check if this slot belongs to our function
            slot_str = str(slot_name)
            if func_name and func_name in slot_str:
                var_name = self._extract_var_from_slot(slot_name)
                if var_name:
                    # Get the set of objects this slot may point to
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
        """Describe an extended type for points-to output.

        Args:
            xtype: The extended type

        Returns:
            String description of the type
        """
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
