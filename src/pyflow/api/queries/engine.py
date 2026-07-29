"""
Graph query engine for PyFlow.
"""

from collections import deque
from typing import Any, Dict, List, Optional, Set, Union

from pyflow.application.errors import TemporaryLimitation
from pyflow.analysis.callgraph import CallGraph
from pyflow.ir.cfg import ssa as cfg_ssa
from pyflow.ir.cfg import transform as cfg_transform
from pyflow.ir.cdg import construct_cdg
from pyflow.analysis.ifds import build_supergraph_from_cfgs
from pyflow.analysis.ifds.frontend.preparation import prepare_program_for_ifds
from pyflow.ir.core import Capabilities, ContextualKey, NodeId, Precision

from .context import QueryContext


class GraphQueryEngine:
    """
    Engine for retrieving and caching graph structures (CFG, SSA, CDG, CallGraph).
    """

    def __init__(self, context: QueryContext):
        self.context = context
        self._cfg_cache: Dict[object, object] = {}
        self._ssa_cache: Dict[object, object] = {}
        self._cdg_cache: Dict[object, object] = {}
        self._ifds_supergraph_cache = None
        self._callgraph_cache: Optional[CallGraph] = None
        self._callgraph_aliases: Dict[str, Set[str]] = {}

    def reset_cache(self):
        """Clear all internal caches."""
        self._cfg_cache.clear()
        self._ssa_cache.clear()
        self._cdg_cache.clear()
        self._ifds_supergraph_cache = None
        self._callgraph_cache = None
        self._callgraph_aliases = {}

    def get_cfg(
        self, function: Union[str, object], *, commit_revision: bool = True
    ):
        """Return a CFG for the given function."""
        code = self.context.resolve_function(function)
        if code not in self._cfg_cache:
            if commit_revision:
                self._cfg_cache[code] = cfg_transform.evaluate(
                    self.context.compiler, code
                )
            else:
                self._cfg_cache[code] = cfg_transform.evaluate(
                    self.context.compiler,
                    code,
                    commit_revision=False,
                )
        return self._cfg_cache[code]

    def get_ssa(self, function: Union[str, object]):
        """Return a CFG annotated with SSA form."""
        code = self.context.resolve_function(function)
        if code not in self._ssa_cache:
            cfg = cfg_transform.evaluate(self.context.compiler, code)
            cfg_ssa.evaluate(self.context.compiler, cfg)
            self._ssa_cache[code] = cfg
        return self._ssa_cache[code]

    def get_cdg(self, function: Union[str, object]):
        """Return a CDG for the given function."""
        code = self.context.resolve_function(function)
        if code not in self._cdg_cache:
            cfg = self.get_cfg(code)
            self._cdg_cache[code] = construct_cdg(cfg)
        return self._cdg_cache[code]

    def get_callgraph(self) -> CallGraph:
        """Return a callgraph derived from revision-aware published facts."""
        if self._callgraph_cache is None:
            catalog = getattr(self.context.program, "ir", None)
            if catalog is None:
                raise TemporaryLimitation("IR catalog is not available.")
            if not (
                catalog.facts.has(Capabilities.CALL_TARGET_CODES)
                or catalog.facts.has(Capabilities.CALL_TARGETS)
            ):
                raise TemporaryLimitation(
                    "Call-target facts are not available; run a callgraph, IPA, or CPA pass."
                )
            callgraph = CallGraph()
            self._callgraph_aliases = {}
            for procedure in catalog.procedures():
                src_code = catalog.code(procedure.code_id)
                src_name = str(procedure.code_id)
                callgraph.add_node(src_name)
                for alias in self.context.code_aliases(src_code):
                    self._callgraph_aliases.setdefault(alias, set()).add(src_name)

            edges = set()
            for key, result in catalog.facts.items(Capabilities.CALL_TARGET_CODES):
                if result.precision is Precision.UNKNOWN or not isinstance(key, NodeId):
                    continue
                edges.update((key.code, target) for target in result.values)
            for key, result in catalog.facts.items(Capabilities.CALL_TARGETS):
                if (
                    result.precision is Precision.UNKNOWN
                    or not isinstance(key, ContextualKey)
                    or not isinstance(key.entity, NodeId)
                ):
                    continue
                edges.update((key.entity.code, target.code) for target in result.values)

            for source_id, target_id in sorted(edges):
                if not catalog.has_procedure(source_id) or not catalog.has_procedure(
                    target_id
                ):
                    continue
                src_name = str(source_id)
                dst_name = str(target_id)
                callgraph.add_edge(src_name, dst_name)
            self._callgraph_cache = callgraph
        return self._callgraph_cache

    def get_callgraph_aliases(self) -> Dict[str, Set[str]]:
        """Return alias -> node-name mapping for the cached call graph."""
        self.get_callgraph()
        return {alias: set(nodes) for alias, nodes in self._callgraph_aliases.items()}

    def get_all_cfgs(
        self, *, ignore_failures: bool = False
    ) -> Dict[object, object]:
        """Return CFGs for all known live code objects."""
        cfgs: Dict[object, object] = {}
        failures: List[str] = []
        for code in getattr(self.context.program, "liveCode", []):
            try:
                cfgs[code] = self.get_cfg(code)
            except Exception as exc:
                name = self.context.code_identifier(code) or self.context.code_name(code) or repr(code)
                failures.append(f"{name}: {exc}")
        if failures and not ignore_failures:
            raise TemporaryLimitation(
                "Unable to build CFGs for IFDS analysis: " + "; ".join(failures[:5])
            )
        return cfgs

    def get_ifds_supergraph(self):
        """Return a cached CFG-backed IFDS supergraph adapter."""
        if self._ifds_supergraph_cache is None:
            prepared = prepare_program_for_ifds(
                self.context.compiler,
                self.context.program,
                get_cfg=self.get_cfg,
            )
            self._ifds_supergraph_cache = build_supergraph_from_cfgs(
                prepared.cfgs,
                include_exceptional_edges=True,
            )
        return self._ifds_supergraph_cache

    def get_cfg_structure(self, function: Union[str, object]) -> Dict[str, Any]:
        """
        Return a JSON-friendly dictionary representation of the CFG.

        Structure:
        {
            "name": "function_name",
            "blocks": [
                {"id": 1, "type": "Suite", "operations": [...]},
                ...
            ],
            "edges": [
                {"src": 1, "dst": 2, "type": "normal"},
                ...
            ]
        }
        """
        cfg = self.get_cfg(function)
        code = self.context.resolve_function(function)
        name = self.context.code_name(code)

        blocks_data = []
        edges_data = []

        visited = set()
        queue = deque([cfg.entryTerminal])

        catalog = getattr(code, "ir_catalog", None)
        local_block_ids = {}

        def get_bid(block):
            if catalog is not None:
                return str(catalog.block_id(block, code))
            explicit = getattr(block, "bid", None)
            if explicit is not None:
                return explicit
            if block not in local_block_ids:
                local_block_ids[block] = f"bb{len(local_block_ids)}"
            return local_block_ids[block]

        while queue:
            block = queue.popleft()
            if block in visited:
                continue
            visited.add(block)

            block_info = {
                "id": get_bid(block),
                "type": block.__class__.__name__,
            }
            blocks_data.append(block_info)

            nxt = getattr(block, "next", None)
            if isinstance(nxt, dict):
                for exit_type, target in nxt.items():
                    if target is None:
                        continue
                    edges_data.append(
                        {
                            "src": get_bid(block),
                            "dst": get_bid(target),
                            "type": exit_type,
                        }
                    )
                    if target not in visited:
                        queue.append(target)
            elif nxt is not None:
                edges_data.append(
                    {
                        "src": get_bid(block),
                        "dst": get_bid(nxt),
                        "type": "normal",
                    }
                )
                if nxt not in visited:
                    queue.append(nxt)

        return {"name": name, "blocks": blocks_data, "edges": edges_data}
