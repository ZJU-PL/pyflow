"""
Graph query engine for PyFlow.
"""

from typing import Any, Dict, List, Optional, Union

from pyflow.analysis.callgraph import CallGraph
from pyflow.analysis.cfg import ssa as cfg_ssa
from pyflow.analysis.cfg import transform as cfg_transform
from pyflow.analysis.cdg import construct_cdg

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
        self._callgraph_cache: Optional[CallGraph] = None

    def reset_cache(self):
        """Clear all internal caches."""
        self._cfg_cache.clear()
        self._ssa_cache.clear()
        self._cdg_cache.clear()
        self._callgraph_cache = None

    def get_cfg(self, function: Union[str, object]):
        """Return a CFG for the given function."""
        code = self.context.resolve_function(function)
        if code not in self._cfg_cache:
            self._cfg_cache[code] = cfg_transform.evaluate(self.context.compiler, code)
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
        """Return a callgraph derived from IPA analysis."""
        if self._callgraph_cache is None:
            ipa = self.context.require_ipa()
            callgraph = CallGraph()
            for context in ipa.contexts.values():
                src_name = self.context.context_name(context)
                if not src_name:
                    continue
                callgraph.add_node(src_name)
                for _, dst in context.invokeOut.keys():
                    dst_name = self.context.context_name(dst)
                    if dst_name:
                        callgraph.add_edge(src_name, dst_name)
            self._callgraph_cache = callgraph
        return self._callgraph_cache

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
        queue = [cfg.entryTerminal]

        def get_bid(b):
            return getattr(b, "bid", id(b))

        while queue:
            block = queue.pop(0)
            if block in visited:
                continue
            visited.add(block)

            block_info = {
                "id": get_bid(block),
                "type": block.__class__.__name__,
            }
            blocks_data.append(block_info)

            if hasattr(block, "next") and isinstance(block.next, dict):
                for exit_type, target in block.next.items():
                    edges_data.append(
                        {
                            "src": get_bid(block),
                            "dst": get_bid(target),
                            "type": exit_type,
                        }
                    )
                    if target not in visited:
                        queue.append(target)

        return {"name": name, "blocks": blocks_data, "edges": edges_data}