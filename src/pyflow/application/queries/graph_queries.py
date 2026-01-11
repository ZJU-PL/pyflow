"""
Graph query helpers for PyFlow.
"""

from typing import Dict, Optional, Union

from pyflow.analysis.callgraph import CallGraph
from pyflow.analysis.cfg import transform as cfg_transform
from pyflow.analysis.cfg import ssa as cfg_ssa
from pyflow.analysis.cdg import construct_cdg


class GraphQueries:
    """Graph query mixin for CFG/SSA/CDG/callgraph."""

    def __init__(self):
        self._cfg_cache: Dict[object, object] = {}
        self._ssa_cache: Dict[object, object] = {}
        self._cdg_cache: Dict[object, object] = {}
        self._callgraph_cache: Optional[CallGraph] = None

    def get_cfg(self, function: Union[str, object]):
        """Return a CFG for the given function."""
        code = self._resolve_function(function)
        if code not in self._cfg_cache:
            self._cfg_cache[code] = cfg_transform.evaluate(self.compiler, code)
        return self._cfg_cache[code]

    def get_ssa(self, function: Union[str, object]):
        """Return a CFG annotated with SSA form."""
        code = self._resolve_function(function)
        if code not in self._ssa_cache:
            cfg = cfg_transform.evaluate(self.compiler, code)
            cfg_ssa.evaluate(self.compiler, cfg)
            self._ssa_cache[code] = cfg
        return self._ssa_cache[code]

    def get_cdg(self, function: Union[str, object]):
        """Return a CDG for the given function."""
        code = self._resolve_function(function)
        if code not in self._cdg_cache:
            cfg = self.get_cfg(code)
            self._cdg_cache[code] = construct_cdg(cfg)
        return self._cdg_cache[code]

    def get_callgraph(self) -> CallGraph:
        """Return a callgraph derived from IPA analysis."""
        if self._callgraph_cache is None:
            ipa = self._require_ipa()
            callgraph = CallGraph()
            for context in ipa.contexts.values():
                src_name = self._context_name(context)
                if not src_name:
                    continue
                callgraph.add_node(src_name)
                for (_, dst) in context.invokeOut.keys():
                    dst_name = self._context_name(dst)
                    if dst_name:
                        callgraph.add_edge(src_name, dst_name)
            self._callgraph_cache = callgraph
        return self._callgraph_cache
