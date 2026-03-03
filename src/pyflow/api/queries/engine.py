"""
Graph query engine for PyFlow.
"""

from collections import deque
from typing import Any, Dict, List, Optional, Set, Union

from pyflow.application.errors import TemporaryLimitation
from pyflow.language.python import ast as py_ast
from pyflow.analysis.callgraph import CallGraph
from pyflow.analysis.cfg import ssa as cfg_ssa
from pyflow.analysis.cfg import transform as cfg_transform
from pyflow.analysis.cdg import construct_cdg
from pyflow.analysis.ifds import build_supergraph_from_cfgs

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
            self._callgraph_aliases = {}
            for context in ipa.contexts.values():
                src_code = getattr(getattr(context, "signature", None), "code", None)
                src_name = self.context.code_identifier(src_code)
                if not src_name:
                    continue
                callgraph.add_node(src_name)
                for alias in self.context.code_aliases(src_code):
                    self._callgraph_aliases.setdefault(alias, set()).add(src_name)
                for _, dst in context.invokeOut.keys():
                    dst_code = getattr(getattr(dst, "signature", None), "code", None)
                    dst_name = self.context.code_identifier(dst_code)
                    if dst_name:
                        callgraph.add_edge(src_name, dst_name)
                        for alias in self.context.code_aliases(dst_code):
                            self._callgraph_aliases.setdefault(alias, set()).add(
                                dst_name
                            )
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
            cfgs = tuple(self.get_all_cfgs(ignore_failures=True).values())
            if not cfgs:
                raise TemporaryLimitation(
                    "Unable to build any CFGs for IFDS analysis."
                )
            self._ensure_ifds_annotations_complete(cfgs)
            self._ifds_supergraph_cache = build_supergraph_from_cfgs(
                cfgs,
                include_exceptional_edges=True,
            )
        return self._ifds_supergraph_cache

    def _ensure_ifds_annotations_complete(self, cfgs) -> None:
        problems: List[str] = []
        seen_codes: Set[object] = set()
        for cfg in cfgs:
            code = getattr(cfg, "code", None)
            if code is None or code in seen_codes:
                continue
            seen_codes.add(code)

            annotation = getattr(code, "annotation", None)
            if getattr(annotation, "contexts", None) is None:
                problems.append(f"{self.context.code_name(code) or repr(code)}: missing code contexts")
                continue

            for node in self._iter_ast_nodes(code):
                node_annotation = getattr(node, "annotation", None)
                if node_annotation is None:
                    continue
                if hasattr(node_annotation, "opReads") and getattr(node_annotation, "opReads", None) is None:
                    problems.append(
                        f"{self.context.code_name(code) or repr(code)}: {type(node).__name__} missing opReads"
                    )
                    break
                if hasattr(node_annotation, "opModifies") and getattr(node_annotation, "opModifies", None) is None:
                    problems.append(
                        f"{self.context.code_name(code) or repr(code)}: {type(node).__name__} missing opModifies"
                    )
                    break
                if hasattr(node_annotation, "references") and getattr(node_annotation, "references", None) is None:
                    name = getattr(node, "name", None)
                    problems.append(
                        f"{self.context.code_name(code) or repr(code)}: local {name if name is not None else '<anon>'} missing references"
                    )
                    break

        if problems:
            raise TemporaryLimitation(
                "IFDS requires annotation-complete programs (run IPA/CPA first): "
                + "; ".join(problems[:5])
            )

    def _iter_ast_nodes(self, node):
        if node is None or isinstance(node, py_ast.leafTypes):
            return
        yield node
        if isinstance(node, (list, tuple)):
            for child in node:
                yield from self._iter_ast_nodes(child)
            return
        if isinstance(node, py_ast.Code):
            params = getattr(node, "codeparameters", None)
            if params is not None:
                yield from self._iter_ast_nodes(getattr(params, "selfparam", None))
                yield from self._iter_ast_nodes(getattr(params, "posonlyparams", ()))
                yield from self._iter_ast_nodes(getattr(params, "params", ()))
                yield from self._iter_ast_nodes(getattr(params, "defaults", ()))
                yield from self._iter_ast_nodes(getattr(params, "vparam", None))
                yield from self._iter_ast_nodes(getattr(params, "kparam", None))
                yield from self._iter_ast_nodes(getattr(params, "returnparams", ()))
            yield from self._iter_ast_nodes(node.ast)
            return

        children = []
        node.visitChildren(children.append)
        for child in children:
            yield from self._iter_ast_nodes(child)

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

        def get_bid(b):
            return getattr(b, "bid", id(b))

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
