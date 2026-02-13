"""
Dumping utilities for Program Dependence Graphs (PDG).

Supported formats:
- text: human-readable edge list + basic stats
- dot: Graphviz DOT format (via pyflow.util.pydot)
- json: machine-readable JSON export
"""

from __future__ import annotations

import json
import os
from typing import List, Optional

import pyflow.util.pydot as pydot
from pyflow.util.io import filesystem

from .graph import ProgramDependenceGraph


class PDGDumper:
    __slots__ = ("pdg",)

    def __init__(self, pdg: ProgramDependenceGraph):
        self.pdg = pdg

    def dump_text(self, path: str, title: str = "Program Dependence Graph") -> None:
        stats = self.pdg.stats()
        with open(path, "w") as f:
            f.write(f"{title}\n{'=' * 60}\n\n")
            f.write(f"Nodes: {stats.nodes}, Edges: {stats.edges}\n")
            f.write(f"Node kinds: {stats.node_kinds}\n")
            f.write(f"Edge kinds: {stats.edge_kinds}\n\n")
            f.write("Edges (source -> target) [kind:label]:\n")
            for e in self.pdg.all_edges():
                lbl = f":{e.label}" if e.label else ""
                f.write(f"  {e.source.node_id} -> {e.target.node_id} [{e.kind}{lbl}]\n")

    def dump_dot(self, path: str, title: str = "PDG") -> None:
        g = pydot.Dot(graph_type="digraph")
        g.set_label(title)

        for n in self.pdg.nodes:
            node_id = f"n_{n.node_id}"
            label = f"{n.node_id}\\n{n.kind}"
            shape = "ellipse"
            if n.kind in ("stmt", "cond"):
                shape = "box"
            elif n.kind in ("entry", "exit"):
                shape = "doublecircle"
            g.add_node(pydot.Node(node_id, label=label, shape=shape))

        for e in self.pdg.all_edges():
            edge_label = e.kind if not e.label else f"{e.kind}:{e.label}"
            g.add_edge(
                pydot.Edge(
                    f"n_{e.source.node_id}", f"n_{e.target.node_id}", label=edge_label
                )
            )

        with open(path, "w") as f:
            f.write("// PDG\n")
            f.write(g.to_string())

    def dump_json(self, path: str, title: str = "PDG") -> None:
        stats = self.pdg.stats()
        data = {
            "title": title,
            "stats": {
                "nodes": stats.nodes,
                "edges": stats.edges,
                "node_kinds": stats.node_kinds,
                "edge_kinds": stats.edge_kinds,
            },
            "nodes": [
                {
                    "id": n.node_id,
                    "kind": n.kind,
                    "label": n.label,
                }
                for n in self.pdg.nodes
            ],
            "edges": [
                {
                    "source": e.source.node_id,
                    "target": e.target.node_id,
                    "kind": e.kind,
                    "label": e.label,
                }
                for e in self.pdg.all_edges()
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


def dump_pdg(
    pdg: ProgramDependenceGraph, path: str, fmt: str = "text", title: str = "PDG"
) -> None:
    dumper = PDGDumper(pdg)
    fmt = fmt.lower()
    if fmt == "text":
        dumper.dump_text(path, title=title)
    elif fmt == "dot":
        dumper.dump_dot(path, title=title)
    elif fmt == "json":
        dumper.dump_json(path, title=title)
    else:
        raise ValueError(f"Unsupported PDG dump format: {fmt}")


def dump_pdg_to_directory(
    pdg: ProgramDependenceGraph,
    directory: str,
    basename: str,
    formats: Optional[List[str]] = None,
    title: str = "PDG",
) -> List[str]:
    if formats is None:
        formats = ["text", "dot", "json"]

    filesystem.ensureDirectoryExists(directory)
    outputs: List[str] = []
    for fmt in formats:
        out = os.path.join(directory, f"{basename}.pdg.{fmt}")
        dump_pdg(pdg, out, fmt=fmt, title=title)
        outputs.append(out)
    return outputs
