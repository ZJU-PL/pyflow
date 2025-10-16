
"""CFG dumping and visualization utilities.

This module provides functionality to dump and visualize control flow graphs
in various formats including DOT graphs for visualization.
"""

import pyflow.util.pydot as pydot
from pyflow.util.typedispatch import *
from pyflow.util.io import filesystem
from pyflow.analysis.cfg import graph as cfg


def makeStr(s):
    """Escape string for use in DOT graph labels.
    
    Args:
        s: String to escape.
        
    Returns:
        str: Escaped string suitable for DOT graphs.
    """
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    return '"%s"' % s


class NodeStyle(TypeDispatcher):
    """Provides styling information for CFG nodes in visualizations.
    
    This class defines colors and shapes for different types of CFG nodes
    when generating visual representations.
    
    Attributes:
        suiteColor: Color for suite nodes.
        switchColor: Color for switch nodes.
        mergeColor: Color for merge nodes.
        yieldColor: Color for yield nodes.
        stateColor: Color for state nodes.
    """
    
    suiteColor = "lightyellow"
    switchColor = "cyan"
    mergeColor = "magenta"
    yieldColor = "aliceblue"

    stateColor = "green"

    @dispatch(cfg.Entry, cfg.Exit)
    def handleTerminal(self, node):
        """Handle terminal nodes (entry/exit).
        
        Args:
            node: Terminal CFG node.
            
        Returns:
            dict: Styling information for terminal nodes.
        """
        return dict(shape="point", fontsize=8)

    @dispatch(cfg.Suite)
    def handleSuite(self, node):
        """Handle suite nodes.
        
        Args:
            node: Suite CFG node.
            
        Returns:
            dict: Styling information for suite nodes.
        """
        label = makeStr("\n".join([repr(op) for op in node.ops]))
        return dict(
            label=label,
            shape="box",
            style="filled",
            fillcolor=self.suiteColor,
            fontsize=8,
        )

    @dispatch(cfg.Switch)
    def handleSwitch(self, node):
        """Handle switch nodes.
        
        Args:
            node: Switch CFG node.
            
        Returns:
            dict: Styling information for switch nodes.
        """
        label = makeStr(repr(node.condition))
        return dict(
            label=label,
            shape="trapezium",
            style="filled",
            fillcolor=self.switchColor,
            fontsize=8,
        )

    @dispatch(cfg.Merge)
    def handleMerge(self, node):
        """Handle merge nodes.
        
        Args:
            node: Merge CFG node.
            
        Returns:
            dict: Styling information for merge nodes.
        """
        label = makeStr("\n".join([repr(phi) for phi in node.phi]))
        return dict(
            label=label,
            shape="invtrapezium",
            style="filled",
            fillcolor=self.mergeColor,
            fontsize=8,
        )

    @dispatch(cfg.Yield)
    def handleYield(self, node):
        return dict(
            label="yield",
            shape="circle",
            style="filled",
            fillcolor=self.yieldColor,
            fontsize=8,
        )

    @dispatch(cfg.State)
    def handleState(self, node):
        label = repr(node.name)
        return dict(
            label=label,
            shape="doublecircle",
            style="filled",
            fillcolor=self.stateColor,
            fontsize=8,
        )


class CFGToDot(TypeDispatcher):
    def __init__(self, g):
        self.g = g
        self.nodes = {}
        self.regions = {}
        self.processed = set()
        self.queue = []

        self.style = NodeStyle()

    def node(self, node):
        key = node

        if key not in self.nodes:
            node.sanityCheck()
            settings = self.style(node)
            result = pydot.Node(id(key), **settings)

            region = self.region(node)

            region.add_node(result)
            self.nodes[key] = result
        else:
            result = self.nodes[key]

        return result

    def region(self, node):
        region = node.region
        if region not in self.regions:
            result = pydot.Cluster(str(id(region)))
            self.regions[region] = result

            if region is not None:
                parent = self.region(region)
                parent.add_subgraph(result)
            else:
                self.g.add_subgraph(result)
        else:
            result = self.regions[region]

        return result

    def edge(self, src, dst, style="solid", color="black"):
        if src is None or dst is None:
            return

        srcnode = self.node(src)
        dstnode = self.node(dst)
        self.g.add_edge(pydot.Edge(srcnode, dstnode, color=color, style=style))

    colors = {
        "normal": "green",
        "fail": "yellow",
        "error": "red",
        "true": "cyan",
        "false": "purple",
    }

    @defaultdispatch
    def default(self, node):
        for name, child in node.next.items():
            if name == "fail" and child is self.failIgnore:
                continue
            elif name == "error" and child is self.errorIgnore:
                continue

            self.mark(child)
            self.edge(node, child, color=self.colors.get(name, "black"))

    # 		for prev in node.reverse():
    # 			self.edge(node, prev, color='red')

    @dispatch(type(None))
    def visitNone(self, node):
        pass

    def mark(self, node):
        assert node is not None
        if node not in self.processed:
            self.processed.add(node)
            self.queue.append(node)

    def process(self, code):
        # self.failIgnore  = code.failTerminal
        self.failIgnore = None

        self.errorIgnore = code.errorTerminal
        self.mark(code.entryTerminal)

        while self.queue:
            current = self.queue.pop()
            self(current)


def dumpGraph(directory, name, format, g, prog="dot"):
    s = g.create(prog=prog, format=format)
    filesystem.writeBinaryData(directory, name, format, s)


def evaluate(compiler, cfg):
    g = pydot.Dot(graph_type="digraph")

    ctd = CFGToDot(g)
    ctd.process(cfg)

    directory = "summaries"
    name = cfg.code.name

    dumpGraph(directory, name, "svg", g)


def generate_clang_style_cfg(cfg):
    """Generate clang-style CFG representation.

    Args:
        cfg: Control flow graph to generate representation for.

    Returns:
        str: Text representation of the CFG in clang-style format.
    """
    try:
        # Collect all nodes using BFS
        visited, queue, all_nodes = set(), [cfg.entryTerminal], []
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            all_nodes.append(node)
            if hasattr(node, 'next'):
                queue.extend(next_node for next_node in node.next.values() if next_node and next_node not in visited)

        node_to_block = {node: f"B{i}" for i, node in enumerate(all_nodes)}

        # Generate CFG content
        content = "CFG:\n"
        for i, node in enumerate(all_nodes):
            try:
                block_id = f"B{i}"
                content += f"\n{block_id}:\n"

                # Block type
                if node == cfg.entryTerminal:
                    content += "  [ENTRY]\n"
                elif node == cfg.normalTerminal:
                    content += "  [EXIT]\n"
                elif node == cfg.failTerminal:
                    content += "  [FAIL EXIT]\n"
                elif node == cfg.errorTerminal:
                    content += "  [ERROR EXIT]\n"
                else:
                    content += f"  [{type(node).__name__}]\n"

                # Node content
                if hasattr(node, 'ops') and node.ops:
                    for op in node.ops:
                        content += f"    {op}\n"
                elif hasattr(node, 'condition') and node.condition:
                    content += f"    Condition: {node.condition}\n"
                elif hasattr(node, 'phi') and node.phi:
                    for phi in node.phi:
                        content += f"    Phi: {phi}\n"

                # Outgoing edges
                if hasattr(node, 'next') and node.next:
                    edges = [f"{name} -> {node_to_block[next_node]}" for name, next_node in node.next.items()
                            if next_node and next_node in node_to_block]
                    content += f"  Succs ({", ".join(edges)})\n"
                else:
                    content += "  Succs ()\n"
            except Exception as e:
                content += f"  Error processing node {i}: {e}\n"

        return content
    except Exception as e:
        return f"Error generating CFG: {e}"
