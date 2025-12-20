"""
DOT graph visualization utilities.

This module provides classes and functions for generating DOT format graph files,
which can be rendered by Graphviz tools. It supports directed and undirected graphs,
subgraphs, clusters, nodes, and edges with customizable attributes.
"""
import os
import re

__all__ = "Digraph", "Style", "createGraphic"

# Regular expression for escaping special characters in DOT field values
makeescape = re.compile(r"[\n\"]")

# Lookup table for escaping special characters in DOT format
lut = {"\n": r"\n", "\t": r"\t", '"': r"\""}


def escapeField(s):
    """
    Escape special characters in a string for use as a DOT field value.
    
    Escapes newlines, tabs, and double quotes to their escaped representations
    to ensure valid DOT syntax.
    
    Args:
        s: String to escape (will be converted to string if not already)
        
    Returns:
        Escaped string safe for use in DOT format
    """
    return makeescape.sub(lambda c: lut[c.group()], str(s))


class Subgraph(object):
    """
    Represents a subgraph in a DOT graph structure.
    
    A Subgraph can be a digraph (directed graph), graph (undirected graph),
    or a nested subgraph. It contains nodes, edges, and nested subgraphs,
    and can output itself in DOT format.
    """
    __slots__ = (
        "graphtype",
        "name",
        "attr",
        "subgraphs",
        "nodes",
        "nameLUT",
        "edges",
        "parent",
        "nodetype",
        "edgetype",
    )

    def __init__(self, graphtype, name, nodetype=None, edgetype=None, **attr):
        """
        Initialize a Subgraph.
        
        Args:
            graphtype: Type of graph - "digraph" (directed) or "graph" (undirected)
            name: Name of the subgraph
            nodetype: Optional default style/attributes for all nodes in this subgraph
            edgetype: Optional default style/attributes for all edges in this subgraph
            **attr: Additional graph-level attributes (e.g., label, fontsize)
        """
        self.graphtype = graphtype

        self.name = name
        self.attr = attr
        self.parent = None

        self.subgraphs = []
        self.nodes = []
        self.edges = []
        self.nameLUT = {}

        self.nodetype = nodetype
        self.edgetype = edgetype

    def isDirected(self):
        """
        Check if this is a directed graph (digraph).
        
        Returns:
            True if this is a digraph, False if it's an undirected graph
        """
        return self.graphtype == "digraph"

    def createDotFile(self, fo):
        """
        Create a DOT file from this subgraph.
        
        Args:
            fo: File object or filename string to write the DOT output to
        """
        if isinstance(fo, str):
            fo = open(fo, "w")
        self.outputDot(fo)

    def outputDot(self, out, tabs=""):
        """
        Output this subgraph in DOT format to the given file object.
        
        Recursively outputs all nested subgraphs, nodes, and edges with
        proper indentation and DOT syntax.
        
        Args:
            out: File object to write to
            tabs: Indentation prefix for this level (used for nested subgraphs)
        """
        indent = tabs + "\t"
        out.write('%s%s "%s" {\n' % (tabs, self.graphtype, escapeField(self.name)))

        # Output attributes
        for k, v in self.attr.items():
            out.write(indent + k + ' = "' + escapeField(v) + '"\n')

        # Output subgraphs
        for sg in self.subgraphs:
            sg.outputDot(out, indent)

        # Output nodes
        if self.nodetype:
            out.write("%snode" % indent)
            dumpAttr(self.nodetype, out)
            out.write(";\n")

        self.nodes.sort(key=lambda n: n.style)
        currentStyle = None
        for n in self.nodes:
            if currentStyle != n.style:
                out.write("%snode" % indent)
                dumpAttr(n.style, out)
                out.write(";\n")
                currentStyle = n.style
            n.dump(out, indent)

        # Output edges
        if self.edgetype:
            out.write("%sedge" % indent)
            dumpAttr(self.edgetype, out)
            out.write(";\n")

        self.edges.sort(key=lambda e: e.style)

        directed = self.isDirected()

        currentStyle = None
        for e in self.edges:
            if currentStyle != e.style:
                out.write("%sedge" % indent)
                dumpAttr(e.style, out)
                out.write(";\n")
                currentStyle = e.style
            e.resolveNodes(self)
            e.dump(out, indent, directed)

        out.write("%s}\n" % (tabs,))

    def subgraph(self, name, **attr):
        """
        Create a nested subgraph within this subgraph.
        
        Args:
            name: Name of the subgraph
            **attr: Additional attributes for the subgraph
            
        Returns:
            The newly created Subgraph instance
        """
        name = str(name)
        sg = Subgraph("subgraph", name, **attr)
        sg.parent = self
        self.subgraphs.append(sg)

        if name[:8] == "cluster_":
            self.registerNode(name, sg)

        return sg

    def cluster(self, name, **attr):
        """
        Create a cluster subgraph (visual grouping in DOT format).
        
        Cluster names are automatically prefixed with "cluster_" which tells
        Graphviz to visually group the nodes within.
        
        Args:
            name: Name of the cluster (will be prefixed with "cluster_")
            **attr: Additional attributes for the cluster
            
        Returns:
            The newly created cluster Subgraph instance
        """
        name = str(name)
        clustername = "cluster_%s" % name
        sg = self.subgraph(clustername, **attr)
        return sg

    def registerNode(self, name, node):
        """
        Register a node in the name lookup table.
        
        Registers the node in this subgraph and all parent subgraphs,
        allowing nodes to be found by name when creating edges.
        
        Args:
            name: Name identifier for the node
            node: Node object to register (can be a Node or Subgraph)
        """
        self.nameLUT[name] = node
        if self.parent:
            self.parent.registerNode(name, node)

    def node(self, name, nodetype=None, **attr):
        """
        Create a node in this subgraph.
        
        Args:
            name: Unique name identifier for the node
            nodetype: Optional style/attributes for this node
            **attr: Additional node attributes (label, shape, color, etc.)
            
        Returns:
            The newly created Node instance
            
        Raises:
            AssertionError: If a node with the given name already exists
        """
        name = str(name)
        assert not name in self.nameLUT, name
        n = Node(name, nodetype, **attr)
        n.parent = self
        self.nodes.append(n)
        self.registerNode(name, n)
        return n

    def getNode(self, n):
        """
        Get a node by name or return the node if it's already a node object.
        
        Searches the name lookup table to find the node. If passed a Node or
        Subgraph object directly, returns it unchanged.
        
        Args:
            n: Node name string, Node object, or Subgraph object
            
        Returns:
            The Node or Subgraph object
            
        Raises:
            AssertionError: If the node name is not found in the lookup table
        """
        if isinstance(n, Node) or isinstance(n, Subgraph):
            return n
        else:
            n = str(n)
            assert n in self.nameLUT, (
                "Cannot find node " + str(n) + "\n\n" + str(self.nameLUT)
            )
            return self.nameLUT[n]

    def edge(self, n1, n2, edgetype=None, **kargs):
        """
        Create an edge between two nodes.
        
        If this is a nested subgraph, the edge is pushed to the root graph.
        Edges can connect multiple nodes in sequence (n1 -> n2 -> n3 -> ...).
        
        Args:
            n1: First node name (source node)
            n2: Second node name (destination node)
            edgetype: Optional style/attributes for this edge
            **kargs: Additional edge attributes (label, color, style, etc.)
            
        Returns:
            The newly created Edge instance
        """
        n1 = str(n1)
        n2 = str(n2)
        if self.parent:
            # Push the edge definition back to the root.
            edgetype = edgetype or self.edgetype
            return self.parent.edge(n1, n2, edgetype, **kargs)
        else:
            nodes = [n1, n2]
            # nodes = [self.getNode(n) for n in nodes]
            e = Edge(nodes, edgetype, **kargs)
            self.edges.append(e)
            return e


class Node(object):
    """
    Represents a node in a DOT graph.
    
    A node has a unique name and optional attributes that control its
    appearance in the rendered graph (shape, color, label, etc.).
    """
    __slots__ = ("name", "attr", "parent", "style")

    # Valid DOT node attributes that can be set
    validattr = [
        "bottomlabel",
        "color",
        "comment",
        "distortion",
        "fillcolor",
        "fixedsize",
        "fontcolor",
        "fontname",
        "fontsize",
        "group",
        "height",
        "label",
        "layer",
        "orientation",
        "peripheries",
        "regular",
        "shape",
        "shapefile",
        "sides",
        "skew",
        "style",
        "toplabel",
        "URL",
        "width",
        "z",
    ]

    def __init__(self, name, nodetype=None, **attr):
        """
        Initialize a Node.
        
        Args:
            name: Unique name identifier for the node (must be a string)
            nodetype: Optional default style/attributes (usually from parent subgraph)
            **attr: Node attributes (label, shape, color, fillcolor, etc.)
        """
        assert isinstance(name, str)
        self.name = name
        self.attr = attr
        self.parent = None
        self.style = nodetype

    def dump(self, out, tabs=""):
        """
        Output this node in DOT format.
        
        Args:
            out: File object to write to
            tabs: Indentation prefix
        """
        out.write('%s"%s"' % (tabs, escapeField(self.name)))
        if self.attr:
            dumpAttr(self.attr, out)
        out.write(";\n")


class Edge(object):
    """
    Represents an edge (connection) between nodes in a DOT graph.
    
    An edge can connect two or more nodes in sequence. It has optional
    attributes that control its appearance (label, color, style, etc.).
    """
    __slots__ = ("nodes", "attr", "style")

    def __init__(self, nodes, edgetype=None, **attr):
        """
        Initialize an Edge.
        
        Args:
            nodes: List of at least 2 node names that this edge connects
            edgetype: Optional default style/attributes (usually from parent subgraph)
            **attr: Edge attributes (label, color, style, etc.)
        """
        assert len(nodes) >= 2
        self.nodes = nodes
        self.attr = attr
        self.style = edgetype

    def resolveNodes(self, subgraph):
        """
        Resolve node names to Node objects using the subgraph's lookup table.
        
        Args:
            subgraph: Subgraph instance to use for node name resolution
        """
        self.nodes = [subgraph.getNode(node) for node in self.nodes]

    def dump(self, out, tabs, directed):
        """
        Output this edge in DOT format.
        
        Args:
            out: File object to write to
            tabs: Indentation prefix
            directed: If True, use "->" (directed edge), else use "--" (undirected)
        """
        assert len(self.nodes) >= 2

        symbol = "->" if directed else "--"

        out.write('%s"%s"' % (tabs, escapeField(self.nodes[0].name)))
        for i in range(1, len(self.nodes)):
            out.write(' %s "%s"' % (symbol, escapeField(self.nodes[i].name)))

        if self.attr:
            dumpAttr(self.attr, out)

        out.write(";\n")


def Style(**kargs):
    """
    Create a style dictionary for nodes or edges.
    
    Validates that all keys and values are strings, as required by DOT format.
    This is a convenience function for creating style dictionaries.
    
    Args:
        **kargs: Style attributes (e.g., shape="box", color="red")
        
    Returns:
        Dictionary of style attributes
        
    Raises:
        AssertionError: If any key or value is not a string
    """
    for k, v in kargs.items():
        assert type(k) == str and type(v) == str
    return kargs


def dumpAttr(attr, out):
    """
    Output attributes in DOT format to the file object.
    
    Formats attributes as [key1="value1", key2="value2", ...]
    
    Args:
        attr: Dictionary of attributes to output
        out: File object to write to
    """
    out.write(" [")
    first = True
    for k, v in attr.items():
        v = str(v)
        assert type(k) == str and type(v) == str
        if first:
            out.write('%s="%s"' % (k, escapeField(v)))
            first = False
        else:
            out.write(', %s="%s"' % (k, escapeField(v)))
    out.write("]")


def Digraph(**attr):
    """
    Create a new directed graph (digraph).
    
    This is the main entry point for creating DOT graphs. Returns a Subgraph
    configured as a digraph that can be populated with nodes and edges.
    
    Args:
        **attr: Graph-level attributes (e.g., label="My Graph", fontsize=12)
        
    Returns:
        A Subgraph instance configured as a digraph
    """
    name = "G"
    return Subgraph("digraph", name, **attr)


def createGraphic(g, name, format="png"):
    """
    Create a graphic file from a graph by generating DOT and compiling it.
    
    First creates a .dot file, then compiles it to the specified image format
    using Graphviz's dot tool.
    
    Args:
        g: Subgraph instance to render
        name: Base name for output files (without extension)
        format: Output image format (e.g., "png", "svg", "pdf")
    """
    dotfile = name + ".dot"
    g.createDotFile(dotfile)
    compileDotFile(name, format)


def compileDotFile(name, format):
    """
    Compile a DOT file to an image using Graphviz.
    
    Note: This function currently hardcodes the Windows path to Graphviz.
    For cross-platform use, the dot executable should be located via PATH
    or a configurable setting.
    
    Args:
        name: Base name of the DOT file (without .dot extension)
        format: Output image format (e.g., "png", "svg", "pdf")
    """
    dotfile = name + ".dot"
    imagefile = name + "." + format
    dot = r"c:\Program Files\ATT\Graphviz\bin\dot.exe"
    # dot = r'c:\Program Files\ATT\Graphviz\bin\neato.exe'

    options = ["-T" + format, "-o" + imagefile, dotfile]
    cmd = ('"%s" ' % dot) + " ".join(options)
    status = os.system(cmd)


if __name__ == "__main__":
    import sys

    boxish = Style(shape="box")
    dotted = Style(style="dotted", color="red")

    g = Digraph("G", edgetype=dotted)
    c1 = g.cluster("sg1")
    c1.node("n1", nodetype=boxish, label="!!!!")
    c1.node("n2")

    c2 = g.cluster("sg2")
    c2.node("n3")
    c2.node("n4")

    g.edge("n1", "n2", "n3", "n4", label="n")

    g.createDotFile(sys.stdout)

    createGraphic(g, "test")
