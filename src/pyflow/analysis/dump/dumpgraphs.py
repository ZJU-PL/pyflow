import os.path
import pyflow.util as util
import pyflow.util.pydot as pydot
from pyflow.util.graphalgorithim import dominator
from pyflow.util.application.async_utils import *
from pyflow.util.io import filesystem
from pyflow.analysis.dump import dumputil


def dumpGraph(directory, name, format, g, prog="dot"):
    s = g.create(prog=prog, format=format)
    filesystem.writeBinaryData(directory, name, format, s)


@async_limited
def dump(compiler, liveInvoke, links, reportDir):
    from pyflow.ir.core import index_program

    catalog = index_program(compiler.program)

    def graph_id(code):
        return "entry" if code is None else str(catalog.procedure(code).code_id)

    def sort_key(code):
        return graph_id(code)

    # Filter out primitive nodes
    def keepCode(code):
        return code is None or not code.annotation.primitive

    head = None
    invokeLUT = {}
    for src, dst in liveInvoke.items():
        if keepCode(src):
            invokeLUT[src] = [code for code in dst if keepCode(code)]

    # Make dominator tree
    tree, idoms = util.graphalgorithim.dominator.dominatorTree(invokeLUT, head)

    # Start graph creation
    g = pydot.Dot(
        graph_type="digraph",
        # overlap='scale',
        rankdir="LR",
        # concentrate=True,
    )

    # Create nodes
    def makeNode(tree, sg, node):
        if node is not None:
            code = node

            if not code.isStandardCode():
                nodecolor = "#4444FF"
            elif code.annotation.descriptive:
                nodecolor = "#FF3333"
            elif code.codeparameters.selfparam is None:
                nodecolor = "#BBBBBB"
            else:
                nodecolor = "#33FF33"
            sg.add_node(
                pydot.Node(
                    graph_id(node),
                    label=dumputil.codeShortName(code),
                    shape="box",
                    style="filled",
                    fontsize=8,
                    fillcolor=nodecolor,
                    URL=links.codeRef(node, None),
                )
            )
        else:
            sg.add_node(
                pydot.Node(
                    graph_id(node),
                    label="entry",
                    shape="point",
                    style="filled",
                    fontsize=8,
                )
            )

        children = tree.get(node)
        if children:
            csg = pydot.Cluster(f"cluster_{graph_id(node)}")
            sg.add_subgraph(csg)
            for child in sorted(children, key=sort_key):
                makeNode(tree, csg, child)

    makeNode(tree, g, head)

    # Create edges
    for src, dsts in sorted(invokeLUT.items(), key=lambda item: sort_key(item[0])):
        # if src is head: continue
        for dst in sorted(dsts, key=sort_key):
            if idoms.get(dst) is src:
                weight = 10
            else:
                weight = 1
            g.add_edge(pydot.Edge(graph_id(src), graph_id(dst), weight=weight))

    # Output
    dumpGraph(reportDir, "invocations", "svg", g)
