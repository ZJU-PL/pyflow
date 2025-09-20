
from pyflow.util.typedispatch import *
from pyflow.language.python import ast
from pyflow.analysis.cfg import graph as cfg
from pyflow.analysis.cfg.dfs import CFGDFS
from pyflow.util.graphalgorithim.merge import serializeMerges


class Expander(TypeDispatcher):
    @defaultdispatch
    def default(self, node):
        pass

    def createTemp(self, node):
        return node.clone()

    @dispatch(cfg.Merge)
    def visitMerge(self, node):
        if node.phi:
            for i, (prev, prevName) in enumerate(node.iterprev()):
                transfer = [
                    (phi.arguments[i], phi.target)
                    for phi in node.phi
                    if phi.arguments[i] is not None
                ]
                if not transfer:
                    continue

                # HACK can't handle pushing assignments up into exceptions?
                assert prevName in ("normal", "true", "false", "entry"), prevName

                transfer, temps = serializeMerges(transfer, self.createTemp)

                stmts = [ast.Assign(src, [dst]) for src, dst in transfer]

                suite = cfg.Suite(prev.region)
                suite.ops = stmts

                prev.insertAtExit(prevName, suite, "normal")

            node.phi = []


def evaluate(compiler, g):
    ex = Expander()
    CFGDFS(post=ex).process(g.entryTerminal)
