"""Inter-procedural Analysis (IPA) for PyFlow.

This package provides inter-procedural analysis capabilities that perform
context-sensitive analysis across function boundaries, enabling precise
modeling of function calls and returns in Python programs.
"""

from pyflow.analysis.cpa import simpleimagebuilder
from .entrypointbuilder import buildEntryPoint
from .dump import Dumper

from .ipanalysis import IPAnalysis

from .memory.extractorpolicy import ExtractorPolicy
from .memory.storegraphpolicy import DefaultStoreGraphPolicy


def dumpAnalysisResults(analysis):
    """Dump IPA analysis results to files.
    
    Args:
        analysis: IPAnalysis object containing analysis results.
    """
    dumper = Dumper("summaries/ipa")

    dumper.index(analysis.contexts.values(), analysis.root)

    for context in analysis.contexts.values():
        dumper.dumpContext(context)


def evaluateWithImage(compiler, prgm):
    """Run IPA analysis with existing store graph image.
    
    Args:
        compiler: Compiler context for the analysis.
        prgm: Program object to analyze.
        
    Returns:
        Result of the IPA analysis.
    """
    with compiler.console.scope("ipa analysis"):
        analysis = IPAnalysis(
            compiler,
            prgm.storeGraph.canonical,
            ExtractorPolicy(compiler.extractor),
            DefaultStoreGraphPolicy(prgm.storeGraph),
        )
        analysis.trace = True

        for ep, args in prgm.entryPoints:
            buildEntryPoint(analysis, ep, args)

        for i in range(5):
            analysis.topDown()
            analysis.bottomUp()

        print("%5d code" % len(analysis.liveCode))
        print("%5d contexts" % len(analysis.contexts))
        print("%.2f ms decompile" % (analysis.decompileTime * 1000.0))

    with compiler.console.scope("ipa dump"):
        dumpAnalysisResults(analysis)


def evaluate(compiler, prgm):
    """Run complete IPA analysis including store graph construction.
    
    Args:
        compiler: Compiler context for the analysis.
        prgm: Program object to analyze.
        
    Returns:
        Result of the IPA analysis.
    """
    simpleimagebuilder.build(compiler, prgm)
    result = evaluateWithImage(compiler, prgm)
    return result
