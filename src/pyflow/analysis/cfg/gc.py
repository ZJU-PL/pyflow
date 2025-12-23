"""Garbage collection for unreachable CFG nodes.

This module removes unreachable CFG nodes and cleans up predecessor
links in merge blocks. After CFG transformations, some blocks may
become unreachable from the entry point. This pass:

1. Identifies all reachable nodes via DFS from entry
2. Removes unreachable predecessors from merge blocks
3. Cleans up the CFG structure

This is important for maintaining CFG integrity after optimizations
that may create unreachable code.
"""

from pyflow.util.typedispatch import *
from pyflow.analysis.cfg import graph as cfg
from pyflow.analysis.cfg.dfs import CFGDFS

# Kills unreachable CFG nodes


class Logger(TypeDispatcher):
    """Collects merge blocks during CFG traversal.
    
    This class is used to identify all merge blocks in the CFG so
    their predecessor lists can be cleaned up.
    
    Attributes:
        merges: List of merge blocks found during traversal
    """
    def __init__(self):
        """Initialize the logger."""
        self.merges = []

    @defaultdispatch
    def default(self, node):
        """Default handler (no action for most nodes).
        
        Args:
            node: CFG node (ignored)
        """
        pass

    @dispatch(cfg.MultiEntryBlock)
    def visitMerge(self, node):
        """Record merge blocks.
        
        Args:
            node: Merge block to record
        """
        self.merges.append(node)


def evaluate(compiler, g):
    """Remove unreachable CFG nodes and clean up merge blocks.
    
    Performs garbage collection on the CFG by:
    1. Finding all reachable nodes via DFS
    2. Removing unreachable predecessors from merge blocks
    3. Cleaning up CFG structure
    
    Args:
        compiler: Compiler context (unused, kept for interface consistency)
        g: CFG Code object to clean up
        
    Note:
        HACK: This exposes internals of merge blocks (_prev) to clean them up.
        Consider adding a proper API for this.
    """
    logger = Logger()
    dfs = CFGDFS(post=logger)
    dfs.process(g.entryTerminal)

    def live(node):
        """Check if a node is reachable from entry.
        
        Args:
            node: CFG node to check
            
        Returns:
            bool: True if node is reachable
        """
        return node in dfs.processed

    for merge in logger.merges:
        for prev in merge._prev:
            assert isinstance(prev, tuple), merge._prev

        # HACK exposes the internals of merge
        # Filter out unreachable predecessors
        filtered = [prev for prev in merge._prev if live(prev[0])]
        merge._prev = filtered
