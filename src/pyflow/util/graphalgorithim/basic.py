"""
Basic graph operations for directed graphs.

This module provides fundamental graph algorithms used throughout pyflow for
analyzing control flow graphs and other directed graph structures.
"""


def reverseDirectedGraph(G):
    """
    Reverse the direction of all edges in a directed graph.

    Given a graph G where G[node] returns an iterable of successor nodes,
    returns a new graph where all edges are reversed (predecessors become
    successors and vice versa).

    Parameters
    ----------
    G : dict
        A directed graph represented as a dictionary mapping nodes to
        iterables of successor nodes. Format: {node: [successor1, successor2, ...]}

    Returns
    -------
    dict
        A new graph with all edges reversed. Format: {node: [predecessor1, predecessor2, ...]}

    Examples
    --------
    >>> G = {1: [2, 3], 2: [3], 3: []}
    >>> reverseDirectedGraph(G)
    {2: [1], 3: [1, 2]}
    """
    out = {}
    for node, nexts in G.items():
        for next in nexts:
            if next not in out:
                out[next] = [node]
            else:
                out[next].append(node)
    return out


def findEntryPoints(G):
    """
    Find all entry points (nodes with no incoming edges) in a directed graph.

    Entry points are nodes that are not reachable from any other node via
    a directed path. These typically represent starting points or external
    entry points in control flow graphs.

    Parameters
    ----------
    G : dict
        A directed graph represented as a dictionary mapping nodes to
        iterables of successor nodes. Format: {node: [successor1, successor2, ...]}

    Returns
    -------
    list
        A list of all entry point nodes (nodes with no predecessors).

    Examples
    --------
    >>> G = {1: [2, 3], 2: [3], 3: []}
    >>> findEntryPoints(G)
    [1]
    >>> G = {1: [2], 2: [1]}  # Cycle
    >>> findEntryPoints(G)
    [1, 2]  # Both are entry points since neither is listed as a successor
    """
    entryPoints = set(G.keys())
    for nexts in G.values():
        for next in nexts:
            if next in entryPoints:
                entryPoints.remove(next)
    return list(entryPoints)
