"""
Graph coloring algorithm for undirected graphs.

This module implements a greedy graph coloring algorithm that assigns colors
to nodes such that no two adjacent nodes share the same color. The algorithm
uses a heuristic that prioritizes nodes with the most remaining uncolored
neighbors.
"""

import collections


def colorGraph(G):
    """
    Color an undirected graph using a greedy algorithm with a degree-based heuristic.

    The algorithm colors nodes one at a time, always choosing the node with
    the most remaining uncolored neighbors. For each node, it assigns the
    lowest-numbered color that is not used by any of its neighbors.

    Parameters
    ----------
    G : dict
        An undirected graph represented as a dictionary mapping nodes to
        iterables of adjacent nodes. The graph must be symmetric: if a in G[b],
        then b must be in G[a]. Format: {node: [neighbor1, neighbor2, ...]}

    Returns
    -------
    tuple of (dict, list, int)
        A 3-tuple containing:
        - solution (dict): Mapping from nodes to their assigned color numbers
        - group (list): List of lists, where group[color] contains all nodes
          with that color
        - numColors (int): The total number of colors used

    Notes
    -----
    The algorithm uses a greedy heuristic that selects nodes with maximum
    remaining uncolored neighbors. This is a heuristic approach and does not
    guarantee optimal coloring (minimum number of colors), but typically
    produces reasonable results efficiently.

    Examples
    --------
    >>> # Simple path graph: 1-2-3
    >>> G = {1: [2], 2: [1, 3], 3: [2]}
    >>> solution, group, numColors = colorGraph(G)
    >>> numColors  # Can be colored with 2 colors
    2
    >>> # Complete graph of 3 nodes: requires 3 colors
    >>> G = {1: [2, 3], 2: [1, 3], 3: [1, 2]}
    >>> solution, group, numColors = colorGraph(G)
    >>> numColors
    3
    """
    solution = {}
    numColors = 0
    constraint = collections.defaultdict(set)  # Maps node -> set of forbidden colors
    group = []  # List of color groups: group[color] = [nodes with this color]

    pending = set()  # Nodes that haven't been colored yet
    remaining = {}  # Maps node -> number of uncolored neighbors

    # Initialize: all nodes are pending, count neighbors for each node
    for node, values in G.items():
        remaining[node] = len(values)
        pending.add(node)

    while pending:
        # Select the next node to color using a greedy heuristic:
        # choose the node with the maximum number of remaining uncolored neighbors.
        # This heuristic helps constrain future choices and often leads to
        # better (fewer color) solutions.
        maxRemain = -1
        maxNode = None
        for node in pending:
            if remaining[node] > maxRemain:
                maxNode = node
                maxRemain = remaining[node]
        assert maxNode is not None
        pending.remove(maxNode)

        # Determine the color for the selected node: find the lowest-numbered
        # color that is not forbidden (i.e., not used by any neighbor)
        current = maxNode
        for color in range(numColors):
            if color not in constraint[current]:
                break
        else:
            # All existing colors are forbidden, need a new color
            color = numColors
            numColors += 1
            group.append([])

        # Assign the color to the node
        solution[current] = color
        group[color].append(current)
        # Update constraints for neighbors: they cannot use this color
        for other in G[current]:
            remaining[other] -= 1  # One fewer uncolored neighbor
            constraint[other].add(color)  # This color is now forbidden

    return solution, group, numColors
