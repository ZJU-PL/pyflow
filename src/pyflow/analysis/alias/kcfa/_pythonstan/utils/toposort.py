from collections import deque, Counter, defaultdict


def topo_adj_list(adj_list):
    """
    adj_list: [[v1,v2,…], …]  # index = source vertex
    returns: list in topological order
    raises:  CycleError if the graph is not a DAG
    """
    n = len(adj_list)
    g = {u: vs for u, vs in enumerate(adj_list)}
    indeg = Counter()
    for u in g:
        indeg[u] += 0               # make sure every node is in the map
    for u, vs in g.items():
        for v in vs:
            indeg[v] += 1

    q = deque([u for u in range(n) if indeg[u] == 0])
    order = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in g[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    if len(order) != n:
        raise CycleError("Graph contains at least one directed cycle")
    return order


def topo_edges(edges, *, n=None):
    """
    edges: list of edges [(u, v), ...]
    returns: list of topological order
    raises:  CycleError if the graph is not a DAG
    """
    if n is None:
        n = max(max(e) for e in edges) + 1 if edges else 0

    g = defaultdict(list)
    indeg = [0] * n
    for u, v in edges:
        g[u].append(v)
        indeg[v] += 1

    q = deque([v for v in range(n) if indeg[v] == 0])
    order = []
    while q:
        u = q.popleft()
        order.append(u)
        for v in g[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)

    if len(order) != n:
        raise CycleError("Graph contains at least one directed cycle")
    return order


class CycleError(ValueError): pass