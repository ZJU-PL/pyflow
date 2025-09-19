def reverseDirectedGraph(G):
    out = {}
    for node, nexts in G.items():
        for next in nexts:
            if next not in out:
                out[next] = [node]
            else:
                out[next].append(node)
    return out


def findEntryPoints(G):
    entryPoints = set(G.keys())
    for nexts in G.values():
        for next in nexts:
            if next in entryPoints:
                entryPoints.remove(next)
    return list(entryPoints)
