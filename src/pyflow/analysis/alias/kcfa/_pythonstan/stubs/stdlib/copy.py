def copy(obj):
    # A may-analysis can treat a shallow copy as aliasing the original
    # reachable objects.  Returning ``obj`` avoids an unresolved
    # ``obj.__class__()`` call while preserving all element/field flow.
    return obj


def deepcopy(obj, memo=None):
    # Deep copies introduce fresh nested identities.  Treating them as the
    # original values is a conservative may-alias approximation; the solver
    # still marks the call incomplete through its native effect summary.
    return obj


Error = Exception
