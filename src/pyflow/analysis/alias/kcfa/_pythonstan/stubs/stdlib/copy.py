def copy(obj):
    new = obj.__class__()
    new.__dict__ = obj.__dict__
    return new


def deepcopy(obj, memo=None):
    new = obj.__class__()
    new.__dict__ = {}
    for k, v in obj.__dict__.items():
        new.__dict__[k] = deepcopy(v, memo)
    return new


Error = Exception
