def beConfused(flag):
    """Test type confusion with boolean flag."""
    if flag:
        return 1
    else:
        return 0


def beConfusedSite(flag):
    """Test type confusion at a specific site."""
    if flag:
        return True
    else:
        return False


def beConfusedConst(value):
    """Test type confusion with constant values."""
    if value > 0:
        return value
    elif value == 0:
        return 0
    else:
        return -value


def confuseMethods(a, b, c, d, e, f):
    """Test method confusion with multiple integer parameters."""
    result = a + b - c * d + e - f
    return result
