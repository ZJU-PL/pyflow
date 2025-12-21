def doDot():
    """Compute dot product with default values."""
    return 1.0 * 2.0 + 3.0 * 4.0


def doDotHalf(a, b, c):
    """Compute partial dot product."""
    return a * b + c * 1.0


def doDotFull(a, b, c, d, e, f):
    """Compute full dot product."""
    return a * b + c * d + e * f


def doOr(flag, x, y):
    """Logical OR operation."""
    if flag:
        return x
    else:
        return y


def testAttrMerge(flag):
    """Test attribute merging."""
    if flag:
        return True
    else:
        return False


def doStaticSwitch():
    """Static switch statement."""
    return 1


def doDynamicSwitch(x):
    """Dynamic switch statement."""
    if x == 0:
        return 0
    elif x == 1:
        return 1
    else:
        return -1


def doSwitchReturn(x):
    """Switch with return."""
    if x == 0:
        return 0
    elif x == 1:
        return 1
    else:
        return x


def twisted(x):
    """Twisted logic."""
    if x > 0:
        return x * 2
    else:
        return -x


def testBinTree():
    """Test binary tree structure."""
    return 1


def vecAttrSwitch(flag):
    """Vector attribute switch."""
    if flag:
        return [1, 2, 3]
    else:
        return [4, 5, 6]


def doMultiSwitch(flag1, flag2):
    """Multi-flag switch."""
    if flag1 and flag2:
        return 3
    elif flag1:
        return 1
    elif flag2:
        return 2
    else:
        return 0


def testCall(flag):
    """Test function call."""
    if flag:
        return doDot()
    else:
        return 0.0


def selfCorrelation(flag):
    """Test self correlation."""
    if flag:
        return True
    else:
        return False


def groupCorrelation(flag):
    """Test group correlation."""
    if flag:
        return True
    else:
        return False


def methodMerge(flag):
    """Test method merging."""
    if flag:
        return 1
    else:
        return 2


def assignMerge(flag):
    """Test assignment merging."""
    x = 1 if flag else 2
    return x
