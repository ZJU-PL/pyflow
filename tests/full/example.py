def f():
    """Simple function for basic testing."""
    return 42


def add(a, b):
    """Add two numbers."""
    return a + b


def call(a, b, c, d):
    """Call with four float parameters."""
    return a + b + c + d


def either(a, b):
    """Return either a or b based on condition."""
    if a > 0:
        return a
    else:
        return b


def inrange(x):
    """Check if x is in range [0, 1]."""
    return 0.0 <= x <= 1.0


def negate(x):
    """Negate an integer."""
    return -x


def negateConst():
    """Negate a constant."""
    return -7


def defaultArgs(a=1, b=2):
    """Function with default arguments."""
    if a is None:
        a = 1
    if b is None:
        b = 2
    return a + b


def switch1(x):
    """Switch statement variant 1."""
    if x < 0.0:
        return -1.0
    elif x == 0.0:
        return 0.0
    else:
        return 1.0


def switch2(x):
    """Switch statement variant 2."""
    if x < -0.5:
        return -2.0
    elif x < 0.5:
        return 0.0
    else:
        return 2.0
