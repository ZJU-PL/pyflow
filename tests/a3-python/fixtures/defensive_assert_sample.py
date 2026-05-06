"""Sample functions for testing defensive assert False guard."""

class Leaf:
    def __init__(self, t, v):
        self.type = t
        self.value = v

NAME = 1
IMPORT_AS_NAME = 256
IMPORT_AS_NAMES = 257

def get_imports_from_children(children):
    """Defensive assert False after exhaustive isinstance/type checks."""
    for child in children:
        if isinstance(child, Leaf):
            if child.type == NAME:
                yield child.value
        elif child.type == IMPORT_AS_NAME:
            orig_name = child.children[0]
            assert isinstance(orig_name, Leaf), "Invalid syntax"
            assert orig_name.type == NAME, "Invalid syntax"
            yield orig_name.value
        elif child.type == IMPORT_AS_NAMES:
            yield from get_imports_from_children(child.children)
        else:
            assert False, "Invalid syntax parsing imports"


def bad_function(data):
    """Non-defensive assert False — should be flagged."""
    result = []
    for item in data:
        result.append(item * 2)
    assert False, "should never reach here"
    return result


def conditional_assert(x):
    """Conditional assertion — should be flagged."""
    assert x > 0, "x must be positive"
    return x * 2
