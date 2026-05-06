# Faithful recreation of fixed code pattern from black bug 14
# Key patterns:
# 1. Nested generator function with yield/yield from
# 2. isinstance() type checks as guards  
# 3. assert False in else branch (defensive assertion)
# 4. assert isinstance(...) as validation

from typing import Set, List, Generator

class Leaf:
    def __init__(self, type_val, value):
        self.type = type_val
        self.value = value

class Node:
    def __init__(self, type_val, children):
        self.type = type_val
        self.children = children

NAME = 1
import_as_name = 256
import_as_names = 257
simple_stmt = 300

def get_future_imports(node: Node) -> Set[str]:
    """Return a set of __future__ imports in the file."""
    imports: Set[str] = set()

    def get_imports_from_children(children: List) -> Generator[str, None, None]:
        for child in children:
            if isinstance(child, Leaf):
                if child.type == NAME:
                    yield child.value
            elif child.type == import_as_name:
                orig_name = child.children[0]
                assert isinstance(orig_name, Leaf), "Invalid syntax parsing imports"
                assert orig_name.type == NAME, "Invalid syntax parsing imports"
                yield orig_name.value
            elif child.type == import_as_names:
                yield from get_imports_from_children(child.children)
            else:
                assert False, "Invalid syntax parsing imports"

    for child in node.children:
        if child.type != simple_stmt:
            break
        first_child = child.children[0]
        if hasattr(first_child, 'children') and len(first_child.children) > 3:
            module_name = first_child.children[1]
            if not isinstance(module_name, Leaf) or module_name.value != "__future__":
                break
            imports |= set(get_imports_from_children(first_child.children[3:]))
        else:
            break
    return imports
