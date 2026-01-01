# Security checker utilities
import ast
import logging
import os.path
import sys

LOG = logging.getLogger(__name__)


def _get_attr_qual_name(node, aliases):
    """Get the full name for the attribute node"""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    elif isinstance(node, ast.Attribute):
        name = f"{_get_attr_qual_name(node.value, aliases)}.{node.attr}"
        return aliases.get(name, name)
    return ""


def get_call_name(node, aliases):
    """Get the qualified name of a function call"""
    if isinstance(node.func, ast.Name):
        func_id = deepgetattr(node, "func.id")
        return aliases.get(func_id, func_id)
    elif isinstance(node.func, ast.Attribute):
        return _get_attr_qual_name(node.func, aliases)
    return ""


def get_func_name(node):
    """Get function name"""
    return node.name


def get_qual_attr(node, aliases):
    """Get qualified attribute name"""
    if not isinstance(node, ast.Attribute):
        return ""
    try:
        val = deepgetattr(node, "value.id")
        prefix = aliases.get(val, val)
    except Exception:
        prefix = ""
    return f"{prefix}.{node.attr}"


def deepgetattr(obj, attr):
    """Recursively get attribute through chain"""
    for key in attr.split("."):
        obj = getattr(obj, key)
    return obj


class InvalidModulePath(Exception):
    pass


def get_module_qualname_from_path(path):
    """Get the module's qualified name by analysis of the path"""
    head, tail = os.path.split(path)
    if not head or not tail:
        raise InvalidModulePath(
            f'Invalid python file path: "{path}" Missing path or file name'
        )

    qname = [os.path.splitext(tail)[0]]
    while head not in ["/", ".", ""]:
        if os.path.isfile(os.path.join(head, "__init__.py")):
            head, tail = os.path.split(head)
            qname.insert(0, tail)
        else:
            break
    return ".".join(qname)


def namespace_path_join(base, name):
    """Extend the current namespace path with an additional name"""
    return f"{base}.{name}"


def namespace_path_split(path):
    """Split the namespace path into a pair (head, tail)"""
    return tuple(path.rsplit(".", 1))


def calc_linerange(node):
    """Calculate linerange for subtree"""
    if hasattr(node, "_bandit_linerange"):
        return node._bandit_linerange

    lines_min = 9999999999
    lines_max = -1
    if hasattr(node, "lineno"):
        lines_min = lines_max = node.lineno

    for n in ast.iter_child_nodes(node):
        lines_minmax = calc_linerange(n)
        lines_min = min(lines_min, lines_minmax[0])
        lines_max = max(lines_max, lines_minmax[1])

    node._bandit_linerange = (lines_min, lines_max)
    return (lines_min, lines_max)


def linerange(node):
    """Get line number range from a node"""
    if hasattr(node, "lineno"):
        return list(range(node.lineno, node.end_lineno + 1))

    if hasattr(node, "_bandit_linerange_stripped"):
        lines_minmax = node._bandit_linerange_stripped
        return list(range(lines_minmax[0], lines_minmax[1] + 1))

    # Strip certain attributes temporarily
    strip_attrs = ["body", "orelse", "handlers", "finalbody"]
    strip_values = {}
    for key in strip_attrs:
        if hasattr(node, key):
            strip_values[key] = getattr(node, key)
            setattr(node, key, [])

    lines_min = 9999999999
    lines_max = -1
    if hasattr(node, "lineno"):
        lines_min = lines_max = node.lineno

    for n in ast.iter_child_nodes(node):
        lines_minmax = calc_linerange(n)
        lines_min = min(lines_min, lines_minmax[0])
        lines_max = max(lines_max, lines_minmax[1])

    # Restore stripped attributes
    for key, value in strip_values.items():
        setattr(node, key, value)

    if lines_max == -1:
        lines_min, lines_max = 0, 1

    node._bandit_linerange_stripped = (lines_min, lines_max)
    lines = list(range(lines_min, lines_max + 1))

    # Handle multiline strings
    if hasattr(node, "_bandit_sibling") and hasattr(node._bandit_sibling, "lineno"):
        start = min(lines)
        delta = node._bandit_sibling.lineno - start
        if delta > 1:
            return list(range(start, node._bandit_sibling.lineno))
    return lines


def check_ast_node(name):
    """Check if the given name is that of a valid AST node"""
    try:
        node = getattr(ast, name)
        if issubclass(node, ast.AST):
            return name
    except AttributeError:
        pass
    raise TypeError(f"Error: {name} is not a valid node type in AST")


def get_nosec(nosec_lines, context):
    """Get nosec comments for a context"""
    for lineno in context["linerange"]:
        if lineno in nosec_lines:
            return nosec_lines[lineno]
    return None
