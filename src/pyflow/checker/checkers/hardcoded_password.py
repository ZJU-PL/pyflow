# Check for hardcoded passwords
import ast
import re

from ..core import issue
from ..core import test_properties as test

RE_WORDS = "(pas+wo?r?d|pass(phrase)?|pwd|token|secrete?)"
RE_CANDIDATES = re.compile(f"(^{RE_WORDS}$|_{RE_WORDS}_|^{RE_WORDS}_|_{RE_WORDS}$)", re.IGNORECASE)


def _get_string(node):
    """Extract a string value from ast.Str or ast.Constant(str)."""
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _report(value):
    """Create a hardcoded password issue"""
    return issue.Issue(
        severity="LOW",
        confidence="MEDIUM",
        cwe=issue.Cwe.HARD_CODED_PASSWORD,
        text=f"Possible hardcoded password: '{value}'",
    )


@test.checks("Str")
@test.with_id("B105")
def hardcoded_password_string(context):
    """Check for hardcoded password strings"""
    node = context.node
    parent = getattr(node, '_bandit_parent', None)
    node_str = _get_string(node)
    if node_str is None:
        return None
    
    if isinstance(parent, ast.Assign):
        # Look for "candidate='some_string'"
        for targ in parent.targets:
            if isinstance(targ, ast.Name) and RE_CANDIDATES.search(targ.id):
                return _report(node_str)
            elif isinstance(targ, ast.Attribute) and RE_CANDIDATES.search(targ.attr):
                return _report(node_str)

    elif isinstance(parent, ast.Subscript) and RE_CANDIDATES.search(node_str):
        # Look for "dict[candidate]='some_string'"
        grandparent = getattr(parent, '_bandit_parent', None)
        if isinstance(grandparent, ast.Assign):
            value_str = _get_string(grandparent.value)
            if value_str is not None:
                return _report(value_str)

    elif isinstance(parent, ast.Compare):
        # Look for "candidate == 'some_string'"
        left = parent.left
        if isinstance(left, (ast.Name, ast.Attribute)) and RE_CANDIDATES.search(left.id if isinstance(left, ast.Name) else left.attr):
            if parent.comparators:
                comp_str = _get_string(parent.comparators[0])
                if comp_str is not None:
                    return _report(comp_str)


@test.checks("Call")
@test.with_id("B106")
def hardcoded_password_funcarg(context):
    """Check for hardcoded password function arguments"""
    # Look for "function(candidate='some_string')"
    for kw in context.node.keywords:
        val_str = _get_string(kw.value)
        if val_str is not None and RE_CANDIDATES.search(kw.arg):
            return _report(val_str)


@test.checks("FunctionDef")
@test.with_id("B107")
def hardcoded_password_default(context):
    """Check for hardcoded password argument defaults"""
    # Look for "def function(candidate='some_string')"
    defs = [None] * (
        len(context.node.args.args) - len(context.node.args.defaults)
    )
    defs.extend(context.node.args.defaults)

    # Go through all (param, value)s and look for candidates
    for key, val in zip(context.node.args.args, defs):
        if isinstance(key, (ast.Name, ast.arg)):
            # Skip if the default value is None
            if val is None or (
                isinstance(val, (ast.Constant, ast.NameConstant))
                and val.value is None
            ):
                continue
            val_str = _get_string(val)
            if val_str is not None and RE_CANDIDATES.search(key.arg):
                return _report(val_str)
