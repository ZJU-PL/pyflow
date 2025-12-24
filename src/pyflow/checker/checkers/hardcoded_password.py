"""
Hardcoded Password Detection.

This module provides security tests that detect hardcoded passwords and
secrets in code. It uses pattern matching to identify variable names that
suggest passwords/secrets and checks if they're assigned string literals.

**Detection Patterns:**
The checker looks for variable names containing password-related keywords:
- password, passwd, passphrase
- pwd
- token
- secret, secrete

**Detection Scenarios:**
1. Variable assignment: `password = "secret123"`
2. Dictionary assignment: `config["password"] = "secret123"`
3. Comparison: `if password == "secret123"`
4. Function arguments: `login(password="secret123")`
5. Function defaults: `def login(password="secret123")`

**Test IDs:**
- B105: Hardcoded password in string assignment
- B106: Hardcoded password in function arguments
- B107: Hardcoded password in function defaults
"""

# Check for hardcoded passwords
import ast
import re

from ..core import issue
from ..core import test_properties as test

# Regular expression for password-related keywords
RE_WORDS = "(pas+wo?r?d|pass(phrase)?|pwd|token|secrete?)"
# Pattern matches: start, end, or anywhere in variable name (case-insensitive)
RE_CANDIDATES = re.compile(f"(^{RE_WORDS}$|_{RE_WORDS}_|^{RE_WORDS}_|_{RE_WORDS}$)", re.IGNORECASE)


def _get_string(node):
    """
    Extract a string value from AST string nodes.
    
    Handles both Python < 3.8 (ast.Str) and Python 3.8+ (ast.Constant)
    for compatibility.
    
    Args:
        node: AST node (Str, Constant, or other)
        
    Returns:
        String value, or None if not a string node
    """
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _report(value):
    """
    Create a hardcoded password issue.
    
    Args:
        value: The hardcoded password value found
        
    Returns:
        Issue object with LOW severity, MEDIUM confidence
    """
    return issue.Issue(
        severity="LOW",
        confidence="MEDIUM",
        cwe=issue.Cwe.HARD_CODED_PASSWORD,
        text=f"Possible hardcoded password: '{value}'",
    )


@test.checks("Str")
@test.with_id("B105")
def hardcoded_password_string(context):
    """
    Check for hardcoded password strings in assignments and comparisons.
    
    Detects hardcoded passwords in:
    1. Variable assignments: `password = "secret123"`
    2. Attribute assignments: `config.password = "secret123"`
    3. Dictionary assignments: `config["password"] = "secret123"`
    4. Comparisons: `if password == "secret123"`
    
    Args:
        context: Context object with string node information
        
    Returns:
        Issue object if hardcoded password detected, None otherwise
    """
    node = context.node
    parent = getattr(node, '_bandit_parent', None)
    node_str = _get_string(node)
    if node_str is None:
        return None
    
    if isinstance(parent, ast.Assign):
        # Look for "candidate='some_string'" in variable assignments
        for targ in parent.targets:
            if isinstance(targ, ast.Name) and RE_CANDIDATES.search(targ.id):
                return _report(node_str)
            elif isinstance(targ, ast.Attribute) and RE_CANDIDATES.search(targ.attr):
                return _report(node_str)

    elif isinstance(parent, ast.Subscript) and RE_CANDIDATES.search(node_str):
        # Look for "dict[candidate]='some_string'" in dictionary assignments
        grandparent = getattr(parent, '_bandit_parent', None)
        if isinstance(grandparent, ast.Assign):
            value_str = _get_string(grandparent.value)
            if value_str is not None:
                return _report(value_str)

    elif isinstance(parent, ast.Compare):
        # Look for "candidate == 'some_string'" in comparisons
        left = parent.left
        if isinstance(left, (ast.Name, ast.Attribute)) and RE_CANDIDATES.search(left.id if isinstance(left, ast.Name) else left.attr):
            if parent.comparators:
                comp_str = _get_string(parent.comparators[0])
                if comp_str is not None:
                    return _report(comp_str)


@test.checks("Call")
@test.with_id("B106")
def hardcoded_password_funcarg(context):
    """
    Check for hardcoded password function arguments.
    
    Detects hardcoded passwords passed as keyword arguments:
    `login(password="secret123")`
    
    Args:
        context: Context object with call node information
        
    Returns:
        Issue object if hardcoded password detected, None otherwise
    """
    # Look for "function(candidate='some_string')" in keyword arguments
    for kw in context.node.keywords:
        val_str = _get_string(kw.value)
        if val_str is not None and RE_CANDIDATES.search(kw.arg):
            return _report(val_str)


@test.checks("FunctionDef")
@test.with_id("B107")
def hardcoded_password_default(context):
    """
    Check for hardcoded password argument defaults.
    
    Detects hardcoded passwords in function parameter defaults:
    `def login(password="secret123"):`
    
    Args:
        context: Context object with function definition information
        
    Returns:
        Issue object if hardcoded password detected, None otherwise
    """
    # Look for "def function(candidate='some_string')" in parameter defaults
    # Align defaults with parameters (defaults only apply to last N parameters)
    defs = [None] * (
        len(context.node.args.args) - len(context.node.args.defaults)
    )
    defs.extend(context.node.args.defaults)

    # Go through all (param, value) pairs and look for password candidates
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
