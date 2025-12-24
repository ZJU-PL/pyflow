"""
Blacklist Checker for Module Imports.

This module provides security tests that check module imports against
a blacklist of dangerous modules. The blacklist includes modules known
to have security implications such as:
- Deserialization modules (pickle, cPickle, dill, shelve)
- Insecure protocols (telnetlib, ftplib)
- Vulnerable XML parsers (xml.etree, xml.sax, xml.dom)
- Weak cryptography (pyCrypto)
- And more...

**Test ID Range:** B401-B415

**Import Types:**
- Import: `import module` statements
- ImportFrom: `from module import name` statements
"""

# Blacklist checker for imports
import ast

from ..core import blacklist
from ..core import test_properties as test


@test.checks("Import")
@test.with_id("B401-B415")
def check_blacklisted_imports(context):
    """
    Check for blacklisted module imports.
    
    Checks all imported module names in an Import statement against
    the import blacklist. Returns a list of issues if any matches are found.
    
    Args:
        context: Context object with import information
        
    Returns:
        List of Issue objects if blacklisted imports found, None otherwise
    """
    if not isinstance(getattr(context, 'node', None), ast.Import):
        return None
    
    issues = [blacklist.blacklist_manager.check_blacklist("Import", alias.name, context) 
              for alias in context.node.names]
    return [issue for issue in issues if issue] or None


@test.checks("ImportFrom")
@test.with_id("B401-B415")
def check_blacklisted_import_from(context):
    """
    Check for blacklisted from imports.
    
    Checks the module name in an ImportFrom statement against the
    import blacklist. Only checks the module, not individual imports.
    
    Args:
        context: Context object with import information
        
    Returns:
        Issue object if blacklisted module found, None otherwise
    """
    node = getattr(context, 'node', None)
    if not isinstance(node, ast.ImportFrom) or not node.module:
        return None
    
    return blacklist.blacklist_manager.check_blacklist("ImportFrom", node.module, context)
