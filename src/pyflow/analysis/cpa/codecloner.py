"""Code cloning utilities for CPA annotation phase.

This module provides utilities for cloning code objects before annotation. Cloning
is necessary because annotations modify the AST in place, and we may want to
preserve the original code or create separate annotated versions.

The cloning process:
1. Creates shallow copies of code objects
2. Deep copies AST nodes (locals, operations) as they are traversed
3. Maintains mappings from original to cloned nodes
4. Preserves structure while allowing independent annotation

Key classes:
- FunctionCloner: Performs deep cloning of code and AST nodes
- NullCloner: No-op cloner that returns originals (for when cloning isn't needed)
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast


def createCodeMap(liveCode):
    """Create initial mapping from original code to cloned code.
    
    This creates shallow copies of code objects. The deep copying of AST nodes
    happens later during traversal via replaceChildren().
    
    Args:
        liveCode: Set or iterable of code objects to clone
        
    Returns:
        Dictionary mapping original code -> cloned code
    """
    codeMap = {}
    for code in liveCode:
        # This is a shallow copy.  A deep copy will be done later.
        cloned = code.clone()
        codeMap[code] = cloned
    return codeMap


# Note that this cloner does NOT modify annotations, which means any
# invocation annotations will still point to the uncloned code.
# This is OK, however, as this cloning transform is designed to happen
# right before the annotations are rewritten.
class FunctionCloner(TypeDispatcher):
    """Clones code objects and their AST nodes for annotation.
    
    This cloner creates deep copies of code objects and their AST nodes, maintaining
    mappings from original to cloned nodes. This allows annotations to be added to
    the cloned code without modifying the original.
    
    The cloning process:
    1. Creates shallow code copies in __init__
    2. Deep copies AST nodes during traversal via process()
    3. Maintains mappings for code, locals, and operations
    
    Note: Annotations are NOT cloned - they are added fresh to cloned nodes.
    This is intentional as cloning happens right before annotation rewriting.
    
    Attributes:
        codeMap: Dictionary mapping original code -> cloned code
        localMap: Dictionary mapping original local -> cloned local (per code)
        opMap: Dictionary mapping original operation -> cloned operation (per code)
    """
    def __init__(self, liveCode):
        """Initialize the cloner with code objects to clone.
        
        Args:
            liveCode: Set or iterable of code objects to clone
        """
        self.codeMap = createCodeMap(liveCode)

    @dispatch(ast.Local)
    def visitLocal(self, node):
        """Clone a local variable node.
        
        Creates a clone if not already cloned, otherwise returns existing clone.
        Uses localMap to ensure each local is cloned only once per code.
        
        Args:
            node: Original Local AST node
            
        Returns:
            Cloned Local AST node
        """
        if not node in self.localMap:
            lcl = node.clone()
            self.localMap[node] = lcl
        else:
            lcl = self.localMap[node]
        return lcl

    @dispatch(ast.Code)
    def visitCode(self, node):
        """Get cloned code object.
        
        Returns the cloned code from codeMap. If code wasn't in liveCode,
        returns None (handles dead direct calls).
        
        Args:
            node: Original Code AST node
            
        Returns:
            Cloned Code AST node, or None if not in codeMap
        """
        # We may encounter dead direct calls that specify an uncloned target.
        # Return None in this case.
        return self.codeMap.get(node)

    @dispatch(ast.leafTypes)
    def visitLeaf(self, node):
        """Handle leaf AST nodes (no cloning needed).
        
        Leaf nodes (constants, etc.) are immutable and don't need cloning.
        
        Args:
            node: Leaf AST node
            
        Returns:
            Original node (no clone needed)
        """
        return node

    @defaultdispatch
    def default(self, node):
        """Default handler for AST nodes.
        
        Clones non-shared nodes by calling rewriteCloned, which recursively
        clones children. Stores mapping in opMap.
        
        Args:
            node: AST node to clone
            
        Returns:
            Cloned AST node
            
        Raises:
            AssertionError: If node is shared (shouldn't be cloned)
        """
        assert not node.__shared__, type(node)
        result = node.rewriteCloned(self)
        self.opMap[node] = result  # TODO this included a lot of non-op junk.
        return result

    def process(self, code):
        """Process a code object to clone its AST nodes.
        
        Initializes per-code mappings and traverses the code's AST to clone
        all nodes. After this, localMap and opMap contain mappings for this code.
        
        Args:
            code: Original code object to process
        """
        self.localMap = {}
        self.opMap = {}

        newcode = self.codeMap[code]
        newcode.replaceChildren(self)

    def op(self, op):
        """Get cloned operation node.
        
        Args:
            op: Original operation node
            
        Returns:
            Cloned operation node
        """
        return self.opMap[op]

    def lcl(self, lcl):
        """Get cloned local variable node.
        
        Args:
            lcl: Original local variable node
            
        Returns:
            Cloned local variable node
        """
        return self.localMap[lcl]

    def code(self, code):
        """Get cloned code object.
        
        Args:
            code: Original code object
            
        Returns:
            Cloned code object
        """
        return self.codeMap[code]


# Same interface, no cloning performed.
class NullCloner(object):
    """No-op cloner that returns original nodes unchanged.
    
    This cloner provides the same interface as FunctionCloner but performs
    no cloning. Used when cloning is not needed (e.g., when annotations can
    be added directly to original code).
    
    All methods return the original nodes unchanged.
    """
    def __init__(self, liveCode):
        """Initialize null cloner (no-op).
        
        Args:
            liveCode: Ignored (no cloning performed)
        """
        pass

    def process(self, code):
        """Process code (no-op).
        
        Args:
            code: Ignored
        """
        pass

    def op(self, op):
        """Return original operation unchanged.
        
        Args:
            op: Original operation node
            
        Returns:
            Original operation node
        """
        return op

    def lcl(self, lcl):
        """Return original local unchanged.
        
        Args:
            lcl: Original local variable node
            
        Returns:
            Original local variable node
        """
        return lcl

    def code(self, code):
        """Return original code unchanged.
        
        Args:
            code: Original code object
            
        Returns:
            Original code object
        """
        return code
