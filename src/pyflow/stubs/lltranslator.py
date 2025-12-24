"""
Low-level translator for converting stub functions to pyflow AST.

This module provides LLTranslator, which translates stub functions written
using low-level operations (load, store, allocate, etc.) into pyflow's AST
representation. The translator:

1. Resolves global names to pyflow objects
2. Translates special low-level operations to AST nodes
3. Handles descriptor operations
4. Optimizes direct calls where possible
5. Manages variable definitions and scoping

The translator is essential for converting stub functions (which use
Python-like syntax with special operations) into analyzable AST representations.
"""

from pyflow.util.typedispatch import *
from pyflow.language.python import ast

# HACK for debugging

import pyflow.optimization as optimization

# import pyflow.optimization.simplify
# import pyflow.optimization.convertboolelimination


def checkCallArgs(node, count):
    """
    Verify that a call node has exactly the specified number of arguments.
    
    Checks that the call has the correct number of positional arguments
    and no keyword, variable, or keyword-only arguments.
    
    Args:
        node: Call AST node to check
        count: Expected number of positional arguments
        
    Raises:
        AssertionError: If argument count doesn't match or extra args present
    """
    assert len(node.args) == count, node
    assert not node.kwds, node
    assert not node.vargs, node
    assert not node.kargs, node


class LLTranslator(TypeDispatcher):
    """
    Translator for converting low-level stub operations to pyflow AST.
    
    LLTranslator walks the AST of a stub function and translates special
    low-level operations (like load, store, allocate) into pyflow AST nodes.
    It also resolves global names, handles descriptor operations, and optimizes
    direct calls where possible.
    
    The translator processes stub functions that use a special syntax:
    - allocate(obj): Create a new object
    - load(obj, field): Load a field from an object
    - store(obj, field, value): Store a value to a field
    - check(obj, field): Check if a field exists
    - loadAttr/storeAttr/checkAttr: Attribute operations
    - loadDict/storeDict/checkDict: Dictionary operations
    - loadArray/storeArray/checkArray: Array operations
    - loadDescriptor/storeDescriptor: Descriptor operations
    
    Attributes:
        compiler: Compiler instance
        func: Python function being translated
        defn: Dictionary mapping AST nodes to their definitions
        specialGlobals: Set of special global names that are operations, not objects
        code: Current code object being processed
        numReturns: Number of return values (determined during translation)
    """
    def __init__(self, compiler, func):
        """
        Initialize a low-level translator.
        
        Args:
            compiler: Compiler instance with extractor and other components
            func: Python function to translate
        """
        self.compiler = compiler
        self.func = func

        # Dictionary mapping AST nodes to their definitions/resolutions
        self.defn = {}

        # Special global names that represent operations, not objects
        # These are translated to specific AST node types
        self.specialGlobals = set(
            (
                "allocate",      # Create new object
                "load",          # Load low-level field
                "store",         # Store to low-level field
                "check",         # Check low-level field existence
                "loadAttr",      # Load attribute
                "storeAttr",     # Store attribute
                "checkAttr",     # Check attribute existence
                "loadDict",      # Load dictionary item
                "storeDict",     # Store dictionary item
                "checkDict",     # Check dictionary key existence
                "loadArray",     # Load array element
                "storeArray",    # Store array element
                "checkArray",    # Check array index existence
                "loadDescriptor",  # Load via descriptor
                "storeDescriptor", # Store via descriptor
            )
        )

    def wrapPyObj(self, pyobj):
        """
        Wrap a Python object in an Existing AST node.
        
        Args:
            pyobj: Python object to wrap
            
        Returns:
            ast.Existing node representing the Python object
        """
        obj = self.compiler.extractor.getObject(pyobj)
        return ast.Existing(obj)

    def resolveGlobal(self, name):
        """
        Resolve a global name to an AST node.
        
        Looks up a global name in the function's globals, the extractor's
        name lookup table, or builtins, and returns an Existing node for it.
        
        Args:
            name: Global name to resolve
            
        Returns:
            ast.Existing node for the resolved object
        """
        glbls = self.func.__globals__

        if name in glbls:
            pyobj = glbls[name]
        elif name in self.compiler.extractor.nameLUT:
            pyobj = self.compiler.extractor.nameLUT[name]
        else:
            pyobj = __builtins__[name]

        e = self.wrapPyObj(pyobj)
        self.defn[e] = e
        return e

    def getDescriptorName(self, cls, name):
        """
        Get the unique slot name for a descriptor.
        
        Extracts a descriptor from a class and returns its unique slot name
        as an Existing node. This is used for descriptor operations.
        
        Args:
            cls: ast.Existing node representing the class
            name: ast.Existing node representing the attribute name (string)
            
        Returns:
            ast.Existing node with the unique slot name for the descriptor
        """
        assert isinstance(cls, ast.Existing)
        assert isinstance(name, ast.Existing)

        pycls = cls.object.pyobj
        pyname = name.object.pyobj

        assert isinstance(pycls, type)
        assert isinstance(pyname, str)

        desc = getattr(pycls, pyname)

        name = self.compiler.slots.uniqueSlotName(desc)
        return self.wrapPyObj(name)

    @dispatch(type(None), str)
    def visitLeaf(self, node):
        """Visit leaf nodes (pass through unchanged)."""
        return node

    @dispatch(ast.Local)
    def visitLocal(self, node):
        """
        Visit a Local variable node.
        
        If the local has been defined (mapped to an Existing node), return
        that definition. Otherwise, return the local unchanged.
        """
        defn = self.defn.get(node)
        if isinstance(defn, ast.Existing):
            return defn
        return node

    @dispatch(ast.Existing)
    def visitExisting(self, node):
        """
        Visit an Existing node.
        
        Records the node in defn dictionary and returns it unchanged.
        """
        self.defn[node] = node
        return node

    def translateName(self, name):
        """
        Translate a name to an AST node.
        
        Handles special names like "internal_self" and special globals,
        otherwise resolves as a global name.
        
        Args:
            name: Name string to translate
            
        Returns:
            AST node representing the name (Local, Existing, or string for special globals)
        """
        if name == "internal_self":
            # Special name for self parameter
            assert self.code.codeparameters.selfparam
            return self.code.codeparameters.selfparam
        elif name in self.specialGlobals:
            # Special operation name (return as string)
            return name
        else:
            # Regular global name
            return self.resolveGlobal(name)

    @dispatch(ast.GetGlobal)
    def visitGetGlobal(self, node):
        node = node.rewriteChildren(self)
        namedefn = self.defn[node.name]
        assert isinstance(namedefn, ast.Existing)
        name = namedefn.object.pyobj
        return self.translateName(name)

    @dispatch(ast.GetCellDeref)
    def visitGetGellDeref(self, node):
        name = node.cell.name
        return self.translateName(name)

    @dispatch(ast.Call)
    def visitCall(self, node):
        """
        Visit a Call node and translate special operations.
        
        This is the core translation method. It handles:
        1. Special low-level operations (allocate, load, store, check, etc.)
           - These are translated to specific AST node types
        2. Direct call optimization
           - If the call target is a known function, convert to DirectCall
           - This enables better analysis and optimization
        
        Special operations translated:
        - allocate(obj) -> Allocate node
        - load(obj, field) -> Load node (LowLevel field type)
        - store(obj, field, value) -> Store node
        - check(obj, field) -> Check node
        - loadAttr/storeAttr/checkAttr -> Attribute operations
        - loadDict/storeDict/checkDict -> Dictionary operations
        - loadArray/storeArray/checkArray -> Array operations
        - loadDescriptor/storeDescriptor -> Descriptor operations
        
        Args:
            node: Call AST node to translate
            
        Returns:
            Translated AST node (may be Call, DirectCall, Load, Store, etc.)
        """
        node = node.rewriteChildren(self)
        original = node

        if node.expr in self.defn:
            defn = self.defn[node.expr]
            if defn in self.specialGlobals:
                # Translate special low-level operations
                if defn == "allocate":
                    checkCallArgs(node, 1)
                    node = ast.Allocate(node.args[0])
                elif defn == "load":
                    checkCallArgs(node, 2)
                    node = ast.Load(node.args[0], "LowLevel", node.args[1])
                elif defn == "store":
                    checkCallArgs(node, 3)
                    node = ast.Store(
                        node.args[0], "LowLevel", node.args[1], node.args[2]
                    )
                elif defn == "check":
                    checkCallArgs(node, 2)
                    node = ast.Check(node.args[0], "LowLevel", node.args[1])
                elif defn == "loadAttr":
                    checkCallArgs(node, 2)
                    node = ast.Load(node.args[0], "Attribute", node.args[1])
                elif defn == "storeAttr":
                    checkCallArgs(node, 3)
                    node = ast.Store(
                        node.args[0], "Attribute", node.args[1], node.args[2]
                    )
                elif defn == "checkAttr":
                    checkCallArgs(node, 2)
                    node = ast.Check(node.args[0], "Attribute", node.args[1])
                elif defn == "loadDict":
                    checkCallArgs(node, 2)
                    node = ast.Load(node.args[0], "Dictionary", node.args[1])
                elif defn == "storeDict":
                    checkCallArgs(node, 3)
                    node = ast.Store(
                        node.args[0], "Dictionary", node.args[1], node.args[2]
                    )
                elif defn == "checkDict":
                    checkCallArgs(node, 2)
                    node = ast.Check(node.args[0], "Dictionary", node.args[1])
                elif defn == "loadArray":
                    checkCallArgs(node, 2)
                    node = ast.Load(node.args[0], "Array", node.args[1])
                elif defn == "storeArray":
                    checkCallArgs(node, 3)
                    node = ast.Store(node.args[0], "Array", node.args[1], node.args[2])
                elif defn == "checkArray":
                    checkCallArgs(node, 2)
                    node = ast.Check(node.args[0], "Array", node.args[1])
                elif defn == "loadDescriptor":
                    # Get descriptor name and translate to attribute load
                    name = self.getDescriptorName(node.args[1], node.args[2])
                    node = ast.Load(node.args[0], "Attribute", name)
                elif defn == "storeDescriptor":
                    # Get descriptor name and translate to attribute store
                    name = self.getDescriptorName(node.args[1], node.args[2])
                    node = ast.Store(node.args[0], "Attribute", name, node.args[3])
                else:
                    assert False, defn
            elif isinstance(defn, ast.Existing):
                # Try to optimize to a direct call
                # Not always possible, depends on the order of declaration.
                # Direct calls enable better analysis and optimization.
                code = self.compiler.extractor.getCall(defn.object)
                if code:
                    node = ast.DirectCall(
                        code, node.expr, node.args, node.kwds, node.vargs, node.kargs
                    )

        # Preserve original annotations
        node.annotation = original.annotation
        return node

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        expr = self(node.expr)
        assert not isinstance(expr, ast.Store), "Must discard stores."

        # A little strange, but it works because there will only be one target in the cases we care about.
        for lcl in node.lcls:
            self.defn[lcl] = expr

        if expr not in self.specialGlobals:
            if node.expr == expr:
                return node
            else:
                return ast.Assign(expr, node.lcls)
        else:
            return ()

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        expr = self(node.expr)
        if isinstance(expr, ast.Store):
            return expr

        if expr not in self.specialGlobals:
            if node.expr == expr:
                return node
            else:
                return ast.Discard(expr)
        else:
            return ()

    @dispatch(ast.ConvertToBool)
    def visitConvertToBool(self, node):
        defn = self.defn.get(node.expr)
        if defn and defn.alwaysReturnsBoolean():
            # It will be a boolean, so don't bother converting...
            return node.expr
        else:
            return node.rewriteChildren(self)

    @dispatch(ast.BinaryOp, ast.Is, ast.GetAttr, ast.GetSubscript, ast.BuildTuple)
    def visitExpr(self, node):
        return node.rewriteChildren(self)

    @dispatch(ast.Switch)
    def visitSwitch(self, node):
        cond = self(node.condition)
        self.defn.clear()

        t = self(node.t)
        self.defn.clear()

        f = self(node.f)
        self.defn.clear()

        result = ast.Switch(cond, t, f)
        result.annotation = node.annotation
        return result

    @dispatch(ast.Return)
    def visitReturn(self, node):
        if len(node.exprs) == 1:
            defn = self.defn.get(node.exprs[0])
            if isinstance(defn, ast.BuildTuple):
                # HACK this transformation can be unsound if any of the arguments to the BuildTuple have been redefined.
                # HACK this may create unwanted multi-returns.
                # HACK no guarentee the number of return args is consistant.
                newexprs = [self(arg) for arg in defn.args]
                self.setNumReturns(len(newexprs))
                return ast.Return(newexprs)

        self.setNumReturns(len(node.exprs))
        return node.rewriteChildren(self)

    def setNumReturns(self, num):
        if self.numReturns is None:
            self.numReturns = num

            p = self.code.codeparameters
            if num != len(p.returnparams):
                returnparams = [ast.Local("internal_return_%d" % i) for i in range(num)]
                self.code.codeparameters = ast.CodeParameters(
                    p.selfparam,
                    p.params,
                    p.paramnames,
                    p.defaults,
                    p.vparam,
                    p.kparam,
                    returnparams,
                )

        else:
            assert num == self.numReturns

    @dispatch(ast.Suite, ast.Condition)
    def visitOK(self, node):
        return node.rewriteChildren(self)

    def process(self, node):
        """
        Process a code node and translate its AST.
        
        Main entry point for translation. Translates the AST, determines
        return count, and applies optimizations.
        
        Args:
            node: Code node to process
            
        Returns:
            The processed code node with translated AST
        """
        self.numReturns = None

        self.code = node
        # Translate the AST
        node.ast = self(node.ast)
        self.code = None

        # Apply optimizations
        optimization.convertboolelimination.evaluateCode(self.compiler, node)
        optimization.simplify.evaluateCode(self.compiler, None, node)

        # astpprint.pprint(node)
        return node


def translate(compiler, func, code):
    """
    Translate a stub function's code to pyflow AST.
    
    Convenience function that creates an LLTranslator and processes a code node.
    
    Args:
        compiler: Compiler instance
        func: Python function being translated
        code: Code node to translate
        
    Returns:
        Translated code node
    """
    llt = LLTranslator(compiler, func)
    return llt.process(code)
