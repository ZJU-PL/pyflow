"""
Stub collector for gathering and registering function stubs.

This module provides the StubCollector class, which is the central component
for collecting, registering, and managing function stubs in pyflow. Stubs are
Python function representations that enable static analysis of built-in and
standard library operations.

The collector provides decorators and utilities for:
- Registering stub functions with the extractor
- Attaching stubs to C function pointers
- Marking functions as primitive, descriptive, or interpreter functions
- Enabling constant folding for stubs
- Replacing attributes with stub implementations
"""

from __future__ import absolute_import

from pyflow._pyflow import cfuncptr
from pyflow.util.monkeypatch import xtypes

from pyflow.util.python import replaceGlobals

from . import lltranslator


class StubCollector(object):
    """
    Collector for gathering and registering function stubs.
    
    The StubCollector is responsible for collecting stub functions from various
    generators and registering them with the compiler's extractor. It provides
    a rich set of decorators and utilities for creating different types of stubs:
    
    - Low-level stubs: Direct implementations using load/store operations
    - Interpreter stubs: Functions that implement Python semantics
    - Primitive stubs: Atomic operations that can't be further analyzed
    - Descriptive stubs: Detailed behavioral descriptions for analysis
    
    Attributes:
        compiler: Compiler instance with extractor and other components
        exports: Dictionary of exported stub functions (name -> function)
        highLevelGlobals: Dictionary of high-level global objects
        highLevelLUT: Lookup table for high-level functions
        codeToFunction: Mapping from code objects to Python functions
    """
    def __init__(self, compiler):
        """
        Initialize a stub collector.
        
        Args:
            compiler: Compiler instance with extractor and other components
        """
        self.compiler = compiler

        # HACK: Reset name lookup table for stub collection
        self.compiler.extractor.nameLUT = {}

        # Dictionary of exported stub functions (name -> function/code)
        self.exports = {}

        # High-level globals available to stub functions
        self.highLevelGlobals = {"method": xtypes.MethodType}
        self.highLevelLUT = {}

        # Mapping from code objects to their original Python functions
        self.codeToFunction = {}

    #####################
    ### Stub building ###
    #####################

    def export(self, funcast):
        """
        Export a stub function for use in other stubs.
        
        Exported functions are registered in the exports dictionary and can
        be referenced by name in other stub generators. This is useful for
        creating reusable stub components.
        
        Args:
            funcast: Function or code object to export
            
        Returns:
            The exported function/code object
            
        Raises:
            AssertionError: If a function with the same name is already exported
        """
        if isinstance(funcast, xtypes.FunctionType):
            name = funcast.func_name
        else:
            name = funcast.name

        assert not name in self.exports
        self.exports[name] = funcast
        return funcast

    def registerFunction(self, func, code):
        """
        Register a stub function with the extractor.
        
        Registers a code object (stub) with the extractor, making it available
        for static analysis. If a Python function is provided, it replaces
        the function's code with the stub.
        
        Args:
            func: Python function object (or None for pure stubs)
            code: Code object representing the stub
        """
        extractor = self.compiler.extractor
        extractor.desc.functions.append(code)
        extractor.nameLUT[code.name] = func

        if func:
            extractor.replaceCode(func, code)
            self.codeToFunction[code] = func

    def llast(self, f):
        """
        Register a low-level AST stub.
        
        Creates a stub from a function that returns a code object directly.
        This is used for stubs that are manually constructed as AST nodes
        rather than decompiled from Python functions.
        
        Args:
            f: Function that returns a code object
            
        Returns:
            The code object returned by f
        """
        code = f()
        assert code.isCode(), type(code)
        self.registerFunction(None, code)
        self.compiler.extractor.desc.functions.append(code)
        return code

    def llfunc(self, func=None, descriptive=False, primitive=False):
        """
        Decorator for creating low-level function stubs.
        
        This is the main decorator for creating stubs. It decompiles a Python
        function into a code object, translates it using LLTranslator, and
        optionally marks it as descriptive or primitive.
        
        Args:
            func: Function to create stub from (if None, returns decorator)
            descriptive: If True, mark as descriptive (detailed behavior)
            primitive: If True, mark as primitive (atomic operation)
            
        Returns:
            If func is provided: the translated code object
            If func is None: a decorator function
            
        Example:
            >>> @collector.llfunc(descriptive=True)
            ... def my_stub(x, y):
            ...     return load(x, "attribute")
        """
        def wrapper(func):
            # Decompile Python function to code object
            code = self.compiler.extractor.decompileFunction(
                func, descriptive=(primitive or descriptive)
            )
            code.rewriteAnnotation(runtime=True)

            self.registerFunction(func, code)

            # Apply annotations based on flags
            if primitive:
                code = self.primitive(code)
            elif descriptive:
                code = self.descriptive(code)

            # Translate low-level operations to pyflow AST
            code = lltranslator.translate(self.compiler, func, code)

            return code

        if func is not None:
            return wrapper(func)
        else:
            return wrapper

    def cfuncptr(self, obj):
        """
        Get a C function pointer from a Python object.
        
        Extracts the underlying C function pointer from a Python callable
        object. This is used to attach stubs to C extension functions.
        
        Args:
            obj: Python callable object (function, method, etc.)
            
        Returns:
            C function pointer
            
        Raises:
            TypeError: If the object doesn't have a C function pointer
        """
        try:
            return cfuncptr(obj)
        except TypeError:
            raise TypeError("Cannot get pointer from %r" % type(obj))

    ############################
    ### Attachment functions ###
    ############################

    def attachAttrPtr(self, t, attr):
        """
        Create a callback that attaches a stub to a type's attribute.
        
        Returns a callback function that, when given a code object, attaches
        it to the C function pointer of a type's attribute. This is used to
        provide stubs for methods defined in C extensions.
        
        Args:
            t: Type/class object
            attr: Attribute name (string)
            
        Returns:
            Callback function that takes a code object and attaches it
            
        Example:
            >>> @collector.attachAttrPtr(str, "upper")
            ... @collector.llfunc
            ... def str_upper(self):
            ...     return allocate(str)
        """
        assert isinstance(t, type), t
        assert isinstance(attr, str), attr

        meth = getattr(t, attr)
        ptr = self.cfuncptr(meth)

        def callback(code):
            assert code.isCode(), type(code)
            self.compiler.extractor.attachStubToPtr(code, ptr)
            return code

        return callback

    def attachPtr(self, pyobj, attr=None):
        """
        Create a callback that attaches a stub to a Python object's pointer.
        
        Returns a callback that attaches a stub to the C function pointer of
        a Python object (or its attribute). Verifies that the attachment
        was successful by checking the binding.
        
        Args:
            pyobj: Python object (function, method, etc.)
            attr: Optional attribute name if attaching to an attribute
            
        Returns:
            Callback function that takes a code object and attaches it
            
        Raises:
            AssertionError: If the attachment fails or binding is incorrect
        """
        original = pyobj
        if attr is not None:
            d = pyobj.__dict__
            assert attr in d, (pyobj, attr)
            pyobj = pyobj.__dict__[attr]

        ptr = self.cfuncptr(pyobj)

        def callback(code):
            assert code.isCode(), type(code)
            extractor = self.compiler.extractor

            extractor.attachStubToPtr(code, ptr)

            # Check the binding to ensure attachment succeeded
            obj = extractor.getObject(pyobj)
            call = extractor.getCall(obj)

            if code is not call:
                print(extractor.pointerToObject)
                print(extractor.pointerToStub)

            assert code is call, (original, pyobj, code, call)

            return code

        return callback

    def fold(self, func):
        """
        Create a callback that enables constant folding for a stub.
        
        Returns a callback that sets both static and dynamic fold functions
        for a code object. This enables constant folding during static analysis.
        
        Args:
            func: Function to use for folding (takes same args as stub)
            
        Returns:
            Callback function that sets fold annotations
            
        Example:
            >>> @collector.fold(lambda x: x + 1)
            ... @collector.llfunc
            ... def increment(x):
            ...     return allocate(x + 1)
        """
        def callback(code):
            assert code.isCode(), type(code)
            code.rewriteAnnotation(staticFold=func, dynamicFold=func)
            return code

        return callback

    def staticFold(self, func):
        """
        Create a callback that enables static-only constant folding.
        
        Similar to fold(), but only sets staticFold (not dynamicFold).
        Use this when the function can be folded at compile time but not
        at runtime.
        
        Args:
            func: Function to use for static folding
            
        Returns:
            Callback function that sets static fold annotation
        """
        def callback(code):
            assert code.isCode(), type(code)
            code.rewriteAnnotation(staticFold=func)
            return code

        return callback

    def descriptive(self, code):
        """
        Mark a code object as descriptive.
        
        Descriptive stubs provide detailed behavioral descriptions that
        enable more precise static analysis. They are analyzed more deeply
        than primitive stubs.
        
        Args:
            code: Code object to mark
            
        Returns:
            The code object (for chaining)
        """
        assert code.isCode(), type(code)
        code.rewriteAnnotation(descriptive=True)
        return code

    def primitive(self, code):
        """
        Mark a code object as primitive.
        
        Primitive stubs are treated as atomic operations that cannot be
        further analyzed. They are marked as descriptive but not runtime,
        meaning they're analyzed but not executed.
        
        Args:
            code: Code object to mark
            
        Returns:
            The code object (for chaining)
        """
        assert code.isCode(), type(code)
        code.rewriteAnnotation(
            descriptive=True, primitive=True, runtime=False, interpreter=False
        )
        return code

    def replaceAttr(self, o, attr):
        """
        Create a callback that replaces an object's attribute with a stub.
        
        Returns a callback that replaces an object's attribute with a stub
        function. This is used to override default behavior with stub
        implementations.
        
        Args:
            o: Object whose attribute to replace
            attr: Attribute name to replace
            
        Returns:
            Callback function that takes a code/function and replaces the attribute
        """
        def callback(obj):
            if not isinstance(obj, xtypes.FunctionType):
                assert obj.isCode(), type(obj)
                f = self.codeToFunction[obj]
            else:
                f = obj
                # assert self.highLevelLUT[f.func_name] == f, "Must declare as high level stub before replacing."
            self.compiler.extractor.replaceAttr(o, attr, f)
            return obj

        return callback


# Global list of stub generator functions
# These are registered via the @stubgenerator decorator
stubgenerators = []


def stubgenerator(f):
    """
    Decorator for registering a stub generator function.
    
    Functions decorated with @stubgenerator are automatically called during
    stub collection to generate stubs for a particular module or category.
    Each generator receives a StubCollector instance and uses it to register
    stubs.
    
    Args:
        f: Function that takes a StubCollector and generates stubs
        
    Returns:
        The function unchanged (decorator just registers it)
        
    Example:
        >>> @stubgenerator
        ... def makeMyStubs(collector):
        ...     @collector.llfunc
        ...     def my_stub(x):
        ...         return load(x, "field")
    """
    stubgenerators.append(f)
    return f


def makeStubs(compiler):
    """
    Create and register all stub functions.
    
    This is the main entry point for stub generation. It creates a StubCollector,
    runs all registered stub generators, and returns the collector with all
    stubs registered.
    
    Args:
        compiler: Compiler instance with extractor and other components
        
    Returns:
        StubCollector instance with all stubs registered
        
    Example:
        >>> collector = makeStubs(compiler)
        >>> # All stubs are now registered and available for analysis
    """
    collector = StubCollector(compiler)
    compiler.extractor.stubs = collector
    # Run all registered stub generators
    for gen in stubgenerators:
        gen(collector)
    return collector
