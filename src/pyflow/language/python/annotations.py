"""Annotations for Python AST nodes.

This module provides annotation classes that attach context-sensitive metadata
to AST nodes. Annotations track:
- Read/modify/allocate information: Which objects are accessed
- Invocation information: Which functions are called
- Lifetime information: Which objects are live/killed
- Origin information: Source location for debugging
- Optimization information: Folding, lowering, runtime information

Annotations are context-sensitive, meaning they can have different values
for different analysis contexts (e.g., different calling patterns).
"""

from pyflow.language.asttools.origin import Origin
from pyflow.language.asttools.annotation import (
    noMod,
    remapContextual,
    annotationSet,
    makeContextualAnnotation,
    mergeContextualAnnotation,
)


def codeOrigin(code, line=None, col=None):
    """Create an Origin from a code object.
    
    Args:
        code: Code object (from function.__code__)
        line: Line number (defaults to code.co_firstlineno)
        col: Column number (optional)
        
    Returns:
        Origin: Origin object with source location information
    """
    if line is None:
        line = code.co_firstlineno
    return Origin(code.co_name, code.co_filename, line, col)


def functionOrigin(func, line=None, col=None):
    """Create an Origin from a function object.
    
    Args:
        func: Function object
        line: Line number (optional)
        col: Column number (optional)
        
    Returns:
        Origin: Origin object with source location information
    """
    return codeOrigin(func.__code__, line, col)


class Annotation(object):
    """Base class for AST node annotations.
    
    Annotations attach metadata to AST nodes. They are immutable and
    provide rewrite() methods for creating modified copies.
    """
    __slots__ = ()


class CodeAnnotation(Annotation):
    """Annotation for code nodes (functions, classes).
    
    CodeAnnotation attaches metadata to code definitions, including:
    - Context information: Analysis contexts for this code
    - Read/modify/allocate: Objects accessed by the code
    - Lifetime information: Objects live/killed at entry/exit
    - Optimization information: Folding, lowering, runtime info
    
    Attributes:
        contexts: Tuple of analysis contexts for this code
        descriptive: Descriptive information about the code
        primitive: Whether code is primitive (built-in)
        staticFold: Static folding information
        dynamicFold: Dynamic folding information
        origin: Source location information
        live: Objects live at entry (context-sensitive)
        killed: Objects killed at exit (context-sensitive)
        codeReads: Objects read by code (context-sensitive)
        codeModifies: Objects modified by code (context-sensitive)
        codeAllocates: Objects allocated by code (context-sensitive)
        lowered: Lowered representation (if applicable)
        runtime: Runtime information
        interpreter: Interpreter information
    """
    __slots__ = [
        "contexts",
        "descriptive",
        "primitive",
        "staticFold",
        "dynamicFold",
        "origin",
        "live",
        "killed",
        "codeReads",
        "codeModifies",
        "codeAllocates",
        "lowered",
        "runtime",
        "interpreter",
    ]

    def __init__(
        self,
        contexts,
        descriptive,
        primitive,
        staticFold,
        dynamicFold,
        origin,
        live,
        killed,
        codeReads,
        codeModifies,
        codeAllocates,
        lowered,
        runtime,
        interpreter,
    ):
        self.contexts = tuple(contexts) if contexts is not None else None
        self.descriptive = descriptive
        self.primitive = primitive
        self.staticFold = staticFold
        self.dynamicFold = dynamicFold
        self.origin = origin
        self.live = live
        self.killed = killed
        self.codeReads = codeReads
        self.codeModifies = codeModifies
        self.codeAllocates = codeAllocates
        self.lowered = lowered
        self.runtime = runtime
        self.interpreter = interpreter

    def rewrite(
        self,
        contexts=noMod,
        descriptive=noMod,
        primitive=noMod,
        staticFold=noMod,
        dynamicFold=noMod,
        origin=noMod,
        live=noMod,
        killed=noMod,
        codeReads=noMod,
        codeModifies=noMod,
        codeAllocates=noMod,
        lowered=noMod,
        runtime=noMod,
        interpreter=noMod,
    ):
        if contexts is noMod:
            contexts = self.contexts
        if descriptive is noMod:
            descriptive = self.descriptive
        if primitive is noMod:
            primitive = self.primitive
        if staticFold is noMod:
            staticFold = self.staticFold
        if dynamicFold is noMod:
            dynamicFold = self.dynamicFold
        if origin is noMod:
            origin = self.origin
        if live is noMod:
            live = self.live
        if killed is noMod:
            killed = self.killed
        if codeReads is noMod:
            codeReads = self.codeReads
        if codeModifies is noMod:
            codeModifies = self.codeModifies
        if codeAllocates is noMod:
            codeAllocates = self.codeAllocates
        if lowered is noMod:
            lowered = self.lowered
        if runtime is noMod:
            runtime = self.runtime
        if interpreter is noMod:
            interpreter = self.interpreter

        return CodeAnnotation(
            contexts,
            descriptive,
            primitive,
            staticFold,
            dynamicFold,
            origin,
            live,
            killed,
            codeReads,
            codeModifies,
            codeAllocates,
            lowered,
            runtime,
            interpreter,
        )

    def contextSubset(self, remap, invokeMapper=None):
        contexts = [self.contexts[i] for i in remap]
        live = remapContextual(self.live, remap)
        killed = remapContextual(self.killed, remap)

        codeReads = remapContextual(self.codeReads, remap)
        codeModifies = remapContextual(self.codeModifies, remap)
        codeAllocates = remapContextual(self.codeAllocates, remap)

        return self.rewrite(
            contexts=contexts,
            live=live,
            killed=killed,
            codeReads=codeReads,
            codeModifies=codeModifies,
            codeAllocates=codeAllocates,
        )


class OpAnnotation(Annotation):
    """Annotation for operation nodes (expressions, statements).
    
    OpAnnotation attaches metadata to operations, including:
    - Invocation information: Which functions are called
    - Read/modify/allocate: Which objects are accessed
    - Origin information: Source location for debugging
    
    Attributes:
        invokes: Functions invoked by this operation (context-sensitive)
        opReads: Objects read by this operation (context-sensitive)
        opModifies: Objects modified by this operation (context-sensitive)
        opAllocates: Objects allocated by this operation (context-sensitive)
        reads: Objects read (final analysis results, context-sensitive)
        modifies: Objects modified (final analysis results, context-sensitive)
        allocates: Objects allocated (final analysis results, context-sensitive)
        origin: Source location information
    """
    __slots__ = (
        "invokes",
        "opReads",
        "opModifies",
        "opAllocates",
        "reads",
        "modifies",
        "allocates",
        "origin",
    )

    def __init__(
        self,
        invokes,
        opReads,
        opModifies,
        opAllocates,
        reads,
        modifies,
        allocates,
        origin,
    ):
        self.invokes = invokes
        self.opReads = opReads
        self.opModifies = opModifies
        self.opAllocates = opAllocates
        self.reads = reads
        self.modifies = modifies
        self.allocates = allocates
        self.origin = origin

    def rewrite(
        self,
        invokes=noMod,
        opReads=noMod,
        opModifies=noMod,
        opAllocates=noMod,
        reads=noMod,
        modifies=noMod,
        allocates=noMod,
        origin=noMod,
    ):
        if invokes is noMod:
            invokes = self.invokes
        if opReads is noMod:
            opReads = self.opReads
        if opModifies is noMod:
            opModifies = self.opModifies
        if opAllocates is noMod:
            opAllocates = self.opAllocates
        if reads is noMod:
            reads = self.reads
        if modifies is noMod:
            modifies = self.modifies
        if allocates is noMod:
            allocates = self.allocates
        if origin is noMod:
            origin = self.origin

        return OpAnnotation(
            invokes,
            opReads,
            opModifies,
            opAllocates,
            reads,
            modifies,
            allocates,
            origin,
        )

    def contextSubset(self, remap, invokeMapper=None):
        invokes = remapContextual(self.invokes, remap, invokeMapper)
        opReads = remapContextual(self.opReads, remap)
        opModifies = remapContextual(self.opModifies, remap)
        opAllocates = remapContextual(self.opAllocates, remap)
        reads = remapContextual(self.reads, remap)
        modifies = remapContextual(self.modifies, remap)
        allocates = remapContextual(self.allocates, remap)
        origin = self.origin

        return OpAnnotation(
            invokes,
            opReads,
            opModifies,
            opAllocates,
            reads,
            modifies,
            allocates,
            origin,
        )

    def compatable(self, codeAnnotation):
        if self.invokes is not None:
            return len(self.invokes[1]) == len(codeAnnotation.contexts)
        return True


class SlotAnnotation(Annotation):
    __slots__ = "references"

    def __init__(self, references=None):
        # assert references is None or isinstance(references, ContextualAnnotation), type(references)
        self.references = references

    def rewrite(self, references=noMod):
        if references is noMod:
            references = self.references

        return SlotAnnotation(references)

    def contextSubset(self, remap, invokeMapper=None):
        references = remapContextual(self.references, remap)
        return self.rewrite(references=references)

    def compatable(self, codeAnnotation):
        if self.references is not None:
            return len(self.references[1]) == len(codeAnnotation.contexts)
        return True


emptyCodeAnnotation = CodeAnnotation(
    None,
    False,
    False,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    False,
    False,
    False,
)
emptyOpAnnotation = OpAnnotation(None, None, None, None, None, None, None, (None,))
emptySlotAnnotation = SlotAnnotation(None)
