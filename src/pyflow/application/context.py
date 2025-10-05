"""Context management for PyFlow static analysis.

This module provides context classes that manage the compilation and analysis
state throughout the PyFlow pipeline.
"""

from pyflow.util.python import uniqueSlotName
from pyflow.util.application.console import Console
import collections


class Slots(object):
    """Manages unique slot names for object descriptors.
    
    This class provides a caching mechanism for generating unique slot names
    from object descriptors, with reverse lookup capability.
    
    Attributes:
        cache: Dictionary mapping descriptors to unique names.
        reverse: Dictionary mapping unique names back to descriptors.
    """
    
    def __init__(self):
        """Initialize the slots manager with empty caches."""
        self.cache = {}
        self.reverse = {}

    def uniqueSlotName(self, descriptor):
        """Get or create a unique slot name for a descriptor.
        
        Args:
            descriptor: Object descriptor to get unique name for.
            
        Returns:
            str: Unique slot name for the descriptor.
        """
        if descriptor in self.cache:
            return self.cache[descriptor]

        uniqueName = uniqueSlotName(descriptor)

        self.cache[descriptor] = uniqueName
        self.reverse[uniqueName] = descriptor

        return uniqueName


class CompilerContext(object):
    """Context for compilation and analysis operations.
    
    This class holds the compilation context including console output,
    program extractor, slot management, statistics, and the current program.
    
    Attributes:
        console: Console object for output operations.
        extractor: Program extractor instance.
        slots: Slots manager for unique naming.
        stats: Statistics collection (defaultdict).
        program: Current program being analyzed.
    """
    __slots__ = "console", "extractor", "slots", "stats", "program"

    def __init__(self, console):
        """Initialize the compiler context.
        
        Args:
            console: Console object for output. If None, creates a default console.
        """
        # Provide a default console if none is supplied
        self.console = console if console is not None else Console()
        self.extractor = None
        self.slots = Slots()
        self.stats = collections.defaultdict(dict)
        self.program = None


class Context(object):
    """A simple context class for PyFlow analysis.
    
    This is a placeholder context class for basic analysis operations.
    """

    def __init__(self):
        """Initialize the context."""
        pass
