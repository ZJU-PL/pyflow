"""
Context management for PyFlow static analysis.

This module provides context classes that manage the compilation and analysis
state throughout the PyFlow pipeline. Contexts maintain shared state like
console output, slot naming, statistics, and the current program being analyzed.

**Context Types:**
- `CompilerContext`: Main compilation context with console, slots, stats
- `Slots`: Manages unique slot names for object descriptors
- `Context`: Simple placeholder context for basic operations
"""

from pyflow.util.python import uniqueSlotName
from pyflow.util.application.console import Console
import collections


class Slots(object):
    """
    Manages unique slot names for object descriptors.
    
    This class provides a caching mechanism for generating unique slot names
    from object descriptors. It maintains bidirectional mappings:
    - Forward: descriptor -> unique name
    - Reverse: unique name -> descriptor
    
    **Purpose:**
    In PyFlow's analysis, objects need unique identifiers (slot names) for
    tracking in data structures like store graphs. This class ensures each
    descriptor gets a consistent unique name and allows reverse lookup.
    
    Attributes:
        cache: Dictionary mapping descriptors to unique names
        reverse: Dictionary mapping unique names back to descriptors
    """
    
    def __init__(self):
        """
        Initialize the slots manager with empty caches.
        
        Creates empty forward and reverse mappings for slot names.
        """
        self.cache = {}
        self.reverse = {}

    def uniqueSlotName(self, descriptor):
        """
        Get or create a unique slot name for a descriptor.
        
        If the descriptor has been seen before, returns the cached name.
        Otherwise, generates a new unique name using uniqueSlotName() and
        caches it in both directions.
        
        Args:
            descriptor: Object descriptor to get unique name for
            
        Returns:
            str: Unique slot name for the descriptor
        """
        if descriptor in self.cache:
            return self.cache[descriptor]

        uniqueName = uniqueSlotName(descriptor)

        self.cache[descriptor] = uniqueName
        self.reverse[uniqueName] = descriptor

        return uniqueName


class CompilerContext(object):
    """
    Context for compilation and analysis operations.
    
    This class holds the compilation context that is shared throughout
    the PyFlow analysis pipeline. It provides:
    - Console output management
    - Program extraction state
    - Slot name management
    - Statistics collection
    - Current program reference
    
    **Usage:**
    The CompilerContext is created at the start of analysis and passed
    to all passes and analysis functions. It maintains state across the
    entire analysis pipeline.
    
    Attributes:
        console: Console object for structured output and logging
        extractor: Program extractor instance (set during extraction phase)
        slots: Slots manager for generating unique slot names
        stats: Statistics collection (nested defaultdict for hierarchical stats)
        program: Current program being analyzed (set during pipeline execution)
    """
    __slots__ = "console", "extractor", "slots", "stats", "program"

    def __init__(self, console):
        """
        Initialize the compiler context.
        
        Creates a new context with the provided console. If no console
        is provided, creates a default Console instance. Initializes
        empty slots manager and statistics collection.
        
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
    """
    A simple context class for PyFlow analysis.
    
    This is a placeholder context class for basic analysis operations
    that don't require the full CompilerContext functionality. It can
    be extended with additional attributes as needed.
    """

    def __init__(self):
        """Initialize the context."""
        pass
