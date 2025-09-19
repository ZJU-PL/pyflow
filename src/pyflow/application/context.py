from pyflow.util.python import uniqueSlotName
from pyflow.util.application.console import Console
import collections


class Slots(object):
    def __init__(self):
        self.cache = {}
        self.reverse = {}

    def uniqueSlotName(self, descriptor):
        if descriptor in self.cache:
            return self.cache[descriptor]

        uniqueName = uniqueSlotName(descriptor)

        self.cache[descriptor] = uniqueName
        self.reverse[uniqueName] = descriptor

        return uniqueName


class CompilerContext(object):
    __slots__ = "console", "extractor", "slots", "stats", "program"

    def __init__(self, console):
        # Provide a default console if none is supplied
        self.console = console if console is not None else Console()
        self.extractor = None
        self.slots = Slots()
        self.stats = collections.defaultdict(dict)
        self.program = None


class Context(object):
    """A simple context class for PyFlow analysis."""

    def __init__(self):
        """Initialize the context."""
        pass
