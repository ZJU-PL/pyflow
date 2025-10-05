"""Dataflow analysis framework for shape analysis.

This module provides the dataflow analysis framework used by shape analysis,
including worklist algorithms and dataflow environments.
"""

from __future__ import absolute_import


class DataflowEnvironment(object):
    """Dataflow environment for shape analysis.
    
    This class manages the dataflow state and observers for shape analysis,
    tracking information flow through the program and managing constraint
    propagation.
    
    Attributes:
        _secondary: Dictionary mapping (point, context, index) to secondary info.
        observers: Dictionary mapping points to lists of observing constraints.
    """
    __slots__ = "_secondary", "observers"

    def __init__(self):
        """Initialize the dataflow environment."""
        self._secondary = {}
        self.observers = {}

    def addObserver(self, index, constraint):
        """Add a constraint as an observer of a specific index.
        
        Args:
            index: The index to observe.
            constraint: The constraint to add as an observer.
        """
        if not index in self.observers:
            self.observers[index] = [constraint]
        else:
            assert constraint not in self.observers[index]
            self.observers[index].append(constraint)

    def merge(self, sys, point, context, index, secondary, canSteal=False):
        """Merge secondary information at a specific point.
        
        Args:
            sys: The analysis system.
            point: Program point where merge occurs.
            context: Analysis context.
            index: Index for the merge.
            secondary: Secondary information to merge.
            canSteal: Whether the secondary information can be stolen.
            
        Returns:
            bool: True if the merge resulted in changes.
        """
        assert not secondary.paths.containsAged()

        # Do the merge
        key = (point, context, index)
        if not key in self._secondary:
            self._secondary[key] = secondary if canSteal else secondary.copy()
            changed = True
        else:
            changed = self._secondary[key].merge(secondary)

        # Did we discover any new information?
        if changed and point in self.observers:
            # Make sure the consumers will be re-evaluated.
            for observer in self.observers[point]:
                sys.worklist.addDirty(observer, key)

    def secondary(self, point, context, index):
        """Get secondary information for a specific key.
        
        Args:
            point: Program point.
            context: Analysis context.
            index: Index.
            
        Returns:
            Secondary information or None if not found.
        """
        key = (point, context, index)
        return self._secondary.get(key)

    def clear(self):
        """Clear all secondary information."""
        self._secondary.clear()


# Processes the queue depth first.
class Worklist(object):
    def __init__(self):
        self.worklist = []
        self.dirty = set()
        self.maxLength = 0
        self.steps = 0
        self.usefulSteps = 0

    def addDirty(self, constraint, index):
        self.useful = True
        key = (constraint, index)
        if key not in self.dirty:
            self.dirty.add(key)
            self.worklist.append(key)

    def pop(self):
        key = self.worklist.pop()
        self.dirty.remove(key)
        return key

    def step(self, sys, trace=False):
        # Track statistics
        self.maxLength = max(len(self.worklist), self.maxLength)

        if trace:
            if self.steps % 100 == 0:
                print(
                    ".",
                )
            if self.steps % 10000 == 0:
                print(sys.dumpStatistics())
        self.steps += 1

        # Process a constraint/index pair
        constraint, index = self.pop()

        self.useful = False

        try:
            constraint.update(sys, index)
        except:
            print(
                "ERROR processing:",
                constraint,
                constraint.inputPoint,
                constraint.outputPoint,
            )
            raise

        if self.useful:
            self.usefulSteps += 1

    def process(self, sys, trace=False, limit=0):
        stop = self.steps + limit
        while self.worklist:
            self.step(sys, trace)

            if limit and self.steps >= stop:
                return False

        return True
