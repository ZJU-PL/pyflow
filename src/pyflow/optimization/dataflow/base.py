"""
Base framework for data flow analysis in pyflow optimizations.

This module provides the foundational infrastructure for forward and backward
data flow analysis used by various optimizations. It includes:

- Lattice values (top, undefined) for abstract interpretation
- Dynamic dictionaries for tracking flow-sensitive information
- Flow dictionaries for managing control flow contours
- Code mutation utilities for transforming ASTs
- Meet functions for combining flow information

The data flow framework is used by:
- Constant folding (forward data flow)
- Dead code elimination (backward data flow)
- Load/store elimination (forward/backward analysis)
- Method call optimization (forward analysis)
"""

import copy
from pyflow.util.typedispatch import *

# HACK should not be dependant on Python?
from pyflow.language.python import ast


class InternalError(Exception):
    """
    Exception raised when an internal error occurs during data flow analysis.
    
    This typically indicates a bug in the optimization or analysis code,
    such as attempting to access a flow contour that doesn't exist.
    """
    pass


class ApplyToCode(TypeDispatcher):
    """
    Applies a strategy to all code nodes without mutation.
    
    This dispatcher traverses the code tree and applies a strategy function
    to each code node, but does not modify the nodes. Useful for analysis
    passes that need to visit all code without transforming it.
    
    Attributes:
        strategy: Function to apply to each code node
    """
    def __init__(self, strategy):
        """
        Initialize code applier.
        
        Args:
            strategy: Function to apply to each code node
        """
        self.strategy = strategy

    @defaultdispatch
    def visitCode(self, node):
        """
        Visit a code node and apply strategy to all children.
        
        Args:
            node: Code node to process
            
        Returns:
            The node unchanged
        """
        assert node.isCode(), type(node)
        for child in node.children():
            self.strategy(child)
        return node


class MutateCode(TypeDispatcher):
    """
    Mutates code nodes by replacing children with transformed versions.
    
    This dispatcher traverses the code tree in forward order and replaces
    each code node's children with transformed versions. Used for forward
    data flow optimizations.
    
    Attributes:
        strategy: Transformation function to apply to each code node
    """
    def __init__(self, strategy):
        """
        Initialize code mutator.
        
        Args:
            strategy: Transformation function to apply
        """
        self.strategy = strategy

    @defaultdispatch
    def visitCode(self, node):
        """
        Visit a code node and replace children with transformed versions.
        
        Args:
            node: Code node to process
            
        Returns:
            The node with transformed children
        """
        assert node.isCode(), type(node)
        node.replaceChildren(self.strategy)
        return node


class MutateCodeReversed(TypeDispatcher):
    """
    Mutates code nodes in reverse order.
    
    This dispatcher traverses the code tree in reverse order and replaces
    each code node's children with transformed versions. Used for backward
    data flow optimizations like dead code elimination.
    
    Attributes:
        strategy: Transformation function to apply to each code node
    """
    def __init__(self, strategy):
        """
        Initialize reverse code mutator.
        
        Args:
            strategy: Transformation function to apply
        """
        self.strategy = strategy

    @defaultdispatch
    def visitCode(self, node):
        """
        Visit a code node and replace children in reverse order.
        
        Args:
            node: Code node to process
            
        Returns:
            The node with transformed children
        """
        assert node.isCode(), type(node)
        node.replaceChildrenReversed(self.strategy)
        return node


class DynamicBase(object):
    """
    Base class for dynamic dictionaries with copy-on-write semantics.
    
    Dynamic dictionaries track flow-sensitive information (like variable values
    or liveness) that changes as control flow progresses. They use copy-on-write
    to efficiently handle branching control flow without unnecessary copying.
    
    Attributes:
        lut: Lookup table mapping keys to values
        shared: Whether this dictionary is shared (copy-on-write flag)
    """
    __slots__ = "lut", "shared"

    def __init__(self, d=None):
        """
        Initialize a dynamic dictionary.
        
        Args:
            d: Optional initial dictionary (if provided, marks as shared)
        """
        if d is None:
            self.lut = {}
            self.shared = False
        else:
            self.lut = d
            self.shared = True

    def split(self):
        """
        Create a copy of this dictionary for branching control flow.
        
        Marks this dictionary as shared and returns a new DynamicDict with
        the same lookup table. The copy will be created on first write.
        
        Returns:
            New DynamicDict sharing the same lookup table
        """
        self.shared = True
        return DynamicDict(self.lut)

    def premutate(self):
        """
        Prepare for mutation by copying if shared.
        
        If this dictionary is shared (used by multiple branches), creates
        a copy before mutation to preserve the original for other branches.
        This implements copy-on-write semantics.
        """
        if self.shared:
            self.lut = copy.copy(self.lut)
            self.shared = False


class Undefined(object):
    """
    Lattice bottom value representing "no information" or "undefined".
    
    In abstract interpretation, undefined represents the absence of information.
    It is the identity element for meet operations (undefined meet X = X).
    """
    def __str__(self):
        return "<lattice bottom>"


undefined = Undefined()


class Top(object):
    """
    Lattice top value representing "all possible values" or "unknown".
    
    In abstract interpretation, top represents complete uncertainty - the value
    could be anything. It dominates in meet operations (top meet X = top).
    """
    def __str__(self):
        return "<lattice top>"


top = Top()


class DynamicDict(DynamicBase):
    """
    Dictionary for tracking flow-sensitive information.
    
    A DynamicDict maps keys (typically variables or memory locations) to
    abstract values (like constant values or liveness information). It uses
    copy-on-write to efficiently handle branching control flow.
    
    The dictionary supports three value types:
    - undefined: No information available (lattice bottom)
    - top: All possible values (lattice top)
    - Concrete values: Specific abstract values
    
    Attributes:
        lut: Lookup table (inherited from DynamicBase)
        shared: Copy-on-write flag (inherited from DynamicBase)
    """
    __slots__ = ()

    def lookup(self, key, default=undefined):
        """
        Look up a value for a key.
        
        Args:
            key: Key to look up
            default: Default value if key not found (default: undefined)
            
        Returns:
            Value associated with key, or default if not found
        """
        if key in self.lut:
            return self.lut[key]
        else:
            return default

    def define(self, key, value):
        """
        Define a value for a key.
        
        Creates a copy if the dictionary is shared (copy-on-write), then
        sets the value. This ensures mutations don't affect other branches.
        
        Args:
            key: Key to define
            value: Value to associate with key
        """
        self.premutate()
        self.lut[key] = value

    def undefine(self, key):
        """
        Remove a key from the dictionary.
        
        Creates a copy if shared, then removes the key. This is used when
        a variable goes out of scope or is killed.
        
        Args:
            key: Key to remove
        """
        if key in self.lut:
            self.premutate()
            del self.lut[key]


def printlut(lut):
    """
    Print a lookup table for debugging.
    
    Args:
        lut: Dictionary to print
    """
    print(len(lut))

    keys = sorted(lut.keys())

    for k in keys:
        print("\t", k, lut[k])


def meet(meetF, *dynamic):
    """
    Compute the meet (greatest lower bound) of multiple dynamic dictionaries.
    
    The meet operation combines information from multiple control flow paths.
    For each key, it applies the meet function to combine values from all
    dictionaries. The result represents the most precise information that is
    true along all paths.
    
    The meet operation:
    - If any path has top, result is top (uncertainty dominates)
    - If no paths have information, result is undefined
    - Otherwise, applies meetF to combine concrete values
    
    Args:
        meetF: Meet function that combines a list of values
        *dynamic: Variable number of DynamicDict instances to meet
        
    Returns:
        tuple: (merged DynamicDict, changed flag)
               - merged: Dictionary with combined information
               - changed: True if result differs from first input
    """
    debug = 0

    # Filter out None dictionaries
    dynamic = [d for d in dynamic if d is not None]

    if not dynamic:
        return None, False
    elif len(dynamic) == 1:
        # Single input, no merging needed
        return dynamic[0], False
    else:
        if debug:
            print("Meet")
            for d in dynamic:
                printlut(d.lut)
        out = DynamicDict()
        changed = False

        # Find all the keys from all dictionaries
        keys = set(dynamic[0].lut.keys())
        for other in dynamic[1:]:
            keys.update(other.lut.keys())

        # Merge values for each key
        for key in keys:
            values = []

            for other in dynamic:
                additional = other.lookup(key)
                if additional is top:
                    # Top dominates - result is top
                    merged = top
                    break
                elif additional is not undefined:
                    # Collect concrete values
                    values.append(additional)
            else:
                # No top found, combine concrete values
                if values:
                    merged = meetF(values)
                else:
                    # No information from any path
                    merged = undefined

            if merged is not undefined:
                out.define(key, merged)

            # Check if result differs from first input
            if merged != dynamic[0].lookup(key):
                changed = True

        if debug:
            print("Out")
            printlut(out.lut)
            # Changed indicates the first dynamic frame has been modified.
        return out, changed


class FlowDict(object):
    """
    Manages flow-sensitive information across control flow contours.
    
    A FlowDict tracks abstract information (like constant values or liveness)
    as control flow progresses through a function. It handles:
    - Saving/restoring state at control flow boundaries (loops, conditionals)
    - Merging information from multiple paths (meet operations)
    - Managing nested control flow structures
    
    The dictionary uses "bags" to store information at control flow points
    (like loop headers or merge points) and merges them when paths reconverge.
    
    Attributes:
        _current: Current dynamic dictionary for the active flow contour
        bags: Dictionary mapping control flow point names to lists of DynamicDicts
        tryLevel: Nesting level of try blocks (for exception handling)
    """
    def __init__(self):
        """Initialize an empty flow dictionary."""
        self._current = DynamicDict()
        self.bags = {}
        self.tryLevel = 0

    def save(self, name):
        """
        Save the current flow state to a bag.
        
        Saves the current dynamic dictionary to a bag (control flow point)
        and clears the current state. Used when entering a control structure
        like a loop or conditional.
        
        Args:
            name: Name of the control flow point
        """
        if self._current is not None:
            if not name in self.bags:
                self.bags[name] = []
            self.bags[name].append(self._current)
            self._current = None

    def restoreDup(self, name):
        """
        Restore and duplicate state from a bag (for reverse dataflow).
        
        Restores state from a bag and creates a copy for reverse traversal.
        Used in backward data flow analysis.
        
        Args:
            name: Name of the control flow point
            
        Raises:
            AssertionError: If bag doesn't exist or has multiple entries
        """
        assert name in self.bags, name
        assert len(self.bags[name]) == 1, self.bags[name]
        self._current = self.bags[name][0].split()

    def pop(self):
        """
        Pop the current flow state.
        
        Returns the current dynamic dictionary and clears it. Used when
        exiting a control structure.
        
        Returns:
            The current dynamic dictionary (or None if already cleared)
        """
        old = self._current
        self._current = None
        return old

    def popSplit(self, count=2):
        """
        Pop and split the current state into multiple copies.
        
        Creates multiple copies of the current state for branching control
        flow (e.g., if/else branches). The first copy is the original,
        subsequent copies are created via split().
        
        Args:
            count: Number of copies to create (must be >= 2)
            
        Returns:
            List of DynamicDict instances (or None if current was None)
        """
        assert count >= 2

        old = self._current
        self._current = None

        if old is not None:
            return [old] + [old.split() for i in range(count - 1)]
        else:
            return [None for i in range(count)]

    def restore(self, dynamic):
        """
        Restore a dynamic dictionary as the current state.
        
        Args:
            dynamic: DynamicDict to restore
            
        Raises:
            AssertionError: If current state is not None
        """
        assert self._current is None
        self._current = dynamic

    def extend(self, name, bag):
        """
        Extend a bag with additional dynamic dictionaries.
        
        Adds dynamic dictionaries to an existing bag. Used to collect
        information from multiple paths that converge at a control point.
        
        Args:
            name: Name of the control flow point
            bag: List of DynamicDict instances to add
        """
        if not name in self.bags:
            self.bags[name] = []
        self.bags[name].extend(bag)

    def saveBags(self):
        """
        Save all bags and return them.
        
        Returns the current bags dictionary and clears it. Used for
        saving state before entering nested control structures.
        
        Returns:
            Dictionary of bags
        """
        old = self.bags
        self.bags = {}
        return old

    def restoreBags(self, bags):
        """
        Restore bags from a saved dictionary.
        
        Args:
            bags: Dictionary of bags to restore
        """
        self.bags = bags

    def restoreAndMergeBags(self, originalbags, newbags):
        """
        Restore original bags and merge in new bags.
        
        Restores the original bags and extends them with new bags. Used
        when exiting nested control structures.
        
        Args:
            originalbags: Original bags to restore
            newbags: New bags to merge in
        """
        self.restoreBags(originalbags)
        for name, bag in newbags.items():
            self.extend(name, bag)

    def mergeCurrent(self, meetF, name):
        """
        Merge bags at a control flow point and set as current.
        
        Merges all dynamic dictionaries in a bag using the meet function
        and sets the result as the current state. Used when paths reconverge
        (e.g., after an if/else or at a loop header).
        
        Args:
            meetF: Meet function to combine values
            name: Name of the control flow point
            
        Raises:
            AssertionError: If current state is not None
        """
        assert self._current is None

        if name in self.bags:
            bag = self.bags[name]
            del self.bags[name]
        else:
            bag = []

        self._current, changed = meet(meetF, *bag)

    def define(self, key, value):
        """
        Define a value in the current flow state.
        
        Args:
            key: Key to define
            value: Value to associate with key
            
        Raises:
            InternalError: If no current flow contour exists
        """
        ##		if self.tryLevel > 0:
        ##			print("Try", key, value)
        if self._current is None:
            raise InternalError("No flow contour exists.")

        return self._current.define(key, value)

    def lookup(self, key):
        """
        Look up a value in the current flow state.
        
        Args:
            key: Key to look up
            
        Returns:
            Value associated with key (or undefined if not found)
            
        Raises:
            InternalError: If no current flow contour exists
        """
        if self._current is None:
            raise InternalError("No flow contour exists.")
        return self._current.lookup(key)

    def undefine(self, key):
        """
        Remove a key from the current flow state.
        
        Args:
            key: Key to remove
            
        Raises:
            InternalError: If no current flow contour exists
        """
        ##		if self.tryLevel > 0:
        ##			print("Try", key, undefined)

        if self._current is None:
            raise InternalError("No flow contour exists.")

        return self._current.undefine(key)


class MayRaise(TypeDispatcher):
    """
    Determines if an AST node may raise an exception.
    
    This dispatcher analyzes AST nodes to determine if they might raise
    exceptions during execution. This information is used by optimizations
    to determine if code can be safely eliminated or reordered.
    
    Returns True if the node may raise, False if it definitely won't.
    """
    @defaultdispatch
    def default(self, node):
        """
        Default: assume node may raise (conservative).
        
        Args:
            node: AST node to check
            
        Returns:
            True (conservative assumption)
        """
        return True

    @dispatch(list, tuple)
    def visitContainer(self, node):
        """
        Check if any element in a container may raise.
        
        Args:
            node: List or tuple node
            
        Returns:
            True if any element may raise, False otherwise
        """
        for child in node:
            if self(child):
                return True
        return False

    @dispatch(ast.Existing)
    def visitExisting(self, node):
        """
        Existing objects never raise (they're constants).
        
        Args:
            node: Existing node
            
        Returns:
            False
        """
        return False

    @dispatch(ast.Local)
    def visitLocal(self, node):
        """
        Local variable access never raises.
        
        Args:
            node: Local node
            
        Returns:
            False
        """
        return False

    @dispatch(ast.BuildTuple, ast.BuildList, ast.BuildMap)
    def visitBuild(self, node):
        """
        Container construction never raises (elements are already evaluated).
        
        Args:
            node: Build node
            
        Returns:
            False
        """
        return False

    @dispatch(ast.Delete)
    def visitDelete(self, node):
        """
        Delete operations may raise, but we assume they don't.
        
        Args:
            node: Delete node
            
        Returns:
            False (HACK: assumes no undefined variables)
        """
        return False  # HACK assumes no undefined variables.

    @dispatch(ast.Assign)
    def visitAssign(self, node):
        """
        Assignment may raise if the expression raises.
        
        Args:
            node: Assign node
            
        Returns:
            True if expression may raise, False otherwise
        """
        return self(node.expr)

    @dispatch(ast.Discard)
    def visitDiscard(self, node):
        """
        Discard may raise if the expression raises.
        
        Args:
            node: Discard node
            
        Returns:
            True if expression may raise, False otherwise
        """
        return self(node.expr)

    @dispatch(ast.Continue, ast.Break)
    def visitLoopFlow(self, node):
        """
        Loop control statements never raise.
        
        Args:
            node: Continue or Break node
            
        Returns:
            False
        """
        return False

    @dispatch(ast.Return)
    def visitReturn(self, node):
        """
        Return may raise if any return expression raises.
        
        Args:
            node: Return node
            
        Returns:
            True if any expression may raise, False otherwise
        """
        return self(node.exprs)
