"""
Canonical Tree Manager for Flow-Sensitive Data Flow Analysis.

This module provides a tree-based representation for flow-sensitive values
where values may differ based on control flow conditions. Unlike BDDs which
use binary decisions, this uses n-ary trees to represent values that depend
on conditions with multiple outcomes.

**Tree Structure:**
- LeafNode: Represents a constant value (same for all paths)
- TreeNode: Represents a value that depends on a condition, with one
  branch for each possible condition value

**Key Concepts:**
- Conditions: Represent control flow decisions (e.g., if conditions)
- Canonical trees: Trees are interned (canonicalized) for efficiency
- Tree functions: Operations on trees (unary, binary, n-ary) with caching
- Simplification: Reduces trees by eliminating unreachable branches

**Use Cases:**
- Flow-sensitive value tracking
- Conditional value propagation
- Path-sensitive analysis
- Set operations with flow sensitivity
"""

import itertools
from pyflow.util.monkeypatch import xcollections


class Condition(object):
    """
    Represents a condition (control flow decision) with multiple possible values.
    
    A condition represents a point in the program where control flow can take
    different paths. Each condition has:
    - A name (for debugging/identification)
    - A unique ID (for ordering)
    - A set of possible values (e.g., True/False for if statements)
    - Masks for each value (boolean trees indicating when that value is taken)
    
    **Condition Ordering:**
    Conditions are ordered by their UID, which determines the order in which
    conditions are evaluated in tree operations. This ordering is important
    for canonicalization.
    
    Attributes:
        name: Human-readable name for the condition
        uid: Unique identifier (for ordering)
        values: List of possible values this condition can take
        mask: Dictionary mapping each value to a boolean tree indicating
              when that value is taken
    """
    __slots__ = "name", "uid", "values", "mask"

    def __init__(self, name, uid, values):
        """
        Initialize a condition.
        
        Args:
            name: Name for the condition
            uid: Unique identifier
            values: List of possible values
        """
        self.name = name
        self.uid = uid
        self.values = values

    def __repr__(self):
        return "cond(%d)" % self.uid

    def __eq__(self, other):
        return self is other

    def __hash__(self):
        return hash(self.uid)

    def __lt__(self, other):
        return self.uid < other.uid

    def __le__(self, other):
        return self.uid <= other.uid

    def __gt__(self, other):
        return self.uid > other.uid

    def __ge__(self, other):
        return self.uid >= other.uid

    def validate(self, values):
        """
        Validate that all values are in this condition's value set.
        
        Args:
            values: Values to validate
            
        Raises:
            AssertionError: If any value is not in the condition's values
        """
        for value in values:
            assert value in self.values


class ConditionManager(object):
    """
    Manages conditions and their canonical representations.
    
    Creates and caches conditions, ensuring that conditions with the same
    name use the same Condition object. Also creates mask trees for each
    condition value that can be used in tree operations.
    
    Attributes:
        conditions: Dictionary mapping condition names to Condition objects
        boolManager: Boolean tree manager (set by BoolManager factory)
    """
    def __init__(self):
        """Initialize a condition manager."""
        self.conditions = {}

    def condition(self, name, values):
        """
        Get or create a condition.
        
        If a condition with the given name exists, validates that the
        values match. Otherwise, creates a new condition with masks.
        
        Args:
            name: Condition name
            values: List of possible values
            
        Returns:
            Condition object
        """
        if name not in self.conditions:
            cond = Condition(name, len(self.conditions), list(values))

            # Create mask trees: for each value, a tree that is True
            # when that value is taken, False otherwise
            mask = {}
            size = len(cond.values)
            for i, value in enumerate(cond.values):
                mask[value] = self.boolManager.tree(
                    cond, tuple(self.boolManager.leaf(j == i) for j in range(size))
                )
            cond.mask = mask

            self.conditions[name] = cond
        else:
            cond = self.conditions[name]
            cond.validate(values)
        return cond


class AbstractNode(object):
    """
    Abstract base class for tree nodes.
    
    All tree nodes have a condition (which may be a special leaf condition)
    and support hashing for canonicalization.
    
    Attributes:
        _hash: Cached hash value
    """
    __slots__ = "_hash", "__weakref__"

    def __hash__(self):
        return self._hash

    def leaf(self):
        """Check if this is a leaf node."""
        return False

    def tree(self):
        """Check if this is a tree node."""
        return False


class LeafNode(AbstractNode):
    """
    Represents a constant value (same for all control flow paths).
    
    Leaf nodes represent values that don't depend on any condition.
    They have a special condition with UID -1 to indicate they're leaves.
    
    Attributes:
        value: The constant value
        cond: Special leaf condition (UID -1)
    """
    cond = Condition(None, -1, 0)  # Special condition for leaves

    __slots__ = "value"

    def __init__(self, value):
        """
        Initialize a leaf node.
        
        Args:
            value: The constant value
        """
        self.value = value
        self._hash = hash(value)

    def __eq__(self, other):
        """Check equality (same type and value)."""
        return self is other or (
            type(self) == type(other) and self.value == other.value
        )

    def __hash__(self):
        return self._hash

    def __repr__(self):
        return "leaf(%r)" % (self.value,)

    def iter(self, cond):
        """
        Iterate over branches for a given condition.
        
        For leaf nodes, returns the same node for all condition values
        (since the value is constant).
        
        Args:
            cond: Condition to iterate over
            
        Returns:
            Tuple of nodes (all the same for leaves)
        """
        return (self,) * len(cond.values)

    def leaf(self):
        """Check if this is a leaf node."""
        return True


class TreeNode(AbstractNode):
    """
    Represents a value that depends on a condition.
    
    Tree nodes branch on a condition, with one branch for each possible
    value of the condition. This allows representing flow-sensitive values
    that differ based on control flow.
    
    **Example:**
    If x depends on condition c (True/False):
    - TreeNode(cond=c, branches=(value_if_true, value_if_false))
    
    Attributes:
        cond: The condition this node branches on
        branches: Tuple of child nodes, one for each condition value
    """
    __slots__ = "cond", "branches"

    def __init__(self, cond, branches):
        """
        Initialize a tree node.
        
        Args:
            cond: Condition to branch on
            branches: Tuple of child nodes (must match condition value count)
            
        Raises:
            AssertionError: If branch count doesn't match condition value count
        """
        assert len(branches) == len(cond.values), "Expected %d branches, got %d." % (
            len(cond.values),
            len(branches),
        )
        self.cond = cond
        self.branches = branches
        self._hash = hash((cond, branches))

    def __eq__(self, other):
        """Check equality (same type, condition, and branches)."""
        return self is other or (
            type(self) == type(other)
            and self.cond == other.cond
            and self.branches == other.branches
        )

    def __hash__(self):
        return self._hash

    def __repr__(self):
        return "tree<%d>%r" % (self.cond.uid, self.branches)

    def iter(self, cond):
        """
        Iterate over branches for a given condition.
        
        If this node branches on the given condition, returns its branches.
        Otherwise, returns this node repeated (since it doesn't depend on
        the condition).
        
        Args:
            cond: Condition to iterate over
            
        Returns:
            Tuple of nodes (branches if matching condition, else repeated self)
        """
        if self.cond is cond:
            return self.branches
        else:
            return (self,) * len(cond.values)

    def branch(self, index):
        """
        Get a specific branch by index.
        
        Args:
            index: Index into condition values
            
        Returns:
            The branch node for that condition value
        """
        return self.branches[index]

    def tree(self):
        """Check if this is a tree node."""
        return True


class NoValue(object):
    """
    Sentinel value indicating no value provided.
    
    Used as a default parameter value to distinguish between "not provided"
    and "provided as None".
    """
    __slots__ = ()


noValue = NoValue()  # Singleton instance


class UnaryTreeFunction(object):
    """
    Applies a unary function to tree nodes with caching.
    
    This class applies a function to tree nodes, handling both leaf nodes
    (constant values) and tree nodes (conditional values). Results are
    cached to avoid recomputation.
    
    **Operation:**
    - Leaf nodes: Apply function directly to the value
    - Tree nodes: Recursively apply to each branch, then combine
    
    Attributes:
        manager: CanonicalTreeManager for creating nodes
        func: Unary function to apply (value -> value)
        cache: Cache of computed results
        cacheHit: Number of cache hits (for statistics)
        cacheMiss: Number of cache misses (for statistics)
    """
    __slots__ = ["manager", "func", "cache", "cacheHit", "cacheMiss"]

    def __init__(self, manager, func):
        """
        Initialize a unary tree function.
        
        Args:
            manager: CanonicalTreeManager instance
            func: Unary function to apply
        """
        self.manager = manager
        self.func = func
        self.cache = {}

    def compute(self, a):
        """
        Compute the function result for a tree node.
        
        Args:
            a: Input tree node
            
        Returns:
            Result tree node
        """
        if a.cond.uid == -1:
            # leaf computation: apply function directly to value
            result = self.manager.leaf(self.func(a.value))
        else:
            # tree computation: apply recursively to each branch
            branches = tuple([self._apply(branch) for branch in a.iter(a.cond)])
            result = self.manager.tree(a.cond, branches)
        return result

    def _apply(self, a):
        """
        Apply function with caching.
        
        Checks cache first, then computes if needed.
        
        Args:
            a: Input tree node
            
        Returns:
            Result tree node
        """
        # See if we've already computed this.
        key = a
        if key in self.cache:
            self.cacheHit += 1
            return self.cache[key]
        else:
            self.cacheMiss += 1

        result = self.compute(a)

        return self.cache.setdefault(key, result)

    def __call__(self, a):
        """
        Apply the function to a tree node.
        
        Args:
            a: Input tree node
            
        Returns:
            Result tree node
        """
        self.cacheHit = 0
        self.cacheMiss = 0
        result = self._apply(a)
        # print("%d/%d" % (self.cacheHit, self.cacheHit+self.cacheMiss))
        self.cache.clear()  # HACK don't retain cache between computations?
        return result


class UnaryTreeVisitor(object):
    __slots__ = ["manager", "func", "cache", "cacheHit", "cacheMiss"]

    def __init__(self, manager, func):
        self.manager = manager
        self.func = func
        self.cache = set()

    def compute(self, context, a):
        if a.cond.uid == -1:
            # leaf computation
            self.func(context, a.value)
        else:
            for branch in a.iter(a.cond):
                self._apply(context, branch)

    def _apply(self, context, a):
        # See if we've alread computed this.
        key = a
        if key in self.cache:
            self.cacheHit += 1
        else:
            self.cacheMiss += 1

        self.compute(context, a)
        self.cache.add(key)

    def __call__(self, context, a):
        self.cacheHit = 0
        self.cacheMiss = 0
        result = self._apply(context, a)
        # print("%d/%d" % (self.cacheHit, self.cacheHit+self.cacheMiss))
        self.cache.clear()  # HACK don't retain cache between computations?
        return result


class BinaryTreeFunction(object):
    """
    Applies a binary function to tree nodes with caching and optimizations.
    
    This class applies a binary function to pairs of tree nodes, with
    support for:
    - Symmetric functions (f(a,b) = f(b,a))
    - Stationary functions (f(a,a) = a)
    - Identity elements (f(a, identity) = a)
    - Null elements (f(a, null) = null)
    
    These properties enable optimizations that avoid unnecessary computation.
    
    Attributes:
        manager: CanonicalTreeManager for creating nodes
        func: Binary function to apply (value, value -> value)
        symmetric: Whether function is symmetric
        stationary: Whether f(a,a) = a
        leftIdentity: Left identity element
        rightIdentity: Right identity element
        leftNull: Left null element
        rightNull: Right null element
        cache: Cache of computed results
        cacheHit: Number of cache hits
        cacheMiss: Number of cache misses
    """
    __slots__ = [
        "manager",
        "func",
        "symmetric",
        "stationary",
        "leftIdentity",
        "rightIdentity",
        "leftNull",
        "rightNull",
        "cache",
        "cacheHit",
        "cacheMiss",
    ]

    def __init__(
        self,
        manager,
        func,
        symmetric=False,
        stationary=False,
        identity=noValue,
        leftIdentity=noValue,
        rightIdentity=noValue,
        null=noValue,
        leftNull=noValue,
        rightNull=noValue,
    ):
        """
        Initialize a binary tree function.
        
        Args:
            manager: CanonicalTreeManager instance
            func: Binary function to apply
            symmetric: Whether function is symmetric
            stationary: Whether f(a,a) = a
            identity: Identity element (if symmetric)
            leftIdentity: Left identity element
            rightIdentity: Right identity element
            null: Null element (if symmetric)
            leftNull: Left null element
            rightNull: Right null element
        """

        assert identity is noValue or isinstance(identity, LeafNode)
        assert leftIdentity is noValue or isinstance(leftIdentity, LeafNode)
        assert rightIdentity is noValue or isinstance(rightIdentity, LeafNode)

        assert null is noValue or isinstance(null, LeafNode)
        assert leftNull is noValue or isinstance(leftNull, LeafNode)
        assert rightNull is noValue or isinstance(rightNull, LeafNode)

        self.manager = manager
        self.func = func
        self.symmetric = symmetric
        self.stationary = stationary

        if symmetric or identity is not noValue:
            assert leftIdentity is noValue
            assert rightIdentity is noValue

            self.leftIdentity = identity
            self.rightIdentity = identity
        else:
            self.leftIdentity = leftIdentity
            self.rightIdentity = rightIdentity

        if symmetric or null is not noValue:
            assert leftNull is noValue
            assert rightNull is noValue

            self.leftNull = null
            self.rightNull = null
        else:
            self.leftNull = leftNull
            self.rightNull = rightNull

        self.cache = {}

    def compute(self, a, b):
        if self.stationary and a is b:
            # f(a, a) = a
            return a

        maxcond = max(a.cond, b.cond)

        if maxcond.uid == -1:
            # leaf/leaf computation
            result = self.manager.leaf(self.func(a.value, b.value))
        else:
            branches = tuple(
                [
                    self._apply(*branches)
                    for branches in zip(a.iter(maxcond), b.iter(maxcond))
                ]
            )
            result = self.manager.tree(maxcond, branches)

        return result

    def _apply(self, a, b):
        # See if we've alread computed this.
        key = (a, b)
        if key in self.cache:
            self.cacheHit += 1
            return self.cache[key]
        else:
            if self.symmetric:
                # If the function is symetric, try swaping the arguments.
                altkey = (b, a)
                if altkey in self.cache:
                    self.cacheHit += 1
                    return self.cache[altkey]

            self.cacheMiss += 1

        # Use identities to bypass computation.
        # This is not very helpful for leaf / leaf pairs, but provides
        # an earily out for branch / leaf pairs.
        if a is self.leftIdentity:
            result = b
        elif a is self.leftNull:
            result = self.leftNull
        elif b is self.rightIdentity:
            result = a
        elif b is self.rightNull:
            result = self.rightNull
        else:
            # Cache miss, no identities, must compute
            result = self.compute(a, b)

        return self.cache.setdefault(key, result)

    def __call__(self, a, b):
        self.cacheHit = 0
        self.cacheMiss = 0
        result = self._apply(a, b)
        # print("%d/%d" % (self.cacheHit, self.cacheHit+self.cacheMiss))
        self.cache.clear()  # HACK don't retain cache between computations?
        return result


class TreeFunction(object):
    def __init__(self, manager, func, multiout=False):
        self.manager = manager
        self.func = func
        self.multiout = multiout
        self.cache = {}

    def compute(self, args):
        maxcond = max(arg.cond for arg in args)

        if maxcond.uid == -1:
            # leaf/leaf computation
            unwrapped = self.func(*[arg.value for arg in args])

            if self.multiout:
                assert unwrapped is not None, (unwrapped, self.func)

                result = tuple(self.manager.leaf(res) for res in unwrapped)
            else:
                result = self.manager.leaf(unwrapped)
        else:
            branches = tuple(
                self._apply(branches)
                for branches in zip(*[arg.iter(maxcond) for arg in args])
            )

            if self.multiout:
                result = tuple(
                    [
                        self.manager.tree(maxcond, branches)
                        for branches in zip(*branches)
                    ]
                )
            else:
                result = self.manager.tree(maxcond, branches)
        return result

    def _apply(self, args):
        # See if we've alread computed this.
        key = args
        if key in self.cache:
            self.cacheHit += 1
            return self.cache[key]
        else:
            self.cacheMiss += 1

        result = self.compute(args)

        return self.cache.setdefault(key, result)

    def __call__(self, *args):
        self.cacheHit = 0
        self.cacheMiss = 0
        result = self._apply(args)
        # print("%d/%d" % (self.cacheHit, self.cacheHit+self.cacheMiss))
        self.cache.clear()  # HACK don't retain cache between computations?
        return result


class CanonicalTreeManager(object):
    """
    Manages canonical (interned) tree representations.
    
    This class provides canonical tree operations where trees with the
    same structure are represented by the same object. This enables:
    - Efficient comparison using identity (`is`)
    - Memory savings through sharing
    - Consistent tree objects across contexts
    
    **Canonicalization:**
    Uses weak caches to intern trees and leaves. Trees are canonicalized
    based on their structure (condition and branches), ensuring that
    equivalent trees are identical objects.
    
    **Tree Simplification:**
    The manager provides operations for simplifying trees:
    - ITE (if-then-else): Conditional selection
    - Restrict: Restrict a tree to specific condition values
    - Simplify: Remove unreachable branches based on domain
    
    Attributes:
        coerce: Function to coerce values to canonical form
        trees: Weak cache of tree nodes
        leaves: Weak cache of leaf nodes
        cache: Temporary cache for operations (cleared after use)
    """
    def __init__(self, coerce=None):
        """
        Initialize a canonical tree manager.
        
        Args:
            coerce: Function to coerce values (e.g., bool, frozenset)
                   If None, uses identity function
        """
        if coerce is None:
            coerce = lambda x: x
        self.coerce = coerce

        self.trees = xcollections.weakcache()
        self.leaves = xcollections.weakcache()

        self.cache = {}

    def leaf(self, value):
        """
        Create or get a canonical leaf node.
        
        Args:
            value: The constant value
            
        Returns:
            Canonical leaf node
        """
        return self.leaves[LeafNode(self.coerce(value))]

    def tree(self, cond, branches):
        """
        Create or get a canonical tree node.
        
        If all branches are the same, returns that branch instead of
        creating a tree (optimization: no need to branch if values are equal).
        
        Args:
            cond: Condition to branch on
            branches: Tuple of branch nodes
            
        Returns:
            Canonical tree node (or branch if all branches are equal)
            
        Raises:
            AssertionError: If branches is not a tuple, or if any branch
                           has a condition >= cond (violates ordering)
        """
        assert isinstance(branches, tuple), type(branches)
        for branch in branches:
            assert isinstance(branch, AbstractNode), branch
            # Ensure condition ordering: tree conditions must be > branch conditions
            assert cond > branch.cond, (cond.uid, branch.cond.uid, branches)

        # Optimization: if all branches are the same, return that branch
        first = branches[0]
        for branch in branches:
            if branch is not first:
                break
        else:
            # They're all the same, don't make a tree.
            return first

        return self.trees[TreeNode(cond, branches)]

    def _ite(self, f, a, b):
        # If f is a constant, pick either a or b.
        if f.cond.uid == -1:
            if f.value:
                return a
            else:
                return b

        # If a and b are equal, f does not matter.
        if a is b:
            return a

        # Check the cache.
        key = (f, a, b)
        if key in self.cache:
            return self.cache[key]

        # Iterate over the branches for all nodes that have uid == maxid
        maxcond = max(f.cond, a.cond, b.cond)
        iterator = zip(f.iter(maxcond), a.iter(maxcond), b.iter(maxcond))
        computed = tuple([self._ite(*args) for args in iterator])
        result = self.tree(maxcond, computed)

        self.cache[key] = result
        return result

    def ite(self, f, a, b):
        """
        If-then-else operation: returns a if f is true, b otherwise.
        
        This is the fundamental conditional operation for trees. It selects
        between two values based on a boolean condition tree.
        
        Args:
            f: Boolean tree (condition)
            a: Value tree if condition is true
            b: Value tree if condition is false
            
        Returns:
            Tree representing the conditional selection
        """
        result = self._ite(f, a, b)
        self.cache.clear()
        return result

    def _restrict(self, a, d, bound):
        """
        Internal method for restricting a tree to specific condition values.
        
        Restricts the tree by fixing certain conditions to specific values,
        effectively eliminating branches that don't match the restrictions.
        
        Args:
            a: Tree to restrict
            d: Dictionary mapping conditions to their fixed values
            bound: Minimum condition UID to consider
            
        Returns:
            Restricted tree
        """
        if a.cond < bound:
            # Early out: condition is below bound, no restriction applies
            # Should also take care of leaf cases.
            return a

        # Have we seen it before?
        if a in self.cache:
            return self.cache[a]

        index = d.get(a.cond)
        if index is not None:
            # Restrict this condition: take only the branch for the fixed value
            result = self._restrict(a.branch(index), d, bound)
        else:
            # No restriction on this condition, recursively restrict branches
            branches = tuple(
                [self._restrict(branch, d, bound) for branch in a.branches]
            )
            result = self.tree(a.cond, branches)

        self.cache[a] = result
        return result

    def restrict(self, a, d):
        """
        Restrict a tree to specific condition values.
        
        Fixes certain conditions to specific values, eliminating branches
        that don't match. This is useful for path-sensitive analysis where
        we know certain conditions must be true/false.
        
        Args:
            a: Tree to restrict
            d: Dictionary mapping conditions to their fixed values
            
        Returns:
            Restricted tree (or original if restrictions are empty)
        """
        # Empty restriction -> no change
        if not d:
            return a

        for cond, index in d.items():
            assert index in cond.values, "Invalid restriction"

        bound = min(d.keys())

        result = self._restrict(a, d, bound)
        self.cache.clear()
        return result

    def _simplify(self, domain, tree, default):
        # If the domain is constant, select between the tree and the default.
        if domain.leaf():
            if domain.value:
                return tree
            else:
                return default

        if tree.leaf():
            # Tree leaf, domain is not completely false.
            return tree

        key = (domain, tree)
        if key in self.cache:
            return self.cache[key]

        if domain.cond < tree.cond:
            branches = tuple(
                [self._simplify(domain, branch, default) for branch in tree.branches]
            )
            result = self.tree(tree.cond, branches)
        else:
            interesting = set()
            newbranches = []
            for domainbranch, treebranch in zip(
                domain.branches, tree.iter(domain.cond)
            ):
                newbranch = self._simplify(domainbranch, treebranch, default)
                newbranches.append(newbranch)

                # If the domain branch is not purely False, the data is interesting
                if not domainbranch.leaf() or domainbranch.value:
                    interesting.add(newbranch)

            if len(interesting) == 1:
                result = interesting.pop()
            else:
                result = self.tree(domain.cond, tuple(newbranches))

        self.cache[key] = result
        return result

    def simplify(self, domain, tree, default):
        """
        Simplify a tree based on a domain (reachability information).
        
        Discards information where the domain is False (unreachable).
        Unlike ROBDD simplification, tree simplification may discard only
        some branches in a node. If the remaining branches are not the same,
        discarded branches are replaced with the default value.
        
        **Difference from ROBDD:**
        ROBDD simplification doesn't need default values because with only
        two branches, discarding one eliminates the node. With n-ary trees,
        we may have multiple branches and need a default for unreachable ones.
        
        Args:
            domain: Boolean tree indicating reachability (True = reachable)
            tree: Value tree to simplify
            default: Default value for unreachable branches
            
        Returns:
            Simplified tree
            
        Note:
            TODO: In the case where domain > tree (domain has more conditions),
            it might be possible to get better results where default comes into play.
        """
        result = self._simplify(domain, tree, default)
        self.cache.clear()
        return result


def BoolManager(conditions):
    """
    Create a boolean tree manager with boolean operations.
    
    Creates a CanonicalTreeManager for boolean values with operations:
    - and_: Logical AND (symmetric, stationary, identity=True, null=False)
    - or_: Logical OR (symmetric, stationary, identity=False, null=True)
    - maybeTrue: Check if True is in a set (for three-valued logic)
    - in_: Check if object is subset of set
    
    Args:
        conditions: ConditionManager instance (gets boolManager attribute set)
        
    Returns:
        CanonicalTreeManager configured for boolean operations
    """
    manager = CanonicalTreeManager(bool)
    conditions.boolManager = manager

    manager.true = manager.leaf(True)
    manager.false = manager.leaf(False)

    manager.and_ = BinaryTreeFunction(
        manager,
        lambda l, r: l & r,
        symmetric=True,
        stationary=True,
        identity=manager.true,
        null=manager.false,
    )
    manager.or_ = BinaryTreeFunction(
        manager,
        lambda l, r: l | r,
        symmetric=True,
        stationary=True,
        identity=manager.false,
        null=manager.true,
    )

    manager.maybeTrue = UnaryTreeFunction(manager, lambda s: True in s)

    # HACK use set operations, so we don't need to create a manager for individual objects?
    manager.in_ = BinaryTreeFunction(manager, lambda o, s: o.issubset(s))

    return manager


def SetManager():
    """
    Create a set tree manager with set operations.
    
    Creates a CanonicalTreeManager for frozenset values with operations:
    - intersect: Set intersection (symmetric, stationary, null=empty)
    - union: Set union (symmetric, stationary, identity=empty)
    - flatten: Flatten a tree of sets into a single set
    
    Returns:
        CanonicalTreeManager configured for set operations
    """
    manager = CanonicalTreeManager(frozenset)

    manager.empty = manager.leaf(frozenset())

    manager.intersect = BinaryTreeFunction(
        manager, lambda l, r: l & r, symmetric=True, stationary=True, null=manager.empty
    )
    manager.union = BinaryTreeFunction(
        manager,
        lambda l, r: l | r,
        symmetric=True,
        stationary=True,
        identity=manager.empty,
    )

    manager._flatten = UnaryTreeVisitor(manager, lambda context, s: context.update(s))

    def flatten(t):
        """
        Flatten a tree of sets into a single set.
        
        Collects all sets from all branches of the tree and unions them.
        
        Args:
            t: Tree of sets
            
        Returns:
            Set containing all elements from all branches
        """
        s = set()
        manager._flatten(s, t)
        return s

    manager.flatten = flatten

    return manager
