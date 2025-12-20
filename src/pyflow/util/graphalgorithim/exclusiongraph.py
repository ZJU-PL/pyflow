"""
Exclusion graph analysis for determining mutually exclusive execution paths.

This module analyzes control flow graphs to identify when nodes are mutually
exclusive, meaning they cannot be executed on the same execution path. This
is useful for optimizations and analysis that need to understand which
branches of conditional statements exclude each other.

The analysis builds on DJ graphs to identify exclusion switches (nodes like
if-statements or switch statements) and tracks which execution paths they
enable, allowing efficient mutual exclusivity queries.
"""

from pyflow.util.graphalgorithim import djtree


class ExclusionGraph(object):
    """
    Represents exclusion relationships between nodes in a control flow graph.

    An exclusion graph tracks information about which nodes are mutually
    exclusive, i.e., cannot be reached on the same execution path. This is
    computed by analyzing exclusion switches (conditional branches) and
    tracking the paths they enable.

    Attributes
    ----------
    exInfo : dict
        Mapping from graph nodes to their ExclusionInfo objects
    """

    def __init__(self):
        """Initialize an empty exclusion graph."""
        self.exInfo = {}

    def getSwitch(self, node):
        """
        Get the exclusion switch associated with a node.

        Parameters
        ----------
        node : any
            A graph node

        Returns
        -------
        ExclusionSwitch or None
            The exclusion switch controlling this node, or None if not under
            any switch
        """
        info = self.exInfo.get(node)
        if info:
            switch = info.switch
        else:
            switch = None  # No exInfo, no switch
        return switch

    def infoNames(self, info):
        """
        Extract names (switch, element) pairs from exclusion information.

        Parameters
        ----------
        info : ExclusionInfo or None
            Exclusion information for a node

        Returns
        -------
        tuple or list
            List of (switch, element) pairs representing path identifiers
        """
        if info is None:
            names = (None,)
        else:
            names = [(info.switch, element) for element in info.mask]
        return names

    def markSwitches(self, switch, partial, complete):
        """
        Mark switch information and check for conflicts while walking up switch chain.

        Parameters
        ----------
        switch : ExclusionSwitch or None
            The switch to process
        partial : set
            Set of partially marked path identifiers
        complete : set
            Set of completely marked path identifiers

        Returns
        -------
        bool
            True if no conflicts found, False if a conflict is detected
        """
        if switch is None:
            return True

        for name in self.infoNames(switch.info):
            if name in complete:
                return False
            else:
                partial.add(name)

        # Recursively process parent switch in the dominance chain
        if switch.idom is not None:
            return self.markSwitches(switch.idom, partial, complete)
        else:
            return True

    def markLeaf(self, info, partial, complete):
        """
        Mark a leaf node's exclusion information and check for conflicts.

        Parameters
        ----------
        info : ExclusionInfo or None
            Exclusion information for the leaf node
        partial : set
            Set of partially marked path identifiers
        complete : set
            Set of completely marked path identifiers

        Returns
        -------
        bool
            True if successfully marked with no conflicts, False otherwise
        """
        for name in self.infoNames(info):
            if name in complete or name in partial:
                return False
            else:
                complete.add(name)
        return True

    def mutuallyExclusive(self, *args):
        """
        Check if the given nodes are mutually exclusive.

        Two or more nodes are mutually exclusive if they cannot be executed
        on the same execution path. This is determined by checking if their
        exclusion paths conflict.

        Parameters
        ----------
        *args : variable number of nodes
            The nodes to check for mutual exclusivity

        Returns
        -------
        bool
            True if all nodes are mutually exclusive (cannot execute together),
            False if they can execute on the same path

        Examples
        --------
        >>> # In an if-else: if branch and else branch are mutually exclusive
        >>> exg.mutuallyExclusive(if_branch, else_branch)
        True
        >>> # Nodes in the same branch are not mutually exclusive
        >>> exg.mutuallyExclusive(if_branch, node_after_if)
        False
        """
        if len(args) < 2:
            return True

        partial = set()  # Paths partially marked (under switches)
        complete = set()  # Paths completely marked (leaf nodes)

        for arg in args:
            info = self.exInfo.get(arg)

            if info is not None:
                # Mark switches in the dominance chain
                if not self.markSwitches(info.switch, partial, complete):
                    return False

            # Mark the leaf node itself
            if not self.markLeaf(info, partial, complete):
                return False

        return True


class ExclusionSwitch(object):
    """
    Represents an exclusion switch: a node that creates mutually exclusive paths.

    An exclusion switch is a control flow node (like an if-statement or
    switch statement) that has multiple successors, where each successor
    represents a mutually exclusive execution path. The switch maintains
    information about which paths (children) are enabled.

    Attributes
    ----------
    idom : ExclusionSwitch or None
        Immediate dominator switch (parent switch in the switch hierarchy)
    info : ExclusionInfo or None
        Exclusion information for this switch node
    dj : DJNode
        The DJ graph node corresponding to this switch
    lut : dict
        Lookup table mapping child nodes to their path identifiers (masks)
    """

    def __init__(self, idom, info, dj):
        """
        Initialize an exclusion switch.

        Parameters
        ----------
        idom : ExclusionSwitch or None
            Immediate dominator switch
        info : ExclusionInfo or None
            Exclusion information
        dj : DJNode
            Corresponding DJ graph node
        """
        assert idom is None or isinstance(idom, ExclusionSwitch), idom
        self.idom = idom
        self.info = info
        self.dj = dj

    def __repr__(self):
        return "exswitch(%r)" % self.dj.node

    def completeMask(self, mask):
        """
        Check if a mask covers all possible paths through this switch.

        Parameters
        ----------
        mask : set
            Set of path identifiers (elements)

        Returns
        -------
        bool
            True if mask covers all paths (len(mask) >= number of children)
        """
        return len(mask) >= len(self.lut)

    def dominates(self, other):
        """
        Check if this switch dominates another switch.

        Parameters
        ----------
        other : ExclusionSwitch
            The other switch to check

        Returns
        -------
        bool
            True if this switch dominates other
        """
        current = other
        while current is not None:
            if self is current:
                return True
            current = current.idom

        return False

    def simplify(self):
        """
        Simplify the switch hierarchy by removing redundant information.

        Updates idom to point directly to the relevant switch, removing
        intermediate nodes if the mask is complete.
        """
        if self.info is not None:
            self.idom = self.info.switch
        else:
            self.idom = None

        if self.idom is None:
            self.info = None


class ExclusionInfo(object):
    """
    Exclusion information for a node in the control flow graph.

    Tracks which exclusion switch controls this node and what path identifiers
    (mask) are associated with it. The mask represents which branches of the
    switch lead to this node.

    Attributes
    ----------
    switch : ExclusionSwitch
        The exclusion switch that controls this node
    dj : DJNode
        The DJ graph node corresponding to this node
    mask : set
        Set of path identifiers indicating which switch branches reach this node
    """

    def __init__(self, switch, dj):
        """
        Initialize exclusion information.

        Parameters
        ----------
        switch : ExclusionSwitch
            The controlling exclusion switch
        dj : DJNode
            The corresponding DJ graph node
        """
        assert isinstance(switch, ExclusionSwitch), switch
        self.switch = switch
        self.dj = dj
        self.mask = set()  # Path identifiers (typically branch indices)

    def simplify(self):
        """
        Simplify by walking up the switch hierarchy when mask is complete.

        If the mask covers all paths of the current switch, we can move up
        to the parent switch, simplifying the representation.
        """
        while self.switch and self.switch.completeMask(self.mask):
            info = self.switch.info
            if info is not None:
                self.switch = info.switch
                self.mask = info.mask
            else:
                self.switch = None
                self.mask = None

    def __repr__(self):
        return "exinfo(%r, %r)" % (self.switch, sorted(self.mask))


class ExclusionGraphBuilder(object):
    """
    Builds an exclusion graph from a control flow graph.

    Identifies exclusion switches (conditional branches), builds the exclusion
    hierarchy, and propagates path information to determine mutual exclusivity.
    """

    def __init__(self, forwardCallback, exclusionCallback):
        """
        Initialize the exclusion graph builder.

        Parameters
        ----------
        forwardCallback : callable
            Function(node) -> iterable of successor nodes
        exclusionCallback : callable
            Function(node) -> bool, returns True if node is a potential
            exclusion switch (e.g., conditional branch)
        """
        self.exgraph = ExclusionGraph()
        self.switches = {}  # DJNode -> ExclusionSwitch mapping
        self.exInfo = self.exgraph.exInfo

        self.forwardCallback = forwardCallback
        self.exclusionCallback = exclusionCallback

    def isExclusionSwitch(self, dj):
        """
        Check if a DJ node represents an exclusion switch.

        Parameters
        ----------
        dj : DJNode
            The DJ node to check

        Returns
        -------
        bool
            True if this DJ node is an exclusion switch
        """
        return dj in self.switches

    def identifyExclusionSwitch(self, dj):
        """
        Determine if a DJ node represents an exclusion switch.

        A node is an exclusion switch if:
        1. It's marked as potentially exclusive by exclusionCallback
        2. It has multiple successors (branches)
        3. It dominates at least one of its successors

        Parameters
        ----------
        dj : DJNode
            The DJ node to check

        Returns
        -------
        bool
            True if this node should be treated as an exclusion switch
        """
        # Must be a potentially exclusive node
        if self.exclusionCallback(dj.node):
            # Must have multiple children (branches)
            children = set(self.forwardCallback(dj.node))
            if len(children) > 1:
                # It must dominate at least one of its children
                # (ensures it's a proper control flow split)
                for d in dj.d:
                    if d.node in children:
                        return True
        return False

    def collectDJ(self, dj):
        """
        Recursively collect exclusion information from the DJ graph.

        Identifies exclusion switches and creates exclusion info for all nodes,
        building the switch hierarchy.

        Parameters
        ----------
        dj : DJNode
            The DJ node to process
        """
        isExclusion = self.identifyExclusionSwitch(dj)

        # Create exclusion info if we're under a switch
        if self.currentSwitch is not None:
            info = ExclusionInfo(self.currentSwitch, dj)
            self.exInfo[dj.node] = info
        else:
            info = None

        if isExclusion:
            # This is a new exclusion switch
            switch = ExclusionSwitch(self.currentSwitch, info, dj)
            self.switches[dj] = switch

            # Temporarily set as current switch and process children
            old = self.currentSwitch
            self.currentSwitch = switch

            for child in dj.d:
                self.collectDJ(child)

            self.currentSwitch = old  # Restore previous switch
        else:
            # Not a switch, just process children
            for child in dj.d:
                self.collectDJ(child)

    def collect(self, dj):
        """
        Start collection from root nodes.

        Parameters
        ----------
        dj : DJNode
            Root DJ node to start collection from
        """
        self.currentSwitch = None
        self.collectDJ(dj)

    def mark(self, dj, mask, isD=True):
        """
        Propagate path mask information through the graph.

        Marks nodes with path identifiers indicating which switch branches
        reach them. Propagates along dominance edges (d) and join edges (j).

        Parameters
        ----------
        dj : DJNode
            The DJ node to mark
        mask : set
            Set of path identifiers to propagate
        isD : bool
            True if propagating along dominance edges, False for join edges
        """
        info = self.exInfo[dj.node]
        diff = mask - info.mask  # Only propagate new identifiers

        if diff:
            info.mask.update(diff)
            if not self.isExclusionSwitch(dj):
                # Propagate to dominance children
                for d in dj.d:
                    self.mark(d, diff)

                # Propagate to join edges that are under the same switch
                for j in dj.j:
                    if info.switch is self.exgraph.getSwitch(j.node):
                        self.mark(j, diff, False)

    def childLUT(self, node):
        """
        Create a lookup table mapping child nodes to their branch indices.

        Parameters
        ----------
        node : any
            A graph node

        Returns
        -------
        dict
            Mapping from child node to set containing its branch index
        """
        lut = {}
        for i, child in enumerate(self.forwardCallback(node)):
            lut[child] = set([i])
        return lut

    def analyize(self):
        """
        Analyze the graph to propagate path masks.

        For each exclusion switch, determines which paths reach each dominated
        node and propagates this information through the graph.
        """
        for dj, switch in self.switches.items():
            # Create lookup table: child -> branch index
            lut = self.childLUT(dj.node)
            switch.lut = lut

            # Mark each dominated child with its branch identifier
            for d in dj.d:
                if d.node in lut:
                    self.mark(d, lut[d.node])

    def simplify(self, dj):
        """
        Simplify exclusion information by removing redundant switches.

        Recursively simplifies exclusion info, removing intermediate switches
        when masks are complete.

        Parameters
        ----------
        dj : DJNode
            The DJ node to simplify
        """
        if dj.node in self.exInfo:
            info = self.exInfo[dj.node]
            info.simplify()

            # Remove info if switch became None (fully simplified)
            if info.switch is None:
                del self.exInfo[dj.node]

        # Recursively simplify children
        for d in dj.d:
            self.simplify(d)

    def process(self, djs):
        """
        Complete the exclusion graph construction process.

        Performs collection, analysis, and simplification phases.

        Parameters
        ----------
        djs : list of DJNode
            Root DJ nodes to process
        """
        # Phase 1: Collect exclusion switches and create exclusion info
        for dj in djs:
            self.collect(dj)

        # Phase 2: Analyze and propagate path masks
        self.analyize()

        # Phase 3: Simplify by removing redundant information
        for dj in djs:
            self.simplify(dj)
        for switch in self.switches.values():
            switch.simplify()

    def dump(self, dj, level):
        """
        Debug method to print exclusion graph structure.

        Parameters
        ----------
        dj : DJNode
            The DJ node to print
        level : int
            Indentation level for pretty printing
        """
        indent = "    " * level

        info = self.exInfo.get(dj.node)
        if info:
            print("%s%r" % (indent, dj.node))
            if info.switch:
                print("%s%r" % (indent, info.switch))
                print("%s%r" % (indent, info.mask))

        level += 1
        for d in dj.d:
            self.dump(d, level)


def build(roots, forwardCallback, exclusionCallback):
    """
    Build an exclusion graph from a control flow graph.

    Constructs a DJ graph first, then builds the exclusion graph on top of it.

    Parameters
    ----------
    roots : iterable
        Root nodes (entry points) of the control flow graph
    forwardCallback : callable
        Function(node) -> iterable of successor nodes
    exclusionCallback : callable
        Function(node) -> bool, returns True if node is a potential
        exclusion switch

    Returns
    -------
    ExclusionGraph
        The constructed exclusion graph for mutual exclusivity queries
    """
    djs = djtree.make(roots, forwardCallback)
    egb = ExclusionGraphBuilder(forwardCallback, exclusionCallback)
    egb.process(djs)
    return egb.exgraph
