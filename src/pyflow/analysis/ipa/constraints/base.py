"""Base constraint class for IPA constraint system.

This module provides the base Constraint class that all IPA constraints
inherit from. Constraints model data flow relationships between nodes
in the inter-procedural analysis.
"""

class Constraint(object):
    """Base class for all IPA constraints.
    
    Constraints represent data flow relationships in the inter-procedural
    analysis. They connect constraint nodes and propagate value changes.
    
    Subclasses implement:
    - attach(): Connect constraint to nodes
    - makeConsistent(): Initialize constraint state
    - changed(): Handle value changes
    - criticalChanged(): Handle critical value changes
    """
    __slots__ = ()

    def init(self, context):
        """Initialize constraint in a context.
        
        Attaches constraint to nodes and makes it consistent with current
        node states.
        
        Args:
            context: Context to initialize constraint in
        """
        self.attach()
        self.makeConsistent(context)

    def isCopy(self):
        """Check if this is a copy constraint.
        
        Returns:
            bool: True if CopyConstraint
        """
        return False

    def isLoad(self):
        """Check if this is a load constraint.
        
        Returns:
            bool: True if LoadConstraint
        """
        return False

    def isStore(self):
        """Check if this is a store constraint.
        
        Returns:
            bool: True if StoreConstraint
        """
        return False

    def isSplit(self):
        """Check if this is a split constraint.
        
        Returns:
            bool: True if SplitConstraint
        """
        return False
