"""Query interface for pointer analysis results.

This module defines the protocol for querying analysis results, decoupled from
the solver implementation to avoid circular dependencies.
"""

from typing import Protocol, Set, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .variable import Variable
    from .object import AbstractObject
    from .heap_model import Field
    from .state import PointsToSet
    from pyflow.analysis.alias.kcfa._pythonstan.graph.call_graph import AbstractCallGraph

__all__ = ["ISolverQuery"]


class ISolverQuery(Protocol):
    """Protocol for querying pointer analysis results.
    
    This protocol defines the interface for retrieving analysis results
    without depending on the solver implementation.
    """
    
    def points_to(self, var: 'Variable') -> 'PointsToSet':
        """Get points-to set for variable.
        
        Args:
            var: Variable to query
        
        Returns:
            Points-to set for variable
        """
        ...
    
    def get_field(self, obj: 'AbstractObject', field: 'Field') -> 'PointsToSet':
        """Get points-to set for object field.
        
        Args:
            obj: Object to query
            field: Field to query
        
        Returns:
            Points-to set for field
        """
        ...
    
    def may_alias(self, v1: 'Variable', v2: 'Variable') -> bool:
        """Check if two variables may alias.
        
        Args:
            v1: First variable
            v2: Second variable
        
        Returns:
            True if variables may point to same object
        """
        ...
    
    def call_graph(self) -> 'AbstractCallGraph':
        """Get constructed call graph.
        
        Returns:
            Call graph
        """
        ...
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics.
        
        Returns:
            Dictionary with analysis statistics
        """
        ...

