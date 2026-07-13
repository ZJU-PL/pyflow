"""Unknown resolution tracking for pointer analysis.

This module tracks unknown/unresolved calls and allocations during analysis,
providing detailed diagnostics and statistics.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional

__all__ = ["UnknownKind", "UnknownRecord", "UnknownTracker"]


class UnknownKind(Enum):
    """Categories of unknown resolution failures."""
    
    CALLEE_EMPTY = "callee_empty"
    """Call with empty points-to set"""
    
    CALLEE_NON_CALLABLE = "callee_non_callable"
    """Attempting to call non-callable object"""
    
    FUNCTION_NOT_IN_REGISTRY = "function_not_in_registry"
    """Function IR not found in registry"""
    
    MISSING_DEPENDENCIES = "missing_dependencies"
    """IR translator or context selector not available"""
    
    DYNAMIC_ATTRIBUTE = "dynamic_attribute"
    """Dynamic attribute access (getattr with variable)"""
    
    FIELD_LOAD_EMPTY = "field_load_empty"
    """Load from empty field"""
    
    IMPORT_NOT_FOUND = "import_not_found"
    """Module import resolution failed"""
    
    ALLOC_CONTEXT_FAILURE = "alloc_context_failure"
    """Context selection failed during allocation"""
    
    TRANSLATION_ERROR = "translation_error"
    """Exception during IR translation"""
    
    MISSING_ARGUMENT = "missing_argument"
    """Missing argument"""


@dataclass
class UnknownRecord:
    """Record of a single unknown resolution failure.
    
    Attributes:
        kind: Category of unknown failure
        location: Location identifier (e.g., "file.py:42" or call site ID)
        message: Descriptive message about the failure
        context: Optional additional context information
    """
    
    kind: UnknownKind
    location: str
    message: str
    context: Optional[str] = None


@dataclass
class UnknownTracker:
    """Tracks unknown resolution failures during analysis.
    
    Provides both summary statistics and detailed records of each unknown
    resolution failure for debugging and analysis quality assessment.
    
    Attributes:
        records: List of all unknown records
        counts_by_kind: Count of unknowns by category
    """
    
    records: List[UnknownRecord] = field(default_factory=list)
    counts_by_kind: Dict[UnknownKind, int] = field(default_factory=dict)
    
    def record(
        self,
        kind: UnknownKind,
        location: str,
        message: str,
        context: Optional[str] = None
    ) -> None:
        """Record an unknown resolution failure.
        
        Args:
            kind: Category of unknown failure
            location: Location identifier
            message: Descriptive message
            context: Optional additional context
        """
        record = UnknownRecord(kind, location, message, context)
        self.records.append(record)
        self.counts_by_kind[kind] = self.counts_by_kind.get(kind, 0) + 1
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary statistics of unknown resolutions.
        
        Returns:
            Dictionary with total count and counts by category
        """
        return {
            "total_unknowns": len(self.records),
            **{f"unknown_{kind.value}": count 
               for kind, count in self.counts_by_kind.items()}
        }
    
    def get_detailed_report(self) -> List[Dict]:
        """Get detailed report of all unknown resolutions.
        
        Returns:
            List of dictionaries with details of each unknown
        """
        return [
            {
                "kind": r.kind.value,
                "location": r.location,
                "message": r.message,
                "context": r.context
            }
            for r in self.records
        ]

