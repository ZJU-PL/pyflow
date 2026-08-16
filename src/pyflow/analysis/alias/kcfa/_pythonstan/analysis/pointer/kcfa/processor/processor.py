"""Base protocol for optional pointer-solver semantic processors."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRStatement
    from ..pointer_flow_graph import NormalNode, PointerFlowNode
    from ..state import PointerAnalysisState
    from ..context import Ctx, Scope, AbstractContext
    from ..constraints import Constraint
    from ..points_to_set import PointsToSet
    from ..object import AbstractObject
    from ..solver import PointerSolver


class Processor(ABC):
    """Provide hooks for Python semantics layered onto the core solver.

    A hook returns ``True`` when the processor handled the event.  The default
    implementations decline every event, allowing subclasses to implement only
    the allocation, call, constraint, or propagation hooks they need.
    """
    
    def handle_allocation(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', context: 'AbstractContext', constraint: 'Constraint') -> bool:
        return False
    
    def handle_call(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', constraint: 'Constraint', callee_obj: 'AbstractObject') -> bool:
        return False
    
    def handle_constraint(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', constraint: 'Constraint', pts: 'PointsToSet') -> bool:
        return False
    
    def handle_new_constraint(self, solver: 'PointerSolver', scope: 'Scope', constraint: 'Constraint') -> bool:
        return False
    
    def handle_pts(self, solver: 'PointerSolver', target: 'PointerFlowNode', scope: 'Scope', pts: 'PointsToSet') -> bool:
        return False

    def handle_new_points_to(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', pts: 'PointsToSet') -> bool:
        return False

    def handle_field_read(
        self, solver, scope, context, base_obj, field, target
    ) -> bool:
        """Install semantic lookup flow for one object/field pair."""
        return False
