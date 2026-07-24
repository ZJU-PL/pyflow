"""Combine multiple semantic processors into one ordered dispatch chain."""

from typing import List, TYPE_CHECKING, Any
from .processor import Processor

if TYPE_CHECKING:
    from ..solver import PointerSolver
    from ..pointer_flow_graph import PointerFlowNode
    from ..context import Ctx, Scope, AbstractContext
    from ..constraints import Constraint
    from ..points_to_set import PointsToSet
    

class ComposeProcessor(Processor):
    """Dispatch each solver event to the first processor that handles it.

    Processor order is significant: once a hook returns ``True``, later
    processors do not observe that event.
    """
    
    def __init__(self, processors: List[Processor]):
        self.processors = processors
    
    def add_processor(self, processor: Processor):
        self.processors.append(processor)
    
    def _call_processors(self, method_name: str, *args, **kwargs) -> bool:
        for processor in self.processors:
            if getattr(processor, method_name)(*args, **kwargs):
                return True
        return False

    def handle_allocation(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', context: 'AbstractContext', constraint: 'Constraint') -> bool:
        return self._call_processors("handle_allocation", solver, target, scope, context, constraint)
    
    def handle_call(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', constraint: 'Constraint', callee_obj: 'AbstractObject') -> bool:
        return self._call_processors("handle_call", solver, target, scope, constraint, callee_obj)
    
    def handle_constraint(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', constraint: 'Constraint', pts: 'PointsToSet') -> bool:
        return self._call_processors("handle_constraint", solver, target, scope, constraint, pts)
    
    def handle_new_constraint(self, solver: 'PointerSolver', scope: 'Scope', constraint: 'Constraint') -> bool:
        return self._call_processors("handle_new_constraint", solver, scope, constraint)
    
    def handle_pts(self, solver: 'PointerSolver', target: 'PointerFlowNode', scope: 'Scope', pts: 'PointsToSet') -> bool:
        return self._call_processors("handle_pts", solver, target, scope, pts)

    def handle_new_points_to(self, solver: 'PointerSolver', target: 'PointerFlowNode', scope: 'Scope', pts: 'PointsToSet') -> bool:
        return self._call_processors("handle_new_points_to", solver, target, scope, pts)
