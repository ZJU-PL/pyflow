from typing import TYPE_CHECKING, Any
from .processor import Processor
from ..points_to_set import PointsToSet
from ..constraints import SuperResolveConstraint, AllocConstraint
from ..object import SuperObject, AllocKind
from pyflow.analysis.pointer._pythonstan.ir.ir_statements import IRCall

if TYPE_CHECKING:
    from ..pointer_flow_graph import NormalNode
    from ..solver import PointerSolver
    from ..context import AbstractContext, Ctx, Scope
    from ..constraints import Constraint


class SuperResolveProcessor(Processor):    
    def handle_allocation(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', context: 'AbstractContext', c: AllocConstraint) -> bool:
        if c.alloc_site.kind != AllocKind.OBJECT:
            return False
        if not self._is_super_alloc(solver, target, c):
            return False
        super_obj = SuperObject(context=context, alloc_site=c.alloc_site, current_class=None, instance_obj=None)
        solver.state._heap.set_obj(scope, context, c.alloc_site, super_obj)
        solver.state.obj_scope[super_obj] = scope
        solver.handle_new_points_to(target, scope, PointsToSet.singleton(super_obj))
        return True

    def handle_constraint(self, solver: 'PointerSolver', target: 'Ctx[Any]', scope: 'Scope', constraint: 'Constraint', pts: 'PointsToSet') -> bool:
        if isinstance(constraint, SuperResolveConstraint):
            return self._apply_super_resolve(solver, scope, target, constraint, pts)
        return False

    def handle_new_constraint(self, solver: 'PointerSolver', scope: 'Scope', constraint: 'Constraint') -> bool:
        if isinstance(constraint, SuperResolveConstraint):
            target = solver.state.get_variable(scope, scope.context, constraint.target)
            solver.state.constraints.add(scope, target, constraint)
            # If target already has objects, apply the constraint immediately
            target_pts = solver.state.get_points_to(target)
            if len(target_pts) > 0:
                self._apply_super_resolve(solver, scope, target, constraint, target_pts)
            return True
        
        return False

    def _apply_super_resolve(self, solver: 'PointerSolver', scope: 'Scope', variable: 'Ctx', c: 'SuperResolveConstraint', pts: 'PointsToSet'):
        """Apply super resolve constraint: populate SuperObject with class/instance.
        
        This constraint resolves super() arguments and creates properly initialized
        SuperObject instances:
        
        1. For explicit super(Class, obj): get class and instance from variables
        2. For implicit super(): look up __class__ cell var and first param
        3. Create SuperObject with current_class and instance_obj set
        4. Add to target variable's points-to set via worklist
        
        The resolved SuperObject then works with state.get_field() for MRO-based
        field resolution via InheritanceConstraint.
        """
        from ..object import SuperObject, ObjectFactory, ClassObject, InstanceObject, MethodObject
        from ..variable import Variable, VariableKind
        from pyflow.analysis.pointer._pythonstan.ir.ir_statements import IRFunc
        
        context = scope.context
        current_class = None
        instance_obj = None
        
        if not c.implicit:
            # Explicit super(Class, instance) - resolve from provided variables
            if c.class_var:
                class_var = solver.state.get_variable(scope, context, c.class_var)
                class_pts = solver.state.get_points_to(class_var)
                for obj in class_pts:
                    if isinstance(obj, ClassObject):
                        current_class = obj
                        break
            
            if c.instance_var:
                instance_var = solver.state.get_variable(scope, context, c.instance_var)
                instance_pts = solver.state.get_points_to(instance_var)
                for obj in instance_pts:
                    # Accept any object as instance (InstanceObject or others)
                    instance_obj = obj
                    break
        else:
            # Implicit super(): resolve from method context when possible
            if isinstance(scope.obj, MethodObject):
                current_class = scope.obj.class_obj
                instance_obj = scope.obj.instance_obj
            
            if current_class is None:
                class_var = Variable(name="__class__", kind=VariableKind.CELL)
                class_ctx = solver.state.get_variable(scope, context, class_var)
                class_pts = solver.state.get_points_to(class_ctx)
                for obj in class_pts:
                    if isinstance(obj, ClassObject):
                        current_class = obj
                        break
            
            if instance_obj is None and isinstance(scope.stmt, IRFunc):
                if scope.stmt.args and scope.stmt.args.args:
                    param_name = scope.stmt.args.args[0].arg
                    self_var = Variable(name=param_name, kind=VariableKind.LOCAL)
                    self_ctx = solver.state.get_variable(scope, context, self_var)
                    instance_pts = solver.state.get_points_to(self_ctx)
                    for obj in instance_pts:
                        instance_obj = obj
                        break
        
        # For each generic SuperObject allocation in pts, create resolved version
        target_var = solver.state.get_variable(scope, context, c.target)
        for super_alloc in pts:
            if not isinstance(super_alloc, SuperObject):
                continue
            # Create SuperObject with resolved class and instance
            resolved_super = ObjectFactory.create_super(
                context=super_alloc.context,
                stmt=super_alloc.alloc_site.stmt,
                current_class=current_class,
                instance_obj=instance_obj
            )
            
            # Add resolved super object to target's points-to set via worklist
            solver.handle_new_points_to(target_var, scope, PointsToSet.singleton(resolved_super))

    def _is_super_alloc(self, solver: 'PointerSolver', target: 'Ctx[Any]', c: AllocConstraint) -> bool:
        if isinstance(c.alloc_site.stmt, IRCall) and c.alloc_site.stmt.func_name == "super":
            return True
        for _, constraint in solver.state.constraints.iter_scoped_by_variable(target):
            if isinstance(constraint, SuperResolveConstraint):
                return True
        return False
 