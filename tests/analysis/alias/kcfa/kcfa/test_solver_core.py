from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.config import Config
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.constraints import AllocConstraint, CopyConstraint
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import AllocKind
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.solver import PointerSolver
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.state import PointerAnalysisState
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.variable import Variable


class RecordingProcessor:
    def __init__(self):
        self.constraints = []

    def handle_new_constraint(self, solver, scope, constraint):
        self.constraints.append((solver, scope, constraint))

    def process_new_points_to(self, solver, scope, node, pts):
        return None


def _solver(module_scope):
    state = PointerAnalysisState()
    processor = RecordingProcessor()
    solver = PointerSolver(state, Config(max_iterations=10), processor)
    return solver, state, processor


def test_solver_requires_current_constructor_dependencies(module_scope):
    solver, state, processor = _solver(module_scope)

    assert solver.state is state
    assert solver.processor is processor
    assert solver.config.max_iterations == 10


def test_add_alloc_constraint_records_static_constraint(module_scope, simple_context, alloc_site_factory):
    solver, state, processor = _solver(module_scope)
    constraint = AllocConstraint(Variable("x"), alloc_site_factory(AllocKind.OBJECT))

    solver.add_constraint(module_scope, simple_context, constraint)

    assert processor.constraints[-1] == (solver, module_scope, constraint)
    assert state._static_constraints == [(module_scope, simple_context, constraint)]


def test_add_copy_constraint_records_static_constraint(module_scope, simple_context):
    solver, state, _processor = _solver(module_scope)
    constraint = CopyConstraint(Variable("src"), Variable("dst"))

    solver.add_constraint(module_scope, simple_context, constraint)

    assert state._static_constraints == [(module_scope, simple_context, constraint)]


def test_empty_solver_fixpoint_terminates(module_scope):
    solver, _state, _processor = _solver(module_scope)

    solver.solve_to_fixpoint()

    assert solver._stats["iterations"] == 0
