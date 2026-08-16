from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.config import Config
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.constraints import AllocConstraint, CallConstraint, CopyConstraint
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.heap_model import attr
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import (
    AllocKind,
    AllocSite,
    NativeObject,
    ObjectFactory,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.points_to_set import PointsToSet
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.pointer_flow_graph import NormalNode
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.processor import Processor
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.processor.normal_call import NormalCallProcessor
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

    def handle_new_points_to(self, solver, target, scope, pts):
        return False

    def handle_pts(self, solver, target, scope, pts):
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
    assert solver.query().get_statistics()["complete"] is True


def test_solver_query_field_is_read_only(
    module_scope, simple_context, object_factory
):
    solver, state, _processor = _solver(module_scope)
    obj = object_factory()
    value = object_factory(AllocKind.LIST)
    field = attr("value")

    assert solver.query().get_field(obj, field).is_empty()
    assert state.has_field(module_scope, simple_context, obj, field) is None

    field_ctx = state.raw_field(module_scope, simple_context, obj, field)
    state.set_points_to(field_ctx, PointsToSet.singleton(value))

    assert set(solver.query().get_field(obj, field)) == {value}


def test_frontend_failure_is_distinct_from_fixpoint_completion(module_scope):
    solver, _state, _processor = _solver(module_scope)
    solver.mark_frontend_incomplete()

    solver.solve_to_fixpoint()
    stats = solver.query().get_statistics()

    assert stats["fixpoint_complete"] is True
    assert stats["frontend_complete"] is False
    assert stats["semantic_complete"] is True
    assert stats["complete"] is False


def test_budget_exhaustion_makes_negative_alias_answer_conservative(
    module_scope, simple_context
):
    state = PointerAnalysisState()
    solver = PointerSolver(state, Config(max_iterations=1), RecordingProcessor())
    solver.add_constraint(
        module_scope,
        simple_context,
        CopyConstraint(Variable("a"), Variable("b")),
    )
    solver.add_constraint(
        module_scope,
        simple_context,
        CopyConstraint(Variable("c"), Variable("d")),
    )

    solver.solve_to_fixpoint()
    a = state.get_variable(module_scope, simple_context, Variable("a"))
    c = state.get_variable(module_scope, simple_context, Variable("c"))

    assert solver.query().get_statistics()["complete"] is False
    assert solver.query().may_alias(a, c) is True


def test_unsupported_builtin_gets_unknown_result_and_diagnostic(
    module_scope, simple_context, call_site_factory
):
    solver, state, _processor = _solver(module_scope)
    call = CallConstraint(
        callee=Variable("unsupported"),
        args=(),
        kwargs=(),
        target=Variable("result"),
        call_site=call_site_factory(),
    )
    builtin = ObjectFactory.create_builtin_function("unsupported", simple_context)

    assert NormalCallProcessor()._handle_builtin_call(
        solver, module_scope, simple_context, call, builtin
    )
    scope, node, pts = state._worklist.pop()
    solver._apply_dynamic(scope, node, pts)

    target = state.get_variable(module_scope, simple_context, Variable("result"))
    assert not state.get_points_to(target).is_empty()
    assert solver.query().get_unknown_summary()["unknown_unknown_builtin"] == 1
    assert solver.query().get_statistics()["semantic_complete"] is False


def test_unmodeled_native_call_marks_semantics_incomplete(
    module_scope, simple_context, call_site_factory
):
    solver, _state, _processor = _solver(module_scope)
    call = CallConstraint(
        callee=Variable("native"),
        args=(Variable("argument"),),
        kwargs=(),
        target=Variable("result"),
        call_site=call_site_factory(),
    )
    native = NativeObject(
        simple_context,
        AllocSite("<native:test.identity>", AllocKind.NATIVE),
        "test.identity",
    )

    solver._handle_native_call(module_scope, simple_context, call, native)

    assert solver.query().get_statistics()["semantic_complete"] is False


def test_core_fixed_point_is_independent_of_worklist_schedule(
    module_scope, simple_context, alloc_site_factory
):
    def solve(policy, seed=0):
        state = PointerAnalysisState(
            worklist_policy=policy,
            worklist_seed=seed,
        )
        solver = PointerSolver(
            state,
            Config(max_iterations=100, worklist_policy=policy, worklist_seed=seed),
            Processor(),
        )
        first_site = alloc_site_factory(AllocKind.OBJECT)
        second_site = alloc_site_factory(AllocKind.LIST)
        for constraint in (
            AllocConstraint(Variable("a"), first_site),
            AllocConstraint(Variable("b"), second_site),
            CopyConstraint(Variable("a"), Variable("out")),
            CopyConstraint(Variable("b"), Variable("out")),
        ):
            solver.add_constraint(module_scope, simple_context, constraint)
        solver.solve_to_fixpoint()
        out = state.get_variable(module_scope, simple_context, Variable("out"))
        return {obj.kind for obj in state.get_points_to(out)}

    expected = solve("fifo")
    assert solve("lifo") == expected
    assert solve("random", 1) == expected
    assert solve("random", 17) == expected


def test_random_schedule_interleaves_all_solver_queue_classes(
    module_scope, simple_context, object_factory
):
    def agenda_order(seed):
        state = PointerAnalysisState(
            worklist_policy="random", worklist_seed=seed
        )
        solver = PointerSolver(
            state,
            Config(
                max_iterations=10,
                worklist_policy="random",
                worklist_seed=seed,
            ),
            Processor(),
        )
        events = []
        state._static_constraints.append((
            module_scope,
            simple_context,
            CopyConstraint(Variable("a"), Variable("b")),
        ))
        state.dependencies.subscribe(
            "agenda-dependency",
            (),
            lambda: events.append("dependency"),
            run_initial=True,
        )
        dynamic_var = state.get_variable(
            module_scope, simple_context, Variable("dynamic")
        )
        state._worklist.add((
            module_scope,
            NormalNode(dynamic_var),
            PointsToSet.singleton(object_factory()),
        ))
        solver._apply_static = (
            lambda *_args: events.append("static") or state
        )
        solver._apply_dynamic = (
            lambda *_args: events.append("dynamic") or state
        )

        for _ in range(3):
            next(solver)
        return tuple(events)

    orders = {agenda_order(seed) for seed in range(20)}

    assert all(set(order) == {"static", "dependency", "dynamic"} for order in orders)
    assert len(orders) > 1
