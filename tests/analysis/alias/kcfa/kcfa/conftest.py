"""Fixtures for the migrated PythonStAn k-CFA pointer analysis tests."""

import ast

import pytest

from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa import (
    AbstractContext,
    AbstractObject,
    AllocKind,
    AllocSite,
    CallSite,
    CallStringContext,
    ConstraintManager,
    ContextSelector,
    Field,
    FieldKind,
    PointerAnalysisState,
    PointsToSet,
    Scope,
    Variable,
    VariableKind,
)
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import ModuleObject
from pyflow.analysis.alias.kcfa._pythonstan.ir.ir_statements import IRAssign, IRModule, IRAstStmt


@pytest.fixture
def empty_context() -> AbstractContext:
    return CallStringContext((), 0)


@pytest.fixture
def simple_context() -> AbstractContext:
    return CallStringContext((), 2)


@pytest.fixture
def ir_stmt_factory():
    counter = {"count": 0}

    def _make_stmt(source: str | None = None):
        counter["count"] += 1
        if source is None:
            source = f"x_{counter['count']} = object()"
        node = ast.parse(source).body[0]
        node.lineno = counter["count"]
        node.col_offset = 0
        return IRAstStmt(node)

    return _make_stmt


@pytest.fixture
def call_site_factory(ir_stmt_factory):
    counter = {"count": 0}

    def _make_call_site(scope_name: str = "test_module") -> CallSite:
        counter["count"] += 1
        return CallSite(ir_stmt_factory(f"r_{counter['count']} = f()"), scope_name, counter["count"])

    return _make_call_site


@pytest.fixture
def context_with_calls(call_site_factory) -> CallStringContext:
    ctx = CallStringContext((), 2)
    return ctx.append(call_site_factory("caller1")).append(call_site_factory("caller2"))


@pytest.fixture
def module_ir() -> IRModule:
    return IRModule("test_module", ast.parse(""), name="test_module")


@pytest.fixture
def module_scope(module_ir, simple_context) -> Scope:
    alloc = AllocSite(module_ir, AllocKind.MODULE)
    obj = ModuleObject(simple_context, alloc, module_ir)
    return Scope.new(obj, None, simple_context, module_ir)


@pytest.fixture
def function_scope(module_scope) -> Scope:
    return module_scope


@pytest.fixture
def method_scope(module_scope) -> Scope:
    return module_scope


@pytest.fixture
def variable_factory():
    def _make_var(
        name: str,
        scope: Scope | None = None,
        context: AbstractContext | None = None,
        kind: VariableKind = VariableKind.LOCAL,
    ) -> Variable:
        return Variable(name, kind)

    return _make_var


@pytest.fixture
def alloc_site_factory(ir_stmt_factory):
    def _make_alloc(
        kind: AllocKind = AllocKind.OBJECT,
        name: str | None = None,
        file: str = "test.py",
    ) -> AllocSite:
        del name, file
        return AllocSite(ir_stmt_factory(), kind)

    return _make_alloc


@pytest.fixture
def object_factory(alloc_site_factory, simple_context):
    def _make_obj(
        kind: AllocKind = AllocKind.OBJECT,
        name: str | None = None,
        context: AbstractContext | None = None,
    ) -> AbstractObject:
        del name
        return AbstractObject(context or simple_context, alloc_site_factory(kind))

    return _make_obj


@pytest.fixture
def field_factory():
    def _make_field(kind: FieldKind = FieldKind.ATTRIBUTE, name: str | None = None) -> Field:
        return Field(kind, name if kind == FieldKind.ATTRIBUTE else None)

    return _make_field


@pytest.fixture
def pts_factory(object_factory):
    def _make_pts(*kinds: AllocKind) -> PointsToSet:
        if not kinds:
            return PointsToSet.empty()
        return PointsToSet.from_objects(object_factory(kind) for kind in kinds)

    return _make_pts


@pytest.fixture
def empty_state(module_scope) -> PointerAnalysisState:
    state = PointerAnalysisState()
    state.global_scope = module_scope
    return state


@pytest.fixture
def state_with_data(empty_state, module_scope, variable_factory, object_factory):
    x = variable_factory("x")
    y = variable_factory("y")
    empty_state.set_points_to(
        module_scope,
        x,
        PointsToSet.singleton(object_factory(AllocKind.OBJECT)),
    )
    empty_state.set_points_to(
        module_scope,
        y,
        PointsToSet.singleton(object_factory(AllocKind.LIST)),
    )
    return empty_state


@pytest.fixture
def constraint_manager() -> ConstraintManager:
    return ConstraintManager()


@pytest.fixture
def context_selector() -> ContextSelector:
    return ContextSelector()
