from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.context import Ctx
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.heap_model import attr
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.variable import (
    FieldAccess,
    Variable,
    VariableFactory,
    VariableKind,
)


def test_variable_kind_matches_current_model():
    assert {kind.value for kind in VariableKind} == {
        "local",
        "parameter",
        "global",
        "nonlocal",
        "cell",
        "temporary",
    }


def test_variable_identity_is_name_and_kind_only():
    assert Variable("x") == Variable("x", VariableKind.LOCAL)
    assert Variable("x") != Variable("x", VariableKind.GLOBAL)
    assert str(Variable("tmp", VariableKind.TEMPORARY)) == "[temporary]tmp"


def test_variable_properties():
    assert Variable("x").is_local
    assert Variable("x", VariableKind.GLOBAL).is_global
    assert Variable("x", VariableKind.TEMPORARY).is_temporary
    assert Variable("x", VariableKind.CELL).is_cell
    assert Variable("x", VariableKind.NONLOCAL).is_nonlocal


def test_variable_factory_uses_current_signature():
    factory = VariableFactory()

    assert factory.make_variable("x") == Variable("x")
    assert factory.make_variable("g", VariableKind.GLOBAL).is_global


def test_field_access_uses_object_and_field(object_factory):
    obj = object_factory()
    field = attr("name")
    access = FieldAccess(obj, field)

    assert access.obj == obj
    assert access.field == field
    assert str(field) in str(access)


def test_contextual_variable_wraps_scope_and_context(module_scope, simple_context):
    var = Variable("x")
    cvar = Ctx(simple_context, module_scope, var)

    assert cvar.context == simple_context
    assert cvar.scope == module_scope
    assert cvar.content == var
