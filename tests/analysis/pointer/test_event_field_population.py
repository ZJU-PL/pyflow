"""Current IRTranslator coverage for container field population."""

import ast

from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.config import Config
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.constraints import (
    AllocConstraint,
    CopyConstraint,
    StoreConstraint,
)
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.heap_model import FieldKind
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.ir_translator import IRTranslator
from pyflow.analysis.pointer._pythonstan.analysis.pointer.kcfa.object import AllocKind
from pyflow.analysis.pointer._pythonstan.ir.ir_statements import IRAssign, IRModule


def _translate_assignment(source: str):
    stmt = ast.parse(source).body[0]
    translator = IRTranslator(Config(index_sensitive=True))
    translator._current_scope = IRModule("test_module", ast.parse(""), name="test_module")
    return translator._translate_assign(IRAssign(stmt))


def _alloc_kinds(constraints):
    return [c.alloc_site.kind for c in constraints if isinstance(c, AllocConstraint)]


def _store_sources(constraints):
    return [c.source.name for c in constraints if isinstance(c, StoreConstraint)]


def _store_fields(constraints):
    return [c.field for c in constraints if isinstance(c, StoreConstraint)]


def test_list_elements_populate_generic_and_index_fields():
    constraints = _translate_assignment("tmp = [x, y, z]")

    assert _alloc_kinds(constraints) == [AllocKind.LIST]
    assert _store_sources(constraints).count("x") == 2
    assert _store_sources(constraints).count("y") == 2
    assert _store_sources(constraints).count("z") == 2
    assert any(field.kind == FieldKind.ELEMENT for field in _store_fields(constraints))
    assert any(field.kind == FieldKind.KEY and field.name == "0" for field in _store_fields(constraints))


def test_name_assignment_generates_copy_constraint():
    constraints = _translate_assignment("dst = src")

    assert constraints == [
        CopyConstraint(
            source=constraints[0].source,
            target=constraints[0].target,
        )
    ]
    assert constraints[0].source.name == "src"
    assert constraints[0].target.name == "dst"


def test_dict_values_populate_key_and_generic_fields():
    constraints = _translate_assignment('tmp = {"a": x, "b": y}')

    assert _alloc_kinds(constraints) == [AllocKind.DICT]
    assert _store_sources(constraints).count("x") == 2
    assert _store_sources(constraints).count("y") == 2
    assert any(field.kind == FieldKind.KEY and field.name == "a" for field in _store_fields(constraints))
    assert any(field.kind == FieldKind.ELEMENT for field in _store_fields(constraints))


def test_tuple_elements_populate_generic_and_index_fields():
    constraints = _translate_assignment("tmp = (a, b, c)")

    assert _alloc_kinds(constraints) == [AllocKind.TUPLE]
    assert _store_sources(constraints).count("a") == 2
    assert _store_sources(constraints).count("b") == 2
    assert _store_sources(constraints).count("c") == 2
    assert any(field.kind == FieldKind.KEY and field.name == "2" for field in _store_fields(constraints))


def test_set_elements_populate_generic_element_fields():
    constraints = _translate_assignment("tmp = {x, y}")

    assert _alloc_kinds(constraints) == [AllocKind.SET]
    assert _store_sources(constraints) == ["x", "y"]
    assert all(field.kind == FieldKind.ELEMENT for field in _store_fields(constraints))
