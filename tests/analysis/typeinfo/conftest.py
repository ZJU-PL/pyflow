"""Fixtures for typeinfo migration tests."""

from __future__ import annotations

import ast
import importlib
import inspect
import textwrap

import pytest

from pyflow.analysis.typeinfo.typesystem import TypeSystem
from pyflow.analysis.typeinfo import _config


@pytest.fixture
def type_system() -> TypeSystem:
    """Provide a plain TypeSystem."""
    return TypeSystem()


def _register_builtin_edges(ts: TypeSystem) -> None:
    """Register subclass edges for common builtin types under object."""
    object_info = ts.to_type_info(object)
    builtins = [str, int, float, complex, bytes, list, set, dict, tuple]
    for bt in builtins:
        bt_info = ts.to_type_info(bt)
        ts.add_subclass_edge(super_class=object_info, sub_class=bt_info)

    # bool inherits from int in Python MRO
    int_info = ts.to_type_info(int)
    bool_info = ts.to_type_info(bool)
    ts.add_subclass_edge(super_class=int_info, sub_class=bool_info)

    # Enable numeric tower (adds complex->float, float->int, int->bool)
    ts.enable_numeric_tower()

    # Register attributes that builtins have for find_by_attribute tests
    for bt in [str, bytes, complex, list, set, dict, tuple]:
        ts.to_type_info(bt).attributes.add("__lt__")
    for bt in [str, bytes]:
        ts.to_type_info(bt).attributes.add("isspace")


def _discover_instance_attributes(cls: type) -> set[str]:
    """Discover instance attributes set in __init__ via AST."""
    attrs: set[str] = set()
    try:
        init_source = inspect.getsource(cls.__init__)
    except (OSError, TypeError):
        return attrs
    try:
        tree = ast.parse(textwrap.dedent(init_source))
    except SyntaxError:
        return attrs
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                ):
                    attrs.add(target.attr)
    return attrs


def _build_type_system_from_module(module_name: str) -> TypeSystem:
    """Build a TypeSystem populated with class hierarchy from a fixture module.

    This replaces Pynguin's ``generate_test_cluster`` for test purposes only.
    """
    module = importlib.import_module(module_name)
    ts = TypeSystem()

    # Register builtins with MRO edges and attributes
    _register_builtin_edges(ts)

    # Register all classes from the module in definition order.
    # Use __dict__ directly to preserve source-order (inspect.getmembers sorts).
    classes: dict[str, type] = {}
    for name, obj in module.__dict__.items():
        if inspect.isclass(obj) and getattr(obj, "__module__", None) == module_name:
            classes[name] = obj
            ts.to_type_info(obj)

    object_info = ts.to_type_info(object)

    # Register subclass edges from Python's MRO
    for _name, obj in classes.items():
        type_info = ts.to_type_info(obj)
        bases = [
            b for b in obj.__bases__ if b is not object and b is not None
        ]
        if not bases:
            ts.add_subclass_edge(
                super_class=object_info, sub_class=type_info
            )
        else:
            for base in bases:
                super_info = ts.to_type_info(base)
                ts.add_subclass_edge(
                    super_class=super_info, sub_class=type_info
                )

    # Collect attributes from each class (dir + instance attrs from __init__)
    for _name, obj in classes.items():
        type_info = ts.to_type_info(obj)
        for attr_name in dir(obj):
            if not attr_name.startswith("_"):
                type_info.attributes.add(attr_name)
        for attr_name in _discover_instance_attributes(obj):
            type_info.attributes.add(attr_name)

    ts.push_attributes_down()
    return ts


@pytest.fixture(scope="module")
def subtyping_cluster():
    """Fixture that provides a type system with the subtyping fixture classes."""
    ts = _build_type_system_from_module(
        "tests.analysis.typeinfo.fixtures.types.subtyping"
    )
    # Simple namespace object to match Pynguin's cluster API
    return type("Cluster", (), {"type_system": ts})()


@pytest.fixture
def reset_settings():
    """Reset relevant _config settings before each test."""
    _config.settings.test_creation = _config.TestCreationConfig()
    _config.settings.generator_selection = _config.GeneratorSelectionConfig()
