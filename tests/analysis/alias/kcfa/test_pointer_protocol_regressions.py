"""User-facing regressions: container protocol, subscripts, and callables.

These cover results that were previously empty (or wrong) while the result
still claimed ``complete=True``, which the semantic contract forbids.
"""

import pytest

from pyflow.analysis.alias.kcfa import PointerAnalysis


def _points(result, name: str) -> set[str]:
    return result.points_to_name_union(name)


def _labels(result, name: str) -> set[str]:
    return {obj.split("@", 1)[0] for obj in _points(result, name)}


def _run(source: str, **kwargs) -> object:
    return PointerAnalysis(source, **kwargs).run()


# ---------------------------------------------------------------------------
# Subscripts
# ---------------------------------------------------------------------------


def test_negative_list_index_resolves_last_element():
    result = _run("""
first = [1]
last = [2]
items = [first, last]
r = items[-1]
""")

    assert result.complete
    assert _points(result, "r") == _points(result, "last")


def test_negative_index_through_length_expression_is_not_empty():
    result = _run("""
a = [1]
b = [2]
items = [a, b]
n = len(items)
r = items[n - 1]
""")

    # ``len(items) - 1`` is not a single constant in the abstract domain, so
    # the sound answer is every element rather than the previous empty set.
    assert _points(result, "r") == _points(result, "a") | _points(result, "b")


def test_non_constant_index_reads_all_elements():
    result = _run("""
a = [1]
b = [2]
items = [a, b]
for i in range(2):
    r = items[i]
""")

    assert result.complete
    assert _points(result, "r") == _points(result, "a") | _points(result, "b")


def test_constant_index_stays_precise():
    result = _run("""
a = [1]
b = [2]
items = [a, b]
first = items[0]
second = items[1]
""")

    assert _points(result, "first") == _points(result, "a")
    assert _points(result, "second") == _points(result, "b")


def test_unknown_mapping_key_falls_back_to_values():
    result = _run("""
a = [1]
b = [2]
d = {'a': a, 'b': b}
for i in range(2):
    r = d[i]
""")

    assert result.complete
    assert _points(result, "r") == _points(result, "a") | _points(result, "b")


def test_negative_mapping_key_is_still_a_key():
    result = _run("""
value = [1]
d = {-1: value}
r = d[-1]
""")

    assert _points(result, "r") == _points(result, "value")


# ---------------------------------------------------------------------------
# Iteration protocol
# ---------------------------------------------------------------------------


def test_mapping_iteration_yields_keys_not_values():
    result = _run("""
value = [1]
d = {'k': value}
for item in d:
    got = item
""")

    assert result.complete
    assert _points(result, "got")
    assert not (_points(result, "got") & _points(result, "value"))
    assert any("'k'" in obj for obj in _points(result, "got"))


def test_mapping_iteration_does_not_create_value_call_edges():
    result = _run("""
class Handler:
    def run(self):
        return [1]
registry = {'a': Handler()}
for name in registry:
    got = name.run()
""")

    # ``name`` is the string key; ``Handler.run`` must not be reachable from
    # the loop body.
    assert any("'a'" in obj for obj in _points(result, "name"))
    assert not _points(result, "got")


def test_list_of_mapping_yields_keys():
    result = _run("""
value = [1]
d = {'k': value}
got = list(d)[0]
""")

    assert _points(result, "got")
    assert not (_points(result, "got") & _points(result, "value"))
    assert any("'k'" in obj for obj in _points(result, "got"))


def test_tuple_of_mapping_yields_keys():
    result = _run("""
value = [1]
d = {'k': value}
got = tuple(d)[0]
""")

    assert not (_points(result, "got") & _points(result, "value"))
    assert any("'k'" in obj for obj in _points(result, "got"))


def test_user_defined_iterable_dispatches_through_dunder_iter():
    result = _run("""
class Box:
    def __iter__(self):
        return iter([[1]])

for item in Box():
    got = item
""")

    assert _points(result, "got")
    assert any("__iter__" in callee for _, callee in result.call_edges())


def test_string_iteration_is_reported_incomplete():
    result = _run("""
text = 'ab'
for ch in text:
    got = ch
""")

    assert not result.complete
    assert result.stop_reason == "semantic_incomplete"


def test_iteration_is_schedule_independent():
    source = """
value = [1]
d = {'k': value}
for item in d:
    got = item
"""
    signatures = set()
    for policy, seed in (("fifo", 0), ("lifo", 0), ("random", 7)):
        result = _run(source, worklist_policy=policy, worklist_seed=seed)
        signatures.add(tuple(sorted(_points(result, "got"))))
    assert len(signatures) == 1


# ---------------------------------------------------------------------------
# Mapping construction
# ---------------------------------------------------------------------------


def test_dict_from_zip_maps_keys_to_values():
    result = _run("""
value = [1]
d = dict(zip(['a'], [value]))
r = d['a']
""")

    assert result.complete
    assert _points(result, "r") == _points(result, "value")


def test_dict_from_pairs_maps_keys_to_values():
    result = _run("""
value = [1]
d = dict([('a', value)])
r = d['a']
""")

    assert _points(result, "r") == _points(result, "value")


def test_dict_copy_preserves_lookup():
    result = _run("""
value = [1]
d = {'a': value}
copy = dict(d)
r = copy['a']
""")

    assert _points(result, "r") == _points(result, "value")


# ---------------------------------------------------------------------------
# Callable attribute values
# ---------------------------------------------------------------------------


def test_function_assigned_to_class_is_callable():
    result = _run("""
class A:
    pass

def m(self):
    return [1]

A.m = m
r = A().m()
""")

    assert result.complete
    assert _points(result, "r")
    assert any("fn m(" in callee for _, callee in result.call_edges())


def test_function_in_instance_dict_is_not_bound():
    # Python only binds functions found on the *class*; ``obj.m = f`` stores a
    # plain callable in the instance ``__dict__`` and ``obj.m()`` raises.
    result = _run("""
class A:
    pass

def m(self):
    return [1]

a = A()
a.m = m
attr = a.m
r = a.m()
""")

    assert "fn m(" in " ".join(_points(result, "attr"))
    assert not _points(result, "r")
    assert any(detail.get("kind") == "invalid_call" for detail in result.unknown_details())


def test_rebound_class_method_keeps_both_possibilities():
    result = _run("""
class A:
    def m(self):
        return [1]

def replacement(self):
    return [2]

A.m = replacement
r = A().m()
""")

    # Flow-insensitive may-analysis: both bindings are feasible.
    assert len(_points(result, "r")) == 2


def test_class_level_function_call_passes_receiver_explicitly():
    result = _run("""
class A:
    pass

def identify(self):
    return self

A.identify = identify
r = A.identify(A())
""")

    assert _points(result, "r")
    assert any("fn identify(" in callee for _, callee in result.call_edges())


@pytest.mark.parametrize("dataclass_expr", ["class A:\n    def m(self): return [1]\nr = A().m()"])
def test_plain_methods_still_resolve(dataclass_expr):
    result = _run(dataclass_expr)
    assert result.complete
    assert _points(result, "r")


# ---------------------------------------------------------------------------
# Fail-visible modelling gaps
# ---------------------------------------------------------------------------


def test_custom_metaclass_call_delegating_to_super_resolves_instance():
    result = _run("""
class Meta(type):
    def __call__(cls, *args, **kwargs):
        return super().__call__(*args, **kwargs)

class A(metaclass=Meta):
    def __init__(self):
        self.v = [1]

r = A().v
""")

    assert result.complete
    assert _points(result, "r")
    assert any("__call__" in callee for _, callee in result.call_edges())


def test_custom_metaclass_call_controls_result_without_default_instance():
    result = _run("""
sentinel = object()

class Meta(type):
    def __call__(cls):
        return sentinel

class A(metaclass=Meta):
    pass

r = A()
""")

    assert result.complete
    assert _points(result, "r") == _points(result, "sentinel")
    assert all("AllocKind.INSTANCE" not in obj for obj in _points(result, "r"))


def test_plain_metaclass_instantiation_still_complete():
    result = _run("""
class Meta(type):
    pass

class A(metaclass=Meta):
    def __init__(self):
        self.v = [1]

r = A().v
""")

    assert result.complete
    assert _points(result, "r")


# ---------------------------------------------------------------------------
# Dynamic imports
# ---------------------------------------------------------------------------


def test_importlib_import_module_resolves_statically_loaded_module():
    result = _run("""
import importlib
import os

module = importlib.import_module("os")
r = module.path
""")

    assert result.complete
    assert _points(result, "r")


def test_importlib_import_module_loads_module_on_demand():
    result = _run("""
import importlib

module = importlib.import_module("json")
r = module.loads
""")

    assert result.complete
    assert any("loads" in obj for obj in _points(result, "r"))


def test_importlib_import_module_unknown_module_is_incomplete():
    result = _run("""
import importlib

module = importlib.import_module("pyflow_missing_module_xyz")
r = module.thing
""")

    assert not result.complete
    assert result.stop_reason == "semantic_incomplete"
