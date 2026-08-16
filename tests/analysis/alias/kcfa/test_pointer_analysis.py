# SPDX-FileCopyrightText: 2026 PyFlow Contributors
# SPDX-License-Identifier: MIT
"""Tests for the migrated PythonStAn pointer analysis module."""

from __future__ import annotations

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from pyflow.analysis.alias.kcfa import AliasStatus, PointerAnalysis
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.context import ParamContext
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import InstanceObject
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.object import ClassObject
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.type_ref import TypeRefKind
from pyflow.analysis.alias.kcfa._pythonstan.analysis.pointer.kcfa.config import Config
from pyflow.analysis.alias.kcfa._pythonstan.world.pipeline import Pipeline
from pyflow.analysis.alias.kcfa._pythonstan.world.namespace import NamespaceManager


def _module_points_to(result, name: str) -> set[str]:
    return set().union(*(
        points_to
        for binding, points_to in result.bindings_for_name(name)
        if "<module " in binding
    ))


class TestBasicPointerAnalysis:

    def test_config_from_empty_dict_uses_dataclass_defaults(self) -> None:
        assert Config.from_dict({}) == Config()

    def test_analysis_results_are_independent_of_worklist_schedule(self) -> None:
        source = """
def first(a, b):
    return a

x = object()
y = []
items = (x, y)
result = first(*items)
"""
        results = [
            PointerAnalysis(
                source,
                k=1,
                worklist_policy=policy,
                worklist_seed=seed,
            ).run().points_to("result")
            for policy, seed in (
                ("fifo", 0),
                ("lifo", 0),
                ("random", 1),
                ("random", 19),
            )
        ]

        assert all(result == results[0] for result in results[1:])

    def test_concurrent_analysis_runs_do_not_share_object_interning(self) -> None:
        sources = [
            "x = object()\ny = x",
            "x = []\ny = x",
            "x = {}\ny = x",
            "x = ()\ny = x",
        ]

        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            results = list(executor.map(lambda source: PointerAnalysis(source).run(), sources))

        for result in results:
            assert result.points_to("x") == result.points_to("y")
            assert result.points_to("x")

    def test_pointer_analysis_accepts_call_depth_above_three(self) -> None:
        result = PointerAnalysis("x = object()", k=4).run()

        assert result.points_to("x")

    def test_list_alias(self) -> None:
        source = "x = [1, 2, 3]\ny = x"
        result = PointerAnalysis(source).run()
        pts_x = result.points_to("x")
        pts_y = result.points_to("y")
        assert pts_x == pts_y
        assert len(pts_x) > 0

    def test_object_call_alias(self) -> None:
        source = "x = object()\ny = x"
        result = PointerAnalysis(source, k=1).run()
        pts_x = result.points_to("x")
        pts_y = result.points_to("y")
        assert pts_x == pts_y
        assert len(pts_x) > 0

    def test_constants(self) -> None:
        source = "x = 42\ny = 3.14"
        result = PointerAnalysis(source).run()
        pts_x = result.points_to("x")
        pts_y = result.points_to("y")
        assert len(pts_x) > 0
        assert len(pts_y) > 0
        assert pts_x != pts_y

    def test_class_instance(self) -> None:
        source = """
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

p = Point(1, 2)
q = p
"""
        result = PointerAnalysis(source, k=1).run()
        pts_p = result.points_to("p")
        pts_q = result.points_to("q")
        assert pts_p == pts_q
        assert len(pts_p) > 0

    def test_inherited_method_return_flows_to_call_target(self) -> None:
        source = """
class A:
    def m(self):
        return object()

class B(A):
    pass

b = B()
y = b.m()
"""
        result = PointerAnalysis(source, k=1).run()
        pts_y = result.points_to("y")

        assert pts_y
        assert any("AllocKind.OBJECT" in obj for obj in pts_y)

    def test_multiple_inheritance_uses_mro_first_method(self) -> None:
        source = """
class A:
    def m(self):
        return object()

class B:
    def m(self):
        return []

class C(A, B):
    pass

c = C()
y = c.m()
"""
        result = PointerAnalysis(source, k=1).run()
        pts_y = result.points_to("y")

        assert pts_y
        assert any("AllocKind.OBJECT" in obj for obj in pts_y)
        assert all("AllocKind.LIST" not in obj for obj in pts_y)

    def test_abstract_base_alternatives_are_not_simultaneous_bases(self) -> None:
        source = """
class A:
    x = object()

class B:
    x = []

Base = A
Base = B

class C(Base):
    pass

y = C.x
"""
        result = PointerAnalysis(source, k=1).run()
        pts_y = result.points_to("y")

        assert any("AllocKind.OBJECT" in obj for obj in pts_y)
        assert any("AllocKind.LIST" in obj for obj in pts_y)

        class_c = next(
            obj
            for obj in result.state._heap.objects.values()
            if isinstance(obj, ClassObject) and obj.ir.name == "C"
        )
        variants = result.state.class_variants(class_c)
        assert len(variants) == 2
        assert all(len(variant.effective_bases) == 1 for variant in variants)
        assert all(
            variant.effective_bases[0].kind is TypeRefKind.USER
            for variant in variants
        )

    def test_metaclass_conflict_does_not_publish_class_variant(self) -> None:
        source = """
class M1(type):
    pass

class M2(type):
    pass

class A(metaclass=M1):
    pass

class B(metaclass=M2):
    pass

class C(A, B):
    pass
"""
        result = PointerAnalysis(source, k=1).run()

        assert not result.points_to("C")
        class_c = next(
            obj
            for obj in result.state._heap.objects.values()
            if isinstance(obj, ClassObject) and obj.ir.name == "C"
        )
        assert not result.state.class_variants(class_c)
        assert result.state.invalid_class_variants(class_c)

    def test_most_derived_compatible_metaclass_is_selected(self) -> None:
        source = """
class M1(type):
    pass

class M2(M1):
    pass

class A(metaclass=M1):
    pass

class B(metaclass=M2):
    pass

class C(A, B):
    pass

x = C()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("x")
        class_c = next(
            obj
            for obj in result.state._heap.objects.values()
            if isinstance(obj, ClassObject) and obj.ir.name == "C"
        )
        variants = result.state.class_variants(class_c)
        assert {variant.metaclass.name for variant in variants} == {"M2"}

    def test_bare_class_annotation_does_not_cut_off_inherited_field(self) -> None:
        source = """
sentinel = object()

class B:
    x = sentinel

class C(B):
    x: int

y = C.x
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("sentinel") <= result.points_to("y")

    def test_deleted_class_field_does_not_cut_off_inherited_field(self) -> None:
        source = """
sentinel = object()

class B:
    x = sentinel

class C(B):
    x = object()
    del x

y = C.x
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("sentinel") <= result.points_to("y")

    def test_class_must_presence_with_suppressed_exception(self) -> None:
        source = """
sentinel = object()

class B:
    x = sentinel

class Suppress:
    def __enter__(self):
        return self

    def __exit__(self, typ, val, tb):
        return True

class C(B):
    with Suppress():
        raise RuntimeError
        x = object()

y = C.x
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("sentinel") <= result.points_to("y")

    def test_class_base_mro_entries(self) -> None:
        source = """
sentinel = object()

class A:
    x = sentinel

class Proxy:
    def __mro_entries__(self, bases):
        return (A,)

class C(Proxy()):
    pass

y = C.x
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y") == result.points_to("sentinel")

    def test_inconsistent_c3_is_not_treated_as_instantiable(self) -> None:
        source = """
class X:
    pass

class Y:
    pass

class A(X, Y):
    pass

class B(Y, X):
    pass

class C(A, B):
    pass

value = C()
"""
        result = PointerAnalysis(source, k=1).run()

        assert not result.points_to("C")
        assert not result.points_to("value")

    def test_local_lexical_class_base_is_resolved(self) -> None:
        source = """
def make_child():
    class Base:
        def m(self):
            return object()

    class Child(Base):
        pass

    return Child

Child = make_child()
y = Child().m()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_qualified_and_computed_class_bases_use_lowered_temporaries(self) -> None:
        source = """
class Namespace:
    pass

class Base:
    def m(self):
        return object()

ns = Namespace()
ns.Base = Base

def choose_base():
    return ns.Base

class Qualified(ns.Base):
    pass

class Computed(choose_base()):
    pass

q = Qualified().m()
c = Computed().m()
"""
        result = PointerAnalysis(source, k=1).run()

        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("q"))
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("c"))

    def test_dict_constructor_keyword_value_flows_to_subscript_load(self) -> None:
        source = '''
v = object()
d = dict(a=v)
y = d["a"]
'''
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y") == result.points_to("v")

    def test_dict_constructor_unpack_flows_to_subscript_load(self) -> None:
        source = '''
v = object()
base = {"a": v}
d = dict(**base)
y = d["a"]
'''
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y") == result.points_to("v")

    def test_function_pointer(self) -> None:
        source = """
def foo():
    return 42

f = foo
"""
        result = PointerAnalysis(source, k=1).run()
        pts_f = result.points_to("f")
        pts_foo = result.points_to("foo")
        assert len(pts_f) > 0
        assert pts_f == pts_foo

    def test_call_edges(self) -> None:
        source = """
def foo():
    return 42

x = foo()
"""
        result = PointerAnalysis(source, k=1).run()
        edges = result.call_edges()
        assert isinstance(edges, list)

    def test_empty_source(self) -> None:
        result = PointerAnalysis("pass").run()
        assert isinstance(result.points_to("x"), set)
        assert len(result.points_to("x")) == 0

    def test_uncalled_function_body_is_not_analyzed(self) -> None:
        source = """
x = [1]
def f():
    x = [2]
    return x
"""
        result = PointerAnalysis(source, k=1).run()
        bindings = result.bindings_for_name("x")
        assert len(bindings) == 1
        assert result.points_to("x") == set().union(*(pts for _, pts in bindings))

    def test_binding_ids_support_precise_points_to_queries(self) -> None:
        source = """
x = object()

def f():
    x = []
    return x

y = f()
"""
        result = PointerAnalysis(source, k=1).run()
        bindings = result.binding_ids_for_name("x")

        assert len(bindings) == 2
        precise_sets = [result.points_to(binding) for binding in bindings]
        assert all(precise_sets)
        assert precise_sets[0].isdisjoint(precise_sets[1])
        assert result.points_to_name_union("x") == set().union(*precise_sets)

    def test_completeness_aware_queries_do_not_treat_empty_as_impossible(self) -> None:
        incomplete = PointerAnalysis(
            'code = input()\nexec(code)\ny = x\n', k=1
        ).run()
        query = incomplete.points_to_query("y")

        assert query.objects == frozenset()
        assert query.complete is False
        assert query.reasons
        assert incomplete.alias_status("x", "y") is AliasStatus.UNKNOWN

        constant_exec = PointerAnalysis(
            'exec("x = object()")\ny = x\n', k=1
        ).run()
        assert constant_exec.points_to("y")
        assert constant_exec.points_to_query("y").complete is True

        complete = PointerAnalysis("a = object()\nb = []\nc = a\n", k=1).run()
        assert complete.alias_status("a", "c") is AliasStatus.ALIASES
        assert complete.alias_status("a", "b") is AliasStatus.DOES_NOT_ALIAS

    def test_incompleteness_is_scoped_to_affected_dataflow_region(self) -> None:
        source = """
safe = object()
other = []

def dynamic():
    code = input()
    exec(code)
    return created

result = dynamic()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to_query("safe").complete is True
        assert analysis.points_to_query("result").complete is False
        assert analysis.alias_status("safe", "other") is AliasStatus.DOES_NOT_ALIAS

    def test_exhaustive_native_return_effect_is_precise_and_complete(self) -> None:
        source = """
import missing_native
sentinel = object()
result = missing_native.identity(sentinel)
"""
        analysis = PointerAnalysis(
            source,
            k=1,
            native_effects=({
                "access_path": "missing_native.identity",
                "kind": "return_argument",
                "arguments": [0],
                "exhaustive": True,
            },),
        ).run()

        assert analysis.points_to("result") == analysis.points_to("sentinel")
        assert analysis.points_to_query("result").complete is True

    def test_native_write_and_escape_effects_update_heap_metadata(self) -> None:
        source = """
import missing_native

class Box:
    pass

box = Box()
sentinel = object()
missing_native.store(box, sentinel)
result = box.value
"""
        analysis = PointerAnalysis(
            source,
            k=1,
            native_effects=(
                {
                    "access_path": "missing_native.store",
                    "kind": "write_argument_field",
                    "arguments": [0],
                    "values": [1],
                    "field": "value",
                    "exhaustive": True,
                },
                {
                    "access_path": "missing_native.store",
                    "kind": "escape_argument",
                    "arguments": [0],
                    "exhaustive": True,
                },
            ),
        ).run()

        assert analysis.points_to("result") == analysis.points_to("sentinel")
        box_objects = {
            obj
            for cvar, points in analysis.state._env.items()
            if getattr(getattr(cvar, "content", None), "name", None) == "box"
            for obj in points
        }
        assert box_objects
        assert all(analysis.state.is_escaped(obj) for obj in box_objects)

    def test_return_values_remain_separate_across_call_contexts(self) -> None:
        source = """
def ident(value):
    return value

a = object()
b = []
x = ident(a)
y = ident(b)
"""
        result = PointerAnalysis(source, k=1).run()

        def module_points_to(name: str) -> set[str]:
            return set().union(*(
                pts
                for binding, pts in result.bindings_for_name(name)
                if "<module " in binding
            ))

        assert module_points_to("x") == module_points_to("a")
        assert module_points_to("y") == module_points_to("b")
        assert module_points_to("x").isdisjoint(module_points_to("y"))

    def test_explicit_nonlocal_resolves_through_lexical_scopes(self) -> None:
        source = """
def outer():
    x = object()
    def middle():
        def inner():
            nonlocal x
            return x
        return inner
    return middle()

f = outer()
y = f()
"""
        result = PointerAnalysis(source, k=1).run()

        assert result.points_to("y")
        assert any("AllocKind.OBJECT" in obj for obj in result.points_to("y"))

    def test_param_context_preserves_argument_order(self) -> None:
        source = """
def first(a, b):
    return a

x = object()
y = []
r1 = first(x, y)
r2 = first(y, x)
"""
        result = PointerAnalysis(source, context_policy="1-param").run()
        callees = [callee for _, callee in result.call_edges() if "first" in callee]

        assert len(callees) == 2
        assert len(set(callees)) == 2

    def test_pointer_stdlib_stubs_are_resolved_from_vendor_tree(
        self, monkeypatch
    ) -> None:
        from pyflow.analysis.alias.kcfa._pythonstan.world import namespace

        monkeypatch.setattr(namespace, "builtin_module_names", lambda: {"math"})
        manager = NamespaceManager()
        manager.build("/tmp", [], mock_libs=True, prefer_mock_libs=True)
        resolved = manager.resolve_import("math")
        assert resolved is not None
        _, path = resolved
        assert Path(path).resolve() == manager.mock_root / "math.py"

    def test_imported_module_attribute_flows_to_local(self, tmp_path) -> None:
        (tmp_path / "mod.py").write_text("v = object()\n", encoding="utf-8")
        entry = tmp_path / "main.py"
        entry.write_text("import mod\nx = mod.v\n", encoding="utf-8")

        pipeline = Pipeline(
            config={
                "filename": str(entry),
                "project_path": str(tmp_path),
                "library_paths": [],
                "mock_libs": True,
                "prefer_mock_libs": True,
                "lazy_ir_construction": False,
                "import_level": -1,
                "time_count": False,
                "analysis": [
                    {
                        "name": "pointer-analysis",
                        "id": "PointerAnalysis",
                        "description": "k-CFA pointer analysis",
                        "prev_analysis": ["cfg"],
                        "inter_procedure": True,
                        "options": {
                            "type": "pointer analysis",
                            "context_policy": "1-cfa",
                        },
                    }
                ],
            }
        )
        pipeline.run()
        result = pipeline.analysis_manager.get_results("pointer-analysis")
        state = result.query()._state
        pts_x = {
            str(obj)
            for cvar, pts in state._env.items()
            if getattr(getattr(cvar, "content", cvar), "name", None) == "x"
            for obj in pts
        }
        assert pts_x

    def test_constructor_param_context_preserves_argument_order(self) -> None:
        source = """
class C:
    pass

a = object()
b = []
x = C(a, b)
y = C(b, a)
"""
        result = PointerAnalysis(source, context_policy="1-param").run()
        signatures = []
        for obj, scope in result.state._internal_scope.items():
            if not isinstance(obj, InstanceObject):
                continue
            if not isinstance(scope.context, ParamContext):
                continue
            signature = scope.context.params[-1]
            signatures.append(tuple(
                entry[2].content.name
                for entry in signature
                if entry[0] == "pos"
            ))

        assert set(signatures) == {("a", "b"), ("b", "a")}

    def test_starred_positional_arguments_expand_by_position(self) -> None:
        source = """
def first(a, b):
    return a

x = object()
y = []
items = (x, y)
result = first(*items)
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("result") == analysis.points_to("x")

    def test_multiple_mapping_expansions_remain_distinct(self) -> None:
        source = """
def second(a, b):
    return b

x = object()
y = []
left = {"a": x}
right = {"b": y}
result = second(**left, **right)
"""
        analysis = PointerAnalysis(source, k=1).run()

        # Dicts are mutable, so allocation-site keys are only hints.  The
        # concrete "b" flow must be retained even if conservative generic
        # mapping flow also reaches the parameter.
        assert analysis.points_to("y") <= analysis.points_to("result")

    def test_class_assignment_does_not_leak_into_module_binding(self) -> None:
        source = """
x = object()
class C:
    x = []

module_x = x
class_x = C.x
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("module_x") == _module_points_to(analysis, "x")
        assert any("AllocKind.OBJECT" in obj for obj in analysis.points_to("module_x"))
        assert any("AllocKind.LIST" in obj for obj in analysis.points_to("class_x"))
        assert analysis.points_to("module_x").isdisjoint(analysis.points_to("class_x"))

    def test_later_assignment_makes_earlier_load_function_local(self) -> None:
        source = """
x = object()
def f():
    before = x
    x = []
    return before

result = f()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert any("AllocKind.LIST" in obj for obj in analysis.points_to("result"))
        assert all("AllocKind.OBJECT" not in obj for obj in analysis.points_to("result"))

    def test_static_method_uses_module_not_class_namespace(self) -> None:
        source = """
x = object()
class C:
    x = []

    @staticmethod
    def f():
        return x

result = C.f()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("result") == _module_points_to(analysis, "x")
        assert all("AllocKind.LIST" not in obj for obj in analysis.points_to("result"))

    def test_targetless_call_in_class_body_translates(self) -> None:
        source = """
def register():
    return object()

class C:
    register()
"""
        result = PointerAnalysis(source, k=1).run()

        assert any("register" in callee for _, callee in result.call_edges())

    def test_duplicate_positional_and_keyword_rejects_call_before_body(self) -> None:
        source = """
def f(a, b):
    return b

x = object()
y = []
z = f(x, a=y)
"""
        result = PointerAnalysis(source, k=1).run()

        assert not result.points_to("z")
        assert not any("f" in callee for _, callee in result.call_edges())
        assert any(
            detail["kind"] == "invalid_call"
            and "multiple values" in detail["message"]
            for detail in result.unknown_details()
        )

    def test_mutated_dict_shape_is_not_rejected_from_allocation_syntax(self) -> None:
        source = """
def f(a):
    return a

x = object()
d = {}
d["a"] = x
result = f(**d)
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("result") == analysis.points_to("x")
        assert not any(
            detail["kind"] == "invalid_call"
            for detail in analysis.unknown_details()
        )

    def test_unknown_star_flows_to_every_feasible_position(self) -> None:
        source = """
def f(a, *rest):
    return a

x = object()
y = []
xs = [x]
result = f(*xs, y)
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("x") <= analysis.points_to("result")
        assert analysis.points_to("y") <= analysis.points_to("result")

    def test_known_star_overflow_rejects_call_before_body(self) -> None:
        source = """
def f(a):
    return object()

x = object()
y = []
items = (x, y)
result = f(*items)
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert not analysis.points_to("result")
        assert any(
            detail["kind"] == "invalid_call"
            and "too many positional" in detail["message"]
            for detail in analysis.unknown_details()
        )

    def test_precise_new_return_does_not_include_synthetic_instance(self) -> None:
        source = """
sentinel = object()

class C:
    def __new__(cls):
        return sentinel

x = C()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("x") == analysis.points_to("sentinel")
        assert all(
            "AllocKind.INSTANCE" not in obj for obj in analysis.points_to("x")
        )

    def test_call_default_is_evaluated_when_definition_executes(self) -> None:
        source = """
x = object()

def make():
    return x

def f(a=make()):
    return a

y = f()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("y") == analysis.points_to("x")
        make_edges = [callee for _, callee in analysis.call_edges() if "make" in callee]
        assert len(make_edges) == 1

    def test_init_is_skipped_for_foreign_instance_returned_by_new(self) -> None:
        source = """
class D:
    pass

foreign = D()

class C:
    def __new__(cls):
        return foreign

    def __init__(self, required):
        self.impossible = []

x = C()
y = x.impossible
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert analysis.points_to("x") == analysis.points_to("foreign")
        assert not analysis.points_to("y")

    def test_invalid_constructor_arguments_do_not_create_instance(self) -> None:
        source = """
class C:
    def __init__(self, required):
        self.required = required

x = C()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert not analysis.points_to("x")
        assert any(
            detail["kind"] == "invalid_call"
            and "missing required" in detail["message"]
            for detail in analysis.unknown_details()
        )

    def test_custom_new_invalid_init_has_no_instance_result(self) -> None:
        source = """
class C:
    def __new__(cls):
        return object.__new__(cls)

    def __init__(self, required):
        pass

x = C()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert not analysis.points_to("x")

    def test_non_none_init_return_has_no_instance_result(self) -> None:
        source = """
class C:
    def __init__(self):
        return object()

x = C()
"""
        analysis = PointerAnalysis(source, k=1).run()

        assert not analysis.points_to("x")
        assert any(
            detail["kind"] == "invalid_call"
            and "non-None" in detail["message"]
            for detail in analysis.unknown_details()
        )
