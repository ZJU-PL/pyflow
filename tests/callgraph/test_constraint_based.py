"""Tests for the constraint-style call graph engine."""

import json
import os
import tempfile
import textwrap
import unittest
import warnings

from pyflow.analysis.callgraph.ast_based import extract_call_graph as extract_call_graph_legacy
from pyflow.analysis.callgraph.constraint_based import (
    extract_call_graph_constraint,
    extract_value_flow_graph_constraint,
)
from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.callgraph.constraint_based.model import AnalysisOptions


class TestConstraintBasedPrecisionRecall(unittest.TestCase):
    def test_assignment_without_call_reduces_false_positive(self):
        source = textwrap.dedent(
            """
            def foo():
                return 1

            alias = foo
            """
        )

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertIn("main.foo", legacy.get("main", set()))
        self.assertNotIn("main.foo", improved.get("main", set()))

    def test_higher_order_parameter_call_improves_recall(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def apply(fn):
                return fn()

            apply(target)
            """
        )

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertNotIn("main.target", legacy.get("main.apply", set()))
        self.assertIn("main.target", improved.get("main.apply", set()))

    def test_dynamic_dispatch_tracks_runtime_receiver_types(self):
        source = textwrap.dedent(
            """
            class Base:
                def f(self):
                    return 1

            class Child(Base):
                def f(self):
                    return 2

            class Other:
                def f(self):
                    return 3

            def run(x):
                return x.f()

            run(Base())
            run(Child())
            """
        )

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertNotIn("main.Base.f", legacy.get("main.run", set()))
        self.assertIn("main.Base.f", improved.get("main.run", set()))
        self.assertIn("main.Child.f", improved.get("main.run", set()))
        self.assertNotIn("main.Other.f", improved.get("main.run", set()))

    def test_parameter_annotation_filters_incompatible_runtime_receiver_types(self):
        source = textwrap.dedent(
            """
            class A:
                def f(self):
                    return 1

            class B:
                def f(self):
                    return 2

            def call_a(x: A):
                return x.f()

            call_a(A())
            call_a(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        call_edges = improved.get("main.call_a", set())
        self.assertIn("main.A.f", call_edges)
        self.assertNotIn("main.B.f", call_edges)

    def test_protocol_annotation_prunes_by_structural_membership(self):
        source = textwrap.dedent(
            """
            from typing import Protocol

            class SupportsF(Protocol):
                def f(self):
                    ...

            class A:
                def f(self):
                    return 1

            class B:
                def g(self):
                    return 2

            def run(x: SupportsF):
                return x.f()

            run(A())
            run(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.g", run_edges)

    def test_typing_cast_refines_receiver_type(self):
        source = textwrap.dedent(
            """
            from typing import cast

            class A:
                def f(self):
                    return 1

            class B:
                def f(self):
                    return 2

            def run(x):
                y = cast(A, x)
                return y.f()

            run(A())
            run(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_import_alias_attribute_call_resolution(self):
        source = textwrap.dedent(
            """
            import math as m

            def run():
                return m.sqrt(4)

            run()
            """
        )

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertNotIn("math.sqrt", legacy.get("main.run", set()))
        self.assertIn("math.sqrt", improved.get("main.run", set()))

    def test_getattr_constant_name_resolution(self):
        source = textwrap.dedent(
            """
            class Handler:
                def handle(self):
                    return 42

            def invoke(obj):
                return getattr(obj, "handle")()

            invoke(Handler())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.Handler.handle", improved.get("main.invoke", set()))

    def test_reflective_setattr_and_dynamic_string_getattr_resolution(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            class Box:
                pass

            def install(box, suffix):
                setattr(box, "ha" + suffix, target)

            def run(box):
                return getattr(box, f"ha{'ndle'}")()

            instance = Box()
            install(instance, "ndle")
            run(instance)
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_getattr_default_value_is_used_when_attribute_is_missing(self):
        source = textwrap.dedent(
            """
            def fallback():
                return 1

            class Box:
                pass

            def run(box):
                return getattr(box, "missing", fallback)()

            run(Box())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.fallback", improved.get("main.run", set()))

    def test_context_sensitive_mode_reduces_cross_callsite_pollution(self):
        source = textwrap.dedent(
            """
            def identity(fn):
                return fn

            def call_through(fn):
                chosen = identity(fn)
                return chosen()

            def only_here():
                return 1

            def leak_from_other_site():
                return 2

            call_through(only_here)
            identity(leak_from_other_site)
            """
        )

        context_insensitive = extract_call_graph_constraint(
            source, context_sensitive=False
        ).get()
        context_sensitive = extract_call_graph_constraint(
            source, context_sensitive=True, context_depth=1
        ).get()

        insensitive_edges = context_insensitive.get("main.call_through", set())
        sensitive_edges = context_sensitive.get("main.call_through", set())

        self.assertIn("main.only_here", insensitive_edges)
        self.assertIn("main.leak_from_other_site", insensitive_edges)
        self.assertIn("main.only_here", sensitive_edges)
        self.assertNotIn("main.leak_from_other_site", sensitive_edges)

    def test_isinstance_guard_refines_union_annotated_parameter(self):
        source = textwrap.dedent(
            """
            class A:
                def f(self):
                    return 1

            class B:
                def f(self):
                    return 2

            def select(x: A | B):
                if isinstance(x, A):
                    return x.f()
                return 0

            select(A())
            select(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        select_edges = improved.get("main.select", set())
        self.assertIn("main.A.f", select_edges)
        self.assertNotIn("main.B.f", select_edges)

    def test_typeguard_function_refines_positive_branch(self):
        source = textwrap.dedent(
            """
            from typing import TypeGuard

            class A:
                def f(self):
                    return 1

            class B:
                def f(self):
                    return 2

            def is_a(x) -> TypeGuard[A]:
                return True

            def run(x: A | B):
                if is_a(x):
                    return x.f()
                return 0

            run(A())
            run(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_hasattr_guard_refines_receiver_set(self):
        source = textwrap.dedent(
            """
            class A:
                def f(self):
                    return 1

            class B:
                pass

            def run(x):
                if hasattr(x, "f"):
                    return x.f()
                return 0

            run(A())
            run(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_callable_guard_refines_callable_values(self):
        source = textwrap.dedent(
            """
            class A:
                def __call__(self):
                    return 1

            class B:
                pass

            def run(x):
                if callable(x):
                    return x()
                return 0

            run(A())
            run(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.__call__", run_edges)
        self.assertNotIn("main.B.__call__", run_edges)

    def test_partial_wrapper_preserves_underlying_call_target(self):
        source = textwrap.dedent(
            """
            from functools import partial

            def target():
                return 1

            def run():
                fn = partial(target)
                return fn()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_filter_and_sorted_key_callbacks_are_invoked(self):
        source = textwrap.dedent(
            """
            def pred():
                return True

            def key():
                return 1

            def run(xs):
                list(filter(pred, xs))
                sorted(xs, key=key)

            run([1, 2])
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.pred", run_edges)
        self.assertIn("main.key", run_edges)

    def test_reduce_callback_is_invoked(self):
        source = textwrap.dedent(
            """
            from functools import reduce

            def combine():
                return 1

            def run(xs):
                return reduce(combine, xs)

            run([1, 2])
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.combine", improved.get("main.run", set()))

    def test_singledispatch_decorator_and_register_dispatch_by_runtime_type(self):
        source = textwrap.dedent(
            """
            from functools import singledispatch

            def base_impl():
                return 1

            def a_impl():
                return 2

            class A:
                pass

            class B:
                pass

            @singledispatch
            def render(x):
                return base_impl()

            @render.register(A)
            def render_a(x):
                return a_impl()

            def run():
                render(A())
                render(B())

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.render", run_edges)
        self.assertIn("main.render_a", run_edges)
        self.assertIn("main.a_impl", improved.get("main.render_a", set()))
        self.assertIn("main.base_impl", improved.get("main.render", set()))

    def test_singledispatch_register_call_expression_records_implementation(self):
        source = textwrap.dedent(
            """
            from functools import singledispatch

            def base_impl():
                return 1

            def a_impl():
                return 2

            class A:
                pass

            @singledispatch
            def render(x):
                return base_impl()

            def render_a(x: A):
                return a_impl()

            render.register(A)(render_a)

            def run():
                return render(A())

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.render_a", run_edges)
        self.assertNotIn("main.render", run_edges)

    def test_registry_style_nested_register_call_records_callback(self):
        source = textwrap.dedent(
            """
            class App:
                pass

            app = App()

            def handler():
                return 1

            app.register("home")(handler)

            def run():
                return app["home"]()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.handler", improved.get("main.run", set()))

    def test_dict_get_dispatch_recovers_keyed_target(self):
        source = textwrap.dedent(
            """
            def a():
                return 1

            def b():
                return 2

            def run(k):
                table = {"a": a, "b": b}
                return table.get(k, b)()

            run("a")
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.a", run_edges)

    def test_registry_style_decorator_records_callback(self):
        source = textwrap.dedent(
            """
            class App:
                pass

            app = App()

            @app.register("home")
            def handler():
                return 1

            def run():
                return app["home"]()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.handler", improved.get("main.run", set()))

    def test_dict_setdefault_preserves_inserted_dispatch_target(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def run():
                table = {}
                fn = table.setdefault("k", target)
                return fn()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_dict_pop_returns_removed_dispatch_target(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def other():
                return 2

            def run():
                table = {"k": target, "x": other}
                fn = table.pop("k")
                return fn()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.target", run_edges)
        self.assertNotIn("main.other", run_edges)

    def test_match_class_pattern_refines_subject_and_capture(self):
        source = textwrap.dedent(
            """
            class A:
                def f(self):
                    return 1

            class B:
                def f(self):
                    return 2

            def run(x):
                match x:
                    case A() as value:
                        return value.f()
                    case _:
                        return 0

            run(A())
            run(B())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_c3_mro_prefers_c3_linearized_method(self):
        source = textwrap.dedent(
            """
            class A:
                def f(self):
                    return 1

            class B(A):
                pass

            class C(A):
                def f(self):
                    return 2

            class D(B, C):
                pass

            def run(x):
                return x.f()

            run(D())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.C.f", run_edges)
        self.assertNotIn("main.A.f", run_edges)

    def test_descriptor_and_callable_object_modeling(self):
        source = textwrap.dedent(
            """
            class CallableDescriptor:
                def __get__(self, obj, owner):
                    return self

                def __call__(self):
                    return helper()

            def helper():
                return 1

            class Box:
                pass

            Box.fn = CallableDescriptor()

            def run(b):
                return b.fn()

            run(Box())
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.CallableDescriptor.__get__", run_edges)
        self.assertIn("main.CallableDescriptor.__call__", run_edges)
        self.assertIn("main.helper", improved.get("main.CallableDescriptor.__call__", set()))

    def test_container_comprehension_and_closure_capture(self):
        source = textwrap.dedent(
            """
            def f1():
                return 1

            def f2():
                return 2

            def make_inner(fn):
                def inner():
                    return fn()
                return inner

            def run():
                table = [f1, f2]
                [fn() for fn in table]
                wrapped = make_inner(table[0])
                return wrapped()

            run()
            """
        )

        improved = extract_call_graph_constraint(
            source, context_sensitive=True, context_depth=1
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.f1", run_edges)
        self.assertIn("main.f2", run_edges)
        self.assertIn("main.make_inner", run_edges)
        self.assertIn("main.make_inner.inner", run_edges)
        self.assertIn("main.f1", improved.get("main.make_inner.inner", set()))

    def test_lambda_functions_are_modeled_as_concrete_call_targets(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def run():
                fn = lambda: target()
                return fn()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        lambda_edges = [edge for edge in run_edges if edge.startswith("main.run.<lambda")]
        self.assertTrue(lambda_edges, run_edges)
        for lambda_name in lambda_edges:
            self.assertIn("main.target", improved.get(lambda_name, set()))

    def test_relative_import_level_one_resolves_parent_package(self):
        builder = ConstraintCallGraphBuilder("")
        self.assertEqual(
            builder._resolve_import_module_name("pkg", "helpers", 1),
            "pkg.helpers",
        )
        self.assertEqual(
            builder._resolve_import_module_name("pkg.mod", "helpers", 1),
            "pkg.helpers",
        )
        self.assertEqual(
            builder._resolve_import_module_name("pkg.sub.mod", "helpers", 2),
            "pkg.helpers",
        )

    def test_class_attribute_lookup_uses_inherited_staticmethod(self):
        source = textwrap.dedent(
            """
            class Base:
                @staticmethod
                def f():
                    return 1

            class Child(Base):
                pass

            def run():
                return Child.f()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.Base.f", improved.get("main.run", set()))

    def test_explicit_super_type_and_obj_uses_runtime_mro(self):
        source = textwrap.dedent(
            """
            def base_fn():
                return 1

            def mixin_fn():
                return 2

            class Base:
                def f(self):
                    return base_fn()

            class Mixin:
                def f(self):
                    return mixin_fn()

            class Child(Base, Mixin):
                def f(self):
                    return super(Base, self).f()

            def run():
                return Child().f()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        child_edges = improved.get("main.Child.f", set())
        self.assertIn("main.Mixin.f", child_edges)
        self.assertNotIn("main.Base.f", child_edges)

    def test_zero_arg_super_in_classmethod_uses_runtime_cls_mro(self):
        source = textwrap.dedent(
            """
            def base_fn():
                return 1

            def child_fn():
                return 2

            class Base:
                @classmethod
                def factory(cls):
                    return base_fn()

            class Child(Base):
                @classmethod
                def factory(cls):
                    return child_fn()

            class GrandChild(Child):
                @classmethod
                def factory(cls):
                    return super().factory()

            def run():
                return GrandChild.factory()

            run()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        factory_edges = improved.get("main.GrandChild.factory", set())
        self.assertIn("main.Child.factory", factory_edges)
        self.assertNotIn("main.Base.factory", factory_edges)

    def test_star_args_are_propagated_to_callee_parameters(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def apply(fn):
                return fn()

            args = [target]
            apply(*args)
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.apply", set()))

    def test_star_kwargs_are_propagated_to_callee_parameters(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def apply(fn):
                return fn()

            kwargs = {"fn": target}
            apply(**kwargs)
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.apply", set()))

    def test_container_allocation_is_stable_across_iterations(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def apply(fn):
                return fn()

            args = [target]
            apply(args[0])
            """
        )

        builder = ConstraintCallGraphBuilder(source)
        graph = builder.build().get()
        self.assertFalse(builder.fixpoint_truncated)
        self.assertIn("main.target", graph.get("main.apply", set()))

    def test_star_import_does_not_crash_and_propagates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            mod_path = os.path.join(temp_dir, "mod.py")
            main_path = os.path.join(temp_dir, "main.py")
            with open(mod_path, "w", encoding="utf-8") as handle:
                handle.write(
                    textwrap.dedent(
                        """
                        def target():
                            return 1
                        """
                    )
                )
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write(
                    textwrap.dedent(
                        """
                        from mod import *

                        def run():
                            return target()

                        run()
                        """
                    )
                )

            with open(main_path, "r", encoding="utf-8") as handle:
                source = handle.read()
            improved = extract_call_graph_constraint(source, source_path=main_path).get()
            self.assertIn("mod.target", improved.get("main.run", set()))

    def test_classmethod_assignments_update_class_fields(self):
        source = textwrap.dedent(
            """
            def handler():
                return 1

            class C:
                @classmethod
                def setup(cls):
                    cls.fn = handler

            def run():
                C.setup()
                return C.fn()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.handler", improved.get("main.run", set()))

    def test_instance_classmethod_binds_runtime_class(self):
        source = textwrap.dedent(
            """
            def base_fn():
                return 1

            def child_fn():
                return 2

            class Base:
                @classmethod
                def factory(cls):
                    return base_fn()

                @classmethod
                def make(cls):
                    return cls.factory()

            class Child(Base):
                @classmethod
                def factory(cls):
                    return child_fn()

            def run():
                return Child().make()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.Base.make", improved.get("main.run", set()))
        self.assertIn("main.Child.factory", improved.get("main.Base.make", set()))

    def test_async_await_and_async_with_are_analyzed(self):
        source = textwrap.dedent(
            """
            class Ctx:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, exc_type, exc, tb):
                    return False

            async def leaf():
                return 1

            async def run(ctx):
                async with ctx:
                    return await leaf()
            """
        )

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.leaf", improved.get("main.run", set()))

    def test_match_case_bodies_are_analyzed(self):
        source = textwrap.dedent(
            """
            def hit():
                return 1

            def run(x):
                match x:
                    case 1:
                        return hit()
                    case _:
                        return 0
            """
        )
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.hit", improved.get("main.run", set()))

    def test_dotted_import_submodule_attribute_call(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pkg_dir = os.path.join(temp_dir, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            with open(os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8") as handle:
                handle.write("")
            with open(os.path.join(pkg_dir, "sub.py"), "w", encoding="utf-8") as handle:
                handle.write("def target():\n    return 1\n")
            main_path = os.path.join(temp_dir, "main.py")
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write(
                    textwrap.dedent(
                        """
                        import pkg.sub

                        def run():
                            return pkg.sub.target()

                        run()
                        """
                    )
                )

            with open(main_path, "r", encoding="utf-8") as handle:
                source = handle.read()
            improved = extract_call_graph_constraint(source, source_path=main_path).get()
            self.assertIn("pkg.sub.target", improved.get("main.run", set()))

    def test_tuple_destructuring_assignment_uses_iterable_members(self):
        source = textwrap.dedent(
            """
            def a():
                return 1

            def b():
                return 2

            def run():
                (fn,) = (a,)
                (fn,) = (b,)
                return fn()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.b", run_edges)
        self.assertFalse(any(edge.startswith("<dynamic>.main.run@") for edge in run_edges))

    def test_global_write_updates_following_calls(self):
        source = textwrap.dedent(
            """
            def a():
                return 1

            def b():
                return 2

            f = a

            def setf():
                global f
                f = b

            def run():
                setf()
                return f()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.b", improved.get("main.run", set()))

    def test_nonlocal_write_updates_outer_scope_variable(self):
        source = textwrap.dedent(
            """
            def a():
                return 1

            def b():
                return 2

            def outer():
                fn = a

                def switch():
                    nonlocal fn
                    fn = b

                switch()
                return fn()

            outer()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        outer_edges = improved.get("main.outer", set())
        self.assertIn("main.outer.switch", outer_edges)
        self.assertIn("main.b", outer_edges)

    def test_function_decorator_is_recorded_as_definition_time_call(self):
        source = textwrap.dedent(
            """
            def deco(fn):
                return fn

            @deco
            def target():
                return 1

            def run():
                return target()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.deco", improved.get("main", set()))
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_try_else_only_executes_on_non_exception_path(self):
        source = textwrap.dedent(
            """
            def handler():
                return 1

            def orelse():
                return 2

            def run():
                try:
                    raise Exception()
                except Exception:
                    handler()
                else:
                    orelse()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.handler", run_edges)
        self.assertNotIn("main.orelse", run_edges)

    def test_exception_handler_name_is_refined_to_exception_instance(self):
        source = textwrap.dedent(
            """
            def helper():
                return 1

            class MyErr(Exception):
                def handle(self):
                    return helper()

            def run():
                try:
                    raise MyErr()
                except MyErr as err:
                    return err.handle()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.MyErr.handle", run_edges)
        self.assertIn("main.helper", improved.get("main.MyErr.handle", set()))

    def test_exception_handler_tuple_refines_name_to_each_exception_type(self):
        source = textwrap.dedent(
            """
            def a_helper():
                return 1

            def b_helper():
                return 2

            class AErr(Exception):
                def handle(self):
                    return a_helper()

            class BErr(Exception):
                def handle(self):
                    return b_helper()

            def run(flag):
                try:
                    if flag:
                        raise AErr()
                    raise BErr()
                except (AErr, BErr) as err:
                    return err.handle()

            run(True)
            """
        )
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.AErr.handle", run_edges)
        self.assertIn("main.BErr.handle", run_edges)

    def test_for_loop_target_uses_iterable_member_values(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def run():
                for fn in [target]:
                    fn()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_unreachable_code_after_return_is_not_analyzed(self):
        source = textwrap.dedent(
            """
            def dead():
                return 1

            def run():
                return
                dead()

            run()
            """
        )
        improved = extract_call_graph_constraint(source).get()
        self.assertNotIn("main.dead", improved.get("main.run", set()))

    def test_positional_only_parameter_is_not_bound_by_keyword(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def invoke(cb, /):
                return cb()

            def run():
                return invoke(cb=target)
            """
        )
        improved = extract_call_graph_constraint(source).get()
        self.assertNotIn("main.target", improved.get("main.invoke", set()))

    def test_keyword_only_parameter_is_not_bound_positionally(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            def invoke(*, cb):
                return cb()

            def run():
                return invoke(target)
            """
        )
        improved = extract_call_graph_constraint(source).get()
        self.assertNotIn("main.target", improved.get("main.invoke", set()))

    def test_with_calls_enter_and_exit_protocol_methods(self):
        source = textwrap.dedent(
            """
            class Ctx:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            def run(ctx):
                with ctx as value:
                    return value

            run(Ctx())
            """
        )
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.Ctx.__enter__", run_edges)
        self.assertIn("main.Ctx.__exit__", run_edges)

    def test_inconsistent_mro_warns_and_uses_conservative_dispatch(self):
        source = textwrap.dedent(
            """
            class A:
                def f(self):
                    return 0

            class B(A):
                def f(self):
                    return 1

            class C(A):
                def f(self):
                    return 2

            class D(B, C):
                pass

            class E(C, B):
                pass

            class F(D, E):
                pass

            def run(x):
                return x.f()

            run(F())
            """
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            improved = extract_call_graph_constraint(source).get()
        self.assertTrue(
            any("Inconsistent MRO detected for main.F" in str(item.message) for item in caught),
            caught,
        )
        run_edges = improved.get("main.run", set())
        self.assertIn("main.B.f", run_edges)
        self.assertIn("main.C.f", run_edges)

    def test_fixpoint_iteration_cap_emits_warning(self):
        source = textwrap.dedent(
            """
            def a():
                return 1

            def b():
                return a()
            """
        )
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(fixpoint_max_iterations=1),
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            builder.build()
        self.assertTrue(
            any(
                "fixpoint hit the iteration cap" in str(item.message)
                for item in caught
            ),
            caught,
        )
        self.assertTrue(builder.fixpoint_truncated)
        self.assertGreaterEqual(builder.fixpoint_iterations, 1)

    def test_fixpoint_warning_can_be_disabled(self):
        source = textwrap.dedent(
            """
            def a():
                return 1

            def b():
                return a()
            """
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            extract_call_graph_constraint(
                source,
                fixpoint_max_iterations=1,
                warn_on_fixpoint_truncation=False,
            )
        self.assertFalse(caught)

    def test_fixture_graph_loading_requires_matching_entry_source(self):
        snippet_main = os.path.join(
            os.path.dirname(__file__),
            "snippets",
            "functions",
            "call",
            "main.py",
        )
        source = textwrap.dedent(
            """
            def local_only():
                return 1
            """
        )
        improved = extract_call_graph_constraint(source, source_path=snippet_main).get()
        self.assertIn("main.local_only", improved)

    def test_fixture_graph_loading_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            snippet_dir = os.path.join(
                temp_dir, "tests", "callgraph", "snippets", "fixture_toggle"
            )
            os.makedirs(snippet_dir, exist_ok=True)
            main_path = os.path.join(snippet_dir, "main.py")
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write("def local_only():\n    return 1\n")
            with open(
                os.path.join(snippet_dir, "callgraph.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump({"main": ["fake.edge"]}, handle)

            source = "def local_only():\n    return 1\n"
            fixture_graph = extract_call_graph_constraint(
                source,
                source_path=main_path,
                allow_fixture_graph_loading=True,
            ).get()
            analyzed_graph = extract_call_graph_constraint(
                source,
                source_path=main_path,
                allow_fixture_graph_loading=False,
            ).get()

            self.assertIn("fake.edge", fixture_graph.get("main", set()))
            self.assertIn("main.local_only", analyzed_graph)

    def test_invalid_fixture_json_falls_back_to_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            snippet_dir = os.path.join(
                temp_dir, "tests", "callgraph", "snippets", "invalid_fixture"
            )
            os.makedirs(snippet_dir, exist_ok=True)
            main_path = os.path.join(snippet_dir, "main.py")
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write("def local_only():\n    return 1\n")
            with open(
                os.path.join(snippet_dir, "callgraph.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write("{ invalid json")

            source = "def local_only():\n    return 1\n"
            improved = extract_call_graph_constraint(source, source_path=main_path).get()
            self.assertIn("main.local_only", improved)

    def test_unresolved_dynamic_calls_have_summary_nodes(self):
        source = textwrap.dedent(
            """
            def run(cb):
                return cb()

            run(42)
            """
        )

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertTrue(
            any(edge.startswith("<dynamic>.main.run@") for edge in run_edges),
            run_edges,
        )

    def test_dynamic_summary_nodes_include_reason_tags(self):
        source = textwrap.dedent(
            """
            class Box:
                pass

            def run(x):
                return x()

            run(Box())
            """
        )
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertTrue(
            any(edge.endswith("[instance_without_call]") for edge in run_edges),
            run_edges,
        )

    def test_value_flow_graph_debug_output_exposes_assignments(self):
        source = textwrap.dedent(
            """
            def target():
                return 1

            alias = target
            """
        )
        as_graph = extract_value_flow_graph_constraint(source)
        self.assertIn("main.alias", as_graph)
        self.assertIn("main.target", as_graph["main.alias"])

    def test_allocation_site_sensitive_instances_reduce_cross_instance_field_pollution(self):
        source = textwrap.dedent(
            """
            class Box:
                def setf(self, fn):
                    self.fn = fn

                def call(self):
                    return self.fn()

            def a():
                return 1

            def b():
                return 2

            def run():
                x = Box()
                y = Box()
                x.setf(a)
                y.setf(b)
                return x.call()

            run()
            """
        )

        insensitive = extract_call_graph_constraint(
            source,
            context_sensitive=True,
            context_depth=1,
            allocation_site_sensitive_instances=False,
        ).get()
        sensitive = extract_call_graph_constraint(
            source,
            context_sensitive=True,
            context_depth=1,
            allocation_site_sensitive_instances=True,
        ).get()

        insensitive_edges = insensitive.get("main.Box.call", set())
        sensitive_edges = sensitive.get("main.Box.call", set())
        self.assertIn("main.a", insensitive_edges)
        self.assertIn("main.b", insensitive_edges)
        self.assertIn("main.a", sensitive_edges)
        self.assertNotIn("main.b", sensitive_edges)


if __name__ == "__main__":
    unittest.main()
