"""Tests for the constraint-style call graph engine."""

import os
import tempfile
import textwrap
import unittest
import warnings

from pyflow.analysis.callgraph.ast_based import extract_call_graph as extract_call_graph_legacy
from pyflow.analysis.callgraph.constraint_based import extract_call_graph_constraint
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


if __name__ == "__main__":
    unittest.main()
