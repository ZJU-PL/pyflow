"""Tests for the constraint-style call graph engine."""

import textwrap
import unittest

from pyflow.analysis.callgraph.ast_based import extract_call_graph as extract_call_graph_legacy
from pyflow.analysis.callgraph.constraint_based import extract_call_graph_constraint


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
