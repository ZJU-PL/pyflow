"""Performance-oriented smoke tests for the constraint-based callgraph solver."""

import textwrap
import unittest

from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.callgraph.constraint_based.model import AnalysisOptions
from pyflow.analysis.callgraph.constraint_based.model import (
    UNKNOWN_VALUE,
    make_string,
)


class TestConstraintBasedPerfSmoke(unittest.TestCase):
    def test_semi_naive_presolve_batches_deep_direct_call_chains(self):
        depth = 120
        lines = ["def target(): return 1", "def f0(value): return value"]
        lines.extend(
            f"def f{index}(value): return f{index - 1}(value)"
            for index in range(1, depth)
        )
        lines.append(f"f{depth - 1}(target)")
        source = "\n".join(lines)

        legacy = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                analyze_reachable_only=True,
                semi_naive_presolve=False,
            ),
        )
        legacy_graph = legacy.build().get()
        semi_naive = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                analyze_reachable_only=True,
                semi_naive_presolve=True,
            ),
        )
        semi_naive_graph = semi_naive.build().get()

        self.assertEqual(semi_naive_graph, legacy_graph)
        self.assertLess(
            semi_naive.fixpoint_iterations, legacy.fixpoint_iterations
        )
        self.assertGreater(semi_naive.solver_stats.semi_naive_constraints, 0)
        self.assertGreater(semi_naive.solver_stats.semi_naive_facts, 0)

    def test_default_fixpoint_budget_is_globally_bounded(self):
        builder = ConstraintCallGraphBuilder("def run():\n    return 1\n")

        builder.build()

        self.assertLessEqual(builder.solver_stats.iteration_budget, 10000)

        explicit = ConstraintCallGraphBuilder(
            "def run():\n    return 1\n",
            options=AnalysisOptions(fixpoint_max_iterations=12000),
        )
        explicit.build()
        self.assertEqual(explicit.solver_stats.iteration_budget, 12000)

    def test_unchanged_binding_does_not_reprocess_existing_values(self):
        builder = ConstraintCallGraphBuilder(
            "",
            options=AnalysisOptions(max_values_per_binding=3),
        )
        current = {make_string("a")}

        changed = builder._merge_value_set(current, {make_string("a")})

        self.assertFalse(changed)
        self.assertEqual(current, {make_string("a")})

    def test_long_string_concatenation_widens_to_unknown(self):
        builder = ConstraintCallGraphBuilder(
            "",
            options=AnalysisOptions(max_concrete_string_length=4),
        )

        combined = builder._combine_string_values(
            {make_string("abcd")}, {make_string("e")}
        )

        self.assertEqual(combined, {UNKNOWN_VALUE})

        strict_builder = ConstraintCallGraphBuilder(
            "",
            options=AnalysisOptions(
                max_concrete_string_length=4,
                strict_precision_mode=True,
            ),
        )
        self.assertEqual(
            strict_builder._combine_string_values(
                {make_string("abcd")}, {make_string("e")}
            ),
            {make_string("abcde")},
        )

    def test_integer_tokens_widen_instead_of_string_concatenating(self):
        builder = ConstraintCallGraphBuilder("")

        self.assertEqual(
            builder._combine_string_values(
                {make_string("#1")}, {make_string("#2")}
            ),
            {make_string("#int")},
        )

    def test_high_fanout_callsites_converge(self):
        source = textwrap.dedent(
            """
            def f0(): return 0
            def f1(): return 1
            def f2(): return 2
            def f3(): return 3
            def f4(): return 4

            def call_all(cbs):
                for cb in cbs:
                    cb()

            def run():
                call_all([f0, f1, f2, f3, f4])
            """
        )
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                requeue_policy="priority",
                max_values_per_binding=128,
                max_contexts_per_scope=64,
            ),
        )
        builder.build()
        self.assertFalse(builder.fixpoint_truncated)
        self.assertGreater(builder.solver_stats.iterations, 0)

    def test_deep_context_chains_respect_context_budget(self):
        source = textwrap.dedent(
            """
            def id_fn(fn):
                return fn

            def a(): return 1
            def b(): return 2
            def c(): return 3
            def d(): return 4

            def run():
                id_fn(a); id_fn(b); id_fn(c); id_fn(d)
            """
        )
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                context_sensitive=True,
                context_depth=3,
                max_contexts_per_scope=2,
                requeue_policy="priority",
            ),
        )
        builder.build()
        self.assertFalse(builder.fixpoint_truncated)
        self.assertGreaterEqual(builder.solver_stats.contexts_capped, 1)

    def test_reflective_dispatch_converges_with_dynamic_summaries(self):
        source = textwrap.dedent(
            """
            class Box:
                pass

            def install(box, name, fn):
                setattr(box, name, fn)

            def a():
                return 1

            def run(box, name):
                return getattr(box, name)()

            box = Box()
            install(box, "do", a)
            run(box, "do")
            run(box, "unknown")
            """
        )
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(requeue_policy="priority", emit_solver_stats=True),
        )
        graph = builder.build().get()
        self.assertFalse(builder.fixpoint_truncated)
        self.assertIn("main.a", graph.get("main.run", set()))
        self.assertGreater(builder.solver_stats.iterations, 0)


if __name__ == "__main__":
    unittest.main()
