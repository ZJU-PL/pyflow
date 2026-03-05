"""Performance-oriented smoke tests for the constraint-based callgraph solver."""

import textwrap
import unittest

from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.callgraph.constraint_based.model import AnalysisOptions


class TestConstraintBasedPerfSmoke(unittest.TestCase):
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
