"""Tests for the constraint-style call graph engine."""

import json
import os
import sys
import tempfile
import textwrap
import unittest
import warnings
from unittest import mock

from pyflow.analysis.callgraph.ast_based import (
    extract_call_graph as extract_call_graph_legacy,
)
from pyflow.analysis.callgraph.constraint_based import (
    extract_call_graph_constraint,
    extract_call_site_edge_index_constraint,
    extract_value_flow_graph_constraint,
)
from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.callgraph.constraint_based.model import AnalysisOptions


class TestConstraintBasedPrecisionRecall(unittest.TestCase):
    def test_assignment_without_call_reduces_false_positive(self):
        source = textwrap.dedent("""
            def foo():
                return 1

            alias = foo
            """)

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertIn("main.foo", legacy.get("main", set()))
        self.assertNotIn("main.foo", improved.get("main", set()))

    def test_higher_order_parameter_call_improves_recall(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def apply(fn):
                return fn()

            apply(target)
            """)

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertNotIn("main.target", legacy.get("main.apply", set()))
        self.assertIn("main.target", improved.get("main.apply", set()))

    def test_call_site_edge_index_preserves_direct_call_site_edges(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def apply(fn):
                return fn()

            apply(target)
            """)

        index = extract_call_site_edge_index_constraint(source)

        apply_sites = [
            (site, callees)
            for site, callees in index.items()
            if site.caller_scope == "main.apply"
        ]
        self.assertEqual(len(apply_sites), 1)
        site, callees = apply_sites[0]
        self.assertEqual(site.ordinal, 0)
        self.assertIn("main.target", callees)

    def test_call_site_edge_index_includes_explicit_additional_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            entry_path = os.path.join(directory, "entry.py")
            extra_path = os.path.join(directory, "configurator.py")
            with open(entry_path, "w", encoding="utf-8") as handle:
                handle.write("pass\n")
            extra_source = "def configure():\n    return 1\nconfigure()\n"
            with open(extra_path, "w", encoding="utf-8") as handle:
                handle.write(extra_source)

            index = extract_call_site_edge_index_constraint(
                "pass\n",
                source_path=entry_path,
                additional_sources={extra_path: extra_source},
            )

        sites = [
            (site, callees)
            for site, callees in index.items()
            if site.source_path == os.path.realpath(extra_path)
        ]
        self.assertEqual(len(sites), 1)
        site, callees = sites[0]
        self.assertTrue(site.is_module_scope)
        self.assertIn("configurator.configure", callees)

    def test_reachable_only_does_not_seed_unimported_additional_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            entry_path = os.path.join(directory, "entry.py")
            extra_path = os.path.join(directory, "unused.py")
            with open(entry_path, "w", encoding="utf-8") as handle:
                handle.write("pass\n")
            extra_source = "def unused():\n    return 1\nunused()\n"
            with open(extra_path, "w", encoding="utf-8") as handle:
                handle.write(extra_source)

            index = extract_call_site_edge_index_constraint(
                "pass\n",
                source_path=entry_path,
                additional_sources={extra_path: extra_source},
                analyze_reachable_only=True,
            )

        self.assertFalse(
            any(site.source_path == os.path.realpath(extra_path) for site in index)
        )

    def test_entry_file_method_seeds_have_lexical_receiver_types(self):
        source = textwrap.dedent("""
            class Handler:
                def parse(self, value):
                    return value

                def run(self, value):
                    return self.parse(value)
            """)

        index = extract_call_site_edge_index_constraint(
            source,
            analyze_reachable_only=True,
            seed_entry_file_scopes=True,
        )
        edges = {
            site.caller_scope: callees
            for site, callees in index.items()
            if site.caller_scope == "main.Handler.run"
        }

        self.assertIn("main.Handler.parse", edges["main.Handler.run"])

    def test_dynamic_dispatch_tracks_runtime_receiver_types(self):
        source = textwrap.dedent("""
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
            """)

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertNotIn("main.Base.f", legacy.get("main.run", set()))
        self.assertIn("main.Base.f", improved.get("main.run", set()))
        self.assertIn("main.Child.f", improved.get("main.run", set()))
        self.assertNotIn("main.Other.f", improved.get("main.run", set()))

    def test_parameter_annotation_filters_incompatible_runtime_receiver_types(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        call_edges = improved.get("main.call_a", set())
        self.assertIn("main.A.f", call_edges)
        self.assertNotIn("main.B.f", call_edges)

    def test_protocol_annotation_prunes_by_structural_membership(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.g", run_edges)

    def test_typing_cast_refines_receiver_type(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_import_alias_attribute_call_resolution(self):
        source = textwrap.dedent("""
            import math as m

            def run():
                return m.sqrt(4)

            run()
            """)

        legacy = extract_call_graph_legacy(source).get()
        improved = extract_call_graph_constraint(source).get()

        self.assertNotIn("math.sqrt", legacy.get("main.run", set()))
        self.assertIn("math.sqrt", improved.get("main.run", set()))

    def test_getattr_constant_name_resolution(self):
        source = textwrap.dedent("""
            class Handler:
                def handle(self):
                    return 42

            def invoke(obj):
                return getattr(obj, "handle")()

            invoke(Handler())
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.Handler.handle", improved.get("main.invoke", set()))

    def test_reflective_setattr_and_dynamic_string_getattr_resolution(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_getattr_default_value_is_used_when_attribute_is_missing(self):
        source = textwrap.dedent("""
            def fallback():
                return 1

            class Box:
                pass

            def run(box):
                return getattr(box, "missing", fallback)()

            run(Box())
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.fallback", improved.get("main.run", set()))

    def test_context_sensitive_mode_reduces_cross_callsite_pollution(self):
        source = textwrap.dedent("""
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
            """)

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
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        select_edges = improved.get("main.select", set())
        self.assertIn("main.A.f", select_edges)
        self.assertNotIn("main.B.f", select_edges)

    def test_typeguard_function_refines_positive_branch(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_hasattr_guard_refines_receiver_set(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_callable_guard_refines_callable_values(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.__call__", run_edges)
        self.assertNotIn("main.B.__call__", run_edges)

    def test_partial_wrapper_preserves_underlying_call_target(self):
        source = textwrap.dedent("""
            from functools import partial

            def target():
                return 1

            def run():
                fn = partial(target)
                return fn()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_filter_and_sorted_key_callbacks_are_invoked(self):
        source = textwrap.dedent("""
            def pred():
                return True

            def key():
                return 1

            def run(xs):
                list(filter(pred, xs))
                sorted(xs, key=key)

            run([1, 2])
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.pred", run_edges)
        self.assertIn("main.key", run_edges)

    def test_reduce_callback_is_invoked(self):
        source = textwrap.dedent("""
            from functools import reduce

            def combine():
                return 1

            def run(xs):
                return reduce(combine, xs)

            run([1, 2])
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.combine", improved.get("main.run", set()))

    def test_callback_registration_apis_invoke_user_callbacks(self):
        source = textwrap.dedent("""
            import atexit
            import signal

            def cleanup():
                return 1

            def handle(signum, frame):
                return cleanup()

            atexit.register(cleanup)
            signal.signal(signal.SIGTERM, handle)
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.cleanup", improved.get("main", set()))
        self.assertIn("main.handle", improved.get("main", set()))
        self.assertIn("main.cleanup", improved.get("main.handle", set()))

    def test_asyncio_task_wrappers_preserve_coroutine_flow(self):
        source = textwrap.dedent("""
            import asyncio

            def leaf():
                return 1

            async def worker():
                return leaf()

            async def run():
                task = asyncio.create_task(worker())
                return await task
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.worker", improved.get("main.run", set()))
        self.assertIn("main.leaf", improved.get("main.worker", set()))

    def test_thread_and_executor_targets_are_invoked(self):
        source = textwrap.dedent("""
            from concurrent.futures import ThreadPoolExecutor
            from threading import Thread

            def worker():
                return 1

            def run():
                Thread(target=worker)
                executor = ThreadPoolExecutor()
                executor.submit(worker)

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.worker", run_edges)

    def test_transparent_functools_decorators_preserve_target(self):
        source = textwrap.dedent("""
            from functools import lru_cache

            @lru_cache()
            def target():
                return 1

            def run():
                return target()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_list_mutation_preserves_callable_elements(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run():
                handlers = []
                handlers.append(target)
                for handler in handlers:
                    handler()
                unique_handlers = set()
                unique_handlers.add(target)
                for handler in unique_handlers:
                    handler()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_deque_mutation_and_sort_key_preserve_callbacks(self):
        source = textwrap.dedent("""
            from collections import deque

            def target():
                return 1

            def key(value):
                return value

            def run():
                handlers = deque()
                handlers.append(target)
                items = [target]
                items.sort(key=key)
                for handler in handlers:
                    handler()
                for item in items:
                    item()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.target", run_edges)
        self.assertIn("main.key", run_edges)

    def test_executor_map_invokes_callback(self):
        source = textwrap.dedent("""
            from concurrent.futures import ThreadPoolExecutor

            def target(value):
                return value

            def run(values):
                executor = ThreadPoolExecutor()
                return executor.map(target, values)

            run([])
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_asyncio_loop_callbacks_and_task_group_preserve_targets(self):
        source = textwrap.dedent("""
            import asyncio

            def callback():
                return 1

            async def worker():
                return callback()

            async def run():
                loop = asyncio.get_running_loop()
                loop.call_soon(callback)
                async with asyncio.TaskGroup() as group:
                    group.create_task(worker())
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.callback", run_edges)
        self.assertIn("main.worker", run_edges)
        self.assertIn("main.callback", improved.get("main.worker", set()))

    def test_contextlib_managers_and_exit_stack_preserve_callbacks(self):
        source = textwrap.dedent("""
            from contextlib import ExitStack, contextmanager

            def helper():
                return 1

            def cleanup():
                return helper()

            @contextmanager
            def managed():
                yield helper()

            def run():
                with managed():
                    pass
                stack = ExitStack()
                stack.callback(cleanup)

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.managed", run_edges)
        self.assertIn("main.cleanup", run_edges)
        self.assertIn("main.helper", improved.get("main.managed", set()))
        self.assertIn("main.helper", improved.get("main.cleanup", set()))

    def test_asynccontextmanager_preserves_generator_body_edges(self):
        source = textwrap.dedent("""
            from contextlib import asynccontextmanager

            def helper():
                return 1

            @asynccontextmanager
            async def managed():
                yield helper()

            async def run():
                async with managed():
                    pass
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.managed", improved.get("main.run", set()))
        self.assertIn("main.helper", improved.get("main.managed", set()))

    def test_singledispatch_decorator_and_register_dispatch_by_runtime_type(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.render", run_edges)
        self.assertIn("main.render_a", run_edges)
        self.assertIn("main.a_impl", improved.get("main.render_a", set()))
        self.assertIn("main.base_impl", improved.get("main.render", set()))

    def test_singledispatch_register_call_expression_records_implementation(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.render_a", run_edges)
        self.assertNotIn("main.render", run_edges)

    def test_registry_style_nested_register_call_records_callback(self):
        source = textwrap.dedent("""
            class App:
                pass

            app = App()

            def handler():
                return 1

            app.register("home")(handler)

            def run():
                return app["home"]()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.handler", improved.get("main.run", set()))

    def test_dict_get_dispatch_recovers_keyed_target(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def run(k):
                table = {"a": a, "b": b}
                return table.get(k, b)()

            run("a")
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.a", run_edges)

    def test_registry_style_decorator_records_callback(self):
        source = textwrap.dedent("""
            class App:
                pass

            app = App()

            @app.register("home")
            def handler():
                return 1

            def run():
                return app["home"]()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.handler", improved.get("main.run", set()))

    def test_dict_setdefault_preserves_inserted_dispatch_target(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run():
                table = {}
                fn = table.setdefault("k", target)
                return fn()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_dict_pop_returns_removed_dispatch_target(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def other():
                return 2

            def run():
                table = {"k": target, "x": other}
                fn = table.pop("k")
                return fn()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.target", run_edges)
        self.assertNotIn("main.other", run_edges)

    def test_dict_update_keeps_existing_and_incoming_dispatch_targets(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def run(flag):
                table = {"k": a}
                if flag:
                    table.update({"k": b})
                return table["k"]()

            run(True)
            run(False)
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.a", run_edges)
        self.assertIn("main.b", run_edges)

    def test_dict_get_includes_default_when_key_may_be_missing(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def pick(flag):
                return "x" if flag else "y"

            def run(flag):
                table = {"x": a}
                return table.get(pick(flag), b)()

            run(True)
            run(False)
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.a", run_edges)
        self.assertIn("main.b", run_edges)

    def test_match_class_pattern_refines_subject_and_capture(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.A.f", run_edges)
        self.assertNotIn("main.B.f", run_edges)

    def test_c3_mro_prefers_c3_linearized_method(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.C.f", run_edges)
        self.assertNotIn("main.A.f", run_edges)

    def test_descriptor_and_callable_object_modeling(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.CallableDescriptor.__get__", run_edges)
        self.assertIn("main.CallableDescriptor.__call__", run_edges)
        self.assertIn(
            "main.helper", improved.get("main.CallableDescriptor.__call__", set())
        )

    def test_container_comprehension_and_closure_capture(self):
        source = textwrap.dedent("""
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
            """)

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
        source = textwrap.dedent("""
            def target():
                return 1

            def run():
                fn = lambda: target()
                return fn()

            run()
            """)
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        lambda_edges = [
            edge for edge in run_edges if edge.startswith("main.run.<lambda")
        ]
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
        source = textwrap.dedent("""
            class Base:
                @staticmethod
                def f():
                    return 1

            class Child(Base):
                pass

            def run():
                return Child.f()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.Base.f", improved.get("main.run", set()))

    def test_explicit_super_type_and_obj_uses_runtime_mro(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        child_edges = improved.get("main.Child.f", set())
        self.assertIn("main.Mixin.f", child_edges)
        self.assertNotIn("main.Base.f", child_edges)

    def test_zero_arg_super_in_classmethod_uses_runtime_cls_mro(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        factory_edges = improved.get("main.GrandChild.factory", set())
        self.assertIn("main.Child.factory", factory_edges)
        self.assertNotIn("main.Base.factory", factory_edges)

    def test_star_args_are_propagated_to_callee_parameters(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def apply(fn):
                return fn()

            args = [target]
            apply(*args)
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.apply", set()))

    def test_star_kwargs_are_propagated_to_callee_parameters(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def apply(fn):
                return fn()

            kwargs = {"fn": target}
            apply(**kwargs)
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.apply", set()))

    def test_container_allocation_is_stable_across_iterations(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def apply(fn):
                return fn()

            args = [target]
            apply(args[0])
            """)

        builder = ConstraintCallGraphBuilder(source)
        graph = builder.build().get()
        self.assertFalse(builder.fixpoint_truncated)
        self.assertIn("main.target", graph.get("main.apply", set()))

    def test_star_import_does_not_crash_and_propagates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            mod_path = os.path.join(temp_dir, "mod.py")
            main_path = os.path.join(temp_dir, "main.py")
            with open(mod_path, "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""
                        def target():
                            return 1
                        """))
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""
                        from mod import *

                        def run():
                            return target()

                        run()
                        """))

            with open(main_path, "r", encoding="utf-8") as handle:
                source = handle.read()
            improved = extract_call_graph_constraint(
                source, source_path=main_path
            ).get()
            self.assertIn("mod.target", improved.get("main.run", set()))

    def test_classmethod_assignments_update_class_fields(self):
        source = textwrap.dedent("""
            def handler():
                return 1

            class C:
                @classmethod
                def setup(cls):
                    cls.fn = handler

            def run():
                C.setup()
                return C.fn()
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.handler", improved.get("main.run", set()))

    def test_instance_classmethod_binds_runtime_class(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.Base.make", improved.get("main.run", set()))
        self.assertIn("main.Child.factory", improved.get("main.Base.make", set()))

    def test_async_await_and_async_with_are_analyzed(self):
        source = textwrap.dedent("""
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
            """)

        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.leaf", improved.get("main.run", set()))

    def test_async_call_without_await_does_not_execute_body_returns(self):
        source = textwrap.dedent("""
            def target():
                return 1

            async def coro():
                return target

            def run():
                fn = coro()
                return fn()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.coro", run_edges)
        self.assertNotIn("main.target", run_edges)

    def test_generator_call_without_iteration_does_not_expose_yields(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def gen():
                yield target

            def run():
                fn = gen()
                return fn()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.gen", run_edges)
        self.assertNotIn("main.target", run_edges)

    def test_match_case_bodies_are_analyzed(self):
        source = textwrap.dedent("""
            def hit():
                return 1

            def run(x):
                match x:
                    case 1:
                        return hit()
                    case _:
                        return 0
            """)
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.hit", improved.get("main.run", set()))

    def test_dotted_import_submodule_attribute_call(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pkg_dir = os.path.join(temp_dir, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            with open(
                os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8"
            ) as handle:
                handle.write("")
            with open(os.path.join(pkg_dir, "sub.py"), "w", encoding="utf-8") as handle:
                handle.write("def target():\n    return 1\n")
            main_path = os.path.join(temp_dir, "main.py")
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""
                        import pkg.sub

                        def run():
                            return pkg.sub.target()

                        run()
                        """))

            with open(main_path, "r", encoding="utf-8") as handle:
                source = handle.read()
            improved = extract_call_graph_constraint(
                source, source_path=main_path
            ).get()
            self.assertIn("pkg.sub.target", improved.get("main.run", set()))

    def test_from_import_submodule_loads_transitive_body_edges(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pkg_dir = os.path.join(temp_dir, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            with open(
                os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8"
            ) as handle:
                handle.write("")
            with open(os.path.join(pkg_dir, "sub.py"), "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""
                        def sink():
                            return 1

                        def target():
                            return sink()
                        """))

            main_path = os.path.join(temp_dir, "main.py")
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""
                        from pkg import sub

                        def run():
                            return sub.target()

                        run()
                        """))

            with open(main_path, "r", encoding="utf-8") as handle:
                source = handle.read()
            improved = extract_call_graph_constraint(
                source,
                source_path=main_path,
                allow_fixture_graph_loading=False,
            ).get()

        self.assertIn("pkg.sub.target", improved.get("main.run", set()))
        self.assertIn("pkg.sub.sink", improved.get("pkg.sub.target", set()))

    def test_constraint_loader_uses_adjacent_pyi_for_external_imports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lib_py = os.path.join(temp_dir, "lib.py")
            lib_pyi = os.path.join(temp_dir, "lib.pyi")
            entry = os.path.join(temp_dir, "app.py")

            with open(lib_py, "w", encoding="utf-8") as handle:
                handle.write("class Client:\n    pass\n")
            with open(lib_pyi, "w", encoding="utf-8") as handle:
                handle.write(
                    "class Client:\n"
                    "    def ping(self) -> None: ...\n"
                )
            source = textwrap.dedent("""
                from lib import Client

                def run():
                    client = Client()
                    return client.ping()

                run()
                """)
            with open(entry, "w", encoding="utf-8") as handle:
                handle.write(source)

            graph = ConstraintCallGraphBuilder(
                source,
                entry_path=entry,
                options=AnalysisOptions(allow_fixture_graph_loading=False),
            ).build().get()

        self.assertIn("lib.Client.ping", graph.get("main.run", set()))

    def test_stub_return_annotation_propagates_instance_methods(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lib_py = os.path.join(temp_dir, "lib.py")
            lib_pyi = os.path.join(temp_dir, "lib.pyi")
            entry = os.path.join(temp_dir, "app.py")

            with open(lib_py, "w", encoding="utf-8") as handle:
                handle.write("")
            with open(lib_pyi, "w", encoding="utf-8") as handle:
                handle.write(
                    "class Client:\n"
                    "    def ping(self) -> None: ...\n"
                    "def make_client() -> Client: ...\n"
                )
            source = textwrap.dedent("""
                from lib import make_client

                def run():
                    client = make_client()
                    return client.ping()

                run()
                """)
            with open(entry, "w", encoding="utf-8") as handle:
                handle.write(source)

            graph = ConstraintCallGraphBuilder(
                source,
                entry_path=entry,
                options=AnalysisOptions(allow_fixture_graph_loading=False),
            ).build().get()

        self.assertIn("lib.make_client", graph.get("main.run", set()))
        self.assertIn("lib.Client.ping", graph.get("main.run", set()))

    def test_stub_annotated_variable_exports_instance_value(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lib_py = os.path.join(temp_dir, "lib.py")
            lib_pyi = os.path.join(temp_dir, "lib.pyi")
            entry = os.path.join(temp_dir, "app.py")

            with open(lib_py, "w", encoding="utf-8") as handle:
                handle.write("")
            with open(lib_pyi, "w", encoding="utf-8") as handle:
                handle.write(
                    "class Client:\n"
                    "    def ping(self) -> None: ...\n"
                    "client: Client\n"
                )
            source = textwrap.dedent("""
                from lib import client

                def run():
                    return client.ping()

                run()
                """)
            with open(entry, "w", encoding="utf-8") as handle:
                handle.write(source)

            graph = ConstraintCallGraphBuilder(
                source,
                entry_path=entry,
                options=AnalysisOptions(allow_fixture_graph_loading=False),
            ).build().get()

        self.assertIn("lib.Client.ping", graph.get("main.run", set()))

    def test_tuple_destructuring_assignment_uses_iterable_members(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def run():
                (fn,) = (a,)
                (fn,) = (b,)
                return fn()

            run()
            """)
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.b", run_edges)
        self.assertFalse(
            any(edge.startswith("<dynamic>.main.run@") for edge in run_edges)
        )

    def test_global_write_updates_following_calls(self):
        source = textwrap.dedent("""
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
            """)
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.b", improved.get("main.run", set()))

    def test_nonlocal_write_updates_outer_scope_variable(self):
        source = textwrap.dedent("""
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
            """)
        improved = extract_call_graph_constraint(source).get()
        outer_edges = improved.get("main.outer", set())
        self.assertIn("main.outer.switch", outer_edges)
        self.assertIn("main.b", outer_edges)

    def test_function_decorator_is_recorded_as_definition_time_call(self):
        source = textwrap.dedent("""
            def deco(fn):
                return fn

            @deco
            def target():
                return 1

            def run():
                return target()

            run()
            """)
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.deco", improved.get("main", set()))
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_class_body_is_analyzed_for_definition_time_calls(self):
        source = textwrap.dedent("""
            def target():
                return 1

            class C:
                target()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.target", improved.get("main.C", set()))

    def test_class_body_bindings_publish_class_attributes(self):
        source = textwrap.dedent("""
            def target():
                return 1

            class C:
                f = target

            def run():
                return C.f()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_relative_import_in_entry_module_uses_package_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pkg_dir = os.path.join(temp_dir, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            with open(os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8"):
                pass
            with open(
                os.path.join(pkg_dir, "helpers.py"), "w", encoding="utf-8"
            ) as handle:
                handle.write("def target():\n    return 1\n")

            entry_path = os.path.join(pkg_dir, "main.py")
            source = textwrap.dedent("""
                from .helpers import target

                def run():
                    return target()

                run()
                """)
            with open(entry_path, "w", encoding="utf-8") as handle:
                handle.write(source)

            improved = extract_call_graph_constraint(
                source,
                source_path=entry_path,
                allow_fixture_graph_loading=False,
            ).get()

        self.assertIn("pkg.helpers.target", improved.get("main.run", set()))

    def test_class_instantiation_records_new_calls(self):
        source = textwrap.dedent("""
            class C:
                def __new__(cls):
                    return super().__new__(cls)

            def run():
                return C()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.C.__new__", improved.get("main.run", set()))

    def test_class_definition_invokes_init_subclass_hook(self):
        source = textwrap.dedent("""
            def target():
                return 1

            class Base:
                def __init_subclass__(cls):
                    return target()

            class Child(Base):
                pass
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        main_edges = improved.get("main", set())
        self.assertIn("main.Base.__init_subclass__", main_edges)
        self.assertIn("main.target", improved.get("main.Base.__init_subclass__", set()))

    def test_class_instantiation_routes_through_metaclass_call(self):
        source = textwrap.dedent("""
            def target():
                return 1

            class Meta(type):
                def __call__(cls, *args, **kwargs):
                    return target

            class C(metaclass=Meta):
                pass

            def run():
                fn = C()
                return fn()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.Meta.__call__", run_edges)
        self.assertIn("main.target", run_edges)

    def test_definition_time_defaults_and_annotations_are_analyzed(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def anno():
                return int

            def f(x: anno() = target()):
                return x
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        main_edges = improved.get("main", set())
        self.assertIn("main.target", main_edges)
        self.assertIn("main.anno", main_edges)

    def test_definition_time_class_base_expression_is_analyzed(self):
        source = textwrap.dedent("""
            class Base:
                def f(self):
                    return 1

            def choose():
                return Base

            class Child(choose()):
                pass

            def run(x):
                return x.f()

            run(Child())
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.choose", improved.get("main", set()))
        self.assertIn("main.Base.f", improved.get("main.run", set()))

    def test_imported_dotted_base_resolves_via_module_chain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pkg_dir = os.path.join(temp_dir, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            with open(os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8"):
                pass
            with open(os.path.join(pkg_dir, "sub.py"), "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""
                        class Base:
                            def f(self):
                                return 1
                        """))

            main_path = os.path.join(temp_dir, "main.py")
            source = textwrap.dedent("""
                import pkg.sub

                class Child(pkg.sub.Base):
                    pass

                def run(x):
                    return x.f()

                run(Child())
                """)
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write(source)

            improved = extract_call_graph_constraint(
                source,
                source_path=main_path,
                allow_fixture_graph_loading=False,
            ).get()

        self.assertIn("pkg.sub.Base.f", improved.get("main.run", set()))

    def test_imported_dotted_annotation_filters_receiver_types(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pkg_dir = os.path.join(temp_dir, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            with open(os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8"):
                pass
            with open(os.path.join(pkg_dir, "sub.py"), "w", encoding="utf-8") as handle:
                handle.write(textwrap.dedent("""
                        class A:
                            def f(self):
                                return 1

                        class B:
                            def f(self):
                                return 2
                        """))

            main_path = os.path.join(temp_dir, "main.py")
            source = textwrap.dedent("""
                import pkg.sub

                def run(x: pkg.sub.A):
                    return x.f()

                run(pkg.sub.A())
                run(pkg.sub.B())
                """)
            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write(source)

            improved = extract_call_graph_constraint(
                source,
                source_path=main_path,
                allow_fixture_graph_loading=False,
            ).get()

        run_edges = improved.get("main.run", set())
        self.assertIn("pkg.sub.A.f", run_edges)
        self.assertNotIn("pkg.sub.B.f", run_edges)

    def test_try_else_only_executes_on_non_exception_path(self):
        source = textwrap.dedent("""
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
            """)
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.handler", run_edges)
        self.assertNotIn("main.orelse", run_edges)

    def test_exception_handler_name_is_refined_to_exception_instance(self):
        source = textwrap.dedent("""
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
            """)
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.MyErr.handle", run_edges)
        self.assertIn("main.helper", improved.get("main.MyErr.handle", set()))

    def test_exception_handler_tuple_refines_name_to_each_exception_type(self):
        source = textwrap.dedent("""
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
            """)
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.AErr.handle", run_edges)
        self.assertIn("main.BErr.handle", run_edges)

    def test_for_loop_target_uses_iterable_member_values(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run():
                for fn in [target]:
                    fn()

            run()
            """)
        improved = extract_call_graph_constraint(source).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_break_preserves_loop_body_assignments_to_post_loop_call(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run(xs):
                fn = None
                for x in xs:
                    fn = target
                    break
                return fn()

            run([1])
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.target", run_edges)
        self.assertFalse(
            any(edge.startswith("<dynamic>.main.run@10:11") for edge in run_edges),
            run_edges,
        )

    def test_try_handler_sees_assignments_before_raise(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run():
                fn = None
                try:
                    fn = target
                    raise RuntimeError()
                except RuntimeError:
                    return fn()

            run()
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.target", run_edges)
        self.assertFalse(
            any(edge.startswith("<dynamic>.main.run@11:15") for edge in run_edges),
            run_edges,
        )

    def test_nonlocal_write_updates_escaped_sibling_closure(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def make():
                x = b

                def setx():
                    nonlocal x
                    x = a

                def read():
                    return x()

                return setx, read

            setter, reader = make()
            setter()
            reader()
            """)

        improved = extract_call_graph_constraint(
            source, context_sensitive=True, context_depth=1
        ).get()
        read_edges = improved.get("main.make.read", set())
        self.assertIn("main.a", read_edges)

    def test_entry_inside_package_loads_absolute_imported_module_body(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_dir = os.path.join(tmpdir, "pkg")
            os.makedirs(pkg_dir)
            with open(os.path.join(pkg_dir, "__init__.py"), "w", encoding="utf-8"):
                pass
            with open(
                os.path.join(pkg_dir, "helper.py"), "w", encoding="utf-8"
            ) as handle:
                handle.write(textwrap.dedent("""
                        def sink():
                            return 1

                        def target():
                            return sink()
                        """))

            entry_path = os.path.join(pkg_dir, "main.py")
            source = textwrap.dedent("""
                import pkg.helper

                def run():
                    return pkg.helper.target()

                run()
                """)
            with open(entry_path, "w", encoding="utf-8") as handle:
                handle.write(source)

            builder = ConstraintCallGraphBuilder(
                source,
                entry_path=entry_path,
                options=AnalysisOptions(allow_fixture_graph_loading=False),
            )
            graph = builder.build().get()

        self.assertIn("pkg.helper", builder.modules)
        self.assertIn("pkg.helper.target", graph.get("main.run", set()))
        self.assertIn("pkg.helper.sink", graph.get("pkg.helper.target", set()))

    def test_conditional_delattr_remains_conservative_and_converges(self):
        source = textwrap.dedent("""
            def target():
                return 1

            class Box:
                pass

            def run(box, flag):
                setattr(box, "f", target)
                if flag:
                    delattr(box, "f")
                return getattr(box, "f")()

            run(Box(), True)
            run(Box(), False)
            """)

        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                context_sensitive=True,
                context_depth=1,
                allow_fixture_graph_loading=False,
            ),
        )
        graph = builder.build().get()
        run_edges = graph.get("main.run", set())

        self.assertFalse(builder.fixpoint_truncated)
        self.assertIn("main.target", run_edges)

    def test_delattr_with_getattr_default_includes_fallback(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def fallback():
                return 2

            class Box:
                pass

            def run(box, flag):
                setattr(box, "f", target)
                if flag:
                    delattr(box, "f")
                return getattr(box, "f", fallback)()

            run(Box(), True)
            run(Box(), False)
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.target", run_edges)
        self.assertIn("main.fallback", run_edges)

    def test_delete_global_binding_keeps_prior_may_target(self):
        source = textwrap.dedent("""
            def target():
                return 1

            x = target

            def kill():
                global x
                del x

            def run():
                kill()
                return x()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.kill", run_edges)
        self.assertIn("main.target", run_edges)

    def test_flow_insensitive_loop_carries_later_target_to_earlier_call(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def run(flag):
                fn = a
                while flag:
                    fn()
                    fn = b

            run(True)
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.a", run_edges)
        self.assertIn("main.b", run_edges)

    def test_flow_insensitive_reassignment_reaches_earlier_call(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def run():
                fn = a
                fn()
                fn = b

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.a", run_edges)
        self.assertIn("main.b", run_edges)

    def test_flow_insensitive_handler_keeps_pre_exception_target(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def boom():
                raise RuntimeError()

            def run():
                fn = a
                try:
                    boom()
                    fn = b
                except RuntimeError:
                    return fn()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.a", run_edges)
        self.assertIn("main.b", run_edges)

    def test_user_getattribute_adds_redirected_call_target(self):
        source = textwrap.dedent("""
            def actual():
                return 1

            class C:
                def declared(self):
                    return 2

                def __getattribute__(self, name):
                    return actual

            def run(value):
                return value.declared()

            run(C())
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.C.__getattribute__", run_edges)
        self.assertIn("main.actual", run_edges)
        self.assertIn("main.C.declared", run_edges)

    def test_post_pop_lookup_keeps_existing_target_for_soundness(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run(flag):
                table = {"k": target}
                if flag:
                    table.pop("k")
                return table["k"]()

            run(True)
            run(False)
            """)

        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                context_sensitive=True,
                context_depth=1,
                allow_fixture_graph_loading=False,
            ),
        )
        graph = builder.build().get()

        self.assertFalse(builder.fixpoint_truncated)
        self.assertIn("main.target", graph.get("main.run", set()))

    def test_delete_then_dict_get_includes_default_fallback(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def fallback():
                return 2

            def run(flag):
                table = {"k": target}
                if flag:
                    del table["k"]
                return table.get("k", fallback)()

            run(True)
            run(False)
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.target", run_edges)
        self.assertIn("main.fallback", run_edges)

    def test_interprocedural_container_write_requeues_reader_scope(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def install(table):
                table["k"] = target

            def run(table):
                install(table)
                return table["k"]()

            run({})
            """)

        improved = extract_call_graph_constraint(
            source,
            context_sensitive=True,
            context_depth=1,
            allow_fixture_graph_loading=False,
        ).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_keyed_subscript_fallback_tracks_wildcard_container_dependency(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def install(table):
                table["other"] = target

            def run(table):
                fn = table["k"]
                install(table)
                return fn()

            run({})
            """)

        improved = extract_call_graph_constraint(
            source,
            context_sensitive=True,
            context_depth=1,
            allow_fixture_graph_loading=False,
        ).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_exec_literal_string_is_analyzed(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run():
                exec("target()")

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_eval_literal_string_is_analyzed(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def run():
                fn = eval("target")
                return fn()

            run()
            """)

        improved = extract_call_graph_constraint(
            source, allow_fixture_graph_loading=False
        ).get()
        self.assertIn("main.target", improved.get("main.run", set()))

    def test_callable_capping_preserves_all_bound_method_targets(self):
        class_defs = "\n".join(
            f"class C{i}:\n" f"    def f(self):\n" f"        return {i}\n"
            for i in range(140)
        )
        items = ", ".join(f"C{i}().f" for i in range(140))
        source = (
            class_defs
            + "\n\n"
            + "def run(cbs):\n"
            + "    for cb in cbs:\n"
            + "        cb()\n\n"
            + f"run([{items}])\n"
        )

        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                max_values_per_binding=128,
                allow_fixture_graph_loading=False,
            ),
        )
        graph = builder.build().get()
        run_edges = graph.get("main.run", set())

        for index in range(140):
            self.assertIn(f"main.C{index}.f", run_edges)

    def test_match_stops_after_definite_class_pattern_match(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            class A:
                pass

            class B:
                pass

            def run(x):
                match x:
                    case A():
                        return a()
                    case _:
                        return b()

            run(A())
            """)

        graph = extract_call_graph_constraint(source).get()
        run_edges = graph.get("main.run", set())
        self.assertIn("main.a", run_edges)
        self.assertNotIn("main.b", run_edges)

    def test_match_skips_statically_false_guard(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            class A:
                pass

            def run(x):
                match x:
                    case A() if False:
                        return a()
                    case _:
                        return b()

            run(A())
            """)

        graph = extract_call_graph_constraint(source).get()
        run_edges = graph.get("main.run", set())
        self.assertNotIn("main.a", run_edges)
        self.assertIn("main.b", run_edges)

    def test_unreachable_code_after_return_is_not_analyzed(self):
        source = textwrap.dedent("""
            def dead():
                return 1

            def run():
                return
                dead()

            run()
            """)
        improved = extract_call_graph_constraint(source).get()
        self.assertNotIn("main.dead", improved.get("main.run", set()))

    def test_positional_only_parameter_is_not_bound_by_keyword(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def invoke(cb, /):
                return cb()

            def run():
                return invoke(cb=target)
            """)
        improved = extract_call_graph_constraint(source).get()
        self.assertNotIn("main.target", improved.get("main.invoke", set()))

    def test_keyword_only_parameter_is_not_bound_positionally(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def invoke(*, cb):
                return cb()

            def run():
                return invoke(target)
            """)
        improved = extract_call_graph_constraint(source).get()
        self.assertNotIn("main.target", improved.get("main.invoke", set()))

    def test_with_calls_enter_and_exit_protocol_methods(self):
        source = textwrap.dedent("""
            class Ctx:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            def run(ctx):
                with ctx as value:
                    return value

            run(Ctx())
            """)
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertIn("main.Ctx.__enter__", run_edges)
        self.assertIn("main.Ctx.__exit__", run_edges)

    def test_inconsistent_mro_warns_and_uses_conservative_dispatch(self):
        source = textwrap.dedent("""
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
            """)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            improved = extract_call_graph_constraint(source).get()
        self.assertTrue(
            any(
                "Inconsistent MRO detected for main.F" in str(item.message)
                for item in caught
            ),
            caught,
        )
        run_edges = improved.get("main.run", set())
        self.assertIn("main.B.f", run_edges)
        self.assertIn("main.C.f", run_edges)

    def test_cyclic_inheritance_uses_conservative_dispatch(self):
        source = textwrap.dedent("""
            class A(B):
                def f(self):
                    return 1

            class B(A):
                def g(self):
                    return 2

            def run(value):
                if isinstance(value, A):
                    return value.f()
                return 0

            run(A())
            """)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            improved = extract_call_graph_constraint(source).get()

        self.assertTrue(
            any("Inconsistent MRO detected" in str(item.message) for item in caught),
            caught,
        )
        self.assertIn("main.A.f", improved.get("main.run", set()))

    def test_joined_string_combinations_are_bounded(self):
        source = textwrap.dedent("""
            def choose(flag):
                if flag:
                    return "left"
                return "right"

            def run():
                first = choose(True)
                second = choose(False)
                return f"{first}:{second}"

            run()
            """)
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(max_values_per_binding=2),
        )

        improved = builder.build().get()

        self.assertIn("main.choose", improved.get("main.run", set()))

    def test_skip_external_modules_keeps_analysis_within_project(self):
        with (
            tempfile.TemporaryDirectory() as project_dir,
            tempfile.TemporaryDirectory() as external_dir,
        ):
            entry_path = os.path.join(project_dir, "main.py")
            external_path = os.path.join(external_dir, "external_dependency.py")
            source = textwrap.dedent("""
                from external_dependency import Map

                class App:
                    url_map_class = Map

                    def make_map(self):
                        return self.url_map_class()

                App().make_map()
                """)
            with open(entry_path, "w", encoding="utf-8") as handle:
                handle.write(source)
            with open(external_path, "w", encoding="utf-8") as handle:
                handle.write("class Map:\n    pass\n")

            with mock.patch.object(sys, "path", [external_dir, *sys.path]):
                builder = ConstraintCallGraphBuilder(
                    source,
                    entry_path=entry_path,
                    options=AnalysisOptions(skip_external_modules=True),
                )
                builder.build()

        self.assertNotIn("external_dependency", builder.modules)

    def test_reachable_only_call_sites_exclude_dead_function_bodies(self):
        source = textwrap.dedent("""
            def target():
                return 1

            def live():
                return target()

            def dead():
                return target()

            live()
            """)

        sites = extract_call_site_edge_index_constraint(
            source,
            analyze_reachable_only=True,
        )

        caller_scopes = {site.caller_scope for site in sites}
        self.assertIn("main.live", caller_scopes)
        self.assertNotIn("main.dead", caller_scopes)

    def test_fixpoint_iteration_cap_emits_warning(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return a()
            """)
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(fixpoint_max_iterations=1),
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            builder.build()
        self.assertTrue(
            any(
                "fixpoint hit the iteration cap" in str(item.message) for item in caught
            ),
            caught,
        )
        self.assertTrue(builder.fixpoint_truncated)
        self.assertGreaterEqual(builder.fixpoint_iterations, 1)

    def test_fixpoint_warning_can_be_disabled(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return a()
            """)
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
        source = textwrap.dedent("""
            def local_only():
                return 1
            """)
        improved = extract_call_graph_constraint(source, source_path=snippet_main).get()
        self.assertIn("main.local_only", improved)

    def test_fixture_graph_loading_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            snippet_dir = os.path.join(
                temp_dir, "tests", "analysis", "callgraph", "snippets", "fixture_toggle"
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
                temp_dir,
                "tests",
                "analysis",
                "callgraph",
                "snippets",
                "invalid_fixture",
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
            improved = extract_call_graph_constraint(
                source, source_path=main_path
            ).get()
            self.assertIn("main.local_only", improved)

    def test_unresolved_dynamic_calls_have_summary_nodes(self):
        source = textwrap.dedent("""
            def run(cb):
                return cb()

            run(42)
            """)

        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertTrue(
            any(edge.startswith("<dynamic>.main.run@") for edge in run_edges),
            run_edges,
        )

    def test_dynamic_summary_nodes_include_reason_tags(self):
        source = textwrap.dedent("""
            class Box:
                pass

            def run(x):
                return x()

            run(Box())
            """)
        improved = extract_call_graph_constraint(source).get()
        run_edges = improved.get("main.run", set())
        self.assertTrue(
            any(edge.endswith("[instance_without_call]") for edge in run_edges),
            run_edges,
        )

    def test_value_flow_graph_debug_output_exposes_assignments(self):
        source = textwrap.dedent("""
            def target():
                return 1

            alias = target
            """)
        as_graph = extract_value_flow_graph_constraint(source)
        self.assertIn("main.alias", as_graph)
        self.assertIn("main.target", as_graph["main.alias"])

    def test_allocation_site_sensitive_instances_reduce_cross_instance_field_pollution(
        self,
    ):
        source = textwrap.dedent("""
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
            """)

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

    def test_priority_scheduler_is_deterministic_for_graph_and_stats(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def choose(fn):
                return fn()

            def run():
                choose(a)
                choose(b)
            """)
        options = AnalysisOptions(
            context_sensitive=True,
            context_depth=2,
            requeue_policy="priority",
            emit_solver_stats=True,
        )
        builder_a = ConstraintCallGraphBuilder(source, options=options)
        graph_a = builder_a.build().get()
        stats_a = dict(builder_a.solver_stats.__dict__)

        builder_b = ConstraintCallGraphBuilder(source, options=options)
        graph_b = builder_b.build().get()
        stats_b = dict(builder_b.solver_stats.__dict__)

        self.assertEqual(graph_a, graph_b)
        self.assertEqual(stats_a, stats_b)

    def test_binding_cap_preserves_all_concrete_callables(self):
        source = textwrap.dedent("""
            def a():
                return 1

            def b():
                return 2

            def c():
                return 3

            def invoke(cb):
                return cb()

            def run(flag):
                if flag == 0:
                    fn = a
                elif flag == 1:
                    fn = b
                else:
                    fn = c
                return invoke(fn)

            run(0)
            run(1)
            run(2)
            """)
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                max_values_per_binding=2,
                strict_precision_mode=False,
                context_sensitive=False,
            ),
        )
        builder.build()
        invoke_inputs = builder.scope_inputs.get(("main.invoke", ("<global>",)), {})
        cb_values = invoke_inputs.get("cb", set())
        function_names = {value.name for value in cb_values if value.kind == "func"}
        self.assertEqual(function_names, {"main.a", "main.b", "main.c"})

    def test_solver_stats_show_requeue_pressure(self):
        source = textwrap.dedent("""
            def a():
                return b()

            def b():
                return a()

            a()
            """)
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                fixpoint_max_iterations=32,
                requeue_policy="priority",
                emit_solver_stats=True,
            ),
        )
        builder.build()
        self.assertGreater(builder.solver_stats.states_requeued, 0)
        self.assertGreater(builder.solver_stats.states_analyzed, 0)
        self.assertLessEqual(
            builder.solver_stats.states_analyzed,
            builder.solver_stats.states_requeued,
        )

    def test_container_invalidation_requeues_only_container_dependents(self):
        unrelated_defs = "\n\n".join(
            f"def unrelated_{index}():\n    return {index}" for index in range(40)
        )
        source = textwrap.dedent("""
                def a():
                    return 1

                def b():
                    return 2

                def mutate(table, flag):
                    if flag:
                        table["k"] = a
                    else:
                        table["k"] = b

                def read(table):
                    return table["k"]()

                def run():
                    table = {}
                    mutate(table, True)
                    mutate(table, False)
                    return read(table)

                run()
                """) + "\n" + unrelated_defs
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                context_sensitive=True,
                context_depth=1,
                requeue_policy="priority",
                emit_solver_stats=True,
                allow_fixture_graph_loading=False,
            ),
        )
        graph = builder.build().get()
        self.assertFalse(builder.fixpoint_truncated)
        self.assertIn("main.b", graph.get("main.read", set()))
        self.assertLess(builder.solver_stats.states_requeued, 140)

    def test_context_budget_cap_degrades_to_global_without_truncation(self):
        source = textwrap.dedent("""
            def id_fn(fn):
                return fn

            def a():
                return 1

            def b():
                return 2

            def c():
                return 3

            def run():
                id_fn(a)
                id_fn(b)
                id_fn(c)
            """)
        builder = ConstraintCallGraphBuilder(
            source,
            options=AnalysisOptions(
                context_sensitive=True,
                context_depth=2,
                max_contexts_per_scope=1,
                requeue_policy="priority",
            ),
        )
        builder.build()
        self.assertFalse(builder.fixpoint_truncated)
        self.assertGreater(builder.solver_stats.contexts_capped, 0)

    def test_loader_traverses_namespace_package_submodule_import(self):
        """Import loading should handle implicit namespace package parents."""
        with tempfile.TemporaryDirectory() as d:
            ns_dir = os.path.join(d, "ns_pkg")
            os.makedirs(ns_dir)
            child_path = os.path.join(ns_dir, "child.py")
            main_path = os.path.join(d, "main.py")
            with open(child_path, "w", encoding="utf-8") as f:
                f.write("def target():\n    return 1\n")
            source = textwrap.dedent("""
                from ns_pkg import child

                def run():
                    return child.target()

                run()
                """)
            with open(main_path, "w", encoding="utf-8") as f:
                f.write(source)

            builder = ConstraintCallGraphBuilder(
                source,
                entry_path=main_path,
                options=AnalysisOptions(allow_fixture_graph_loading=False),
            )
            builder._load_modules()

            self.assertIn("ns_pkg.child", builder.modules)


if __name__ == "__main__":
    unittest.main()
