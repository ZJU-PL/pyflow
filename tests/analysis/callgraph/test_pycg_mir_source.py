"""Source-to-MIR-to-PyCG integration tests with no expected-file fallback."""

import textwrap

import pytest

from pyflow.analysis.callgraph.pycg_mir import (
    analyze_file_pycg_mir,
    analyze_program,
    extract_call_graph_pycg_mir,
)
from pyflow.ir.mir import LoweringError, lower_file, lower_source


def analyze(source):
    program = lower_source(textwrap.dedent(source), module_name="main")
    return analyze_program(program, max_iterations=128, raise_on_truncation=True)


@pytest.mark.parametrize(
    "source, edges",
    [
        (
            """
            def target(): pass
            def choose(callback): return callback
            alias = choose(target)
            alias()
            """,
            {("main", "main.choose"), ("main", "main.target")},
        ),
        (
            """
            def target(): pass
            def factory(callback):
                def inner(): callback()
                return inner
            closed = factory(target)
            closed()
            """,
            {
                ("main", "main.factory"),
                ("main", "main.factory.inner"),
                ("main.factory.inner", "main.target"),
            },
        ),
        (
            """
            def first(): second()
            def second(): first()
            first()
            """,
            {
                ("main", "main.first"),
                ("main.first", "main.second"),
                ("main.second", "main.first"),
            },
        ),
        (
            """
            def first(): pass
            def second(): pass
            def apply(callback=first, *, named=first):
                callback()
                named()
            apply(named=second)
            """,
            {("main.apply", "main.first"), ("main.apply", "main.second")},
        ),
        (
            """
            def first(): pass
            def second(): pass
            def apply(*callbacks, **named):
                callbacks[0]()
                named['callback']()
            apply(first, callback=second)
            """,
            {("main.apply", "main.first"), ("main.apply", "main.second")},
        ),
        (
            """
            def target(): pass
            class A:
                def __init__(self, callback): self.callback = callback
                def method(self): self.callback()
            class B(A): pass
            B(target).method()
            """,
            {
                ("main", "main.A.__init__"),
                ("main", "main.A.method"),
                ("main.A.method", "main.target"),
            },
        ),
        (
            """
            def forward(): pass
            def reflected(): pass
            class A:
                def __add__(self, other):
                    forward()
                    return NotImplemented
            class B:
                def __radd__(self, other): reflected()
            A() + B()
            """,
            {
                ("main", "main.A.__add__"),
                ("main", "main.B.__radd__"),
                ("main.A.__add__", "main.forward"),
                ("main.B.__radd__", "main.reflected"),
            },
        ),
        (
            """
            class Operator:
                def __call__(self, other): return other
            class A:
                __add__ = Operator()
            A() + A()
            """,
            {("main", "main.Operator.__call__")},
        ),
        (
            """
            def target(): pass
            class A:
                @property
                def callback(self): return target
            A().callback()
            """,
            {("main", "main.A.callback"), ("main", "main.target")},
        ),
        (
            """
            def first(): pass
            def second(): pass
            class A:
                @staticmethod
                def direct(callback): callback()
                @classmethod
                def class_apply(cls, callback): callback()
            A.direct(first)
            A.class_apply(second)
            """,
            {
                ("main", "main.A.direct"),
                ("main", "main.A.class_apply"),
                ("main.A.direct", "main.first"),
                ("main.A.class_apply", "main.second"),
            },
        ),
        (
            """
            def target(): pass
            class A:
                def __bool__(self):
                    target()
                    return True
            if A(): pass
            """,
            {("main", "main.A.__bool__"), ("main.A.__bool__", "main.target")},
        ),
        (
            """
            def target(): pass
            class A: pass
            value = A()
            value.callback = target
            value.callback()
            """,
            {("main", "main.target")},
        ),
    ],
    ids=[
        "returned_function",
        "closure",
        "mutual_recursion",
        "defaults_and_keywords",
        "variadic_containers",
        "inheritance_and_constructor",
        "forward_and_reflected_operators",
        "callable_operator",
        "property_returned_callable",
        "static_and_class_methods",
        "implicit_truth_call",
        "dynamic_attribute",
    ],
)
def test_source_protocols_propagate_required_edges(source, edges):
    result = analyze(source)
    assert result.converged
    assert edges <= set(result.call_graph.edges())
    assert all("$mir_" not in name for name in result.call_graph.nodes())


def test_local_imports_use_source_files_without_executing_them(tmp_path):
    helper = tmp_path / "helper.py"
    helper.write_text("def target(): pass\n", encoding="utf-8")
    entry = tmp_path / "main.py"
    entry.write_text("from helper import target\ntarget()\n", encoding="utf-8")
    result = analyze_program(lower_file(entry), raise_on_truncation=True)
    assert "helper.target" in result.call_graph.get()["main"]
    output = analyze_file_pycg_mir(str(entry), project_root=str(tmp_path))
    assert "helper.target" in output and "main" in output


def test_source_argument_is_authoritative_and_neighbor_fixture_is_ignored(tmp_path):
    entry = tmp_path / "main.py"
    entry.write_text("raise RuntimeError('Do not read this source')\n", encoding="utf-8")
    (tmp_path / "callgraph.json").write_text(
        '{"fixture_only": ["invented.target"]}', encoding="utf-8"
    )
    graph = extract_call_graph_pycg_mir("def actual(): pass\nactual()\n", source_path=str(entry))
    assert "main.actual" in graph.get()["main"]
    assert "fixture_only" not in graph.get()
    assert graph.analysis_result.converged


def test_unavailable_import_is_reported_instead_of_an_empty_graph():
    with pytest.raises(LoweringError):
        extract_call_graph_pycg_mir("import pyflow_test_definitely_unavailable_module\n")


def test_uncalled_functions_retain_known_callees_with_unknown_parameters():
    result = analyze("""
        def known(value): pass
        def uncalled(value): known(value)
    """)
    assert "main.known" in result.call_graph.get()["main.uncalled"]


def test_source_path_retains_package_context_without_replacing_source_text(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helpers.py").write_text("def target(): pass\n", encoding="utf-8")
    entry = package / "entry.py"
    entry.write_text("raise RuntimeError('Do not analyze the disk copy')\n", encoding="utf-8")
    graph = extract_call_graph_pycg_mir(
        "from .helpers import target\ntarget()\n", source_path=str(entry)
    )
    assert "package.helpers.target" in graph.get()["package.entry"]
    assert graph.analysis_result.converged


def test_lazy_generator_yields_a_callable_that_flows_through_next():
    result = analyze("""
        def target(): pass
        def values(): yield target
        generated = values()
        next(generated)()
    """)
    assert {"main.values", "main.target"} <= result.call_graph.get()["main"]


def test_uniterated_generator_has_no_caller_edge_and_reachable_mode_stays_lazy():
    program = lower_source(
        textwrap.dedent("""
        def hidden(): pass
        def values():
            hidden()
            yield None
        generated = values()
    """),
        module_name="main",
    )
    whole = analyze_program(program, max_iterations=128, raise_on_truncation=True)
    assert "main.values" not in whole.call_graph.get()["main"]
    # Like other uncalled definitions, the all-functions policy may analyze the
    # generator's own outgoing edges without inventing an invocation of it.
    assert "main.hidden" in whole.call_graph.get()["main.values"]
    reachable = analyze_program(
        program, analyze_all_functions=False, max_iterations=128, raise_on_truncation=True
    )
    assert "main.values" not in reachable.reachable_cfgs
    assert "main.hidden" not in reachable.reachable_cfgs
    assert "main.values" not in reachable.call_graph.get()["main"]


def test_yield_from_propagates_delegated_callable_returns():
    result = analyze("""
        def target(): pass
        def inner(): yield target
        def outer(): yield from inner()
        next(outer())()
    """)
    assert {"main.outer", "main.target"} <= result.call_graph.get()["main"]
    assert "main.inner" in result.call_graph.get()["main.outer"]


def test_generator_expression_callback_is_attributed_to_generator_body():
    result = analyze("""
        def callback(value): return value
        generated = (callback(value) for value in [1, 2])
        next(generated)
    """)
    generators = [name for name in result.call_graph.nodes() if "<genexpr" in name]
    assert len(generators) == 1
    generator = generators[0]
    assert generator in result.call_graph.get()["main"]
    assert "main.callback" in result.call_graph.get()[generator]


def test_long_string_does_not_expand_unrelated_protocol_iteration_budget():
    source = (
        "unrelated = " + repr("a" * 600) + "\n"
        "def target(): pass\n"
        "def apply(callback): callback()\n"
        "apply(target)\n"
    )
    result = analyze_program(
        lower_source(source, module_name="main"),
        max_iterations=64,
        raise_on_truncation=True,
    )
    assert result.iterations <= 48
    assert "main.target" in result.call_graph.get()["main.apply"]
