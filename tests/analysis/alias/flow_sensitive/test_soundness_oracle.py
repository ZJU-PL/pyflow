"""Small exhaustive concrete oracles for the bounded heap-analysis subset."""

from __future__ import annotations

from itertools import product

from pyflow.analysis.alias.flow_sensitive import HeapAnalysis
from pyflow.language.python import ast as py_ast


def _code(name: str, body: py_ast.Suite, *, params=(), returns=()):
    return py_ast.Code(
        name,
        py_ast.CodeParameters(
            selfparam=None,
            posonlyparams=[],
            posonlynames=[],
            params=list(params),
            paramnames=[param.name for param in params],
            defaults=[],
            vparam=None,
            kparam=None,
            returnparams=list(returns),
            type_params=None,
        ),
        body,
    )


def _existing(value):
    return py_ast.Existing(py_ast.program.Object(value))


def _concrete_results() -> set[str]:
    """Execute the finite branch/store/load family concretely."""
    results: set[str] = set()
    for update_first, load_first in product((False, True), repeat=2):
        heap = {"first": "old_first", "second": "old_second"}
        if update_first:
            heap["first"] = "new_first"
        else:
            heap["second"] = "new_second"
        results.add(heap["first" if load_first else "second"])
    return results


def test_exhaustive_branch_store_load_results_are_abstractly_represented():
    update_first = py_ast.Local("update_first")
    load_first = py_ast.Local("load_first")
    first = py_ast.Local("first")
    second = py_ast.Local("second")
    old_first = py_ast.Local("old_first")
    old_second = py_ast.Local("old_second")
    new_first = py_ast.Local("new_first")
    new_second = py_ast.Local("new_second")
    loaded = py_ast.Local("loaded")

    def allocate(local):
        return py_ast.Assign(py_ast.BuildList([]), [local])

    code = _code(
        "oracle",
        py_ast.Suite(
            [
                allocate(first),
                allocate(second),
                allocate(old_first),
                allocate(old_second),
                allocate(new_first),
                allocate(new_second),
                py_ast.SetAttr(old_first, first, _existing("x")),
                py_ast.SetAttr(old_second, second, _existing("x")),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), update_first),
                    py_ast.Suite(
                        [
                            py_ast.SetAttr(
                                new_first,
                                first,
                                _existing("x"),
                            )
                        ]
                    ),
                    py_ast.Suite(
                        [
                            py_ast.SetAttr(
                                new_second,
                                second,
                                _existing("x"),
                            )
                        ]
                    ),
                ),
                py_ast.Switch(
                    py_ast.Condition(py_ast.Suite([]), load_first),
                    py_ast.Suite(
                        [
                            py_ast.Assign(
                                py_ast.GetAttr(
                                    first,
                                    _existing("x"),
                                ),
                                [loaded],
                            )
                        ]
                    ),
                    py_ast.Suite(
                        [
                            py_ast.Assign(
                                py_ast.GetAttr(
                                    second,
                                    _existing("x"),
                                ),
                                [loaded],
                            )
                        ]
                    ),
                ),
            ]
        ),
        params=(update_first, load_first),
    )

    analysis = HeapAnalysis()
    graph = analysis.analyze(None, code)
    heap = analysis.heap
    assert heap is not None
    abstract_results = heap.locations_for_local(code, loaded)
    concrete_locals = {
        name: local
        for name, local in (
            ("old_first", old_first),
            ("old_second", old_second),
            ("new_first", new_first),
            ("new_second", new_second),
        )
    }

    for result_name in _concrete_results():
        concrete_location = heap.locations_for_local(
            code, concrete_locals[result_name]
        )[0]
        assert any(
            graph.may_alias(concrete_location, abstract_location)
            for abstract_location in abstract_results
        ), result_name


def test_generated_field_subscript_and_nested_call_families_are_sound():
    for use_subscript, through_call in product((False, True), repeat=2):
        update_first = py_ast.Local("update_first")
        load_first = py_ast.Local("load_first")
        first = py_ast.Local("first")
        second = py_ast.Local("second")
        values = {
            name: py_ast.Local(name)
            for name in (
                "old_first",
                "old_second",
                "new_first",
                "new_second",
            )
        }
        loaded = py_ast.Local("loaded")

        formal = py_ast.Local("formal")
        identity = _code(
            "identity",
            py_ast.Suite([py_ast.Return([formal])]),
            params=(formal,),
            returns=(py_ast.Local("returned"),),
        )

        def value_expression(local):
            if not through_call:
                return local
            return py_ast.DirectCall(
                identity,
                None,
                [local],
                [],
                None,
                None,
            )

        def store(container, local):
            if use_subscript:
                return py_ast.SetSubscript(
                    value_expression(local),
                    container,
                    _existing("x"),
                )
            return py_ast.SetAttr(
                value_expression(local),
                container,
                _existing("x"),
            )

        def load(container):
            if use_subscript:
                return py_ast.GetSubscript(container, _existing("x"))
            return py_ast.GetAttr(container, _existing("x"))

        code = _code(
            "generated_oracle",
            py_ast.Suite(
                [
                    py_ast.Assign(py_ast.BuildList([]), [first]),
                    py_ast.Assign(py_ast.BuildList([]), [second]),
                    *(
                        py_ast.Assign(py_ast.BuildList([]), [local])
                        for local in values.values()
                    ),
                    store(first, values["old_first"]),
                    store(second, values["old_second"]),
                    py_ast.Switch(
                        py_ast.Condition(py_ast.Suite([]), update_first),
                        py_ast.Suite([store(first, values["new_first"])]),
                        py_ast.Suite([store(second, values["new_second"])]),
                    ),
                    py_ast.Switch(
                        py_ast.Condition(py_ast.Suite([]), load_first),
                        py_ast.Suite([py_ast.Assign(load(first), [loaded])]),
                        py_ast.Suite([py_ast.Assign(load(second), [loaded])]),
                    ),
                ]
            ),
            params=(update_first, load_first),
        )

        analysis = HeapAnalysis()
        graph = analysis.analyze(None, code)
        heap = analysis.heap
        assert heap is not None
        abstract_results = heap.locations_for_local(code, loaded)
        for result_name in _concrete_results():
            concrete_location = heap.locations_for_local(
                code,
                values[result_name],
            )[0]
            assert any(
                graph.may_alias(concrete_location, abstract_location)
                for abstract_location in abstract_results
            ), (use_subscript, through_call, result_name)
