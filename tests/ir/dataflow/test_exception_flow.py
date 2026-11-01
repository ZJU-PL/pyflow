"""Value-flow regressions for exception-aware DDG construction."""

import ast as python_ast
import textwrap

import pytest

from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.ir.dataflow import graph
from pyflow.ir.dataflow.convert import evaluateCode
from pyflow.ir.ddg import construct_ddg


def convert(source):
    code = (
        ASTConverter()._convert_function_def(python_ast.parse(textwrap.dedent(source)).body[0]).code
    )
    return code, evaluateCode(None, code)


def values(slot):
    """Trace value inputs, excluding control predicates and heap ordering."""
    pending, seen, constants = [slot], set(), set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        if isinstance(node, graph.ExistingNode):
            constants.add(node.ref.pyobj)
        elif isinstance(node, graph.Gate):
            pending.append(node.read)
        elif isinstance(node, graph.Split):
            pending.append(node.read)
        elif isinstance(node, graph.Merge):
            pending.extend(node.reads)
        elif isinstance(node, graph.LocalNode) and node.defn is not None:
            pending.append(node.defn)
    return constants


def returned_values(code, dataflow):
    return values(dataflow.exit.reads[code.codeparameters.returnparams[0]])


def test_handler_reads_assignments_completed_before_raise():
    code, dataflow = convert("""
        def f():
            x = 0
            try:
                x = 1
                raise ValueError()
                x = 99
            except:
                return x
    """)
    assert returned_values(code, dataflow) == {1}
    assert construct_ddg(dataflow).op_node_map


def test_failing_rhs_merges_prior_states_without_committing_result():
    code, dataflow = convert("""
        def f(risky):
            x = 0
            try:
                risky()
                x = 1
                x = risky()
            except:
                return x
            return 2
    """)
    assert returned_values(code, dataflow) == {0, 1, 2}


def test_normal_and_handler_states_merge_before_finally():
    code, dataflow = convert("""
        def f(risky):
            try:
                risky()
                x = 1
            except:
                x = 2
            else:
                x = 3
            finally:
                y = x
            return y
    """)
    assert returned_values(code, dataflow) == {2, 3}


@pytest.mark.parametrize("body", ["return 1", "raise ValueError()"])
def test_finally_return_overrides_pending_completion(body):
    code, dataflow = convert(f"""
        def f():
            try:
                {body}
            finally:
                return 2
    """)
    assert returned_values(code, dataflow) == {2}


def test_finally_raise_discards_pending_return():
    code, dataflow = convert("""
        def f():
            try:
                return 1
            finally:
                raise ValueError()
    """)
    assert not dataflow.exit.reads


@pytest.mark.parametrize("transfer", ["break", "continue"])
def test_finally_updates_loop_completion_state(transfer):
    code, dataflow = convert(f"""
        def f(flag):
            x = 0
            while flag:
                try:
                    {transfer}
                finally:
                    x = 7
            return x
    """)
    assert returned_values(code, dataflow) == {0, 7}


def test_nested_exception_reaches_outer_handler_after_cleanup():
    code, dataflow = convert("""
        def f():
            try:
                try:
                    raise ValueError()
                finally:
                    x = 7
            except:
                return x
    """)
    assert returned_values(code, dataflow) == {7}


def test_bound_exception_preserves_raised_value():
    code, dataflow = convert("""
        def f():
            try:
                raise 7
            except ValueError as error:
                return error
    """)
    assert returned_values(code, dataflow) == {7}


def test_inner_handled_exception_restores_outer_bare_raise_value():
    code, dataflow = convert("""
        def f():
            try:
                try:
                    raise 7
                except:
                    try:
                        raise 9
                    except:
                        pass
                    raise
            except ValueError as error:
                return error
    """)
    assert returned_values(code, dataflow) == {7}


@pytest.mark.parametrize("prefix", ["", "async "])
def test_context_managers_generate_ddg(prefix):
    code, dataflow = convert(f"""
        {prefix}def f(cm):
            {prefix}with cm as value:
                return value
    """)
    assert dataflow.exit.reads
    assert construct_ddg(dataflow).op_node_map
