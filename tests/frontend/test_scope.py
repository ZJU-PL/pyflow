import ast

import pytest

from pyflow.frontend.conversion.scope import (
    analyze_function_body,
    body_contains_zero_arg_super,
    collect_descendant_scope_directives,
    collect_function_scope,
    direct_child_captures,
)


def _legacy_contains_yield(node):
    class YieldVisitor(ast.NodeVisitor):
        found = False

        def visit_Yield(self, child):
            self.found = True

        def visit_YieldFrom(self, child):
            self.found = True

        def visit_FunctionDef(self, child):
            if child is node:
                self.generic_visit(child)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, child):
            return None

    visitor = YieldVisitor()
    visitor.visit(node)
    return visitor.found


@pytest.mark.parametrize(
    "source",
    [
        """
def outer(a):
    x = a
    def child(q=default_factory()):
        global shared
        nonlocal x
        y = x + q
        def grandchild():
            nonlocal y
            yield y
        return y
    callback = lambda z: x + z
    if x:
        yield x
    class Nested(Base):
        def method(self):
            return super().method()
""",
        """
async def outer(flag):
    value = 1
    if flag:
        async def child(arg):
            nonlocal value
            return value + arg
    return lambda item: value + item
""",
        """
def outer():
    def child():
        yield 1
    return child
""",
    ],
)
def test_single_pass_function_analysis_matches_legacy_collectors(source):
    node = ast.parse(source).body[0]
    body = list(node.body)
    analysis = analyze_function_body(body)

    global_names, nonlocal_names, bound, loaded = collect_function_scope(body)
    descendant_global, descendant_nonlocal = collect_descendant_scope_directives(
        body
    )
    parameter_names = {
        argument.arg
        for argument in (
            *getattr(node.args, "posonlyargs", ()),
            *node.args.args,
            *node.args.kwonlyargs,
        )
    }
    if node.args.vararg is not None:
        parameter_names.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        parameter_names.add(node.args.kwarg.arg)
    parent_bound = (bound | parameter_names) - global_names - nonlocal_names

    assert set(analysis.global_names) == global_names
    assert set(analysis.nonlocal_names) == nonlocal_names
    assert set(analysis.bound) == bound
    assert set(analysis.loaded) == loaded
    assert set(analysis.descendant_global_names) == descendant_global
    assert set(analysis.descendant_nonlocal_names) == descendant_nonlocal
    assert analysis.direct_child_captures(parent_bound) == direct_child_captures(
        body, parent_bound
    )
    assert analysis.has_zero_arg_super == body_contains_zero_arg_super(body)
    assert analysis.has_yield == _legacy_contains_yield(node)
