"""Tests for McCabe cyclomatic complexity analysis."""

import ast

import pytest

from pyflow.language.asttools import mccabe_complexity

_expr_as_statement = """
def f():
    0xF00D
"""

_sequential = """
def f(n):
    k = n + 4
    s = k + n
    return s
"""

_sequential_unencapsulated = """
k = 2 + 4
s = k + 3
"""

_if_elif_else_dead_path = """
def f(n):
    if n > 3:
        return "bigger than three"
    elif n > 4:
        return "is never executed"
    else:
        return "smaller than or equal to three"
"""

_for_loop = """
def f():
    for i in range(10):
        print(i)
"""

_for_else = """
def f(my_list):
    for i in my_list:
        print(i)
    else:
        print(None)
"""

_recursive = """
def f(n):
    if n > 4:
        return f(n - 1)
    else:
        return n
"""

_nested_functions = """
def a():
    def b():
        def c():
            pass
        c()
    b()
"""

_try_else = """
try:
    print(1)
except TypeA:
    print(2)
except TypeB:
    print(3)
else:
    print(4)
"""

_async_keywords = """
async def foo_bar(a, b, c):
    await whatever(a, b, c)
    if await b:
        pass

    async with c:
        pass

    async for x in a:
        pass
"""

_annotated_assign = """
def f():
    x: Any = None
"""


@pytest.mark.parametrize(
    "code, expected_complexity",
    [
        pytest.param("def f(): pass", 1, id="trivial"),
        pytest.param(_expr_as_statement, 1, id="expression-as-statement"),
        pytest.param(_sequential, 1, id="sequential"),
        pytest.param(_sequential_unencapsulated, 0, id="sequential-unencapsulated"),
        pytest.param(_if_elif_else_dead_path, 3, id="if-elif-else-dead-path"),
        pytest.param(_for_loop, 2, id="for-loop"),
        pytest.param(_for_else, 2, id="for-else"),
        pytest.param(_recursive, 2, id="recursive"),
        pytest.param(_nested_functions, 3, id="nested-functions"),
        pytest.param(_try_else, 4, id="try-else"),
        pytest.param(_async_keywords, 3, id="async-keywords"),
        pytest.param(_annotated_assign, 1, id="annotated-assign"),
    ],
)
def test_mccabe_complexity(code: str, expected_complexity: int):
    tree = ast.parse(code)
    complexity = mccabe_complexity(tree)
    assert complexity == expected_complexity
