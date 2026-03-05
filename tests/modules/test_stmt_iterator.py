import ast
import sys
from types import SimpleNamespace

sys.modules.setdefault("astor", SimpleNamespace(to_source=lambda node: ""))

from pyflow.language.modules.util import StmtIterator


def _to_source_names(module):
    return [type(stmt).__name__ for stmt in module.body]


def test_stmt_iterator_iterates_top_level_statements():
    src = "a = 1\nb = 2\n"
    it = StmtIterator(src)
    nodes = list(it)
    assert [type(unit.node).__name__ for unit in nodes[:2]] == ["Assign", "Assign"]


def test_stmt_iterator_insert_before_and_after():
    src = "a = 1\nb = 2\n"
    it = StmtIterator(src)
    first = next(it)
    assert isinstance(first.node, ast.Assign)

    it.insert_before(ast.parse("pre = 0").body[0])
    it.insert_after(ast.parse("post = 3").body[0])

    assert _to_source_names(it.ast) == ["Assign", "Assign", "Assign", "Assign"]


def test_stmt_iterator_replace_and_remove():
    src = "a = 1\nb = 2\nc = 3\n"
    it = StmtIterator(src)
    first = next(it)
    assert isinstance(first.node, ast.Assign)
    it.replace(ast.parse("a = 100").body[0])

    second = next(it)
    assert isinstance(second.node, ast.Assign)
    it.remove()

    assert len(it.ast.body) == 2
    assert isinstance(it.ast.body[0], ast.Assign)
    assert isinstance(it.ast.body[1], ast.Assign)
