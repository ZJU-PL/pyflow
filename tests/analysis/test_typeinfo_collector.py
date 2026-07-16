from __future__ import annotations

from pyflow.analysis.typeinfo import collect_pyflow_type_info, collect_python_type_info
from pyflow.language.python import ast

from tests.analysis.ifds._support import make_code


def test_collect_python_type_info_from_annotations_and_literals():
    source = """
class Box(Base):
    value: int = 1

def f(x: str, *args: bytes, flag: bool = False) -> list[int]:
    y: dict[str, int] = {}
    z = [x]
    return [1]
"""

    info = collect_python_type_info(source)

    assert info.types_for("Box") == ("Base",)
    assert info.types_for("Box.value") == ("int",)
    assert info.types_for("f") == ("list[int]",)
    assert info.types_for("f.x") == ("str",)
    assert info.types_for("f.args") == ("bytes",)
    assert info.types_for("f.flag") == ("bool",)
    assert info.types_for("f.y") == ("dict[str, int]", "dict")
    assert info.types_for("f.z") == ("list",)


def test_collect_pyflow_type_info_from_alias_and_assignments():
    alias_value = ast.Existing(ast.program.Object(int))
    local_list = ast.Local("items")
    local_number = ast.Local("count")
    code, _ = make_code(
        "main",
        [],
        [
            ast.TypeAlias("UserId", [], alias_value),
            ast.Assign(ast.BuildList([]), [local_list]),
            ast.Assign(ast.Existing(ast.program.Object(3)), [local_number]),
        ],
    )

    info = collect_pyflow_type_info((code,))

    assert info.types_for("main.UserId") == ("int",)
    assert info.types_for("main.items") == ("list",)
    assert info.types_for("main.count") == ("int",)
