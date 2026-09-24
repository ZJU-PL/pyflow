import ast

from pyflow.language.modules.imports import iter_import_nodes_in_scope


def _imported_modules(source: str) -> list[str]:
    tree = ast.parse(source)
    return [
        node.module or ""
        for node in iter_import_nodes_in_scope(tree.body)
        if isinstance(node, ast.ImportFrom)
    ]


def test_runtime_import_scan_skips_type_checking_only_imports():
    modules = _imported_modules(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from pkg import typing_only\n"
        "else:\n"
        "    from pkg import runtime_fallback\n"
        "if not TYPE_CHECKING:\n"
        "    from pkg import runtime_direct\n"
        "if typing.TYPE_CHECKING:\n"
        "    from pkg import qualified_typing_only\n"
    )

    assert modules == ["typing", "pkg", "pkg"]
