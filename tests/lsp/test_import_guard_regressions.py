"""Cross-module, byte-protocol and guard regressions from top100 evaluation."""

import pytest
from pyflow.lsp.workspace import SourceIndex
from pyflow.lsp.document_analysis import infer_document
from pyflow.analysis.typeinfo.core.typesystem import CallableType


def inferred(source):
    return infer_document("/tmp/guards.py", "guards", source)


def errors(source):
    return [d for d in inferred(source).diagnostics if d.code == "annotation-mismatch"]


def test_sibling_imports_link_definitions_references_and_member_calls(tmp_path):
    model = tmp_path / "inference/model.py"
    generate = tmp_path / "inference/generate.py"
    sources = {
        str(model): "class Transformer:\n    def generate(self): pass\n",
        str(generate): "from model import Transformer\nmodel = Transformer()\nmodel.generate()\n",
    }
    index = SourceIndex(sources, (tmp_path,))
    uri = generate.as_uri()
    assert index.definitions_at(uri, 1, 10)[0].uri == model.as_uri()
    assert index.definitions_at(uri, 2, 8)[0].start_line == 1
    assert any(item.uri == uri for item in index.rename_ranges_at(model.as_uri(), 0, 8))


def test_global_import_precedes_package_prefix_and_missing_exports_do_not_fall_through(tmp_path):
    paths = {name: tmp_path / name for name in ("model.py", "pkg/model.py", "pkg/script.py")}
    sources = {
        str(paths["model.py"]): "class Global: pass\n",
        str(paths["pkg/model.py"]): "class Local: pass\n",
        str(paths["pkg/script.py"]): "from model import Global, Local\ng=Global()\nl=Local()\n",
    }
    index = SourceIndex(sources, (tmp_path,))
    uri = paths["pkg/script.py"].as_uri()
    assert index.definitions_at(uri, 1, 3)[0].uri == paths["model.py"].as_uri()
    assert all(
        item.uri != paths["pkg/model.py"].as_uri() for item in index.definitions_at(uri, 2, 3)
    )


def test_sibling_import_namespace_and_package_init(tmp_path):
    model = tmp_path / "pkg/model.py"
    script = tmp_path / "pkg/__init__.py"
    sources = {str(model): "class Thing: pass\n", str(script): "import model as m\nx=m.Thing()\n"}
    index = SourceIndex(sources, (tmp_path,))
    assert index.definitions_at(script.as_uri(), 1, 5)[0].uri == model.as_uri()


def test_prefix_import_dependencies_invalidate_unresolved_exports(tmp_path):
    model = tmp_path / "pkg/model.py"
    script = tmp_path / "pkg/script.py"
    sources = {str(model): "x=1\n", str(script): "from model import Thing\nx=Thing()\n"}
    old = SourceIndex(sources, (tmp_path,))
    sources[str(model)] = "class Thing: pass\n"
    current = old.with_source_files(sources)
    assert current.definitions_at(script.as_uri(), 1, 3)[0].uri == model.as_uri()


@pytest.mark.parametrize(
    "guard",
    [
        'if not isinstance(data["size"], int):\n        return 0',
        'assert isinstance(data["size"], int)',
    ],
)
def test_subscript_isinstance_guards_narrow(guard):
    source = f'def f(data: dict[str, int | str]) -> int:\n    {guard}\n    value: int = data["size"]\n    return value\n'
    assert not errors(source)


def test_subscript_none_guard_narrows_list_index():
    assert not errors(
        "def f(data: list[int | None]) -> int:\n    if data[0] is None:\n        return 0\n    return data[0]\n"
    )


@pytest.mark.parametrize("kind,value", [("bytes", "b'abc'"), ("bytearray", "bytearray(b'abc')")])
def test_binary_index_returns_int_and_slice_preserves_container(kind, value):
    assert not errors(
        f"def first(data: {kind}) -> int:\n    return data[0]\ndef rest(data: {kind}) -> {kind}:\n    return data[1:]\n"
    )
    assert errors(f"def first(data: {kind}) -> {kind}:\n    return data[0]\n")


def test_tuple_variants_unpack_by_compatible_arity_and_position():
    source = """def iter_tlv(flag):
    yield (1, b'value', 0, 2) if flag else (1, b'value')
def find_tag(flag) -> bytes | None:
    return next((v for t, v in iter_tlv(flag) if t == 1), None)
"""
    assert not errors(source)
    assert errors(source.replace("-> bytes | None", "-> int | None"))


@pytest.mark.parametrize(
    "module,alias", [("typing", "t"), ("typing", "types_alias"), ("collections.abc", "cabc")]
)
def test_callable_import_aliases_preserve_structural_callable(module, alias):
    source = f"import {module} as {alias}\ndef make() -> {alias}.Callable[[int], int]:\n    def inner(value: int) -> int: return value\n    return inner\n"
    result = inferred(source)
    assert isinstance(result.functions["guards.make"].return_type, CallableType)
    assert not errors(source)
    assert errors(source.replace(f"{alias}.Callable[[int], int]", f"{alias}.Callable[[str], str]"))


def test_optional_alias_and_nested_forward_references_resolve():
    source = 'import typing as t\ndef f(value: t.Optional[int]) -> "t.Optional[int]":\n    return value\n'
    assert not [
        d
        for d in inferred(source).diagnostics
        if d.code in {"unresolved-annotation", "annotation-mismatch"}
    ]


def test_assert_narrows_optional_and_false_assert_terminates():
    source = "def f(index: int | None) -> int:\n    assert index is not None\n    return index\n"
    result = inferred(source)
    assert not [
        d for d in result.diagnostics if d.code in {"annotation-mismatch", "unsupported-statement"}
    ]
    assert not errors(
        "from typing import Never\ndef f() -> Never:\n    assert False\n    return 1\n"
    )


def test_never_missing_termination_remains_an_error():
    assert errors(
        'from typing import NoReturn\ndef missing_exit() -> NoReturn:\n    print("still returns")\n'
    )
    assert errors("from typing import NoReturn\ndef wrong_return() -> NoReturn:\n    return None\n")


def test_imported_abort_is_nonreturning_but_shadowed_abort_is_not():
    assert not errors(
        "from werkzeug.exceptions import abort as stop\nfrom typing import NoReturn\ndef f() -> NoReturn:\n    stop(404)\n"
    )
    assert errors(
        "from werkzeug.exceptions import abort as stop\nfrom typing import NoReturn\ndef f(stop) -> NoReturn:\n    stop(404)\n"
    )


@pytest.mark.parametrize(
    "assignment",
    ['data["size"] = "bad"', 'data = {"size": "bad"}', 'other = data\n    other["size"] = "bad"'],
)
def test_mutations_invalidate_subscript_guard_facts(assignment):
    source = f'def f(data: dict[str, int | str]) -> int:\n    assert isinstance(data["size"], int)\n    {assignment}\n    return data["size"]\n'
    assert errors(source)


def test_reassigned_dynamic_index_invalidates_guarded_element():
    source = 'def f(data: dict[str, int | str], key: str) -> int:\n    assert isinstance(data[key], int)\n    key="another"\n    return data[key]\n'
    assert errors(source)


def test_fresh_dictionary_literals_use_contextual_key_and_value_types():
    assert not errors('_services: dict[str, tuple] = {"gyro": (True, 104., 104)}\n')
    assert not errors('def f() -> dict[str, object]:\n    return {"result": None}\n')
    assert not errors(
        'def f(flag) -> dict[str, object] | None:\n    if flag:\n        return {"result": (1, 2)}\n    return None\n'
    )
    assert errors('_services: dict[str, tuple[int, ...]] = {"gyro": ("bad",)}\n')
    assert errors('def f() -> dict[str, int]:\n    return {"result": "bad"}\n')


def test_mutable_dictionary_aliases_remain_invariant():
    assert errors("def f(data: dict[str, int]) -> dict[str, object]:\n    return data\n")
    assert errors('data: dict[str, int] = {"x": 1}\nwide: dict[str, object] = data\n')
    assert errors(
        'def f(value: list[int]) -> dict[str, list[object]]:\n    return {"value": value}\n'
    )


def test_source_class_shadowing_a_typing_module_alias_remains_a_class_annotation():
    source = "import typing as t\nclass t:\n    class Callable: pass\ndef f(value: t.Callable) -> t.Callable:\n    return value\n"
    assert not isinstance(inferred(source).functions["guards.f"].return_type, CallableType)


def test_deleting_guarded_container_invalidates_element_facts():
    source = 'def f(data: dict[str, int | str]) -> int:\n    assert isinstance(data["size"], int)\n    del data["size"]\n    return data["size"]\n'
    assert errors(source)


def test_assert_on_object_can_reach_none_branch():
    assert errors(
        'def f(value: object) -> int:\n    if value is None:\n        return "bad"\n    return 1\n'
    )
