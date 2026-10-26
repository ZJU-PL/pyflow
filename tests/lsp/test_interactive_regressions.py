"""Regressions for interactive inference, shard invalidation and editor requests."""

import asyncio
from pathlib import Path

import pytest

from pyflow.analysis.typeinfo.core.typesystem import ANY, Instance, NoneType, TypeSystem
from pyflow.analysis.typeinfo.inference.domain import _normalize_types
from pyflow.lsp import AnalysisManager, LspHandler
from pyflow.lsp.document_analysis import document_diagnostics, infer_document
from pyflow.lsp.workspace import SourceIndex


def indexed(tmp_path, source):
    path = tmp_path / "app.py"
    return SourceIndex({str(path): source}, (tmp_path,)), path


def mismatches(source):
    return [
        d
        for d in infer_document("/tmp/interactive.py", "interactive", source).diagnostics
        if d.code == "annotation-mismatch"
    ]


def test_mutual_subtypes_keep_precise_representative_and_none():
    system = TypeSystem()
    string = Instance(system.to_class_descriptor(str))
    precise = Instance(system.to_class_descriptor(list), (string,))
    broad = Instance(system.to_class_descriptor(list), (ANY,))
    assert system.is_subtype(precise, broad) and system.is_subtype(broad, precise)
    expected = frozenset((precise, NoneType()))
    assert _normalize_types((precise, broad, NoneType()), system) == expected
    assert _normalize_types((NoneType(), broad, precise), system) == expected


def test_empty_list_default_does_not_erase_annotated_container():
    source = """from typing import List, Optional
class Span: pass
class Text:
    def __init__(self, spans: Optional[List[Span]] = None):
        self._spans: List[Span] = spans or []
"""
    assert not mismatches(source)
    assert mismatches("items: list[str] = [1]\n")


@pytest.mark.parametrize(
    "marker,body",
    [
        ("class API(Protocol):", "..."),
        ("class API(Protocol):", '"docstring"; pass'),
        ("class API(ABC):\n    @abstractmethod", "pass"),
        ("class API(ABC):\n    @abstractmethod", "raise NotImplementedError()"),
        ("class API:\n    @overload", "..."),
    ],
)
def test_empty_interface_stubs_use_declared_return(marker, body):
    source = f"from typing import Protocol, overload\nfrom abc import ABC, abstractmethod\n{marker}\n    def run(self) -> int:\n        {body}\n"
    assert not mismatches(source)


def test_concrete_and_nonempty_abstract_returns_are_still_checked():
    assert mismatches("def run() -> int:\n    pass\n")
    assert mismatches(
        'from abc import abstractmethod\nclass API:\n    @abstractmethod\n    def run(self) -> int:\n        return "bad"\n'
    )


@pytest.mark.parametrize(
    "imports,call",
    [
        ("import sys", "sys.exit(1)"),
        ("from sys import exit as stop", "stop(1)"),
        ("import os", "os._exit(1)"),
        ("import pytest", 'pytest.fail("bad")'),
        ("import pytest", 'pytest.skip("skip")'),
        ("from pytest import xfail", 'xfail("expected")'),
    ],
)
def test_termination_calls_do_not_fall_through(imports, call):
    assert not mismatches(
        f'{imports}\nfrom typing import NoReturn\ndef end() -> NoReturn:\n    {call}\n    return "unreachable"\n'
    )


def test_sys_parameter_and_plain_exit_are_not_termination_models():
    assert mismatches(
        "import sys\nfrom typing import NoReturn\ndef end(sys) -> NoReturn:\n    sys.exit(1)\n"
    )
    assert mismatches(
        "from typing import NoReturn\ndef exit(code):\n    return None\ndef end() -> NoReturn:\n    exit(1)\n"
    )


def test_starred_zip_produces_variadic_rows_and_fixed_zip_stays_fixed():
    assert not mismatches(
        "def rows(columns: list[list[int]]) -> list[tuple[int, ...]]:\n    return list(zip(*columns))\n"
    )
    result = infer_document("/tmp/zip.py", "zip_probe", 'fixed = list(zip([1], ["x"]))\n')
    assert "tuple[int, str]" in str(result.type_of("fixed"))


def test_interactive_diagnostics_do_not_run_taint(tmp_path, monkeypatch):
    import pyflow.lsp.document_analysis as analysis

    index, path = indexed(tmp_path, 'value: int = "bad"\n')

    def forbidden(*args):
        pytest.fail("typing diagnostics invoked interprocedural taint")

    monkeypatch.setattr(analysis, "security_diagnostics", forbidden)
    assert any(
        item["code"] == "annotation-mismatch" for item in document_diagnostics(index, path.as_uri())
    )


def test_call_hierarchy_prepare_selects_callee_at_call_token(tmp_path):
    source = "def called(): pass\ndef caller():\n    called()\n"
    path = tmp_path / "app.py"
    path.write_text(source)
    manager = AnalysisManager()
    manager.load_source_workspaces([str(tmp_path)])
    handler = LspHandler(manager)

    def prepare(line, character):
        return handler._handle_call_hierarchy_prepare(
            {
                "textDocument": {"uri": path.as_uri()},
                "position": {"line": line, "character": character},
            }
        )

    assert prepare(2, 7)[0]["name"] == "called"
    assert prepare(1, 7)[0]["name"] == "caller"


def test_body_edit_reuses_unrelated_and_consumer_resolutions(tmp_path):
    provider, consumer, other = [
        str(tmp_path / f"{name}.py") for name in ("provider", "consumer", "other")
    ]
    sources = {
        provider: "def f():\n    return 1\n",
        consumer: "from provider import f\nf()\n",
        other: "x = 1\n",
    }
    old = SourceIndex(sources, (tmp_path,))
    sources[provider] += "# comment\n"
    new = old.with_source_files(sources)
    assert new._resolved_files[provider] is not old._resolved_files[provider]
    assert new._resolved_files[consumer] is old._resolved_files[consumer]
    assert new._resolved_files[other] is old._resolved_files[other]
    assert new.definitions_at(Path(consumer).as_uri(), 1, 0)[0].uri == Path(provider).as_uri()


def test_changed_exports_invalidate_transitive_reexports_but_not_other_files(tmp_path):
    paths = {
        name: str(tmp_path / f"{name}.py") for name in ("provider", "bridge", "consumer", "other")
    }
    sources = {
        paths["provider"]: "def f(): pass\n",
        paths["bridge"]: "from provider import f\n",
        paths["consumer"]: "from bridge import f\nf()\n",
        paths["other"]: "x = 1\n",
    }
    old = SourceIndex(sources, (tmp_path,))
    # Both changed shards must still propagate invalidation through the bridge.
    sources[paths["provider"]] = "\ndef f(): pass\n"
    sources[paths["bridge"]] += "# comment\n"
    new = old.with_source_files(sources)
    assert new._resolved_files[paths["consumer"]] is not old._resolved_files[paths["consumer"]]
    assert new._resolved_files[paths["other"]] is old._resolved_files[paths["other"]]
    result = new.definitions_at(Path(paths["consumer"]).as_uri(), 1, 0)
    assert result[0].start_line == 1
    del sources[paths["provider"]]
    newer = new.with_source_files(sources)
    assert all(
        location.uri != Path(paths["provider"]).as_uri()
        for location in newer.definitions_at(Path(paths["consumer"]).as_uri(), 1, 0)
    )


OVERLOADS = '''from typing import overload
@overload
def process(x: int) -> int: ...
@overload
def process(x: str) -> str: ...
def process(x: int | str) -> int | str:
    """Process a value."""
    return x
process(1)
'''


def test_overloads_keep_implementation_outline_navigation_and_hover(tmp_path):
    index, path = indexed(tmp_path, OVERLOADS)
    declarations = [symbol for symbol in index.symbols if symbol.name == "process"]
    assert len(declarations) == 3
    outline = [
        symbol
        for symbol in index.document_symbol_tree(path.as_uri())
        if symbol["name"] == "process"
    ]
    assert len(outline) == 1
    assert outline[0]["selectionRange"]["start"]["line"] == 5
    assert outline[0]["range"]["end"]["line"] == 7
    assert index.definitions_at(path.as_uri(), 8, 3)[0].start_line == 5
    hover = index.hover_at(path.as_uri(), 8, 3)["contents"]["value"]
    assert "x: int" in hover and "x: str" in hover
    assert (
        len(
            [
                location
                for location in index.rename_ranges_at(path.as_uri(), 8, 3)
                if location.start_line in {2, 4, 5}
            ]
        )
        == 3
    )


def test_signature_help_shows_overloads_and_active_argument(tmp_path):
    index, path = indexed(tmp_path, OVERLOADS)
    result = index.signature_help(path.as_uri(), 8, 9)
    assert len(result["signatures"]) == 2
    assert "x: int" in result["signatures"][0]["label"]
    assert "x: str" in result["signatures"][1]["label"]
    assert result["activeParameter"] == 0


def test_signature_help_supports_incomplete_calls_and_keyword_only_params(tmp_path):
    text = '''def connect(host: str, port: int = 80, *, timeout: float = 3):
    """Connect to a host."""
    pass
connect("host", timeout=2)
'''
    index, path = indexed(tmp_path, text)
    incomplete = text.rsplit("connect(", 1)[0] + 'connect("host", timeout='
    index = index.with_source_files({str(path): incomplete})
    result = index.signature_help(path.as_uri(), 3, len('connect("host", timeout='))
    signature = result["signatures"][0]
    assert signature["label"] == "connect(host: str, port: int = 80, *, timeout: float = 3)"
    assert signature["activeParameter"] == 2
    assert "Connect to a host." in signature["documentation"]["value"]
    start, end = signature["parameters"][2]["label"]
    assert signature["label"][start:end] == "timeout: float = 3"


def test_signature_help_skips_bound_receiver_and_nested_commas(tmp_path):
    source = "class Client:\n    def send(self, values, timeout=3): pass\nc = Client()\nc.send((1, 2), 4)\n"
    index, path = indexed(tmp_path, source)
    result = index.signature_help(path.as_uri(), 3, len("c.send((1, 2), "))
    assert result["signatures"][0]["label"] == "send(values, timeout = 3)"
    assert result["activeParameter"] == 1


def test_document_highlights_are_scoped_and_document_local(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("def f(value):\n    return value\ndef g(value):\n    return value\n")
    manager = AnalysisManager()
    manager.load_source_workspaces([str(tmp_path)])
    result = LspHandler(manager)._handle_document_highlight(
        {"textDocument": {"uri": path.as_uri()}, "position": {"line": 0, "character": 8}}
    )
    assert {item["range"]["start"]["line"] for item in result} == {0, 1}
    assert {item["range"]["start"]["line"]: item["kind"] for item in result} == {0: 3, 1: 2}


@pytest.mark.parametrize(
    "comment",
    [
        "# type: ignore",
        "# type: ignore[name-defined]",
        "# noqa",
        "# noqa: F821",
        "# noqa: E501, F821",
    ],
)
def test_undefined_name_comment_directives(tmp_path, comment):
    index, path = indexed(tmp_path, f"unknown_name {comment}\n")
    assert not [
        d for d in document_diagnostics(index, path.as_uri()) if d["code"] == "undefined-name"
    ]


@pytest.mark.parametrize(
    "suffix", ["# type: ignore[arg-type]", "# noqa: E501", '; marker = "# noqa: F821"']
)
def test_unrelated_directives_and_string_literals_do_not_hide_names(tmp_path, suffix):
    index, path = indexed(tmp_path, f"unknown_name {suffix}\n")
    assert any(d["code"] == "undefined-name" for d in document_diagnostics(index, path.as_uri()))


def test_name_error_guard_only_suppresses_eager_protected_body(tmp_path):
    source = """try:
    get_ipython
    def lazy():
        return missing_later
except NameError:
    pass
else:
    missing_else
finally:
    missing_finally
missing_after
"""
    index, path = indexed(tmp_path, source)
    lines = {
        d["range"]["start"]["line"]
        for d in document_diagnostics(index, path.as_uri())
        if d["code"] == "undefined-name"
    }
    assert lines == {3, 7, 9, 10}


def test_generic_protocol_stubs_are_not_concrete_missing_returns():
    assert not mismatches(
        'from typing import Protocol, TypeVar\nT = TypeVar("T")\nclass API(Protocol[T]):\n    def run(self) -> int: ...\n'
    )


def test_three_mutually_consistent_generics_do_not_erase_concrete_alternatives():
    system = TypeSystem()

    def container(raw):
        return Instance(
            system.to_class_descriptor(list), (Instance(system.to_class_descriptor(raw)),)
        )

    first, second = container(int), container(str)
    broad = Instance(system.to_class_descriptor(list), (ANY,))
    assert _normalize_types((first, broad, second), system) == frozenset((first, second))


def test_new_module_invalidates_previously_unresolved_import(tmp_path):
    consumer, provider = str(tmp_path / "consumer.py"), str(tmp_path / "provider.py")
    sources = {consumer: "from provider import f\nf()\n"}
    old = SourceIndex(sources, (tmp_path,))
    sources[provider] = "def f(): pass\n"
    new = old.with_source_files(sources)
    assert new.definitions_at(Path(consumer).as_uri(), 1, 0)[0].uri == Path(provider).as_uri()


def test_overload_parameter_rename_includes_all_signatures_and_keyword_call(tmp_path):
    source = OVERLOADS.replace("process(1)", "process(x=1)")
    index, path = indexed(tmp_path, source)
    ranges = index.rename_ranges_at(path.as_uri(), 5, 12)
    assert {location.start_line for location in ranges} == {2, 4, 5, 7, 8}
    from pyflow.lsp.refactor import validate_rename

    validate_rename(index, index.symbol_at(path.as_uri(), 5, 12), ranges, "value")
    completion = next(
        item for item in index.completion_items(path.as_uri(), 8, 4) if item["label"] == "process"
    )
    assert "x: int" in completion["detail"] and "x: str" in completion["detail"]


def test_signature_help_constructor_and_class_static_methods(tmp_path):
    source = """class Client:
    def __init__(self, url, timeout=3): pass
    @classmethod
    def create(cls, url): pass
    @staticmethod
    def parse(text): pass
Client("url", 4)
Client.create("url")
Client.parse("text")
"""
    index, path = indexed(tmp_path, source)
    for line, column, label in [
        (6, 13, "__init__(url, timeout = 3)"),
        (7, 14, "create(url)"),
        (8, 13, "parse(text)"),
    ]:
        assert index.signature_help(path.as_uri(), line, column)["signatures"][0]["label"] == label


def test_termination_models_do_not_match_source_classes_or_shadowed_imports():
    assert mismatches(
        "from typing import NoReturn\nclass sys:\n    @staticmethod\n    def exit(code): pass\ndef end() -> NoReturn:\n    sys.exit(1)\n"
    )
    assert mismatches(
        "import sys\nfrom typing import NoReturn\ndef end() -> NoReturn:\n    sys = object()\n    sys.exit(1)\n"
    )


def test_name_error_guard_includes_eager_defaults_and_class_bodies(tmp_path):
    source = """try:
    def lazy(value=probe):
        return lazy_probe
    class C:
        value = class_probe
except NameError:
    pass
"""
    index, path = indexed(tmp_path, source)
    lines = {
        d["range"]["start"]["line"]
        for d in document_diagnostics(index, path.as_uri())
        if d["code"] == "undefined-name"
    }
    assert lines == {2}


def test_nonreturning_short_circuit_fallback_does_not_add_none_return():
    assert not mismatches(
        "import sys\nfrom typing import NoReturn\ndef end() -> NoReturn:\n    None or sys.exit(1)\n"
    )


def test_resolution_cache_does_not_retain_old_workspace_snapshots(tmp_path):
    import gc
    import weakref

    index, path = indexed(tmp_path, "x = 1\n")
    reference = weakref.ref(index._resolver)
    updated = index.with_source_files({str(path): "x = 1\n# edit\n"})
    del index
    gc.collect()
    assert reference() is None
    assert updated.symbols
