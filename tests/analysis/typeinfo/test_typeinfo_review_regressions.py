"""Language semantics and failure isolation reported in real-project reviews."""

from types import SimpleNamespace
import ast

import pytest

from pyflow.analysis.typeinfo import StaticTypeInferenceEngine, TypeInfoService
from pyflow.analysis.typeinfo.core.typesystem import ANY, Instance, TupleType, UnionType
from pyflow.api.queries.type_info import TypeInfoQueries
from pyflow.cli.lsp import _dispatch_query
from pyflow.language.modules.project_resolution import ProjectContext


def raw_types(typ):
    if isinstance(typ, Instance):
        return {typ.type.raw_type}
    if isinstance(typ, UnionType):
        return set().union(*(raw_types(item) for item in typ.items))
    return set()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_context_binding_uses_enter_result_including_inherited_methods(asynchronous):
    prefix = "async " if asynchronous else ""
    enter = "__aenter__" if asynchronous else "__enter__"
    exit_method = "__aexit__" if asynchronous else "__exit__"
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        f"class Base:\n    {prefix}def {enter}(self) -> int: return 42\n"
        f"    {prefix}def {exit_method}(self, *args): pass\n"
        "class Ctx(Base): pass\n"
        f"{prefix}def f():\n    {prefix}with Ctx() as val:\n        return val\n",
    )
    assert raw_types(result.functions["sample.f"].return_type) == {int}
    assert result.status == "complete"


def test_multiple_context_bindings_support_unpacking_and_prior_bound_values():
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        "class Ctx:\n"
        "    def __enter__(self): return (1, 'two')\n"
        "    def __exit__(self, *args): pass\n"
        "def f():\n"
        "    with Ctx() as (x, y), Ctx() as other:\n"
        "        return x, y, other\n",
    )
    typ = result.functions["sample.f"].return_type
    assert isinstance(typ, TupleType)
    assert raw_types(typ.args[0]) == {int}
    assert raw_types(typ.args[1]) == {str}
    assert isinstance(typ.args[2], TupleType)


def test_unknown_context_protocol_reports_partial_without_binding_context_object():
    result = StaticTypeInferenceEngine().infer_source(
        "sample", "class Ctx: pass\ndef f():\n    with Ctx() as val:\n        return val\n"
    )
    assert result.functions["sample.f"].return_type is None
    assert result.functions["sample.f"].return_value.unknown
    assert result.status == "partial"
    assert [d.code for d in result.diagnostics] == ["unmodeled-context-manager"]


def test_context_union_keeps_unknown_protocol_alternatives():
    result = StaticTypeInferenceEngine().infer_source(
        "sample",
        "class Good:\n    def __enter__(self) -> int: return 1\n"
        "class Bad: pass\n"
        "def f(flag):\n    ctx = Good() if flag else Bad()\n"
        "    with ctx as value:\n        return value\n",
    )
    value = result.functions["sample.f"].return_value
    assert raw_types(value.public_type()) == {int}
    assert value.unknown
    assert result.status == "partial"


@pytest.mark.parametrize("style", ["sphinx", "epydoc"])
def test_documented_parameter_and_return_hints_reach_engine_and_service(style):
    hints = (
        ":type value: int or str\n    :rtype: bool"
        if style == "sphinx"
        else "@type value: int or str\n    @rtype: bool"
    )
    source = f'def f(value):\n    """{hints}"""\n    return unknown_call(value)\n'
    result = StaticTypeInferenceEngine().infer_source("sample", source)
    summary = result.functions["sample.f"]
    assert raw_types(summary.parameters["value"].public_type()) == {int, str}
    assert raw_types(summary.return_type) == {bool}
    service = TypeInfoService()
    service.collect_module("sample", source=source)
    signature = service.signature_of("sample", "f")
    assert raw_types(signature.params["value"]) == {int, str}
    assert raw_types(signature.returns) == {bool}
    assert signature.source == "docstring"


def test_annotations_and_observed_calls_take_precedence_over_documentation():
    source = '''
def annotated(value: int) -> str:
    """:type value: bytes
    :rtype: float
    """
    return "value"
def identity(value):
    """:type value: str
    :rtype: str
    """
    return value
answer = identity(1)
'''
    service = TypeInfoService()
    service.collect_module("sample", source=source)
    signature = service.signature_of("sample", "annotated")
    assert raw_types(signature.params["value"]) == {int}
    assert raw_types(signature.returns) == {str}
    signature = service.signature_of("sample", "identity")
    assert raw_types(signature.params["value"]) == {int}
    assert raw_types(signature.returns) == {int}
    assert raw_types(service.type_of("sample", "answer")) == {int}


def test_unresolved_documented_alternatives_do_not_produce_definite_partial_union():
    service = TypeInfoService()
    service.collect_module(
        "sample",
        source='def f(value):\n    """:type value: int or MissingType"""\n    return value\n',
    )
    assert service.signature_of("sample", "f").params["value"] is None


@pytest.mark.parametrize(
    "error", [AssertionError("tuple invariant"), AttributeError("missing model")]
)
def test_inference_failure_preserves_annotations_and_collects_stubs(monkeypatch, tmp_path, error):
    path = tmp_path / "sample.py"
    path.write_text("known: int = 1\ndef f(value: int) -> int: return value\n")
    (tmp_path / "sample.pyi").write_text("stubbed: str\n")

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(StaticTypeInferenceEngine, "infer_source", fail)
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("sample", source=path.read_text(), path=str(path))
    assert raw_types(service.type_of("sample", "known")) == {int}
    assert raw_types(service.type_of("sample", "stubbed")) == {str}
    assert service.type_of("sample", "unknown") is None
    assert service.inference_result("sample").status == "partial"
    diagnostics = service.diagnostics()
    assert any(
        item.code == "type_source_failed" and type(error).__name__ in item.message
        for item in diagnostics
    )
    assert "sample" not in service._collecting_modules
    # A second query must not repeat the failing analysis or duplicate errors.
    assert service.diagnostics() == diagnostics


def test_dependency_failure_is_visible_in_parent_analysis(tmp_path):
    (tmp_path / "broken.py").write_text("def invalid(: pass\n")
    source = "from broken import Missing\ndef f(value: Missing): return value\n"
    service = TypeInfoService(ProjectContext(tmp_path))
    service.collect_module("sample", source=source)
    assert service.inference_result("broken").status == "partial"
    assert service.inference_result("sample").status == "partial"
    assert service.signature_of("sample", "f").params["value"] is ANY
    assert any(d.code == "type_dependency_partial" for d in service.diagnostics())
    assert service.inference_result("sample").converged
    assert all(
        d.severity == "warning"
        for d in service.diagnostics()
        if d.code == "type_dependency_partial"
    )


def test_source_loading_failure_cleans_collection_guard(monkeypatch):
    service = TypeInfoService()

    def fail(*args):
        raise OSError("unreadable source")

    monkeypatch.setattr(service, "_load_module_source", fail)
    service.collect_module("sample")
    assert service.inference_result("sample").status == "partial"
    assert not service._collecting_modules


def test_stub_failure_does_not_discard_source_facts(monkeypatch):
    service = TypeInfoService()

    def fail(*args, **kwargs):
        raise AttributeError("stub model missing")

    monkeypatch.setattr(service.stub_resolver, "resolve", fail)
    service.collect_module("sample", source="known: int = 1\n")
    assert raw_types(service.type_of("sample", "known")) == {int}
    assert service.inference_result("sample").status == "partial"
    assert any(d.code == "type_stub_failed" for d in service.diagnostics())


def test_service_does_not_swallow_cancellation(monkeypatch):
    service = TypeInfoService()

    def cancel(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(StaticTypeInferenceEngine, "infer_source", cancel)
    with pytest.raises(KeyboardInterrupt):
        service.collect_module("sample", source="value = 1\n")
    assert not service._collecting_modules


@pytest.mark.skipif(not hasattr(ast, "TryStar"), reason="except* requires Python 3.11")
def test_unsupported_statement_invalidates_written_bindings_and_reports_partial():
    result = StaticTypeInferenceEngine().infer_source(
        "sample", "value = 1\ntry:\n    value = 'changed'\nexcept* ValueError:\n    pass\n"
    )
    assert result.type_of("value") is None
    assert result.status == "partial"
    assert any(d.code == "unsupported-statement" for d in result.diagnostics)


def test_unsupported_expression_reports_partial():
    result = StaticTypeInferenceEngine().infer_source("sample", "values = [*[1]]\n")
    assert result.status == "partial"
    assert any(d.code == "unsupported-expression" for d in result.diagnostics)


def test_cli_partial_diagnostics_are_opt_in_and_legacy_json_is_preserved(capsys):
    service = TypeInfoService()
    service.collect_module("sample", source="def invalid(: pass")
    server = SimpleNamespace(
        current_snapshot=lambda: SimpleNamespace(
            queries=SimpleNamespace(type_info=TypeInfoQueries(service))
        )
    )
    args = SimpleNamespace(
        get_callers=None,
        get_callees=None,
        get_callgraph=False,
        get_type=["sample", "1", "0"],
        include_diagnostics=False,
    )
    assert _dispatch_query(server, args) is None
    assert "partial" in capsys.readouterr().err
    args.include_diagnostics = True
    output = _dispatch_query(server, args)
    assert output["type"] is None
    assert output["status"] == "partial"
    assert output["diagnostics"][0]["code"] == "type_source_failed"
    assert "Traceback" not in capsys.readouterr().err
