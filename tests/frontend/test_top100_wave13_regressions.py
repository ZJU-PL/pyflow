"""Regression tests for Wave 13 top-100 TypeInfo, CallGraph, and MIR fixes."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from pyflow.analysis.astcollector import getOps
from pyflow.analysis.callgraph import extract_call_graph_constraint, publication
from pyflow.analysis.typeinfo.core.typesystem import Instance, LiteralType, TypeSystem
from pyflow.analysis.typeinfo.generation.constants import (
    collect_static_constants,
    find_packages,
)
from pyflow.analysis.typeinfo.inference.domain import AbstractTypeValue
from pyflow.analysis.typeinfo.inference.models import InferredSymbol, ModuleInferenceResult
from pyflow.analysis.typeinfo.inference.project_config import load_project_settings
from pyflow.analysis.typeinfo.inference.string_patterns import infer_regex_from_methods
from pyflow.analysis.typeinfo.inference.validation import ObservedType, validate_observed_types
from pyflow.analysis.typeinfo.query.service import TypeInfoService
from pyflow.analysis.typeinfo.resolution.imports import iter_module_imports
from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import InterfaceBuildOptions, build_interface_from_paths
from pyflow.ir.core import Capabilities
from pyflow.ir.mir.lowering import LoweringBudgetError, lower_source
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.python import ast as pyflow_ast
from pyflow.util.application.console import Console


def _infer_with_service(tmp_path: Path, files: dict[str, str], target: str):
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    svc = TypeInfoService(ProjectContext(tmp_path))
    svc.collect_module(target)
    return svc, svc.inference_result(target)


def test_typeinfo_module_may_be_project_rejects_dotted_class_on_py_file(tmp_path: Path) -> None:
    """``mod.Class`` on non-package ``mod.py`` must collect ``mod``, not bogus ``mod.Class``."""
    svc, res = _infer_with_service(
        tmp_path,
        {
            "models.py": ("class Widget:\n" "    def value(self) -> int:\n" "        return 42\n"),
            "app.py": (
                "import models\n" "def use(w: models.Widget) -> int:\n" "    return w.value()\n"
            ),
        },
        "app",
    )
    assert res is not None
    assert not svc._module_may_be_project("models.Widget")
    assert "models.Widget" not in svc._collected_modules
    assert "models" in svc._collected_modules
    assert str(res.functions["app.use"].return_value.public_type()) == "int"


def test_typeinfo_dotted_name_bound_via_missing_external_import_not_name_defined(
    tmp_path: Path,
) -> None:
    """Dotted annotations whose root is imported from an absent package must not emit name-defined."""
    _, res = _infer_with_service(
        tmp_path,
        {
            "server.py": (
                "try:\n"
                "    from nonexistent_aiohttp_pkg import web\n"
                "except ImportError:\n"
                "    web = None\n"
                "def handle(req: web.Request) -> web.Response:\n"
                "    raise NotImplementedError\n"
                "def bad(x: TrulyMissingRoot.Thing) -> None:\n"
                "    pass\n"
            )
        },
        "server",
    )
    assert res is not None
    name_defined = [d.message for d in res.diagnostics if d.code == "name-defined"]
    assert not any("web.Request" in m or "web.Response" in m for m in name_defined)
    assert any("TrulyMissingRoot.Thing" in m for m in name_defined)


def test_typeinfo_literal_dict_key_subscript_index(tmp_path: Path) -> None:
    """Valid string/int literal keys on ``dict[Literal[...], V]`` must not trigger ``index``."""
    _, res = _infer_with_service(
        tmp_path,
        {
            "locales.py": (
                "from typing import Literal\n"
                "def read(cfg: dict[Literal['link_text', 'language_name'], str]) -> tuple[str, str]:\n"
                "    good = cfg['language_name']\n"
                "    bad = cfg['typo']\n"
                "    return good, bad\n"
            )
        },
        "locales",
    )
    assert res is not None
    index_diags = [d for d in res.diagnostics if d.code == "index"]
    assert len(index_diags) == 1
    assert index_diags[0].span is not None
    assert index_diags[0].span.lineno == 4


def test_typeinfo_reannotated_or_rebound_parameter_subscript_assignment(tmp_path: Path) -> None:
    """Re-annotating/rebinding a ``list[...]`` parameter to ``dict[...]`` must not emit stale ``list-item``."""
    _, res = _infer_with_service(
        tmp_path,
        {
            "collator.py": (
                "from typing import Any\n"
                "def convert(x: Any) -> Any:\n"
                "    return x\n"
                "def process(features: list[dict[str, Any]]) -> dict[str, Any]:\n"
                "    features: dict[str, Any] = convert(features)\n"
                "    features['has_dummy_image'] = True\n"
                "    return features\n"
            )
        },
        "collator",
    )
    assert res is not None
    assert not [d for d in res.diagnostics if d.code in {"list-item", "dict-item"}]


def test_typeinfo_getattr_and_hasattr_guards_suppress_false_attr_defined(tmp_path: Path) -> None:
    """Attributes guarded by ``if getattr(obj, 'x', None):`` or ``if hasattr(obj, 'x'):`` are valid."""
    _, res = _infer_with_service(
        tmp_path,
        {
            "guarded.py": (
                "class Base:\n"
                "    def start(self) -> None:\n"
                "        pass\n"
                "def cleanup(obj: Base) -> None:\n"
                "    if getattr(obj, 'cdp_manager', None):\n"
                "        obj.cdp_manager.close()\n"
                "    elif getattr(obj, 'browser_context', None) is not None:\n"
                "        obj.browser_context.close()\n"
                "    if hasattr(obj, 'extra_hook'):\n"
                "        obj.extra_hook()\n"
                "    _ = obj.truly_missing\n"
            )
        },
        "guarded",
    )
    assert res is not None
    attr_msgs = [d.message for d in res.diagnostics if d.code == "attr-defined"]
    assert len(attr_msgs) == 1
    assert "truly_missing" in attr_msgs[0]


def test_typeinfo_constants_without_setuptools_and_parse_error_logging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``generation.constants`` works without setuptools and logs bad files without UnboundLocalError."""
    import pyflow.analysis.typeinfo.generation.constants as constants_mod

    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "good.py").write_text("X = 123\nS = 'hello'\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    monkeypatch.setattr(constants_mod, "_setuptools_find_packages", None)
    assert find_packages(tmp_path) == ["mypkg"]
    pool = collect_static_constants(tmp_path, module_names=["broken"])
    assert 123 in pool.get_all_constants_for(int)
    assert "hello" in pool.get_all_constants_for(str)


def test_typeinfo_imports_trystar_validation_literal_config_bool_and_string_patterns(
    tmp_path: Path,
) -> None:
    """Verify TryStar imports, LiteralType validation, bool config rejection, and string_patterns guards."""
    import ast

    tree = ast.parse("try:\n    import os\nexcept* ValueError:\n    import sys\n")
    imported = [alias.name for stmt in iter_module_imports(tree.body) for alias in stmt.names]
    assert imported == ["os", "sys"]

    ts = TypeSystem()
    lit_str = LiteralType("ok", Instance(ts.to_class_descriptor(str)))
    result = ModuleInferenceResult(
        module_name="m",
        symbols={"m.x": InferredSymbol(name="m.x", value=AbstractTypeValue.from_type(lit_str))},
    )
    assert validate_observed_types(result, [ObservedType(str, symbol="m.x")]) == []
    assert len(validate_observed_types(result, [ObservedType(int, symbol="m.x")])) == 1

    (tmp_path / "pyflow.toml").write_text("[typeinfo]\nmax_iterations = true\n", encoding="utf-8")
    assert "max_iterations" not in load_project_settings(tmp_path)

    pattern = infer_regex_from_methods(
        {
            "split": [None],  # type: ignore[list-item]
            "startswith": [("pre_", "alt_")],  # type: ignore[list-item]
            "zfill": [0, -2, "not_an_int"],  # type: ignore[list-item]
            "ljust": [0],  # type: ignore[list-item]
        }
    )
    assert pattern is not None


def test_callgraph_fstring_slice_trystar_raise_assert_except_delete_and_targets() -> None:
    """Constraint callgraph must not drop calls in f-strings, slices, TryStar, targets, etc."""
    source = """
def _content_summary(b): return b
def width(): return 10
def val(): return 1
def s(): return 1
def e(): return 3
def t(): return 1
def h1(): pass
def h2(): pass
def get_exc(): return ValueError
def exc(): return ValueError()
def cause(): return RuntimeError()
def cond(): return True
def msg(): return "err"
def idx(): return 0
def get_obj(): return object()

def f_fstring(blocks):
    for i, b in enumerate(blocks, 1):
        print(f"{i}. {_content_summary(b)} {val():{width()}}")

def f_slice(xs):
    return xs[s():e():t()]

def f_trystar():
    try:
        h1()
    except* get_exc():
        h2()

def f_raise_assert():
    assert cond(), msg()
    raise exc() from cause()

def f_targets(d):
    d[idx()] = val()
    d[idx()] += val()
    get_obj().x = val()
    del (d[idx()],)
"""
    adj = extract_call_graph_constraint(source).get()
    assert {"main._content_summary", "main.val", "main.width"} <= adj["main.f_fstring"]
    assert {"main.s", "main.e", "main.t"} <= adj["main.f_slice"]
    assert {"main.h1", "main.h2", "main.get_exc"} <= adj["main.f_trystar"]
    assert {"main.cond", "main.msg", "main.exc", "main.cause"} <= adj["main.f_raise_assert"]
    assert {"main.idx", "main.val", "main.get_obj"} <= adj["main.f_targets"]


def test_callgraph_match_statement_preserves_subsequent_cases_for_refutable_patterns() -> None:
    """Refutable patterns on unknown/bool/sequence/sub-pattern subjects must not kill later cases."""
    source = """
def on_text(): pass
def on_link(): pass
def on_true(): pass
def on_false(): pass
def on_one(): pass
def on_two(): pass

def render(kind):
    match kind:
        case "text":
            on_text()
        case "link":
            on_link()

def check_bool(flag):
    match bool(flag):
        case True:
            on_true()
        case False:
            on_false()

def check_seq():
    xs = [1, 2]
    match xs:
        case [a]:
            on_one()
        case [a, b]:
            on_two()
"""
    adj = extract_call_graph_constraint(source).get()
    assert {"main.on_text", "main.on_link"} <= adj["main.render"]
    assert {"main.on_true", "main.on_false"} <= adj["main.check_bool"]
    assert {"main.on_one", "main.on_two"} <= adj["main.check_seq"]


def test_callgraph_publication_matches_by_source_location_not_shifted_ir_ordinals(
    tmp_path: Path,
) -> None:
    """Synthetic ``interpreter__*`` ops must not steal call targets from subsequent source calls."""
    src = tmp_path / "sample.py"
    src.write_text(
        "def helper(x):\n"
        "    return x + 1\n\n"
        "def caller(items):\n"
        "    out = []\n"
        "    for item in items:\n"
        "        if item > 0:\n"
        "            out.append(helper(item))\n"
        "    return out\n",
        encoding="utf-8",
    )
    compiler = CompilerContext(Console(out=io.StringIO(), verbose=False))
    program = Program()
    opts = InterfaceBuildOptions(
        verbose=False, dependency_strategy="stubs", include_main_entry_points=True
    )
    program.interface, all_src = build_interface_from_paths([src], opts)
    compiler.extractor = Extractor(compiler, verbose=False, source_code=all_src)
    extract_program(compiler, program)
    publication.publish_constraint_callgraph_facts(program, all_src)

    call_types = (pyflow_ast.Call, pyflow_ast.DirectCall, pyflow_ast.MethodCall)
    matched_helper_on_real_call = False
    for proc in program.ir.procedures():
        code = program.ir.code(proc.code_id)
        if code.codeName() != "caller":
            continue
        for op in getOps(code)[0]:
            if not isinstance(op, call_types):
                continue
            nid = program.ir.node_id(op, code)
            fact = program.ir.facts.query(Capabilities.CALL_TARGET_CODES, nid)
            targets = {cid.qualname for cid in (fact.values if fact else ())}
            expr = getattr(op, "expr", None)
            if isinstance(expr, pyflow_ast.Existing) and "interpreter" in str(expr.object):
                assert not targets, f"Synthetic interpreter op falsely matched {targets}"
            elif isinstance(expr, pyflow_ast.Local) and expr.name == "helper":
                assert any(name == "helper" or name.endswith(".helper") for name in targets)
                matched_helper_on_real_call = True
    assert matched_helper_on_real_call


def test_mir_lower_source_enforces_max_seconds_during_import_discovery(tmp_path: Path) -> None:
    """``lower_source(..., max_seconds=...)`` must bound ``_discover`` before compiling."""
    pkg = tmp_path / "bigpkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    for i in range(40):
        nxt = f"from . import m{i + 1}\n" if i < 39 else ""
        (pkg / f"m{i}.py").write_text(f"{nxt}VALUE = {i}\n", encoding="utf-8")

    with pytest.raises(LoweringBudgetError):
        lower_source(
            (pkg / "m0.py").read_text(encoding="utf-8"),
            module_name="bigpkg.m0",
            filename=str(pkg / "m0.py"),
            project_root=str(tmp_path),
            follow_imports=True,
            import_policy="opaque",
            max_seconds=1e-9,
        )
