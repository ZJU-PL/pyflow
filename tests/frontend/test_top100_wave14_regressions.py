"""Regression tests for Wave 14 fixes across IFDS, CallGraph, TypeInfo, and Alias."""

from __future__ import annotations

from pathlib import Path

from pyflow.analysis.callgraph.constraint_based.engine import ConstraintCallGraphBuilder
from pyflow.analysis.callgraph.constraint_based.model import AnalysisOptions
from pyflow.analysis.ifds import build_supergraph_from_cfgs
from pyflow.analysis.ifds.analyses.flow_paths import collect_flow_paths
from pyflow.analysis.ifds.core.solver import SolverOptions
from pyflow.analysis.typeinfo.inference.cache import ProjectInferenceCache
from pyflow.analysis.typeinfo.inference.engine import StaticTypeInferenceEngine
from pyflow.analysis.typeinfo.inference.project import ProjectTypeInferenceEngine
from pyflow.api.ifds import run_nullness_analysis, run_typestate_analysis
from pyflow.application import context
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.python import ast as py_ast
from tests.analysis.ifds._support import build_cfg, make_code


def _write_module(tmp_path: Path, rel: str, content: str) -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_nullness_ignores_none_inside_call_args_fstrings_and_containers(tmp_path: Path):
    """Literal None in call args, f-string format_spec, or containers must not taint the call result."""
    entry = _write_module(
        tmp_path,
        "client.py",
        """
class Wrapper:
    def __init__(self, first, second):
        self.first = first
        self.second = second

    def to(self, device):
        return self

def make_request(token: str):
    headers = {"Authorization": f"Bearer {token}", "X-Opt": None}
    req = Request("https://example.com", headers=headers)
    wrapped = Wrapper(None, "decoder.pt").to("cpu")
    return req.full_url, wrapped.second.upper()

make_request("secret")
""",
    )
    _session, result = run_nullness_analysis(
        [entry],
        entry_file=entry,
        registry_frameworks=("stdlib",),
        solver_options=SolverOptions(max_seconds=3.0),
    )
    assert result.findings == ()


def test_nullness_binds_method_constructor_classmethod_staticmethod_and_super(tmp_path: Path):
    """Receiver shifting must handle constructors, bound methods, classmethods, staticmethods, and super()."""
    entry = _write_module(
        tmp_path,
        "methods.py",
        """
class Base:
    def __init__(self, a):
        self.a = a

class Foo(Base):
    def __init__(self, x):
        super().__init__(x)
        self.x = x

    def bar(self, y):
        return self.x.strip()

    @classmethod
    def make(cls, z):
        return cls(z)

    @staticmethod
    def helper(w):
        return w.strip()

def run():
    obj = Foo("ok")
    obj.bar(None)
    Foo.make("ok")
    Foo.helper("ok")

run()
""",
    )
    _session, result = run_nullness_analysis(
        [entry],
        entry_file=entry,
        solver_options=SolverOptions(max_seconds=3.0),
    )
    assert result.findings == ()


def test_nullness_attribute_guard_does_not_mark_receiver_null(tmp_path: Path):
    """Checking ``if self.attr is not None:`` must refine ``self.attr``, never mark ``self`` null."""
    entry = _write_module(
        tmp_path,
        "attr_guard.py",
        """
class Previewer:
    def __init__(self):
        self.factors = None

    def decode(self):
        if self.factors is not None:
            return self.factors.shape
        return self.fallback()

    def fallback(self):
        return 0

def main():
    p = Previewer()
    return p.decode()

main()
""",
    )
    _session, result = run_nullness_analysis(
        [entry],
        entry_file=entry,
        solver_options=SolverOptions(max_seconds=3.0),
    )
    assert result.findings == ()


def test_nullness_refines_truthiness_isinstance_shortcircuit_or_and_non_null_defaults(
    tmp_path: Path,
):
    """Truthiness, isinstance, ``a or fallback``, and ``dict.get(k, non_null)`` eliminate None."""
    entry = _write_module(
        tmp_path,
        "guards.py",
        """
import os
import re

def build_client():
    return object()

def process(text, data, opener=None):
    m = re.search("abc", text)
    if m:
        _ = m.group(0)

    if not isinstance(data, dict):
        raise ValueError("expected dict")
    _ = data.get("missing", {}).items()

    env_val = os.environ.get("MY_VAR", "")
    _ = env_val.strip()

    client = opener or build_client()
    return client.open()

process("abc", {"k": 1})
""",
    )
    _session, result = run_nullness_analysis(
        [entry],
        entry_file=entry,
        registry_frameworks=("stdlib",),
        solver_options=SolverOptions(max_seconds=3.0),
    )
    assert result.findings == ()


def test_nullness_tracks_collection_method_calls_on_source_ast(tmp_path: Path):
    """Real source ``Call(GetAttr(...))`` collection mutators/accessors propagate nullness."""
    entry = _write_module(
        tmp_path,
        "collections_case.py",
        """
def main():
    src = {"payload": None}
    items = {}
    items.update(src)
    copied = items.copy()
    val = copied.get("payload")
    return val.strip()

main()
""",
    )
    _session, result = run_nullness_analysis(
        [entry],
        entry_file=entry,
        solver_options=SolverOptions(max_seconds=3.0),
    )
    assert any(
        f.kind == "attribute_access" and f.expression_label == "val" for f in result.findings
    )


def test_typestate_handles_source_close_and_init_attribute_ownership(tmp_path: Path):
    """Source ``f.close()`` transitions state, ``self.fp = open(...)`` transfers ownership, and leaks dedup."""
    entry = _write_module(
        tmp_path,
        "resources.py",
        """
class Logger:
    def __init__(self, path):
        self.fp = open(path, "w")

def safe_close(path):
    fp = open(path, "r")
    fp.close()

def use_after_close(path):
    fp = open(path, "r")
    fp.close()
    fp.read()

def run():
    Logger("a.log")
    safe_close("b.txt")
    use_after_close("c.txt")

run()
""",
    )
    _session, result = run_typestate_analysis(
        [entry],
        entry_file=entry,
        enabled_protocols=("resource", "python-builtins"),
        solver_options=SolverOptions(max_seconds=3.0),
    )
    # Logger.__init__ stores fp on self -> must not report a leak.
    assert not any(
        f.operation_name == "__init__" and f.kind in {"resource_leak", "file_leak"}
        for f in result.findings
    )
    # safe_close closes fp -> must not report a leak on the normal path.
    assert not any(f.operation_name == "safe_close" for f in result.findings)
    # use_after_close reads after close -> must detect use_after_close!
    assert any(f.kind == "use_after_close" and f.resource_label == "fp" for f in result.findings)


def test_collect_flow_paths_does_not_crash_with_missing_adapter():
    """InterproceduralFlowPathAnalysis must store ``self.adapter`` and solve cleanly."""
    compiler = context.CompilerContext(None)
    work_code, _ = make_code("work", [], [py_ast.Return([])], return_name="work_ret")
    main_code, _ = make_code(
        "main",
        [],
        [
            py_ast.Discard(py_ast.DirectCall(work_code, None, [], [], None, None)),
            py_ast.Return([]),
        ],
        return_name="main_ret",
    )
    work_cfg = build_cfg(compiler, work_code)
    main_cfg = build_cfg(compiler, main_code)
    adapter = build_supergraph_from_cfgs([main_cfg, work_cfg])
    result = collect_flow_paths(adapter, [adapter.supergraph.entry_of(main_cfg)])
    assert any("work()" in labels for labels in result.labels_by_node.values())


def test_callgraph_prioritizes_entry_module_scopes_ahead_of_alphabetically_earlier_imports(
    tmp_path: Path,
):
    """Entry module ``main.*`` scopes must not be starved behind imported ``aaa_*`` modules."""
    _write_module(tmp_path, "pkg/__init__.py", "")
    for i in range(12):
        body = "\n".join(f"def aaa_fn_{i}_{j}():\n    return {j}" for j in range(15))
        _write_module(tmp_path, f"pkg/aaa_mod_{i}.py", body + "\n")
    _write_module(tmp_path, "pkg/helper.py", "def target():\n    return 42\n")
    imports = "\n".join(f"from . import aaa_mod_{i}" for i in range(12))
    entry = _write_module(
        tmp_path,
        "pkg/entry.py",
        f"{imports}\nfrom .helper import target\n\ndef entry_fn():\n    return target()\n",
    )
    builder = ConstraintCallGraphBuilder(
        entry.read_text(encoding="utf-8"),
        entry_path=str(entry),
        options=AnalysisOptions(fixpoint_max_iterations=30, fixpoint_max_seconds=5.0),
    )
    cg = builder.build()
    callees = cg.get().get("main.entry_fn", set())
    assert any(c.endswith("helper.target") for c in callees)


def test_callgraph_publication_distinguishes_chained_calls_by_end_span(tmp_path: Path):
    """Chained calls like ``super().__init__(x)`` share start (line, col) but have distinct end spans."""
    entry = _write_module(
        tmp_path,
        "chained.py",
        """
class Base:
    def __init__(self, x):
        self.x = x

class Sub(Base):
    def __init__(self, x):
        super().__init__(x)

Sub(1)
""",
    )
    session, _res = run_nullness_analysis(
        [entry],
        entry_file=entry,
        solver_options=SolverOptions(max_seconds=3.0),
    )
    for node in session.adapter.supergraph.ordered_nodes():
        if node.kind != "call":
            continue
        eff = session.adapter.effect_of(node)
        if eff is not None and eff.call_name == "super":
            assert session.adapter.callees_of(node) == ()


def test_typeinfo_getattr_is_not_none_narrowing_does_not_crash(tmp_path: Path):
    """``if getattr(obj, 'attr', None) is not None:`` must use ``_remove_none`` without AttributeError."""
    source = """
class Box:
    attr: str | None = None

def read_attr(box: Box) -> str:
    if getattr(box, "attr", None) is not None:
        return box.attr
    return "default"
"""
    ctx = ProjectContext(str(tmp_path))
    result = StaticTypeInferenceEngine(ctx).infer_source("demo", source)
    assert not any(d.severity == "error" for d in result.diagnostics)
    assert result.converged


def test_project_typeinfo_converges_in_single_pass_on_acyclic_dag(tmp_path: Path):
    """Acyclic project graphs should converge in 1 iteration without redundant re-analysis."""
    _write_module(tmp_path, "mypkg/__init__.py", "")
    _write_module(tmp_path, "mypkg/leaf.py", "def make_num() -> int:\n    return 1\n")
    _write_module(
        tmp_path,
        "mypkg/mid.py",
        "from mypkg.leaf import make_num\ndef double() -> int:\n    return make_num() * 2\n",
    )
    _write_module(
        tmp_path,
        "mypkg/top.py",
        "from mypkg.mid import double\nVALUE = double()\n",
    )
    ctx = ProjectContext(str(tmp_path))
    eng = ProjectTypeInferenceEngine(ctx, cache=ProjectInferenceCache())
    result = eng.infer_project(["mypkg.top"], discover_imports=True)
    assert result.converged
    assert result.iterations == 1
    assert not any(d.code == "module-inference-error" for d in result.diagnostics)
