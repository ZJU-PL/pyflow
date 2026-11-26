"""Regression tests for frontend robustness and performance issues found on top100."""

from __future__ import annotations

import ast
import gc
import io
import weakref
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.frontend.conversion import source as conv_source
from pyflow.frontend.conversion.ast import ASTConverter
from pyflow.frontend.entry_discovery import discover_entry_files
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.frameworks import http_entry_functions
from pyflow.frontend.interface_builder import InterfaceBuildOptions, build_interface_from_paths
from pyflow.frontend.resolution.dependencies import DependencyResolver
from pyflow.frontend.resolution.hierarchy import ClassHierarchy
from pyflow.language.modules.project_resolution import ProjectContext
from pyflow.language.modules.type_stubs import StubResolver
from pyflow.language.python import ast as pyflow_ast
from pyflow.language.python import ir_metadata
from pyflow.language.source_compat import normalize_legacy_python_syntax, parse_python_source
from pyflow.util.application.console import Console


def test_class_hierarchy_mro_for_object_builtins_generic_and_forward_bases():
    hierarchy = ClassHierarchy(verbose=False)

    assert hierarchy.get_mro("builtins.object") == ["builtins.object"]
    assert hierarchy.get_mro("builtins.Exception") == [
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ]
    assert hierarchy.get_mro("builtins.ValueError") == [
        "builtins.ValueError",
        "builtins.Exception",
        "builtins.BaseException",
        "builtins.object",
    ]
    assert hierarchy.resolve_base_class("dict", "mod") == "builtins.dict"
    assert hierarchy.resolve_base_class("list", "mod") == "builtins.list"

    # Forward-referenced dotted base (a.py extracted before z.py) + PEP 560 Generic.
    sources = {
        "/proj/a.py": (
            "from abc import ABC\n"
            "from typing import Generic, TypeVar\n"
            "import z\n"
            "T = TypeVar('T')\n"
            "class MyErr(ValueError):\n"
            "    pass\n"
            "class MyDict(dict):\n"
            "    pass\n"
            "class Child(z.Base):\n"
            "    pass\n"
            "class CacheStore(ABC, Generic[T], z.ComponentBase[T]):\n"
            "    pass\n"
        ),
        "/proj/z.py": (
            "from typing import Generic, TypeVar\n"
            "T = TypeVar('T')\n"
            "class Base:\n"
            "    def ping(self):\n"
            "        return 1\n"
            "class ComponentBase(Generic[T]):\n"
            "    pass\n"
        ),
    }
    compiler = CompilerContext(Console(verbose=False))
    extractor = Extractor(compiler, verbose=False, source_code=sources, analysis_root="/proj")
    program = extractor.extract_from_multiple_files(sources)
    ch = program.class_hierarchy

    assert ch.get_mro("a.MyErr")[0:3] == ["a.MyErr", "builtins.ValueError", "builtins.Exception"]
    assert ch.get_mro("a.MyDict") == ["a.MyDict", "builtins.dict", "builtins.object"]
    assert ch.resolve_method("a.Child", "ping") == "z.Base"
    cache_mro = ch.get_mro("a.CacheStore")
    assert cache_mro[0] == "a.CacheStore"
    assert "z.ComponentBase" in cache_mro
    assert "typing.Generic" in cache_mro
    assert cache_mro.index("z.ComponentBase") < cache_mro.index("typing.Generic")


def test_normalize_legacy_python_syntax_distinguishes_pep758_from_py2():
    pep758 = (
        "try:\n"
        "    work()\n"
        "except KeyError, ValueError:\n"
        "    pass\n"
        "except IndexError, UnboundLocalError, TypeError:  # comment\n"
        "    pass\n"
        "except httpx.HTTPError, OSError:\n"
        "    pass\n"
        "try:\n"
        "    work()\n"
        "except* ValueError, KeyError:\n"
        "    pass\n"
    )
    tree = parse_python_source(pep758, "pep758.py")
    handlers = tree.body[0].handlers
    assert len(handlers) == 3
    assert all(h.name is None for h in handlers)
    assert [e.id for e in handlers[0].type.elts] == ["KeyError", "ValueError"]
    assert [e.id for e in handlers[1].type.elts] == ["IndexError", "UnboundLocalError", "TypeError"]
    assert len(handlers[2].type.elts) == 2
    assert isinstance(tree.body[1].handlers[0].type, ast.Tuple)

    py2 = (
        "try:\n"
        "    work()\n"
        "except ValueError, exc:\n"
        "    log(exc)\n"
        "except (KeyError, TypeError), err:\n"
        "    log(err)\n"
    )
    py2_tree = parse_python_source(py2, "py2.py")
    assert py2_tree.body[0].handlers[0].name == "exc"
    assert isinstance(py2_tree.body[0].handlers[0].type, ast.Name)
    assert py2_tree.body[0].handlers[1].name == "err"
    assert isinstance(py2_tree.body[0].handlers[1].type, ast.Tuple)

    # DependencyResolver should parse the same PEP 758 source without diagnostics.
    resolver = DependencyResolver(strategy="ast_only", verbose=False)
    funcs = resolver.extract_functions(f"def run():\n    pass\n{pep758}", "pep758.py")
    assert "run" in funcs
    assert resolver.get_diagnostics() == []


def test_typeshed_inherited_methods_do_not_leak_or_misassociate():
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        mod_a = root / "models.py"
        mod_b = root / "views.py"
        mod_a.write_text(
            "from enum import Enum\n"
            "from collections import UserList\n"
            "class Color(Enum):\n"
            "    RED = 'red'\n"
            "    def label(self):\n"
            "        return self.RED\n"
            "class Items(UserList):\n"
            "    def total(self):\n"
            "        return len(self)\n",
            encoding="utf-8",
        )
        mod_b.write_text(
            "class AdminSite:\n"
            "    def index(self, request, extra_context=None):\n"
            "        return request\n"
            "    def name(self):\n"
            "        return 'admin'\n",
            encoding="utf-8",
        )

        interface, sources = build_interface_from_paths([mod_a, mod_b], InterfaceBuildOptions())
        by_cls = {decl.typeobj.__name__: decl for decl in interface.cls}

        assert set(by_cls["Color"]._method.keys()) == {"label"}
        assert set(by_cls["Items"]._method.keys()) == {"total"}

        compiler = CompilerContext(Console(verbose=False))
        program = Program()
        program.interface = interface
        compiler.extractor = Extractor(compiler, verbose=False, source_code=sources)
        extract_program(compiler, program)

        assert compiler.extractor.function_extractor.get_diagnostics() == []
        assert conv_source._is_external_runtime_file("/any/path/enum.pyi")
        assert conv_source._is_external_runtime_file(
            str(Path(conv_source._PYFLOW_STUBS_DIR) / "typeshed" / "stdlib" / "enum.pyi")
        )


def test_class_proxy_handles_reserved_type_dunders_including_types_pyi():
    resolver = DependencyResolver(strategy="ast_only", verbose=False)
    source = (
        "import types\n"
        "class Weird(types.MethodType):\n"
        "    @property\n"
        "    def __qualname__(self) -> str:\n"
        "        return 'Weird'\n"
        "    def ok(self):\n"
        "        return 1\n"
    )
    resolver.extract_functions(source, "weird.py")
    classes = resolver.get_module_classes("weird.py")
    assert "Weird" in classes
    assert "ok" in resolver.get_public_method_specs(classes["Weird"])
    assert resolver.get_diagnostics() == []


def test_module_scope_names_do_not_leak_across_files():
    sources = {
        "/proj/a.py": "ValueError = 1\nopen = 2\n",
        "/proj/b.py": "def f():\n    open('x')\n    raise ValueError('bad')\n",
    }
    ext_both = Extractor(
        CompilerContext(Console(verbose=False)),
        verbose=False,
        source_code=sources,
        analysis_root="/proj",
    )
    prog_both = ext_both.extract_from_multiple_files(sources)
    ext_single = Extractor(
        CompilerContext(Console(verbose=False)),
        verbose=False,
        source_code={"/proj/b.py": sources["/proj/b.py"]},
        analysis_root="/proj",
    )
    prog_single = ext_single.extract_from_multiple_files({"/proj/b.py": sources["/proj/b.py"]})

    f_both = next(c for c in prog_both.liveCode if c.codeName() == "f")
    f_single = next(c for c in prog_single.liveCode if c.codeName() == "f")
    assert [repr(b) for b in f_both.ast.blocks] == [repr(b) for b in f_single.ast.blocks]


def test_relative_imports_in_package_init_files_resolve_within_package():
    sources = {
        "/proj/pkg/__init__.py": "from .utils import TopUtil\n",
        "/proj/pkg/sub/__init__.py": "from .models import User\nclass SubUser(User):\n    pass\n",
        "/proj/pkg/sub/models.py": "class User:\n    def greet(self):\n        return 'hi'\n",
    }
    ext = Extractor(
        CompilerContext(Console(verbose=False)),
        verbose=False,
        source_code=sources,
        analysis_root="/proj",
    )
    prog = ext.extract_from_multiple_files(sources)
    assert ext._module_imports["pkg"]["TopUtil"] == "pkg.utils.TopUtil"
    assert ext._module_imports["pkg.sub"]["User"] == "pkg.sub.models.User"
    assert prog.class_hierarchy.resolve_method("pkg.sub.SubUser", "greet") == "pkg.sub.models.User"

    resolver = DependencyResolver(strategy="ast_only", source_files=sources, analysis_root="/proj")
    resolver.preload_sources(sources)
    assert (
        resolver._module_cache["/proj/pkg/__init__.py"]["imports"]["TopUtil"] == "pkg.utils.TopUtil"
    )
    assert (
        resolver._module_cache["/proj/pkg/sub/__init__.py"]["imports"]["User"]
        == "pkg.sub.models.User"
    )


def test_ast_converter_handles_deep_elif_and_ifexp_chains_without_recursion_error():
    n = 500
    elif_src = (
        "def dispatch(x):\n"
        "    if x == 0:\n"
        "        return 0\n"
        + "".join(f"    elif x == {i}:\n        return {i}\n" for i in range(1, n))
        + "    return -1\n"
    )
    ifexp_src = "val = " + "".join(f"{i} if c else " for i in range(n)) + "0\n"

    conv = ASTConverter(verbose=False, retain_source_syntax=False)
    suite1 = conv.convert_python_ast_to_pyflow(ast.parse(elif_src).body)
    suite2 = conv.convert_python_ast_to_pyflow(ast.parse(ifexp_src).body)
    assert len(suite1.blocks) == 1
    assert len(suite2.blocks) == 1


def test_starred_type_unpacking_and_starred_class_bases_emit_no_approx_warnings():
    src = (
        "from typing import Any, Callable, Generic, TypeVarTuple\n"
        "Ts = TypeVarTuple('Ts')\n"
        "class Box(Generic[*Ts]):\n"
        "    pass\n"
        "def log(fn: Callable[[*Ts], Any], *args: *Ts) -> None:\n"
        "    pass\n"
        "bases = (object,)\n"
        "class Dynamic(*bases):\n"
        "    pass\n"
    )
    conv = ASTConverter(verbose=False, retain_source_syntax=False)
    conv.convert_python_ast_to_pyflow(ast.parse(src).body)
    assert conv.approximation_warnings == []


def test_build_interface_does_not_emit_secondary_keyerror_on_unreadable_file():
    with TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad_coding.py"
        bad.write_bytes(b"# coding: uft-8\nx = 1\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            interface, sources = build_interface_from_paths([bad], InterfaceBuildOptions())
        output = buf.getvalue()
        assert "Could not read" in output
        assert "Could not parse file" not in output
        assert sources == {}
        assert interface.func == []


def test_entry_discovery_resolves_setup_py_entry_points_variable_and_ini_string(tmp_path):
    pkg = tmp_path / "demo"
    pkg.mkdir()
    entry = pkg / "cli.py"
    entry.write_text("def main():\n    pass\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "entry_points = {'console_scripts': ['demo = demo.cli:main']}\n"
        "setup(name='demo', entry_points=entry_points)\n",
        encoding="utf-8",
    )
    candidates = discover_entry_files(tmp_path)
    assert [c.path for c in candidates] == [Path("demo/cli.py")]
    assert candidates[0].command == "demo"

    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        'setup(name="demo", entry_points="[console_scripts]\\ndemo = demo.cli:main\\n")\n',
        encoding="utf-8",
    )
    candidates_ini = discover_entry_files(tmp_path)
    assert [c.path for c in candidates_ini] == [Path("demo/cli.py")]


def test_ir_metadata_and_class_info_do_not_leak_programs_after_gc():
    source = (
        "class Service:\n"
        "    def run(self, x):\n"
        "        def inner(y):\n"
        "            return x + y\n"
        "        return inner(len([1, 2]))\n"
    )
    for retain in (False, True):
        compiler = CompilerContext(Console(verbose=False))
        program = Program()
        compiler.extractor = Extractor(
            compiler,
            verbose=False,
            source_code={"svc.py": source},
            retain_source_syntax=retain,
        )
        extract_program(compiler, program)

        cls_info = program.class_hierarchy.get_class_info("svc.Service")
        if retain:
            assert cls_info.ast_node is not None
        else:
            assert cls_info.ast_node is None

        run_code = next(c for c in program.liveCode if c.codeName() == "Service.run")
        assert ir_metadata.code_child_codes(run_code) is not None
        assert len(ir_metadata.code_child_codes(run_code)) == 1
        code_ref = weakref.ref(run_code)
        prog_ref = weakref.ref(program)

        del run_code, cls_info, program, compiler
        gc.collect()

        assert code_ref() is None
        assert prog_ref() is None
        assert len(ir_metadata._CALL_ARGUMENT_ORDERS) == 0
        assert len(ir_metadata._CODE_DEFINITION_ANNOTATIONS) == 0
        assert len(ir_metadata._CLASS_CELLS) == 0
        assert len(ir_metadata._GIR_SOURCE_NODES) == 0


def test_http_entry_functions_skips_parsing_non_framework_files():
    sources = {
        "plain.py": "def helper(x):\n    return x + 1\n",
        "web.py": (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/ping')\n"
            "def ping():\n"
            "    return 'ok'\n"
        ),
    }
    with patch("pyflow.frontend.frameworks.ast.parse", wraps=ast.parse) as spy:
        entries = http_entry_functions(sources)
    assert entries == {("web.py", "ping")}
    assert spy.call_count == 1


def test_project_context_caches_realpath_and_stub_resolver_lazy_cache(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    mod = pkg / "mod.py"
    mod.write_text("x = 1\n", encoding="utf-8")

    ctx = ProjectContext(tmp_path, sys_path=[str(tmp_path)])
    assert ctx.module_name_from_path(mod) == "pkg.mod"
    assert ctx._realpath_cache

    resolver = StubResolver(ctx, typeshed_roots=[])
    assert resolver._stub_cache_instance is None
