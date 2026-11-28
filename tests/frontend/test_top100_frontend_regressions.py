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


def test_class_hierarchy_external_base_keeps_object_last_in_mro():
    ch = ClassHierarchy()
    ch.register_class("Base", [], "mod")
    ch.register_class("OtherBase", [], "mod")
    ch.register_class("Sub", ["Base"], "mod")
    ch.get_class_info("mod.Sub").resolved_bases = ["mod.Base"]
    ch.register_class("Mixed", ["Sub", "ext.Trait"], "mod")
    ch.get_class_info("mod.Mixed").resolved_bases = ["mod.Sub", "ext.Trait"]
    ch.register_class("Other", ["ext.Trait", "OtherBase"], "mod")
    ch.get_class_info("mod.Other").resolved_bases = ["ext.Trait", "mod.OtherBase"]
    ch.register_class("Combined", ["Other", "Mixed"], "mod")
    ch.get_class_info("mod.Combined").resolved_bases = ["mod.Other", "mod.Mixed"]

    mixed_mro = ch.get_mro("mod.Mixed")
    assert mixed_mro[-1] == "builtins.object"
    assert mixed_mro.index("ext.Trait") < mixed_mro.index("builtins.object")
    combined_mro = ch.get_mro("mod.Combined")
    assert combined_mro[-1] == "builtins.object"
    assert ch.get_mro("ext.Trait") == ["ext.Trait"]


def test_extractor_self_redefinition_class_does_not_create_mro_cycle():
    source = (
        "class Base:\n"
        "    def a(self): return 1\n"
        "class Child(Base):\n"
        "    def b(self): return 2\n"
        "class Child(Child):\n"
        "    def c(self): return 3\n"
    )
    compiler = CompilerContext(Console(verbose=False))
    program = Program()
    compiler.extractor = Extractor(
        compiler,
        verbose=False,
        source_code={"mod.py": source},
        defer_semantics=True,
    )
    extract_program(compiler, program)

    mro = program.class_hierarchy.get_mro("mod.Child")
    assert mro == ["mod.Child", "mod.Base", "builtins.object"]


def test_value_table_for_code_tracks_defined_values_and_ir_core_slots():
    from pyflow.ir.core.ids import CodeId, NodeId, ScopeId, SymbolId
    from pyflow.ir.core.semantics import ControlEffects, OperationSemantics
    from pyflow.ir.core.storage import LocalStorage
    from pyflow.ir.core.symbols import Symbol, SymbolKind, Value, ValueTable

    code_id = CodeId("mod", "f")
    scope_id = ScopeId(code_id, 0)
    sym_id = SymbolId(scope_id, 0)
    node_id = NodeId(code_id, 0)

    vt = ValueTable()
    val = vt.define(sym_id, node_id)
    assert vt.for_code(code_id) == (val,)

    # Hot IR identity/semantic records must stay slotted (no per-instance __dict__).
    for obj in (
        code_id,
        node_id,
        sym_id,
        val,
        Symbol(sym_id, "x", SymbolKind.LOCAL),
        ControlEffects(),
        OperationSemantics(),
        LocalStorage(sym_id),
    ):
        assert not hasattr(obj, "__dict__"), f"{type(obj).__name__} unexpectedly has __dict__"


def test_ddg_chain_compression_matches_point_reaching_on_loops_and_kills():
    from pyflow.ir.cfg import transform as cfg_transform
    from pyflow.ir.ddg import construct_ddg

    source = (
        "def f(items, obj):\n"
        "    total = 0\n"
        "    for x in items:\n"
        "        total = total + x\n"
        "        obj.val = total\n"
        "        y = obj.val\n"
        "        if y > 10:\n"
        "            del total\n"
        "            total = 0\n"
        "    return total\n"
    )
    compiler = CompilerContext(Console(verbose=False))
    program = Program()
    compiler.extractor = Extractor(
        compiler, verbose=False, source_code={"m.py": source}, defer_semantics=False
    )
    extract_program(compiler, program)
    code = next(c for c in program.liveCode if c.codeName() == "f")
    cfg = cfg_transform.evaluate(compiler, code)
    ddg = construct_ddg(cfg)
    assert ddg.all_edges()


def test_cli_lsp_source_query_index_handles_non_utf8_and_parent_build_dir(tmp_path):
    from pyflow.cli.lsp import _source_query_index

    # Place repo inside a directory named 'build' to ensure parent path parts are not ignored.
    project = tmp_path / "build" / "myproj"
    project.mkdir(parents=True)
    latin1_file = project / "latin1.py"
    latin1_file.write_bytes(b"# -*- coding: latin-1 -*-\ndef caf\xe9():\n    return 1\n")
    bom_file = project / "bom.py"
    bom_file.write_bytes("\ufeffdef greet():\n    return 'hi'\n".encode("utf-8"))

    index = _source_query_index(project)
    names = {sym.name for sym in index.symbols}
    assert "greet" in names
    assert any(name.startswith("caf") for name in names)


def test_class_hierarchy_partial_mro_fallback_and_dotted_external_bases():
    import pytest
    from pyflow.frontend.resolution.hierarchy import MROError

    hierarchy = ClassHierarchy(verbose=False)
    # Dotted imported base resolves even when target class is unregistered/external.
    assert hierarchy.resolve_base_class("nn.Module", "mod", {"nn": "torch.nn"}) == "torch.nn.Module"

    # Partial extraction pattern (Home Assistant ModbusThermostat without RestoreEntity loaded):
    # ModbusStructEntity(ModbusBaseEntity, RestoreEntity) + ClimateEntity(Entity)
    # where RestoreEntity is unregistered creates a synthetic C3 conflict unless handled safely.
    hierarchy.register_class("Entity", [], "ha.entity", methods={"entity_id"})
    hierarchy.register_class("ModbusBaseEntity", ["Entity"], "ha.modbus")
    hierarchy.get_class_info("ha.modbus.ModbusBaseEntity").resolved_bases = ["ha.entity.Entity"]
    hierarchy.register_class(
        "ModbusStructEntity", ["ModbusBaseEntity", "RestoreEntity"], "ha.modbus"
    )
    hierarchy.get_class_info("ha.modbus.ModbusStructEntity").resolved_bases = [
        "ha.modbus.ModbusBaseEntity",
        "ha.restore.RestoreEntity",
    ]
    hierarchy.register_class("ClimateEntity", ["Entity"], "ha.climate", methods={"set_temp"})
    hierarchy.get_class_info("ha.climate.ClimateEntity").resolved_bases = ["ha.entity.Entity"]
    hierarchy.register_class(
        "ModbusThermostat", ["ModbusStructEntity", "RestoreEntity", "ClimateEntity"], "ha.modbus"
    )
    hierarchy.get_class_info("ha.modbus.ModbusThermostat").resolved_bases = [
        "ha.modbus.ModbusStructEntity",
        "ha.restore.RestoreEntity",
        "ha.climate.ClimateEntity",
    ]

    mro = hierarchy.get_mro("ha.modbus.ModbusThermostat")
    assert mro[0] == "ha.modbus.ModbusThermostat"
    assert mro[-1] == "builtins.object"
    assert (
        hierarchy.resolve_method("ha.modbus.ModbusThermostat", "set_temp")
        == "ha.climate.ClimateEntity"
    )
    assert hierarchy.resolve_method("ha.modbus.ModbusThermostat", "entity_id") == "ha.entity.Entity"

    # Genuinely inconsistent fully-registered hierarchies must still raise MROError.
    bad = ClassHierarchy(verbose=False)
    bad.register_class("X", [], "m")
    bad.register_class("Y", [], "m")
    bad.register_class("A", ["X", "Y"], "m")
    bad.get_class_info("m.A").resolved_bases = ["m.X", "m.Y"]
    bad.register_class("B", ["Y", "X"], "m")
    bad.get_class_info("m.B").resolved_bases = ["m.Y", "m.X"]
    bad.register_class("C", ["A", "B"], "m")
    bad.get_class_info("m.C").resolved_bases = ["m.A", "m.B"]
    with pytest.raises(MROError):
        bad.get_mro("m.C")


def test_extractor_strips_non_package_src_prefix_and_preserves_nested_origins(tmp_path):
    pkg = tmp_path / "src" / "demo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    mod = pkg / "worker.py"
    src = (
        "def run(items):\n"
        "    total = 0\n"
        "    for item in items:\n"
        "        if item:\n"
        "            with ctx():\n"
        "                total += item\n"
        "    return total\n"
    )
    mod.write_text(src, encoding="utf-8")

    ext = Extractor(
        CompilerContext(Console(verbose=False)),
        verbose=False,
        source_code={str(mod): src},
        analysis_root=str(tmp_path),
    )
    assert ext._get_module_name(str(mod)) == "demo.worker"
    prog = ext.extract_from_multiple_files({str(mod): src})
    run_code = next(c for c in prog.liveCode if c.codeName() == "run")
    assert run_code.annotation.origin is not None

    conv = ASTConverter(verbose=False, retain_source_syntax=False)
    conv.current_filename = str(mod)
    suite = conv.convert_python_ast_to_pyflow(ast.parse(src).body)
    assert conv._origin_propagated_ids
    assert suite.blocks[0].annotation.origin is not None


def test_interface_builder_default_entry_args_fast_path():
    import inspect
    from pyflow.frontend.interface_builder import _default_entry_args
    from pyflow.frontend.resolution.ast_index import ASTFunctionProxy

    sig = inspect.Signature(
        [
            inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter("x", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter("y", inspect.Parameter.POSITIONAL_OR_KEYWORD, default=1),
        ]
    )
    proxy = ASTFunctionProxy(
        name="compute",
        qualname="Demo.compute",
        module="mod",
        filename="mod.py",
        firstlineno=1,
        signature=sig,
    )
    with patch(
        "pyflow.frontend.interface_builder.inspect.signature", wraps=inspect.signature
    ) as spy:
        assert _default_entry_args(object.__init__, skip_first=True) == ((), ())
        args, keywords = _default_entry_args(proxy, skip_first=True)
        assert len(args) == 2
        assert keywords == ()
        assert spy.call_count == 0


def test_detect_entry_file_skips_parsing_nested_scripts(tmp_path):
    from pyflow.frontend.entry_discovery import detect_entry_file

    nested = tmp_path / "sub" / "tool.py"
    nested.parent.mkdir()
    nested.write_text("if __name__ == '__main__':\n    pass\n", encoding="utf-8")

    with patch("pyflow.frontend.entry_discovery.ast.parse", wraps=ast.parse) as mock_parse:
        assert detect_entry_file(tmp_path) is None
        assert mock_parse.call_count == 0

    candidates = discover_entry_files(tmp_path)
    assert len(candidates) == 1
    assert not candidates[0].auto_select
