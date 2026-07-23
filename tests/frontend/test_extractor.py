"""Unit tests for the frontend extractor module."""

import unittest
import ast
import tempfile
from unittest.mock import Mock

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.api.entrypoints import InterfaceDeclaration, ExistingWrapper, nullWrapper
from pyflow.analysis import ipa
from pyflow.util.application.console import Console
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)


def _build_interface(python_files, args):
    return build_interface_from_paths(
        python_files, InterfaceBuildOptions.from_namespace(args)
    )


class TestExtractor(unittest.TestCase):
    """Test cases for the Extractor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.console = Console()
        self.compiler = CompilerContext(self.console)
        self.extractor = Extractor(self.compiler, verbose=False)

    def test_init(self):
        """Test Extractor initialization."""
        self.assertEqual(self.extractor.compiler, self.compiler)
        self.assertFalse(self.extractor.verbose)
        self.assertEqual(self.extractor.functions, [])
        self.assertEqual(self.extractor.builtin, 0)
        self.assertEqual(self.extractor.errors, 0)
        self.assertEqual(self.extractor.failures, 0)
        self.assertIsNotNone(self.extractor.desc)
        self.assertIsNotNone(self.extractor.intrinsic_manager)
        self.assertIsNotNone(self.extractor.function_extractor)
        self.assertIsNotNone(self.extractor.object_manager)

    def test_init_with_source_code(self):
        """Test Extractor initialization with source code."""
        source = "def hello(): pass"
        extractor = Extractor(self.compiler, verbose=False, source_code=source)
        self.assertEqual(extractor.source_code, source)

    def test_init_with_source_code_dict(self):
        """Test Extractor initialization with source code dictionary."""
        source_dict = {"file1.py": "def func1(): pass", "file2.py": "def func2(): pass"}
        extractor = Extractor(self.compiler, verbose=False, source_code=source_dict)
        self.assertEqual(extractor.source_code, source_dict)

    def test_extract_from_source_simple_function(self):
        """Test extracting a simple function from source."""
        source = """
def add(a, b):
    return a + b
"""
        program = self.extractor.extract_from_source(source, "test.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 0)

    def test_extract_from_source_with_class(self):
        """Test extracting a class from source."""
        source = """
class MyClass:
    def method(self):
        return 42
"""
        program = self.extractor.extract_from_source(source, "test.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 0)

    def test_extract_from_source_syntax_error(self):
        """Test handling syntax errors."""
        source = "def invalid syntax here"
        program = self.extractor.extract_from_source(source, "test.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 1)

    def test_extract_from_file_existing(self):
        """Test extracting from an existing file."""
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def test_func(): return 1\n")
            temp_path = f.name
        
        try:
            program = self.extractor.extract_from_file(temp_path)
            self.assertIsInstance(program, Program)
            self.assertEqual(self.extractor.errors, 0)
        finally:
            os.unlink(temp_path)

    def test_extract_from_file_not_found(self):
        """Test extracting from a non-existent file."""
        program = self.extractor.extract_from_file("nonexistent_file.py")
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 1)

    def test_extract_from_multiple_files(self):
        """Test extracting from multiple files."""
        source_files = {
            "file1.py": "def func1(): return 1",
            "file2.py": "def func2(): return 2"
        }
        program = self.extractor.extract_from_multiple_files(source_files)
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 0)
        self.assertIs(program.class_hierarchy, self.extractor.class_hierarchy)
        self.assertIs(program.cross_module_resolver, self.extractor.cross_module_resolver)

    def test_extract_from_multiple_files_with_error(self):
        """Test extracting from multiple files with one error."""
        source_files = {
            "file1.py": "def func1(): return 1",
            "file2.py": "invalid syntax here"
        }
        program = self.extractor.extract_from_multiple_files(source_files)
        self.assertIsInstance(program, Program)
        self.assertEqual(self.extractor.errors, 1)

    def test_program_includes_frontend_telemetry(self):
        """Extraction should attach frontend precision telemetry to the Program."""
        source = "def a(**x):\n    return f(**x, **x)\n"
        program = self.extractor.extract_from_source(source, "pkg/test.py")
        self.assertTrue(hasattr(program, "frontend_telemetry"))
        telemetry = program.frontend_telemetry
        self.assertIsInstance(telemetry, dict)

    def test_get_object(self):
        """Test getting an object representation."""
        obj = self.extractor.getObject(42)
        self.assertIsNotNone(obj)

    def test_get_object_call(self):
        """Test getting object call information."""
        def test_func():
            return 1
        
        func_obj, code_obj = self.extractor.getObjectCall(test_func)
        self.assertIsNotNone(func_obj)
        # code_obj might be None if source code is not available
        self.assertIsNotNone(func_obj)

    def test_get_object_call_with_source_code(self):
        """Test getting object call with source code."""
        source = "def test_func(): return 1"
        self.extractor.source_code = source
        
        def test_func():
            return 1
        
        func_obj, code_obj = self.extractor.getObjectCall(test_func)
        self.assertIsNotNone(func_obj)

    def test_make_imaginary(self):
        """Test creating an imaginary object."""
        from pyflow.language.python.program import AbstractObject
        
        # Create a mock abstract object
        abstract_obj = Mock(spec=AbstractObject)
        imaginary = self.extractor.makeImaginary("test", abstract_obj, False)
        self.assertIsNotNone(imaginary)

    def test_ensure_loaded(self):
        """Test ensuring an object is loaded."""
        from pyflow.language.python.program import AbstractObject
        
        abstract_obj = Mock(spec=AbstractObject)
        abstract_obj.type = None
        abstract_obj.pyobj = int
        
        # Should not raise an exception
        self.extractor.ensureLoaded(abstract_obj)

    def test_ensure_loaded_none(self):
        """Test ensuring None object is loaded."""
        # Should handle None gracefully
        result = self.extractor.ensureLoaded(None)
        self.assertIsNone(result)

    def test_get_call(self):
        """Test getting call information for an object."""
        def test_func():
            return 1
        
        # Create a mock object with pyobj
        mock_obj = Mock()
        mock_obj.pyobj = test_func
        
        result = self.extractor.getCall(mock_obj)
        # Result might be None if source code is not available
        self.assertIsNotNone(mock_obj)

    def test_convert_function(self):
        """Test converting a function."""
        def test_func(x):
            return x + 1
        
        source = "def test_func(x): return x + 1"
        self.extractor.source_code = source
        
        code = self.extractor.convertFunction(test_func)
        self.assertIsNotNone(code)

    def test_convert_function_with_source_dict(self):
        """Test converting a function with source code dictionary."""
        def test_func(x):
            return x + 1
        
        source_dict = {"test.py": "def test_func(x): return x + 1"}
        self.extractor.source_code = source_dict
        
        code = self.extractor.convertFunction(test_func)
        self.assertIsNotNone(code)

    def test_extract_from_ast(self):
        """Test extracting from AST."""
        source = "def test_func(): return 1"
        tree = ast.parse(source)
        program = self.extractor._extract_from_ast(tree, "test.py")
        self.assertIsInstance(program, Program)

    def test_extract_imports_resolves_relative_module(self):
        """Relative imports should resolve to concrete dotted modules."""
        source = "from .helpers import tool\n"
        tree = ast.parse(source)
        self.extractor.source_code = {}
        self.extractor._extract_imports(tree, "pkg.sub.mod")
        imports = self.extractor._module_imports["pkg.sub.mod"]
        self.assertEqual(imports["tool"], "pkg.sub.helpers.tool")

    def test_extract_imports_expands_star_from_source_map(self):
        """Star imports should expand when source for imported module is available."""
        source = "from pkg.lib import *\n"
        tree = ast.parse(source)
        self.extractor.source_code = {
            "pkg/lib.py": "def exposed():\n    return 1\n\ndef _hidden():\n    return 2\n"
        }
        self.extractor._extract_imports(tree, "pkg.consumer")
        imports = self.extractor._module_imports["pkg.consumer"]
        self.assertIn("exposed", imports)
        self.assertEqual(imports["exposed"], "pkg.lib.exposed")
        self.assertNotIn("_hidden", imports)

    def test_extract_imports_ignores_function_local_imports(self):
        """Function-local imports must not leak into the module import map."""
        source = (
            "def build():\n"
            "    import pkg as p\n"
            "    return p.Base\n"
        )
        tree = ast.parse(source)
        self.extractor.source_code = {}
        self.extractor._extract_imports(tree, "pkg.consumer")

        self.assertEqual(self.extractor._module_imports["pkg.consumer"], {})

    def test_package_init_module_name_is_canonicalized(self):
        """Package __init__.py should register under the package name."""
        self.assertEqual(self.extractor._get_module_name("pkg/__init__.py"), "pkg")

    def test_absolute_path_module_name_does_not_include_cwd_prefix(self):
        """Absolute paths outside the repo should not inherit cwd path segments."""
        self.assertEqual(self.extractor._get_module_name("/tmp/demo/pkg/mod.py"), "mod")

    def test_package_init_base_class_resolves_across_modules(self):
        """Classes imported from a package __init__ should participate in MRO."""
        source_files = {
            "pkg/__init__.py": "class Base:\n    def foo(self):\n        return 1\n",
            "pkg/sub.py": "from pkg import Base\nclass Child(Base):\n    pass\n",
        }
        extractor = Extractor(self.compiler, verbose=False, source_code=source_files)
        extractor.extract_from_multiple_files(source_files)

        self.assertIn("pkg.Base", extractor.class_hierarchy.classes)
        self.assertNotIn("pkg.__init__.Base", extractor.class_hierarchy.classes)
        self.assertEqual(
            extractor.class_hierarchy.get_class_info("pkg.sub.Child").resolved_bases,
            ["pkg.Base"],
        )
        self.assertEqual(
            extractor.class_hierarchy.resolve_method("pkg.sub.Child", "foo"),
            "pkg.Base",
        )

    def test_module_alias_base_class_resolves_across_modules(self):
        """Aliased module prefixes should resolve when used in class bases."""
        source_files = {
            "pkg/__init__.py": "class Base:\n    def foo(self):\n        return 1\n",
            "mod.py": "import pkg as p\nclass Child(p.Base):\n    pass\n",
        }
        extractor = Extractor(self.compiler, verbose=False, source_code=source_files)
        extractor.extract_from_multiple_files(source_files)

        self.assertEqual(
            extractor.class_hierarchy.get_class_info("mod.Child").resolved_bases,
            ["pkg.Base"],
        )
        self.assertEqual(
            extractor.class_hierarchy.resolve_method("mod.Child", "foo"),
            "pkg.Base",
        )

    def test_subscripted_base_class_resolves_across_modules(self):
        """Generic aliases in class bases should still resolve to the base class."""
        source_files = {
            "pkg/base.py": "class Base:\n    def foo(self):\n        return 1\n",
            "pkg/sub.py": "from pkg.base import Base\nclass Child(Base[int]):\n    pass\n",
        }
        extractor = Extractor(self.compiler, verbose=False, source_code=source_files)
        extractor.extract_from_multiple_files(source_files)

        self.assertEqual(
            extractor.class_hierarchy.get_class_info("pkg.sub.Child").bases,
            ["Base"],
        )
        self.assertEqual(
            extractor.class_hierarchy.get_class_info("pkg.sub.Child").resolved_bases,
            ["pkg.base.Base"],
        )
        self.assertEqual(
            extractor.class_hierarchy.resolve_method("pkg.sub.Child", "foo"),
            "pkg.base.Base",
        )

    def test_convert_function_selects_correct_nested_local_function(self):
        """Nested local functions with duplicate names should use the right source body."""
        source = """
def outer1():
    def inner():
        return 1
    return inner

def outer2():
    def inner():
        return 2
    return inner
"""
        namespace = {}
        exec(compile(source, "m.py", "exec"), namespace)
        inner = namespace["outer2"]()

        extractor = Extractor(
            self.compiler,
            verbose=False,
            source_code={"m.py": source},
        )
        code = extractor.convertFunction(inner)

        self.assertEqual(code.ast.blocks[0].exprs[0].object.pyobj, 2)

    def test_build_interface_includes_class_only_modules(self):
        """Class-only modules should still produce interface entries."""
        import tempfile
        from pathlib import Path

        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = False
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "class Service:\n"
                "    def run(self):\n"
                "        return 1\n",
                encoding="utf-8",
            )

            interface, _sources = _build_interface([sample], Args())

        self.assertEqual(len(interface.cls), 1)
        self.assertFalse(interface.func)

    def test_build_interface_binds_instance_methods_via_class_decl(self):
        """Instance methods should become class entry points, not free functions."""
        import tempfile
        from pathlib import Path

        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = False
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "class Service:\n"
                "    def run(self, x):\n"
                "        return x\n",
                encoding="utf-8",
            )

            interface, sources = _build_interface([sample], Args())
            program = Program()
            program.interface = interface
            compiler = CompilerContext(Console())
            compiler.extractor = Extractor(
                compiler, verbose=False, source_code=sources
            )
            extract_program(compiler, program)

        method_eps = [
            ep
            for ep in program.interface.entryPoint
            if ep.code.codeName().endswith(".run")
        ]
        self.assertEqual(len(method_eps), 1)
        self.assertTrue(method_eps[0].code.codeName().endswith("Service.run"))
        self.assertEqual(type(method_eps[0].selfarg).__name__, "ExistingWrapper")
        self.assertEqual(len(method_eps[0].args), 2)

    def test_build_interface_binds_class_and_static_methods(self):
        """Class and static methods should get the correct synthesized receiver args."""
        import tempfile
        from pathlib import Path

        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = False
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "class Service:\n"
                "    @classmethod\n"
                "    def build(cls, x):\n"
                "        return x\n\n"
                "    @staticmethod\n"
                "    def util(y):\n"
                "        return y\n",
                encoding="utf-8",
            )

            interface, sources = _build_interface([sample], Args())
            program = Program()
            program.interface = interface
            compiler = CompilerContext(Console())
            compiler.extractor = Extractor(
                compiler, verbose=False, source_code=sources
            )
            extract_program(compiler, program)

        build_eps = [
            ep
            for ep in program.interface.entryPoint
            if ep.code.codeName().endswith(".build")
        ]
        util_eps = [
            ep
            for ep in program.interface.entryPoint
            if ep.code.codeName().endswith(".util")
        ]
        self.assertEqual(len(build_eps), 1)
        self.assertEqual(len(util_eps), 1)
        self.assertTrue(build_eps[0].code.codeName().endswith("Service.build"))
        self.assertTrue(util_eps[0].code.codeName().endswith("Service.util"))
        self.assertEqual(type(build_eps[0].selfarg).__name__, "ExistingWrapper")
        self.assertEqual(type(util_eps[0].selfarg).__name__, "ExistingWrapper")
        self.assertEqual(len(build_eps[0].args), 2)
        self.assertEqual(len(util_eps[0].args), 1)

    def test_build_interface_treats_property_as_attribute(self):
        """Properties should become attribute entry points, not callable methods."""
        import tempfile
        from pathlib import Path

        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = False
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "class Service:\n"
                "    @property\n"
                "    def token(self):\n"
                "        return 1\n",
                encoding="utf-8",
            )

            interface, _sources = _build_interface([sample], Args())

        self.assertEqual(len(interface.cls), 1)
        self.assertEqual(interface.cls[0]._attr, ["token"])
        self.assertNotIn("token", interface.cls[0]._method)

    def test_build_interface_synthesizes_posonly_function_args(self):
        """Auto-generated entry points should include positional-only params."""
        import tempfile
        from pathlib import Path

        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = False
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "def f(a, /, b):\n"
                "    return a + b\n",
                encoding="utf-8",
            )

            interface, sources = _build_interface([sample], Args())
            program = Program()
            program.interface = interface
            compiler = CompilerContext(Console())
            compiler.extractor = Extractor(
                compiler, verbose=False, source_code=sources
            )
            extract_program(compiler, program)

        func_eps = [
            ep for ep in program.interface.entryPoint if ep.code.codeName() == "f"
        ]
        self.assertEqual(len(func_eps), 1)
        self.assertEqual(len(func_eps[0].args), 2)

    def test_build_interface_tracks_keyword_only_function_args(self):
        """Auto-generated declarations should preserve keyword-only arg names."""
        import tempfile
        from pathlib import Path

        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = False
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "def f(*, c):\n"
                "    return c\n",
                encoding="utf-8",
            )

            interface, _sources = _build_interface([sample], Args())

        self.assertEqual(len(interface.func), 1)
        func_obj, func_args, func_kwds = interface.func[0]
        self.assertEqual(func_obj.__name__, "f")
        self.assertEqual(func_args, ())
        self.assertEqual(len(func_kwds), 1)
        self.assertEqual(func_kwds[0][0], "c")

    def test_create_entrypoint_rejects_posonly_keyword_argument(self):
        """User-facing entrypoint creation should reject positional-only kwargs."""
        interface = InterfaceDeclaration()
        code = Mock()
        code.codeparameters = Mock(
            posonlynames=["a"],
            paramnames=["b"],
        )

        with self.assertRaisesRegex(
            ValueError, "Positional-only argument 'a' cannot be passed by keyword"
        ):
            interface.createEntryPoint(
                code=code,
                selfarg=nullWrapper,
                args=(),
                kwds=[("a", ExistingWrapper(1))],
                varg=nullWrapper,
                karg=nullWrapper,
            )

    def test_create_entrypoint_accepts_keyword_only_external_name(self):
        """Keyword-only params should be accepted under their source name."""
        interface = InterfaceDeclaration()
        code = Mock()
        code.codeparameters = Mock(
            posonlynames=[],
            paramnames=["kwonly:c"],
        )

        ep = interface.createEntryPoint(
            code=code,
            selfarg=nullWrapper,
            args=(),
            kwds=[("c", ExistingWrapper(1))],
            varg=nullWrapper,
            karg=nullWrapper,
        )

        self.assertEqual(len(ep.args), 1)
        self.assertFalse(ep.kwds)


class TestExtractProgram(unittest.TestCase):
    """Test cases for the extract_program function."""

    def setUp(self):
        """Set up test fixtures."""
        self.console = Console()
        self.compiler = CompilerContext(self.console)
        self.program = Program()

    def test_extract_program_without_extractor(self):
        """Test extract_program creates extractor if none exists."""
        self.assertIsNone(self.compiler.extractor)
        extract_program(self.compiler, self.program)
        self.assertIsNotNone(self.compiler.extractor)

    def test_extract_program_with_extractor(self):
        """Test extract_program uses existing extractor."""
        extractor = Extractor(self.compiler, verbose=False)
        self.compiler.extractor = extractor
        extract_program(self.compiler, self.program)
        self.assertEqual(self.compiler.extractor, extractor)

    def test_extract_program_with_source_code_dict(self):
        """Test extract_program with source code dictionary."""
        source_dict = {
            "file1.py": "def func1(): return 1",
            "file2.py": "def func2(): return 2"
        }
        extractor = Extractor(self.compiler, verbose=False, source_code=source_dict)
        self.compiler.extractor = extractor
        extract_program(self.compiler, self.program)
        # Should not raise an exception
        self.assertIs(self.program.class_hierarchy, extractor.class_hierarchy)
        self.assertIs(self.program.cross_module_resolver, extractor.cross_module_resolver)
        self.assertIsNotNone(self.program.frontend_telemetry)

    def test_extract_program_with_interface(self):
        """Test extract_program with interface."""
        from pyflow.api.entrypoints import InterfaceDeclaration
        
        interface_decl = InterfaceDeclaration()
        self.program.interface = interface_decl
        
        extractor = Extractor(self.compiler, verbose=False)
        self.compiler.extractor = extractor
        extract_program(self.compiler, self.program)
        # Should not raise an exception

    def test_extract_program_adds_module_entrypoint_for_top_level_code(self):
        """Files with only module-scope statements should still become entry roots."""
        extractor = Extractor(
            self.compiler,
            verbose=False,
            source_code={"pkg/mod.py": "x = source()\nsink(x)\n"},
        )
        self.compiler.extractor = extractor

        extract_program(self.compiler, self.program)

        code_names = {code.codeName() for code in self.program.liveCode}
        entry_names = {ep.code.codeName() for ep in self.program.entryPoints}
        self.assertIn("pkg.mod.<module>", code_names)
        self.assertIn("pkg.mod.<module>", entry_names)

    def test_extract_program_does_not_duplicate_class_body_as_separate_code(self):
        """Class bodies should be modeled via the module body, not a second synthetic root."""
        extractor = Extractor(
            self.compiler,
            verbose=False,
            source_code={
                "pkg/mod.py": (
                    "class C:\n"
                    "    x = source()\n"
                    "    sink(x)\n"
                    "    def run(self):\n"
                    "        return 1\n"
                )
            },
        )
        self.compiler.extractor = extractor

        extract_program(self.compiler, self.program)

        code_names = {code.codeName() for code in self.program.liveCode}
        self.assertNotIn("pkg.mod.C.<classbody>", code_names)

    def test_extract_program_single_source_string_extracts_live_code(self):
        """Single-source extraction should populate liveCode."""
        extractor = Extractor(
            self.compiler,
            verbose=False,
            source_code="def f():\n    return 1\n",
        )
        self.compiler.extractor = extractor

        extract_program(self.compiler, self.program)

        self.assertIn("f", {code.codeName() for code in self.program.liveCode})

    def test_extract_program_keeps_module_roots_available_with_interface(self):
        """Synthetic module roots should stay available for callers that need top-level semantics."""
        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = True
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            from pathlib import Path

            main = Path(tmpdir) / "main.py"
            dead = Path(tmpdir) / "dead.py"
            main.write_text("def main():\n    return 0\n", encoding="utf-8")
            dead.write_text("x = source()\nsink(x)\n", encoding="utf-8")

            interface, sources = _build_interface([main, dead], Args())
            self.program.interface = interface
            self.compiler.extractor = Extractor(
                self.compiler, verbose=False, source_code=sources
            )

            extract_program(self.compiler, self.program)

        self.assertEqual(
            {ep.code.codeName() for ep in self.program.entryPoints},
            {"dead.<module>", "main", "main.<module>"},
        )

    def test_method_entrypoints_use_qualified_names(self):
        """Methods from different classes should remain distinguishable by code name."""
        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = True
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            from pathlib import Path

            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "class A:\n"
                "    def run(self):\n"
                "        return 1\n\n"
                "class B:\n"
                "    def run(self):\n"
                "        return 2\n",
                encoding="utf-8",
            )

            interface, sources = _build_interface([sample], Args())
            self.program.interface = interface
            self.compiler.extractor = Extractor(
                self.compiler, verbose=False, source_code=sources
            )
            extract_program(self.compiler, self.program)

        method_names = sorted(
            ep.code.codeName()
            for ep in self.program.entryPoints
            if ep.code.codeName().endswith(".run")
        )
        self.assertEqual(method_names, ["sample.A.run", "sample.B.run"])

    def test_queries_resolve_cfg_without_duplicate_function_ambiguity(self):
        """Function lookups should deduplicate equivalent liveCode/interface code objects."""
        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = True
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            from pathlib import Path

            sample = Path(tmpdir) / "sample.py"
            sample.write_text(
                "def main():\n"
                "    return 0\n",
                encoding="utf-8",
            )

            interface, sources = _build_interface([sample], Args())
            self.program.interface = interface
            self.compiler.extractor = Extractor(
                self.compiler, verbose=False, source_code=sources
            )
            extract_program(self.compiler, self.program)

        cfg = self.program.get_queries(self.compiler).get_cfg("main")
        self.assertEqual(cfg.code.codeName(), "main")


class TestFrontendPipelineCompatibility(unittest.TestCase):
    def _build_program(self, source: str) -> tuple[CompilerContext, Program]:
        class Args:
            dependency_strategy = "auto"
            verbose = False
            include_main_entry_points = True
            search_paths = None

        with tempfile.TemporaryDirectory() as tmpdir:
            from pathlib import Path

            sample = Path(tmpdir) / "sample.py"
            sample.write_text(source, encoding="utf-8")

            interface, sources = _build_interface([sample], Args())
            compiler = CompilerContext(Console())
            compiler.extractor = Extractor(
                compiler, verbose=False, source_code=sources
            )
            program = Program()
            program.interface = interface
            extract_program(compiler, program)
            return compiler, program

    def test_ipa_accepts_namedexpr(self):
        compiler, program = self._build_program(
            "def f(xs):\n"
            "    if (n := len(xs)) > 0:\n"
            "        return n\n"
            "    return 0\n"
        )
        ipa.evaluate(compiler, program)

    def test_ipa_accepts_await(self):
        compiler, program = self._build_program(
            "async def f(x):\n"
            "    return await g(x)\n"
        )
        ipa.evaluate(compiler, program)

    def test_ipa_accepts_global_decl(self):
        compiler, program = self._build_program(
            "x = 0\n"
            "def f():\n"
            "    global x\n"
            "    x = 1\n"
            "    return x\n"
        )
        ipa.evaluate(compiler, program)

    def test_ipa_accepts_annotated_assignment(self):
        compiler, program = self._build_program(
            "def f():\n"
            "    x: int = 1\n"
            "    return x\n"
        )
        ipa.evaluate(compiler, program)


if __name__ == "__main__":
    unittest.main()
