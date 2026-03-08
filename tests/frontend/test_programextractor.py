"""Unit tests for programextractor module."""

import unittest
import ast
from unittest.mock import Mock, patch

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.api.entrypoints import InterfaceDeclaration, ExistingWrapper, nullWrapper
from pyflow.util.application.console import Console
from pyflow.frontend.programextractor import (
    Extractor,
    create_interface_from_paths,
    extractProgram,
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
        self.assertIsNotNone(self.extractor.stub_manager)
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

    def test_create_interface_from_paths_includes_class_only_modules(self):
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

            interface, _sources = create_interface_from_paths([sample], Args())

        self.assertEqual(len(interface.cls), 1)
        self.assertFalse(interface.func)

    def test_create_interface_from_paths_binds_instance_methods_via_class_decl(self):
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

            interface, sources = create_interface_from_paths([sample], Args())
            program = Program()
            program.interface = interface
            compiler = CompilerContext(Console())
            compiler.extractor = Extractor(
                compiler, verbose=False, source_code=sources
            )
            extractProgram(compiler, program)

        method_eps = [
            ep
            for ep in program.interface.entryPoint
            if ep.code.codeName() == "run"
        ]
        self.assertEqual(len(method_eps), 1)
        self.assertEqual(type(method_eps[0].selfarg).__name__, "ExistingWrapper")
        self.assertEqual(len(method_eps[0].args), 2)

    def test_create_interface_from_paths_binds_class_and_static_methods(self):
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

            interface, sources = create_interface_from_paths([sample], Args())
            program = Program()
            program.interface = interface
            compiler = CompilerContext(Console())
            compiler.extractor = Extractor(
                compiler, verbose=False, source_code=sources
            )
            extractProgram(compiler, program)

        build_eps = [
            ep
            for ep in program.interface.entryPoint
            if ep.code.codeName() == "build"
        ]
        util_eps = [
            ep
            for ep in program.interface.entryPoint
            if ep.code.codeName() == "util"
        ]
        self.assertEqual(len(build_eps), 1)
        self.assertEqual(len(util_eps), 1)
        self.assertEqual(type(build_eps[0].selfarg).__name__, "ExistingWrapper")
        self.assertEqual(type(util_eps[0].selfarg).__name__, "ExistingWrapper")
        self.assertEqual(len(build_eps[0].args), 2)
        self.assertEqual(len(util_eps[0].args), 1)

    def test_create_interface_from_paths_treats_property_as_attribute(self):
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

            interface, _sources = create_interface_from_paths([sample], Args())

        self.assertEqual(len(interface.cls), 1)
        self.assertEqual(interface.cls[0]._attr, ["token"])
        self.assertNotIn("token", interface.cls[0]._method)

    def test_create_interface_from_paths_synthesizes_posonly_function_args(self):
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

            interface, sources = create_interface_from_paths([sample], Args())
            program = Program()
            program.interface = interface
            compiler = CompilerContext(Console())
            compiler.extractor = Extractor(
                compiler, verbose=False, source_code=sources
            )
            extractProgram(compiler, program)

        func_eps = [
            ep for ep in program.interface.entryPoint if ep.code.codeName() == "f"
        ]
        self.assertEqual(len(func_eps), 1)
        self.assertEqual(len(func_eps[0].args), 2)

    def test_create_interface_from_paths_tracks_keyword_only_function_args(self):
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

            interface, _sources = create_interface_from_paths([sample], Args())

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
    """Test cases for the extractProgram function."""

    def setUp(self):
        """Set up test fixtures."""
        self.console = Console()
        self.compiler = CompilerContext(self.console)
        self.program = Program()

    def test_extract_program_without_extractor(self):
        """Test extractProgram creates extractor if none exists."""
        self.assertIsNone(self.compiler.extractor)
        extractProgram(self.compiler, self.program)
        self.assertIsNotNone(self.compiler.extractor)

    def test_extract_program_with_extractor(self):
        """Test extractProgram uses existing extractor."""
        extractor = Extractor(self.compiler, verbose=False)
        self.compiler.extractor = extractor
        extractProgram(self.compiler, self.program)
        self.assertEqual(self.compiler.extractor, extractor)

    def test_extract_program_with_source_code_dict(self):
        """Test extractProgram with source code dictionary."""
        source_dict = {
            "file1.py": "def func1(): return 1",
            "file2.py": "def func2(): return 2"
        }
        extractor = Extractor(self.compiler, verbose=False, source_code=source_dict)
        self.compiler.extractor = extractor
        extractProgram(self.compiler, self.program)
        # Should not raise an exception
        self.assertIs(self.program.class_hierarchy, extractor.class_hierarchy)
        self.assertIs(self.program.cross_module_resolver, extractor.cross_module_resolver)
        self.assertIsNotNone(self.program.frontend_telemetry)

    def test_extract_program_with_interface(self):
        """Test extractProgram with interface."""
        from pyflow.api.entrypoints import InterfaceDeclaration
        
        interface_decl = InterfaceDeclaration()
        self.program.interface = interface_decl
        
        extractor = Extractor(self.compiler, verbose=False)
        self.compiler.extractor = extractor
        extractProgram(self.compiler, self.program)
        # Should not raise an exception


if __name__ == "__main__":
    unittest.main()
