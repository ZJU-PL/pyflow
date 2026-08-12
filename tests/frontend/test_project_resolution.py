import ast
import tempfile
import unittest
from pathlib import Path

from pyflow.language.modules.project_resolution import (
    ProjectContext,
    check_sys_path_modifications,
    transform_path_to_dotted,
)
from pyflow.language.modules.imports import discover_module_exports


class TestProjectResolution(unittest.TestCase):
    def test_discover_exports_uses_top_level_dotted_import_binding(self):
        exports = discover_module_exports(
            "import package.module\nimport package.other as alias\n"
        )

        self.assertEqual(exports, ["alias", "package"])

    def test_transform_path_to_dotted_prefers_shortest_sys_path(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            nested = root / "venv" / "lib"
            pkg = nested / "pkg"
            pkg.mkdir(parents=True)
            module = pkg / "mod.py"
            module.write_text("VALUE = 1\n", encoding="utf-8")

            dotted, is_package = transform_path_to_dotted(
                [str(root), str(nested)], module
            )

            self.assertEqual(dotted, ("pkg", "mod"))
            self.assertFalse(is_package)

    def test_module_name_from_path_prefers_project_root_over_shorter_sys_path(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            package = root / "pkg"
            package.mkdir()
            module = package / "mod.py"
            module.write_text("", encoding="utf-8")
            context = ProjectContext(root, sys_path=[str(package)])

            self.assertEqual(context.module_name_from_path(module), "pkg.mod")

    def test_workspace_roots_use_the_same_nearest_root_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            backend = root / "backend"
            frontend = root / "frontend"
            backend_module = backend / "pkg" / "api.py"
            frontend_module = frontend / "pkg" / "ui.py"
            backend_module.parent.mkdir(parents=True)
            frontend_module.parent.mkdir(parents=True)
            backend_module.write_text("", encoding="utf-8")
            frontend_module.write_text("", encoding="utf-8")
            context = ProjectContext(
                root,
                sys_path=[],
                workspace_roots=[backend, frontend],
            )

            self.assertEqual(context.module_name_from_path(backend_module), "pkg.api")
            self.assertEqual(context.module_name_from_path(frontend_module), "pkg.ui")

    def test_get_sys_path_adds_project_and_parent_paths_like_jedi(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            package = root / "pkg"
            sub = package / "sub"
            sub.mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
            script = sub / "mod.py"
            script.write_text("", encoding="utf-8")

            context = ProjectContext(root, sys_path=[])
            paths = context.get_sys_path(script_path=script)

            self.assertEqual(paths[0], str(root))
            self.assertIn(str(sub), paths)
            self.assertNotIn(str(package), paths)

    def test_sys_path_modification_detection_uses_module_relative_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            module = root / "pkg" / "mod.py"
            module.parent.mkdir()
            module.write_text("", encoding="utf-8")
            source = "import sys\nsys.path.append('../vendor')\n"

            paths = check_sys_path_modifications(source, str(module))

            self.assertEqual(
                paths,
                [str((root / "vendor").resolve(strict=False))],
            )

    def test_resolve_relative_import_for_package_module(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            context = ProjectContext(root, sys_path=[])
            current = root / "pkg" / "sub" / "mod.py"
            current.parent.mkdir(parents=True)
            current.write_text("", encoding="utf-8")

            resolved = context.resolve_import_name(
                "pkg.sub.mod", "tools", 2, current_path=current
            )

            self.assertEqual(resolved, "pkg.tools")

    def test_relative_import_beyond_top_level_is_unresolved(self):
        context = ProjectContext(sys_path=[])

        resolved = context.resolve_import_name(
            "pkg.sub.mod",
            "tools",
            3,
            current_path="pkg/sub/mod.py",
        )

        self.assertIsNone(resolved)

    def test_find_module_prefers_package_over_same_named_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "choice.py").write_text("MODULE = True\n", encoding="utf-8")
            package = root / "choice"
            package.mkdir()
            init = package / "__init__.py"
            init.write_text("PACKAGE = True\n", encoding="utf-8")
            context = ProjectContext(root, sys_path=[])

            resolution = context.find_module("choice")

            self.assertEqual(resolution.path, str(init.absolute()))
            self.assertTrue(resolution.is_package)

    def test_find_module_rejects_child_of_shadowing_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pkg.py").write_text("VALUE = 1\n", encoding="utf-8")
            package = root / "pkg"
            package.mkdir()
            (package / "child.py").write_text("VALUE = 2\n", encoding="utf-8")
            context = ProjectContext(root, sys_path=[])

            self.assertIsNone(context.find_module("pkg.child"))

    def test_find_module_supports_standalone_pyi_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "only_stub.pyi"
            stub.write_text("def build() -> int: ...\n", encoding="utf-8")
            context = ProjectContext(root, sys_path=[])

            resolution = context.find_module("only_stub")

            self.assertEqual(resolution.path, str(stub.absolute()))

    def test_find_module_does_not_cache_filesystem_misses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = ProjectContext(root, sys_path=[])
            self.assertIsNone(context.find_module("created_later"))

            module = root / "created_later.py"
            module.write_text("VALUE = 1\n", encoding="utf-8")

            self.assertEqual(
                context.find_module("created_later").path,
                str(module.absolute()),
            )

    def test_find_module_supports_implicit_namespace_packages(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ns = root / "ns_pkg"
            ns.mkdir()
            (ns / "child.py").write_text("def f():\n    return 1\n", encoding="utf-8")
            context = ProjectContext(root, sys_path=[])

            namespace = context.find_module("ns_pkg")
            child = context.find_module("ns_pkg.child")

            self.assertIsNotNone(namespace)
            self.assertTrue(namespace.is_namespace)
            self.assertEqual(namespace.path, None)
            self.assertEqual(child.path, str((ns / "child.py").absolute()))

    def test_iter_imported_modules_emits_submodule_imports_through_namespace(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ns = root / "ns_pkg"
            ns.mkdir()
            (ns / "child.py").write_text("def f():\n    return 1\n", encoding="utf-8")
            context = ProjectContext(root, sys_path=[])
            tree = ast.parse("from ns_pkg import child\n")

            imports = list(
                context.iter_imported_modules(
                    tree,
                    current_module="main",
                    current_path=str(root / "main.py"),
                )
            )

            self.assertEqual(imports, ["ns_pkg", "ns_pkg.child"])


if __name__ == "__main__":
    unittest.main()
