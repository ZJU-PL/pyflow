"""Regression tests for interface-builder robustness (MRO/BOM/silent failures)."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)


def _build(paths):
    return build_interface_from_paths(paths, InterfaceBuildOptions())


class TestInterfaceBuilderRobustness(unittest.TestCase):
    def test_inconsistent_mro_proxy_falls_back_instead_of_crashing(self):
        source = (
            "class A:\n"
            "    pass\n"
            "\n"
            "class B(A):\n"
            "    pass\n"
            "\n"
            "class C(A, B):\n"
            "    pass\n"
        )
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "mro_sample.py"
            path.write_text(source, encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                interface, sources = _build([path])

        self.assertIn(str(path), sources)
        self.assertIn("Inconsistent MRO", stdout.getvalue())
        class_names = {decl.typeobj.__name__ for decl in interface.cls}
        self.assertEqual(class_names, {"A", "B", "C"})

    def test_utf8_bom_file_still_yields_functions(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom_sample.py"
            path.write_text("﻿def helper():\n    return 1\n", encoding="utf-8")
            interface, _sources = _build([path])

        function_names = {entry[0].__name__ for entry in interface.func}
        self.assertIn("helper", function_names)

    def test_syntax_error_file_emits_always_on_warning(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.py"
            path.write_text("def oops(:\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                interface, sources = _build([path])

        output = stdout.getvalue()
        self.assertIn("Warning", output)
        self.assertIn(str(path), output)
        self.assertIn(str(path), sources)
        self.assertEqual(interface.func, [])

    def test_nonexistent_file_warns_and_continues(self):
        path = Path("/nonexistent/pyflow_robustness_missing_file.py")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            interface, sources = _build([path])

        self.assertNotIn(str(path), sources)
        self.assertIn("Warning", stdout.getvalue())
        self.assertIn(str(path), stdout.getvalue())
        self.assertEqual(interface.func, [])


if __name__ == "__main__":
    unittest.main()
