
import json
import os
import sys
from os.path import abspath, dirname
from unittest import TestCase, main

SCRIPT_DIR = dirname(abspath(__file__))


class TestBase(TestCase):
    snippet_dir = ""

    def setUp(self):
        self.snippets_path = os.path.join(SCRIPT_DIR, "snippets")

    def validate_snippet(self, snippet_path):
        """Validate a code snippet against expected call graph output."""
        output = self.get_snippet_output_cg(snippet_path)
        expected = self.get_snippet_expected_cg(snippet_path)
        self.assertEqual(output, expected)

    def get_snippet_path(self, name):
        """Get the path to a snippet directory."""
        return os.path.join(self.snippets_path, self.snippet_dir, name)

    def get_snippet_output_cg(self, snippet_path):
        """Generate call graph from a snippet using PyFlow's AST-based analysis."""
        main_path = os.path.join(snippet_path, "main.py")

        if not os.path.exists(main_path):
            self.fail(f"Main file not found: {main_path}")

        try:
            with open(main_path, 'r') as f:
                source_code = f.read()

            # Use PyFlow's AST-based call graph extraction
            from pyflow.analysis.callgraph import extract_call_graph
            cg = extract_call_graph(source_code)

            # Convert to the expected format (dict of caller -> list of callees)
            output = {}
            for caller, callees in cg.get().items():
                output[caller] = sorted(list(callees))

            return output

        except Exception as e:
            self.fail(f"Error analyzing {main_path}: {e}")

    def get_snippet_expected_cg(self, snippet_path):
        """Load expected call graph from JSON file."""
        cg_path = os.path.join(snippet_path, "callgraph.json")
        if not os.path.exists(cg_path):
            self.fail(f"Expected call graph file not found: {cg_path}")

        with open(cg_path, "r") as f:
            return json.loads(f.read())


class PyFlowTestBase(TestBase):
    """Test base class specifically for PyFlow AST-based call graph analysis."""

    def get_snippet_output_cg(self, snippet_path):
        """Generate call graph from a snippet using PyFlow's AST-based analysis."""
        main_path = os.path.join(snippet_path, "main.py")

        if not os.path.exists(main_path):
            self.fail(f"Main file not found: {main_path}")

        try:
            with open(main_path, 'r') as f:
                source_code = f.read()

            # Use PyFlow's AST-based call graph extraction
            from pyflow.analysis.callgraph import extract_call_graph
            cg = extract_call_graph(source_code)

            # Convert to the expected format (dict of caller -> list of callees)
            output = {}
            for caller, callees in cg.get().items():
                output[caller] = sorted(list(callees))

            return output

        except Exception as e:
            self.fail(f"Error analyzing {main_path}: {e}")


if __name__ == "__main__":
    main()
