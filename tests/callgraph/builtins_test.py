import os

from .base import PyFlowTestBase


class BuiltinsTest(PyFlowTestBase):
    snippet_dir = "builtins"

    def test_functions(self):
        self.validate_snippet(self.get_snippet_path("functions"))

    def test_map(self):
        self.validate_snippet(self.get_snippet_path("map"))

    def test_types(self):
        self.validate_snippet(self.get_snippet_path("types"))
