import os
import sys
import os.path as path

# Add the tests directory to Python path so we can import base
sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from .base import PyFlowTestBase


class DirectCallsTest(PyFlowTestBase):
    snippet_dir = "direct_calls"

    def test_assigned_call(self):
        self.validate_snippet(self.get_snippet_path("assigned_call"))

    def test_imported_return_call(self):
        self.validate_snippet(self.get_snippet_path("imported_return_call"))

    def test_return_call(self):
        self.validate_snippet(self.get_snippet_path("return_call"))

    def test_with_parameters(self):
        self.validate_snippet(self.get_snippet_path("with_parameters"))
