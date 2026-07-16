
import os

from .base import PyFlowTestBase

class DynamicTest(PyFlowTestBase):
    snippet_dir = "dynamic"

    def test_eval(self):
        self.validate_snippet(self.get_snippet_path("eval"))
