"""Tests for isolated runtime dependency probing."""

import subprocess
import unittest
from unittest.mock import patch

from pyflow.frontend.resolution.runtime_probe import probe_function_names


class TestRuntimeProbe(unittest.TestCase):
    def test_program_output_does_not_corrupt_probe_protocol(self):
        names = probe_function_names(
            "print('application output')\ndef local_function():\n    return 1\n",
            "sample.py",
            allow_stub_imports=False,
        )

        self.assertEqual(names, ["local_function"])

    def test_large_program_output_is_discarded(self):
        names = probe_function_names(
            "print('x' * 2_000_000)\ndef local_function():\n    return 1\n",
            "sample.py",
            allow_stub_imports=False,
        )

        self.assertEqual(names, ["local_function"])

    @patch("pyflow.frontend.resolution.runtime_probe.subprocess.run")
    def test_timeout_is_reported_as_runtime_error(self, run):
        run.side_effect = subprocess.TimeoutExpired("python", 0.01)

        with self.assertRaisesRegex(RuntimeError, "timed out after 0.01 seconds"):
            probe_function_names(
                "while True:\n    pass\n",
                "sample.py",
                allow_stub_imports=False,
                timeout_seconds=0.01,
            )


if __name__ == "__main__":
    unittest.main()
