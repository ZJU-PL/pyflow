"""Integration tests for the analysis pipeline (extract + evaluate)."""

from __future__ import absolute_import

from pathlib import Path

import pytest

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import evaluate as pipeline_evaluate
from pyflow.frontend.programextractor import (
    create_interface_from_paths,
    extractProgram,
    Extractor,
)
from pyflow.util.application.console import Console


def _make_args(verbose: bool = False):
    """Minimal args namespace for create_interface_from_paths."""
    class Args:
        dependency_strategy = "auto"

    args = Args()
    args.verbose = verbose
    return args


@pytest.mark.integration
class TestPipelineIntegration:
    """Run the real extraction + legacy pipeline and assert it completes."""

    def test_pipeline_evaluate_completes_on_simple_file(
        self, tmp_path: Path
    ) -> None:
        """Extract a single-file program and run the legacy pipeline; no exception."""
        sample = tmp_path / "simple.py"
        sample.write_text(
            "def foo(x):\n    return x + 1\n",
            encoding="utf-8",
        )
        python_files = [sample]
        args = _make_args(verbose=False)

        console = Console(verbose=False)
        compiler = CompilerContext(console)
        program = Program()

        program.interface, all_source_code = create_interface_from_paths(
            python_files, args
        )
        compiler.extractor = Extractor(
            compiler, verbose=False, source_code=all_source_code
        )
        extractProgram(compiler, program)

        assert program.interface.func, "Expected at least one function in interface"

        pipeline_evaluate(compiler, program, "integration_test")
        # No exception means success
