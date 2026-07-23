"""Integration tests for the analysis pipeline (extract + evaluate)."""

from __future__ import absolute_import

from pathlib import Path

import pytest

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import evaluate as pipeline_evaluate
from pyflow.frontend.extractor import Extractor, extract_program
from pyflow.frontend.interface_builder import (
    InterfaceBuildOptions,
    build_interface_from_paths,
)
from pyflow.util.application.console import Console


def _make_options(verbose: bool = False) -> InterfaceBuildOptions:
    return InterfaceBuildOptions(verbose=verbose)


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
        options = _make_options(verbose=False)

        console = Console(verbose=False)
        compiler = CompilerContext(console)
        program = Program()

        program.interface, all_source_code = build_interface_from_paths(
            python_files, options
        )
        compiler.extractor = Extractor(
            compiler, verbose=False, source_code=all_source_code
        )
        extract_program(compiler, program)

        assert program.interface.func, "Expected at least one function in interface"

        pipeline_evaluate(compiler, program, "integration_test")
        # No exception means success
