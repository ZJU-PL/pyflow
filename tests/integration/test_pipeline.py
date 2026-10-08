"""Integration tests for the analysis pipeline (extract + Pipeline)."""

from __future__ import absolute_import

from pathlib import Path

import pytest

from pyflow.application.context import CompilerContext
from pyflow.application.program import Program
from pyflow.application.pipeline import Pipeline
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
    """Run the real extraction + canonical pipeline and assert it completes."""

    def test_pipeline_completes_on_simple_file(self, tmp_path: Path) -> None:
        """Extract a single-file program and run the canonical pipeline; no exception."""
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

        program.interface, all_source_code = build_interface_from_paths(python_files, options)
        compiler.extractor = Extractor(compiler, verbose=False, source_code=all_source_code)
        extract_program(compiler, program)

        assert program.interface.func, "Expected at least one function in interface"

        Pipeline().run(program, compiler=compiler, name="integration_test")
        # No exception means success

    def test_default_pass_manager_refreshes_facts_after_simplification(
        self, tmp_path: Path
    ) -> None:
        """The default pipeline must not feed stale CPA facts to lifetime."""
        sample = tmp_path / "arithmetic.py"
        sample.write_text(
            "def add(left, right):\n    return left + right\n",
            encoding="utf-8",
        )
        options = _make_options(verbose=False)
        console = Console(verbose=False)
        compiler = CompilerContext(console)
        program = Program()
        program.interface, all_source_code = build_interface_from_paths([sample], options)
        compiler.extractor = Extractor(compiler, verbose=False, source_code=all_source_code)
        extract_program(compiler, program)

        results = Pipeline().run(program, compiler=compiler, name="integration_test")

        assert results["lifetime_after_simplify"].success
        assert results["clone"].success
        assert results["simplify_final"].success


@pytest.mark.integration
def test_optional_reports_use_refreshed_facts(monkeypatch, tmp_path):
    from pyflow.application.session import AnalysisOptions
    from pyflow.analysis.dump import dumpreport
    from pyflow import stats

    sample = tmp_path / "reports.py"
    sample.write_text("def add(left, right):\n    return left + right\n")
    compiler = CompilerContext(Console(verbose=False))
    program = Program()
    program.interface, source = build_interface_from_paths([sample], _make_options())
    compiler.extractor = Extractor(compiler, verbose=False, source_code=source)
    extract_program(compiler, program)
    program.session.configure(AnalysisOptions(dump_reports=True, dump_stats=True))
    observed = []

    def statistics(_compiler, current, _name, **_kwargs):
        assert current.session.get_result("cpa") is not None
        observed.append("stats")

    def report(_compiler, current, _name):
        assert current.session.get_result("cpa") is not None
        assert current.session.get_result("lifetime") is not None
        observed.append("report")

    monkeypatch.setattr(stats, "contextStats", statistics)
    monkeypatch.setattr(dumpreport, "evaluate", report)
    Pipeline().run(program, compiler=compiler)
    assert observed == ["stats", "report"]
