"""CLI integration tests for `pyflow security`."""

from __future__ import absolute_import

from pathlib import Path

import pytest

import pyflow.cli.security as security_cli


def _security_args(
    targets: list[str],
    *,
    output: Path | None = None,
    verbose: bool = False,
) -> object:
    """Build a minimal args object for run_security_analysis.
    Always pass output to a temp file to avoid writing to sys.stdout
    (which can break pytest's capture).
    """
    class Args:
        pass

    args = Args()
    args.targets = targets
    args.recursive = False
    args.verbose = verbose
    args.debug = False
    args.exclude = None
    args.engine = "pattern"
    args.taint_engine = "ast"
    args.micro_bench = None
    args.format = "text"
    args.output = output
    return args


@pytest.mark.integration
class TestSecurityCLI:
    """Run the real security subcommand and assert on exit code and output."""

    def test_security_cli_finds_issue_exit_code(
        self, sample_file_with_issue: Path, tmp_path: Path
    ) -> None:
        """Running security on a file with a finding returns exit code 1."""
        out = tmp_path / "out.txt"
        args = _security_args([str(sample_file_with_issue)], output=out)
        exit_code = security_cli.run_security_analysis(args.targets, args)
        assert exit_code == 1

    def test_security_cli_clean_file_exit_code(
        self, sample_file_clean: Path, tmp_path: Path
    ) -> None:
        """Running security on a file with no issues returns exit code 0."""
        out = tmp_path / "out.txt"
        args = _security_args([str(sample_file_clean)], output=out)
        exit_code = security_cli.run_security_analysis(args.targets, args)
        assert exit_code == 0

    def test_security_cli_text_output_contains_issue_id(
        self, sample_file_with_issue: Path, tmp_path: Path
    ) -> None:
        """With --format text, output file contains the expected test ID (B105)."""
        out_file = tmp_path / "out.txt"
        args = _security_args([str(sample_file_with_issue)], output=out_file)
        exit_code = security_cli.run_security_analysis(args.targets, args)
        assert exit_code == 1
        content = out_file.read_text()
        assert "B105" in content or "password" in content.lower()
