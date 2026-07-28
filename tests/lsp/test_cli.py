"""Tests for pyflow.cli.lsp — CLI argument parsing for lsp/mcp/query."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest

from pyflow.cli.lsp import (
    add_lsp_parser,
    add_mcp_parser,
    add_query_parser,
    _dispatch_query,
)
from pyflow.lsp import PyflowAnalysisServer

# ---------------------------------------------------------------------------
# Fixture: parser builders
# ---------------------------------------------------------------------------


@pytest.fixture
def lsp_parser():
    from argparse import ArgumentParser

    p = ArgumentParser()
    sub = p.add_subparsers(dest="command")
    add_lsp_parser(sub)
    return p


@pytest.fixture
def mcp_parser():
    from argparse import ArgumentParser

    p = ArgumentParser()
    sub = p.add_subparsers(dest="command")
    add_mcp_parser(sub)
    return p


@pytest.fixture
def query_parser():
    from argparse import ArgumentParser

    p = ArgumentParser()
    sub = p.add_subparsers(dest="command")
    add_query_parser(sub)
    return p


def _parse(parser, argv):
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# lsp
# ---------------------------------------------------------------------------


class TestLspParser:
    def test_lsp_defaults(self, lsp_parser):
        args = _parse(lsp_parser, ["lsp"])
        assert args.command == "lsp"
        assert args.root is None
        assert args.mode == "full"

    def test_lsp_accepts_analysis_mode(self, lsp_parser):
        assert _parse(lsp_parser, ["lsp", "--mode", "basic"]).mode == "basic"

    def test_lsp_with_root(self, lsp_parser):
        args = _parse(lsp_parser, ["lsp", "--root", "/tmp/project"])
        assert args.root is not None
        assert args.root == Path("/tmp/project")

    def test_lsp_with_root_short(self, lsp_parser):
        args = _parse(lsp_parser, ["lsp", "-r", "/tmp/project"])
        assert args.root == Path("/tmp/project")

    def test_lsp_has_func_default(self, lsp_parser):
        args = _parse(lsp_parser, ["lsp"])
        assert hasattr(args, "func")
        assert callable(args.func)


class TestMcpParser:
    def test_mcp_defaults(self, mcp_parser):
        args = _parse(mcp_parser, ["mcp"])
        assert args.command == "mcp"
        assert args.root is None
        assert args.mode == "full"

    def test_mcp_accepts_advanced_mode(self, mcp_parser):
        assert _parse(mcp_parser, ["mcp", "--mode", "advanced"]).mode == "advanced"

    def test_mcp_with_root(self, mcp_parser):
        args = _parse(mcp_parser, ["mcp", "--root", "/tmp/project"])
        assert args.root == Path("/tmp/project")

    def test_mcp_has_func_default(self, mcp_parser):
        args = _parse(mcp_parser, ["mcp"])
        assert hasattr(args, "func")
        assert callable(args.func)


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


class TestQueryParser:
    def test_query_requires_input_path(self, query_parser):
        with pytest.raises(SystemExit):
            _parse(query_parser, ["query"])

    def test_query_minimal(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f)])
        assert args.command == "query"
        assert str(args.input_path) == str(f)

    def test_query_get_callers(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--get-callers", "foo"])
        assert args.get_callers == "foo"

    def test_query_get_callees(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--get-callees", "bar"])
        assert args.get_callees == "bar"

    def test_query_get_callgraph(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--get-callgraph"])
        assert args.get_callgraph is True

    def test_query_get_type(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--get-type", "mod", "10", "3"])
        assert args.get_type == ["mod", "10", "3"]

    def test_query_get_cfg(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--get-cfg", "func"])
        assert args.get_cfg == "func"

    def test_query_get_aliases(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--get-aliases", "var"])
        assert args.get_aliases == "var"

    def test_query_list_functions(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--list-functions"])
        assert args.list_functions is True

    def test_query_output(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        out = tmp_path / "out.json"
        args = _parse(query_parser, ["query", str(f), "--output", str(out)])
        assert str(args.output) == str(out)

    def test_query_pretty(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f), "--pretty"])
        assert args.pretty is True

    def test_query_has_func_default(self, query_parser, tmp_path):
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = _parse(query_parser, ["query", str(f)])
        assert hasattr(args, "func")
        assert callable(args.func)

    def test_query_dispatch_shows_capabilities_when_no_flag_given(self, tmp_path):
        """When no --get-* flag is given, _dispatch_query returns capabilities."""
        f = tmp_path / "sample.py"
        f.write_text("x = 1")
        args = Namespace(
            command="query",
            input_path=f,
            get_callers=None,
            get_callees=None,
            get_callgraph=False,
            get_type=None,
            get_cfg=None,
            get_aliases=None,
            list_functions=False,
            output=None,
            pretty=False,
            func=lambda a: None,
        )
        from unittest.mock import MagicMock

        server = MagicMock(spec=PyflowAnalysisServer)
        server.get_capabilities.return_value = {"callgraph": True}
        server.program = MagicMock()
        server.program.liveCode = []

        result = _dispatch_query(server, args)
        assert result == {"callgraph": True}
