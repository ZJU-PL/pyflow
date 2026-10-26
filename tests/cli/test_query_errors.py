"""One-shot query failures must be concise and must not leak tracebacks."""

from __future__ import annotations

import json
from argparse import ArgumentParser

import pytest

from pyflow.cli.lsp import add_query_parser, run_query


def _args(*argv):
    parser = ArgumentParser()
    add_query_parser(parser.add_subparsers())
    return parser.parse_args(["query", *map(str, argv)])


def test_query_get_cfg_reports_single_file_syntax_error(tmp_path, capsys):
    source = tmp_path / "bad.py"
    source.write_text("def broken(:\n    pass\n", encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        run_query(_args(source, "--get-cfg", "f"))

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Could not parse" in captured.err
    assert "invalid syntax" in captured.err
    assert "Traceback" not in captured.err


def test_query_get_callgraph_reports_single_file_syntax_error(tmp_path, capsys):
    source = tmp_path / "bad.py"
    source.write_text("def broken(:\n    pass\n", encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        run_query(_args(source, "--get-callgraph"))

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Could not analyze" in captured.err
    assert "invalid syntax" in captured.err
    assert "Traceback" not in captured.err


def test_query_list_functions_reports_single_file_syntax_error(tmp_path, capsys):
    source = tmp_path / "bad.py"
    source.write_text("def broken(:\n    pass\n", encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        run_query(_args(source, "--list-functions"))

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Could not parse" in captured.err
    assert "invalid syntax" in captured.err


def test_query_list_functions_keeps_good_files_and_warns_about_bad_ones(tmp_path, capsys):
    (tmp_path / "good.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    (tmp_path / "bad.py").write_text("def broken(:\n    pass\n", encoding="utf-8")

    run_query(_args(tmp_path, "--list-functions"))

    captured = capsys.readouterr()
    assert json.loads(captured.out) == ["good.f"]
    assert "Warning: Could not parse" in captured.err
    assert "bad.py" in captured.err


def test_query_get_cfg_error_lists_public_candidates_only(tmp_path, capsys):
    source = tmp_path / "mod.py"
    source.write_text(
        "def greet(name):\n    return name\n\ndef caller():\n    return greet('x')\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as raised:
        run_query(_args(source, "--get-cfg", "missing"))

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Available candidates" in captured.err
    assert "greet" in captured.err
    assert "<module>" not in captured.err
    assert "<locals>" not in captured.err
    assert "@" not in captured.err.split("Available candidates:", 1)[1]


def test_query_get_cfg_ambiguous_name_uses_public_names(tmp_path, capsys):
    (tmp_path / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def f():\n    return 2\n", encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        run_query(_args(tmp_path, "--get-cfg", "f"))

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ambiguous" in captured.err
    assert "a.f" in captured.err
    assert "b.f" in captured.err
    assert "<module>" not in captured.err
    assert "<locals>" not in captured.err
    assert "@" not in captured.err
