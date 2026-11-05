"""Standalone ``pyflow typeinfo`` CLI tests."""

from __future__ import annotations

import importlib
import json

cli_main = importlib.import_module("pyflow.cli.main")


def _run(monkeypatch, capsys, *argv: str) -> tuple[int, str, str]:
    monkeypatch.setattr(cli_main.sys, "argv", ["pyflow", "typeinfo", *map(str, argv)])
    code = cli_main.main()
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_typeinfo_symbol_json_from_single_file(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        """
def add(value: int) -> int:
    return value + 1
""",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source, "--symbol", "add", "--json")

    assert code == 0, err
    payload = json.loads(out)
    assert payload["module"] == "app"
    assert payload["symbol"] == "app.add"
    assert payload["type"] == "Callable[[int], int]"
    assert payload["status"] == "complete"


def test_typeinfo_expression_json_uses_source_position(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "value: int = 1\nresult = value + 2\n",
        encoding="utf-8",
    )

    code, out, err = _run(
        monkeypatch,
        capsys,
        source,
        "--line",
        "2",
        "--column",
        "9",
        "--json",
    )

    assert code == 0, err
    payload = json.loads(out)
    assert payload == {
        "module": "app",
        "line": 2,
        "column": 9,
        "type": "int",
        "complete": True,
        "unknown": False,
        "status": "complete",
    }


def test_typeinfo_diagnostics_json(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def f(value: int) -> int:\n    return value\n\nresult: str = f(1)\n",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "diagnostics", "--json")

    assert code == 0, err
    diagnostics = json.loads(out)
    assert any(item["code"] == "annotation-mismatch" for item in diagnostics)
    assert any(item["lineno"] == 4 for item in diagnostics)


def test_typeinfo_directory_requires_and_accepts_module(tmp_path, monkeypatch, capsys) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "mod.py").write_text("VALUE: int = 1\nRESULT = VALUE + 1\n", encoding="utf-8")

    code, out, err = _run(
        monkeypatch,
        capsys,
        tmp_path,
        "--module",
        "pkg.mod",
        "--symbol",
        "RESULT",
        "--json",
    )

    assert code == 0, err
    payload = json.loads(out)
    assert payload["symbol"] == "pkg.mod.RESULT"
    assert payload["type"] == "int"


def test_typeinfo_directory_missing_module_is_concise(tmp_path, monkeypatch, capsys) -> None:
    code, out, err = _run(
        monkeypatch,
        capsys,
        tmp_path,
        "--module",
        "missing.mod",
        "--symbol",
        "VALUE",
    )

    assert code == 2
    assert out == ""
    assert "module 'missing.mod' was not found" in err
    assert "Traceback" not in err


def test_typeinfo_requires_line_and_column_together(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")

    code, out, err = _run(monkeypatch, capsys, source, "--line", "1")

    assert code == 2
    assert out == ""
    assert "--line and --column" in err


def test_typeinfo_default_mode_lists_function_signatures(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "value: int = 1\n\ndef add(x: int) -> str:\n    return str(x)\n",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source)

    assert code == 0, err
    assert "app: complete" in out
    assert "app.add: Callable[[int], str]" in out
    assert "app.value: int" not in out


def test_typeinfo_types_mode_lists_all_symbols(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "value: int = 1\n\ndef add(x: int) -> str:\n    return str(x)\n",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "types")

    assert code == 0, err
    assert "app.value: int" in out
    assert "app.add: Callable[[int], str]" in out


def test_typeinfo_summary_keeps_count_only_mode(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text("value: int = 1\n", encoding="utf-8")

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "summary")

    assert code == 0, err
    assert "symbols=1" in out
    assert "app.value: int" not in out


def test_typeinfo_default_json_lists_type_facts(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "value: int = 1\n\nclass Client:\n    def fetch(self, url: str) -> bytes:\n        return b''\n",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "types", "--json")

    assert code == 0, err
    report = json.loads(out)[0]
    assert report["types"]["app.value"]["type"] == "int"
    assert report["types"]["app.Client.fetch"]["type"] == "Callable[[str], bytes]"


def test_typeinfo_default_human_output_truncates_long_type_lists(
    tmp_path, monkeypatch, capsys
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "\n".join(f"value_{index}: int = {index}" for index in range(25)) + "\n",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "types")

    assert code == 0, err
    assert out.count("  app.value_") == 20
    assert "5 more type facts" in out


def test_typeinfo_max_types_zero_shows_all_and_json_is_always_complete(
    tmp_path, monkeypatch, capsys
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "\n".join(f"value_{index}: int = {index}" for index in range(25)) + "\n",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "types", "--max-types", "0")
    assert code == 0, err
    assert out.count("  app.value_") == 25
    assert "more type facts" not in out

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "types", "--json")
    assert code == 0, err
    report = json.loads(out)[0]
    assert "app.value_24" in report["types"]
