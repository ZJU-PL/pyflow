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


def test_typeinfo_types_mode_is_complete(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "\n".join(f"value_{index}: int = {index}" for index in range(25)) + "\n",
        encoding="utf-8",
    )

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "types")

    assert code == 0, err
    assert out.count("  app.value_") == 25
    assert "more type facts" not in out


def test_typeinfo_respects_pep263_non_utf8_encoding_cookie(tmp_path, monkeypatch, capsys) -> None:
    source = tmp_path / "latin1_mod.py"
    source.write_bytes(b"# -*- coding: latin-1 -*-\n" b'TITLE: str = "caf\xe9"\n')

    code, out, err = _run(monkeypatch, capsys, source, "--mode", "types", "--json")

    assert code == 0, err
    report = json.loads(out)[0]
    assert report["types"]["latin1_mod.TITLE"]["type"] == "str"


def test_typeinfo_directory_scan_skips_unparseable_files_with_warning(
    tmp_path, monkeypatch, capsys
) -> None:
    (tmp_path / "good.py").write_text("VALUE: int = 1\n", encoding="utf-8")
    (tmp_path / "legacy_py2.py").write_text("print 'python2'\n", encoding="utf-8")
    (tmp_path / "bad_bytes.py").write_bytes(b"\xff\xfeinvalid\n")

    code, out, err = _run(monkeypatch, capsys, tmp_path, "--mode", "summary", "--json")

    assert code == 0, err
    assert "Warning: skipping" in err
    payload = {item["module"]: item for item in json.loads(out)}
    assert "good" in payload
    assert payload["good"]["status"] == "complete"
    assert "bad_bytes" not in payload


def test_typeinfo_directory_scan_uses_src_layout_and_skips_non_identifier_dirs(
    tmp_path, monkeypatch, capsys
) -> None:
    pkg = tmp_path / "src" / "demo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "core.py").write_text("ANSWER: int = 42\n", encoding="utf-8")
    (pkg / "app.py").write_text(
        "from demo.core import ANSWER\nDOUBLE = ANSWER + ANSWER\n", encoding="utf-8"
    )
    template = tmp_path / "templates" / "{{cookiecutter.pkg}}"
    template.mkdir(parents=True)
    (template / "__init__.py").write_text("{{ cookiecutter.name }}\n", encoding="utf-8")
    hyphen_dir = tmp_path / "my-scripts"
    hyphen_dir.mkdir()
    (hyphen_dir / "tool.py").write_text("X = 1\n", encoding="utf-8")

    code, out, err = _run(monkeypatch, capsys, tmp_path, "--mode", "types", "--json")

    assert code == 0, err
    payload = {item["module"]: item for item in json.loads(out)}
    assert "demo.core" in payload
    assert "demo.app" in payload
    assert not any(name.startswith("src.") for name in payload)
    assert not any("cookiecutter" in name for name in payload)
    assert not any("my-scripts" in name for name in payload)
    assert payload["demo.app"]["types"]["demo.app.DOUBLE"]["type"] == "int"


def test_typeinfo_directory_summary_computes_diagnostics_once(
    tmp_path, monkeypatch, capsys
) -> None:
    from pyflow.analysis.typeinfo.query.service import TypeInfoService

    (tmp_path / "a.py").write_text("X: str = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("Y: int = 2\n", encoding="utf-8")
    (tmp_path / "c.py").write_text("Z: str = 3\nW: int = 'bad'\n", encoding="utf-8")

    calls = 0
    original = TypeInfoService.diagnostics

    def counting_diagnostics(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        return original(self, *args, **kwargs)

    monkeypatch.setattr(TypeInfoService, "diagnostics", counting_diagnostics)
    code, out, err = _run(monkeypatch, capsys, tmp_path, "--mode", "summary", "--json")

    assert code == 0, err
    assert calls == 1
    payload = {item["module"]: item for item in json.loads(out)}
    assert payload["a"]["diagnostics"] >= 1
    assert payload["b"]["diagnostics"] == 0
    assert payload["c"]["diagnostics"] >= 2
