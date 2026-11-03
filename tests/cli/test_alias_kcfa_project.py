import argparse
import json

from pyflow.cli import alias


def _args(*argv):
    parser = argparse.ArgumentParser()
    alias.add_alias_parser(parser.add_subparsers())
    return parser.parse_args(["alias", *map(str, argv)])


def test_kcfa_cli_resolves_project_imports(tmp_path, capsys):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "model.py").write_text("class A: pass\na = A()\n", encoding="utf-8")
    entry = tmp_path / "main.py"
    entry.write_text(
        "from pkg.model import A, a\naa = a\ninstance = A()\n",
        encoding="utf-8",
    )

    args = _args(entry, "--engine", "kcfa", "--json", "--max-seconds", "20")
    assert alias.run_alias_analysis(str(entry), args) == 0

    payload = json.loads(capsys.readouterr().out)
    variables = payload[0]["variables"]
    assert any("A()" in item for item in variables["instance"]["points_to"])
    assert variables["aa"]["points_to"] == variables["a"]["points_to"]
    assert not any("<native" in item for item in variables["instance"]["points_to"])
