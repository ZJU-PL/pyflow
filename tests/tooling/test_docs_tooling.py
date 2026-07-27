from __future__ import annotations

from pathlib import Path
from typing import Any, cast

try:
    import tomllib as tomli  # type: ignore[import-untyped]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli  # type: ignore[import-not-found]


ROOT = Path(__file__).resolve().parents[2]


def _read_text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _load_toml(relative_path: str) -> dict[str, Any]:
    return cast(dict[str, Any], tomli.loads(_read_text(relative_path)))


def test_pyproject_uses_a_real_build_system() -> None:
    data = _load_toml("pyproject.toml")
    build_system = cast(dict[str, Any], data["build-system"])
    project = cast(dict[str, Any], data["project"])
    extras = cast(dict[str, list[str]], project["optional-dependencies"])

    assert build_system["requires"] == ["setuptools>=61.0", "wheel"]
    assert build_system["build-backend"] == "setuptools.build_meta"
    assert project["requires-python"] == ">=3.10"
    assert "pycg==0.0.6" not in cast(list[str], project["dependencies"])
    assert extras["callgraph"] == ["pycg==0.0.6"]
    assert any(item.startswith("tomli;") for item in extras["dev"])
    assert any(item.startswith("tomli;") for item in extras["test"])


def test_cli_reference_matches_current_commands() -> None:
    docs = _read_text("CLI.md")

    expected = [
        "`optimize`",
        "`callgraph`",
        "`ir`",
        "`security`",
        "--opt-passes PASS1 [PASS2 ...]",
        "--dump-cdg FUNCTION",
        "--dump-ddg FUNCTION",
        "--algorithm`, `-a`: `simple`, `constraint`, or `pycg`",
        "--engine ast-scanner",
        "``--engine ast-dataflow``",
        "``--engine ifds``",
        "``--engine cpg``",
        "--function FUNCTION",
        "--sources NAME [NAME ...]",
        "--sinks NAME [NAME ...]",
    ]

    for token in expected:
        assert token in docs


def test_makefile_serve_target_uses_docs_build_dir() -> None:
    makefile = _read_text("Makefile")
    docs_serve = "cd docs && python -m http.server 8000 --directory "
    docs_serve += "_build/html"

    assert "black src/ tests/" in makefile
    assert "flake8 src/ tests/" in makefile
    assert "pytest -m integration tests/integration" in makefile
    assert docs_serve in makefile
    assert "scripts/" not in makefile
