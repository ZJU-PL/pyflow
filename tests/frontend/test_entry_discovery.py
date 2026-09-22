from __future__ import annotations

from pathlib import Path

import pytest

from pyflow.frontend.entry_discovery import (
    EntryCandidate,
    detect_entry_file,
    discover_entry_files,
    resolve_entry_file,
)


def test_detect_entry_file_prefers_project_script_metadata(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("print('demo')\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('fallback')\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project.scripts]\ndemo = "demo.cli:main"\n', encoding="utf-8"
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_detect_entry_file_does_not_guess_from_project_name(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    cli = package / "cli.py"
    server = package / "server.py"
    cli.write_text("def main(): pass\n", encoding="utf-8")
    server.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "demo"

[project.scripts]
demo = "demo.cli:main"
demo-server = "demo.server:main"
""",
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) is None


def test_detect_entry_file_rejects_ambiguous_scripts(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    for name in ("client", "server"):
        (package / f"{name}.py").write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "demo"

[project.scripts]
client = "demo.client:main"
server = "demo.server:main"
""",
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) is None
    assert [candidate.command for candidate in discover_entry_files(tmp_path)] == [
        "client",
        "server",
    ]


def test_detect_entry_file_rejects_multiple_package_mains(tmp_path):
    for package_name in ("client", "server"):
        package = tmp_path / "src" / package_name
        package.mkdir(parents=True)
        (package / "__main__.py").write_text("print('run')\n", encoding="utf-8")

    assert detect_entry_file(tmp_path) is None


def test_detect_entry_file_uses_configured_package_root(tmp_path):
    package = tmp_path / "lib" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """[project.scripts]
demo = "demo.cli:main"

[tool.setuptools.packages.find]
where = ["lib"]
""",
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_detect_entry_file_supports_setuptools_qualified_setup_call(tmp_path):
    package = tmp_path / "demo"
    package.mkdir()
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        "import setuptools\n"
        "setuptools.setup(entry_points={\n"
        "    'console_scripts': ['demo=demo.cli:main'],\n"
        "})\n",
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_detect_entry_file_supports_tuple_console_scripts(tmp_path):
    package = tmp_path / "demo"
    package.mkdir()
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(entry_points={\n"
        "    'console_scripts': ('demo=demo.cli:main',),\n"
        "})\n",
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_detect_entry_file_supports_poetry_script_tables(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.scripts]\n"
        'demo = { callable = "demo.cli:main", type = "console" }\n',
        encoding="utf-8",
    )

    candidates = discover_entry_files(tmp_path)

    assert candidates == [
        type(candidates[0])(entry.relative_to(tmp_path), "tool.poetry.scripts", "demo")
    ]


def test_resolve_entry_file_accepts_explicit_relative_path(tmp_path):
    entry = tmp_path / "train.py"
    entry.write_text("print('train')\n", encoding="utf-8")

    assert resolve_entry_file(tmp_path, "train.py") == entry.resolve()


def test_resolve_entry_file_rejects_paths_outside_project(tmp_path):
    outside = tmp_path.parent / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")

    try:
        resolve_entry_file(tmp_path, outside)
    except ValueError as error:
        assert "outside project root" in str(error)
    else:
        raise AssertionError("Expected an out-of-project entry to be rejected")


def test_setuptools_packages_list_form_does_not_crash(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.setuptools]\npackages = ["demo"]\n\n'
        '[project.scripts]\ndemo = "demo.cli:main"\n',
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_setuptools_packages_list_entries_are_search_bases(tmp_path):
    package = tmp_path / "source" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.setuptools]\npackages = ["source/demo"]\n\n'
        '[project.scripts]\ndemo = "demo.cli:main"\n',
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_setuptools_packages_find_table_keeps_working(tmp_path):
    package = tmp_path / "custom" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.setuptools.packages.find]\nwhere = ["custom"]\n\n'
        '[project.scripts]\ndemo = "demo.cli:main"\n',
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_detect_entry_file_supports_poetry_string_scripts(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.scripts]\ndemo = "demo.cli:main"\n', encoding="utf-8"
    )

    candidates = discover_entry_files(tmp_path)

    assert candidates == [
        EntryCandidate(entry.relative_to(tmp_path), "tool.poetry.scripts", "demo")
    ]


def test_detect_entry_file_supports_poetry_reference_tables(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.scripts]\n"
        'demo = { reference = "demo.cli:main", type = "console" }\n',
        encoding="utf-8",
    )

    candidates = discover_entry_files(tmp_path)

    assert candidates == [
        EntryCandidate(entry.relative_to(tmp_path), "tool.poetry.scripts", "demo")
    ]


def test_detect_entry_file_supports_project_entry_points(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project.entry-points.console_scripts]\ndemo = "demo.cli:main"\n',
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_discover_entry_files_reports_project_entry_point_group(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project.entry-points."console_scripts"]\ndemo = "demo.cli:main"\n',
        encoding="utf-8",
    )

    candidates = discover_entry_files(tmp_path)

    assert candidates == [
        EntryCandidate(
            entry.relative_to(tmp_path),
            'project.entry-points."console_scripts"',
            "demo",
        )
    ]


def test_detect_entry_file_supports_setup_cfg_entry_points(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text(
        "[options.entry_points]\n"
        "console_scripts =\n"
        "    demo = demo.cli:main\n",
        encoding="utf-8",
    )

    assert detect_entry_file(tmp_path) == entry.relative_to(tmp_path)


def test_discover_entry_files_reports_setup_cfg_entry_points(tmp_path):
    package = tmp_path / "src" / "demo"
    package.mkdir(parents=True)
    entry = package / "cli.py"
    entry.write_text("def main(): pass\n", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text(
        "[options.entry_points]\n"
        "console_scripts =\n"
        "    demo = demo.cli:main\n"
        "    demo-extra = demo.cli:extra\n",
        encoding="utf-8",
    )

    candidates = discover_entry_files(tmp_path)

    assert candidates == [
        EntryCandidate(entry.relative_to(tmp_path), "setup.cfg entry_points", "demo"),
        EntryCandidate(
            entry.relative_to(tmp_path), "setup.cfg entry_points", "demo-extra"
        ),
    ]


@pytest.mark.parametrize(
    "pyproject_text",
    [
        pytest.param('[tool]\nsetuptools = "not-a-table"\n', id="tool-setuptools-string"),
        pytest.param('[tool.setuptools]\npackages = ["demo"]\n', id="packages-list"),
        pytest.param(
            '[tool.setuptools.packages]\nfind = ["oops"]\n', id="packages-find-list"
        ),
        pytest.param('project = "not-a-table"\n', id="project-string"),
        pytest.param('[tool.poetry]\nscripts = "oops"\n', id="poetry-scripts-string"),
        pytest.param(
            '[project.entry-points.console_scripts]\ndemo = 42\n',
            id="entry-point-value-int",
        ),
        pytest.param("this is not = = valid toml [[[", id="malformed-toml"),
    ],
)
def test_discover_entry_files_tolerates_malformed_shapes(tmp_path, pyproject_text):
    (tmp_path / "main.py").write_text("print('fallback')\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(pyproject_text, encoding="utf-8")

    candidates = discover_entry_files(tmp_path)

    assert [candidate.path for candidate in candidates] == [Path("main.py")]


def test_discover_entry_files_tolerates_malformed_setup_cfg(tmp_path):
    (tmp_path / "main.py").write_text("print('fallback')\n", encoding="utf-8")
    (tmp_path / "setup.cfg").write_text("not an ini file = = =\n", encoding="utf-8")

    candidates = discover_entry_files(tmp_path)

    assert [candidate.path for candidate in candidates] == [Path("main.py")]
