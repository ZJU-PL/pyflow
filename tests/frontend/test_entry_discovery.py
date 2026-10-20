from __future__ import annotations

from pathlib import Path

import pytest

from pyflow.frontend.entry_discovery import (
    EntryCandidate,
    detect_entry_file,
    discover_entry_files,
    resolve_entry_file,
)


@pytest.mark.parametrize(
    "relative", ["__main__.py", "src/app.py", "src/demo/subpackage/__main__.py"]
)
def test_standard_and_nested_entries_are_discovered(relative, tmp_path):
    entry = tmp_path / relative
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text("print('entry')\n")
    assert detect_entry_file(tmp_path) == Path(relative)


@pytest.mark.parametrize("name", ["train.py", "evaluate.py", "server.py", "experiment.py"])
def test_application_specific_names_do_not_imply_an_entry(name, tmp_path):
    path = tmp_path / name
    path.write_text("def worker():\n    pass\n")
    assert discover_entry_files(tmp_path) == []
    assert detect_entry_file(tmp_path) is None
    assert resolve_entry_file(tmp_path, name) == path.resolve()
    path.write_text("if __name__ == '__main__':\n    pass\n")
    assert detect_entry_file(tmp_path) == Path(name)


def test_main_guards_have_priority_over_filename_guesses_and_preserve_ambiguity(tmp_path):
    (tmp_path / "app.py").write_text("def helper():\n    pass\n")
    (tmp_path / "experiment.py").write_text("if __name__ == '__main__':\n    pass\n")
    assert detect_entry_file(tmp_path) == Path("experiment.py")
    (tmp_path / "evaluate.py").write_text("if __name__ == '__main__':\n    pass\n")
    assert detect_entry_file(tmp_path) is None
    assert {item.path for item in discover_entry_files(tmp_path)} == {
        Path("experiment.py"),
        Path("evaluate.py"),
    }


def test_application_specific_filename_is_valid_when_declared_in_metadata(tmp_path):
    (tmp_path / "train.py").write_text("def start():\n    pass\n")
    (tmp_path / "pyproject.toml").write_text('[project.scripts]\ntrainer = "train:start"\n')
    assert detect_entry_file(tmp_path) == Path("train.py")


def test_unique_script_guard_is_discovered_and_hidden_test_scripts_are_ignored(tmp_path):
    entry = tmp_path / "scripts" / "serve_demo.py"
    entry.parent.mkdir()
    entry.write_text("if __name__ == '__main__':\n    print('run')\n")
    for directory in ("tests", ".venv"):
        ignored = tmp_path / directory
        ignored.mkdir()
        (ignored / "__main__.py").write_text("pass\n")
    assert detect_entry_file(tmp_path) is None
    candidates = discover_entry_files(tmp_path)
    assert [candidate.path for candidate in candidates] == [entry.relative_to(tmp_path)]
    assert not candidates[0].auto_select
    assert resolve_entry_file(tmp_path, entry.relative_to(tmp_path)) == entry.resolve()
    (entry.parent / "other.py").write_text("if '__main__' == __name__:\n    pass\n")
    assert detect_entry_file(tmp_path) is None


def test_auxiliary_preparation_script_is_not_selected_as_project_entry(tmp_path):
    (tmp_path / "train.py").write_text("def train():\n    pass\n")
    preparation = tmp_path / "data" / "dataset" / "prepare.py"
    preparation.parent.mkdir(parents=True)
    preparation.write_text("if __name__ == '__main__':\n    pass\n")
    assert detect_entry_file(tmp_path) is None
    assert [item.path for item in discover_entry_files(tmp_path)] == [
        preparation.relative_to(tmp_path)
    ]
    assert resolve_entry_file(tmp_path, "train.py") == (tmp_path / "train.py").resolve()


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
        "[tool.poetry.scripts]\n" 'demo = { callable = "demo.cli:main", type = "console" }\n',
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
        '[tool.setuptools]\npackages = ["demo"]\n\n' '[project.scripts]\ndemo = "demo.cli:main"\n',
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
        "[tool.poetry.scripts]\n" 'demo = { reference = "demo.cli:main", type = "console" }\n',
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
        "[options.entry_points]\n" "console_scripts =\n" "    demo = demo.cli:main\n",
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
        EntryCandidate(entry.relative_to(tmp_path), "setup.cfg entry_points", "demo-extra"),
    ]


@pytest.mark.parametrize(
    "pyproject_text",
    [
        pytest.param('[tool]\nsetuptools = "not-a-table"\n', id="tool-setuptools-string"),
        pytest.param('[tool.setuptools]\npackages = ["demo"]\n', id="packages-list"),
        pytest.param('[tool.setuptools.packages]\nfind = ["oops"]\n', id="packages-find-list"),
        pytest.param('project = "not-a-table"\n', id="project-string"),
        pytest.param('[tool.poetry]\nscripts = "oops"\n', id="poetry-scripts-string"),
        pytest.param(
            "[project.entry-points.console_scripts]\ndemo = 42\n",
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
