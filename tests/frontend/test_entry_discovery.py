from __future__ import annotations

from pyflow.frontend.entry_discovery import detect_entry_file, resolve_entry_file


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
