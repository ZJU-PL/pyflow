"""Integration tests for repo-level regression corpus tooling."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
COLLECT = ROOT / "scripts" / "evaluation" / "collect_repo_level_corpus.py"
RUN = ROOT / "scripts" / "evaluation" / "run_repo_level_regression.py"
CORPUS_ROOT = ROOT / "evaluation" / "repo_level"


@pytest.mark.integration
class TestRepoLevelCorpus:
    """Validate end-to-end repo-level corpus collection and execution."""

    def test_manifest_has_all_projects(self) -> None:
        manifest = json.loads((CORPUS_ROOT / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["version"] == 1
        
        expected_projects = {"cli_tool", "data_pipeline", "ml_utils", "repo_sample", "web_framework"}
        actual_projects = {p["name"] for p in manifest["projects"]}
        assert actual_projects == expected_projects

    def test_run_repo_level_regression_on_all_projects(self, tmp_path: Path) -> None:
        report_path = tmp_path / "report.json"
        subprocess.run(
            [
                sys.executable,
                str(RUN),
                "--corpus",
                str(CORPUS_ROOT),
                "--output",
                str(report_path),
            ],
            check=True,
            cwd=str(ROOT),
        )

        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert "projects" in report
        
        expected_projects = {"cli_tool", "data_pipeline", "ml_utils", "repo_sample", "web_framework"}
        actual_projects = {p["project"] for p in report["projects"]}
        assert actual_projects == expected_projects

        for project in report["projects"]:
            assert project["files"] > 0
            assert project["errors"] == 0
            assert project["failures"] == 0
            assert project["live_code"] > 0
            telemetry = project.get("frontend_telemetry", {})
            assert isinstance(telemetry, dict)

    def test_collect_repo_level_corpus_from_single_project(self, tmp_path: Path) -> None:
        out = tmp_path / "repo_level"
        project_path = CORPUS_ROOT / "corpus" / "repo_sample"
        cmd = [
            sys.executable,
            str(COLLECT),
            "--output",
            str(out),
            "--project",
            str(project_path),
        ]
        subprocess.run(cmd, check=True, cwd=str(ROOT))

        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["version"] == 1
        assert len(manifest["projects"]) == 1
        project = manifest["projects"][0]
        assert project["name"] == "repo_sample"
        assert project["python_files"] >= 10
        assert project["path"] == "corpus/repo_sample"
