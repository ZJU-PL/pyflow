from __future__ import annotations

import json

import pytest

from tools.security_benchmark_runner.adapters import AdapterResult
from tools.security_benchmark_runner.manifest import BenchmarkManifest
from tools.security_benchmark_runner.runner import BenchmarkRunner, RunnerOptions


class _Adapter:
    def run(self, context):
        report = context.run_dir / "report.json"
        report.write_text('{"findings": []}\n', encoding="utf-8")
        return AdapterResult(
            status="complete",
            commands=(),
            tool_version="test 1.0",
            raw_output=report.name,
            finding_count=0,
        )


def test_runner_records_reproducible_result_and_resumes(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    manifest = BenchmarkManifest.from_dict(
        {
            "schema_version": 1,
            "name": "local-corpus",
            "samples": [
                {
                    "id": "sample-one",
                    "source": {"kind": "local", "path": str(source)},
                    "labels": {"cwe": "CWE-22"},
                }
            ],
        },
        base_dir=tmp_path,
    )
    monkeypatch.setattr(
        "tools.security_benchmark_runner.runner.adapter_for",
        lambda _name, _config: _Adapter(),
    )
    options = RunnerOptions(
        output_dir=tmp_path / "output",
        engines=("fake",),
    )

    first = BenchmarkRunner(manifest, options).run()
    second = BenchmarkRunner(manifest, options).run()

    assert first["status_counts"] == {"complete": 1}
    assert second["resumed_count"] == 1
    result_path = tmp_path / "output" / "runs/sample-one/fake/result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["source"]["tree_sha256"]
    assert result["labels"] == {"cwe": "CWE-22"}
    assert result["raw_output"] == "report.json"


def test_runner_refuses_to_resume_with_different_configuration(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("pass\n", encoding="utf-8")
    manifest = BenchmarkManifest.from_dict(
        {
            "schema_version": 1,
            "name": "config-check",
            "samples": [
                {
                    "id": "sample-one",
                    "source": {"kind": "local", "path": str(source)},
                }
            ],
        }
    )
    monkeypatch.setattr(
        "tools.security_benchmark_runner.runner.adapter_for",
        lambda _name, _config: _Adapter(),
    )
    output = tmp_path / "output"
    BenchmarkRunner(
        manifest,
        RunnerOptions(output_dir=output, engines=("fake",), timeout_seconds=10),
    ).run()

    with pytest.raises(ValueError, match="configuration differs"):
        BenchmarkRunner(
            manifest,
            RunnerOptions(output_dir=output, engines=("fake",), timeout_seconds=20),
        ).run()
