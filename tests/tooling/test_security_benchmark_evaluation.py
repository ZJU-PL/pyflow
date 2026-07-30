from __future__ import annotations

import json

from tools.security_benchmark_evaluation.evaluation import evaluate_results


def _write_result(root, sample, engine, report_name, report, *, cwe="CWE-89"):
    run_dir = root / "runs" / sample / engine
    run_dir.mkdir(parents=True)
    if isinstance(report, str):
        (run_dir / report_name).write_text(report, encoding="utf-8")
    else:
        (run_dir / report_name).write_text(json.dumps(report), encoding="utf-8")
    (run_dir / "result.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "benchmark": "test",
                "sample_id": sample,
                "engine": engine,
                "status": "complete",
                "labels": {"cwe": cwe},
                "raw_output": report_name,
            }
        ),
        encoding="utf-8",
    )


def test_evaluation_normalizes_json_and_applies_rule_mapping(tmp_path):
    results = tmp_path / "results"
    _write_result(
        results,
        "one",
        "bandit",
        "report.json",
        {
            "results": [
                {
                    "test_id": "B608",
                    "issue_text": "SQL query construction",
                    "filename": "app.py",
                    "line_number": 12,
                }
            ]
        },
    )
    mapping = tmp_path / "mapping.json"
    mapping.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engines": {"bandit": {"rules": {"B608": ["CWE-89"]}}},
            }
        ),
        encoding="utf-8",
    )

    metrics = evaluate_results(results, tmp_path / "evaluated", mapping_path=mapping)

    assert metrics["by_engine"]["bandit"]["recall_all"] == 1.0
    normalized = json.loads(
        (tmp_path / "evaluated/normalized.jsonl").read_text(encoding="utf-8")
    )
    assert normalized["findings"][0]["cwes"] == ["CWE-89"]
    assert normalized["findings"][0]["line"] == 12


def test_evaluation_extracts_sarif_cwe_tags_and_does_not_report_precision(tmp_path):
    results = tmp_path / "results"
    _write_result(
        results,
        "one",
        "codeql",
        "report.sarif",
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "py/sql-injection",
                                    "properties": {"tags": ["external/cwe/cwe-089"]},
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/sql-injection",
                            "message": {"text": "unsafe query"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )

    metrics = evaluate_results(results, tmp_path / "evaluated")

    assert metrics["overall"]["recall_completed"] == 1.0
    assert "precision" not in metrics["overall"]
    assert "not computed" in metrics["metric_semantics"]["precision"]


def test_evaluation_marks_failed_runs_incomplete_without_raw_output(tmp_path):
    run_dir = tmp_path / "results/runs/one/custom"
    run_dir.mkdir(parents=True)
    (run_dir / "result.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "benchmark": "test",
                "sample_id": "one",
                "engine": "custom",
                "status": "failed",
                "labels": {"cwe": "CWE-22"},
                "raw_output": None,
            }
        ),
        encoding="utf-8",
    )

    metrics = evaluate_results(tmp_path / "results", tmp_path / "evaluated")

    assert metrics["overall"]["incomplete_run_count"] == 1
    assert metrics["overall"]["recall_all"] == 0.0
    assert metrics["overall"]["recall_completed"] is None


def test_pysa_jsonl_ignores_configuration_and_model_rows(tmp_path):
    results = tmp_path / "results"
    _write_result(
        results,
        "one",
        "pysa",
        "taint-output.json",
        """{"file_version":3,"config":{}}
{"kind":"model","data":{"callable":"app.source"}}
{"kind":"issue","data":{"code":9001,"line":10,"message":"flow"}}
""",
        cwe="CWE-78",
    )
    mapping = tmp_path / "mapping.json"
    mapping.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engines": {"pysa": {"rules": {"9001": ["CWE-78"]}}},
            }
        ),
        encoding="utf-8",
    )

    metrics = evaluate_results(results, tmp_path / "evaluated", mapping_path=mapping)

    assert metrics["overall"]["warning_count"] == 1
    assert metrics["overall"]["detected_run_count"] == 1


def test_evaluation_normalizes_semgrep_nested_fields(tmp_path):
    results = tmp_path / "results"
    _write_result(
        results,
        "one",
        "semgrep",
        "report.json",
        {
            "results": [
                {
                    "check_id": "python.shell-true",
                    "path": "app.py",
                    "start": {"line": 5, "col": 9},
                    "extra": {
                        "message": "shell execution",
                        "severity": "ERROR",
                        "metadata": {"cwe": "CWE-78"},
                    },
                }
            ]
        },
        cwe="CWE-78",
    )

    metrics = evaluate_results(results, tmp_path / "evaluated")
    normalized = json.loads(
        (tmp_path / "evaluated/normalized.jsonl").read_text(encoding="utf-8")
    )

    assert metrics["overall"]["recall_all"] == 1.0
    assert normalized["findings"][0] == {
        "column": 9,
        "cwes": ["CWE-78"],
        "file": "app.py",
        "line": 5,
        "message": "shell execution",
        "raw_index": 0,
        "rule_id": "python.shell-true",
        "severity": "ERROR",
    }
