"""Regression tests for real-world PySASTBench matching semantics."""

from evaluation.pysastbench import bench_realworld


def test_cwe_hierarchy_is_used_by_realworld_matching(tmp_path):
    project = tmp_path / "CVE-TEST" / "sample-vul"
    project.mkdir(parents=True)
    target = project / "app.py"
    target.write_text("def run():\n    pass\n", encoding="utf-8")
    metadata = {
        "CVE-TEST": {
            "CWE Type": "77;707",
            "vul position": "app.py:run",
        }
    }
    record = {
        "engine": "ifds",
        "project": str(project),
        "cve": "CVE-TEST",
        "payload": {
            "findings": [
                {
                    "procedure": "run",
                    "cwe": "CWE-78",
                    "cwes": ["CWE-78", "CWE-77"],
                    "primary_location": {
                        "uri": str(target),
                        "start_line": 1,
                    },
                }
            ]
        },
    }

    assert bench_realworld._detected(record, metadata)
