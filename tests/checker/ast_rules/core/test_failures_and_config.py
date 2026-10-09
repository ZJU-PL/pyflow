"""Rule failures and configured checks must be visible to report consumers."""

import io
import json

from pyflow.checker.ast_rules.checkers import asserts
from pyflow.checker.ast_rules.core.config import SecurityConfig
from pyflow.checker.ast_rules.core.manager import SecurityManager
from pyflow.checker.formatters import json as json_formatter, sarif


def _scan(tmp_path, source, config=None):
    path = tmp_path / "sample.py"
    path.write_text(source)
    manager = SecurityManager(config or SecurityConfig())
    manager.discover_files([str(path)])
    manager.run_tests()
    return manager


def test_assert_rule_receives_defaults_and_counts_actual_findings(tmp_path):
    manager = _scan(tmp_path, "assert True\nassert False\n")
    assert [item.test_id for item in manager.results] == ["B101", "B101"]
    assert manager.get_errors() == []
    assert manager.metrics.data["_totals"]["SEVERITY.LOW"] == 2
    assert manager.metrics.data["_totals"]["CONFIDENCE.HIGH"] == 2
    assert manager.metrics.issues == 2
    assert manager.scores[0]["SEVERITY"][1] == 6


def test_assert_rule_honors_config_without_leaking_between_managers(tmp_path):
    configuration = SecurityConfig()
    configuration.set_option("assert_used", {"skips": ["*/sample.py"]})
    assert _scan(tmp_path, "assert True\n", configuration).results == []
    assert len(_scan(tmp_path, "assert True\n").results) == 1


def test_rule_failures_enter_json_and_sarif_without_repeated_tracebacks(
    tmp_path, monkeypatch, caplog
):
    def broken(context, config):
        raise RuntimeError("deliberate failure")

    broken._checks = ["Assert"]
    broken._test_id = "B101"
    broken._takes_config = "assert_used"
    monkeypatch.setattr(asserts, "assert_used", broken)
    manager = _scan(tmp_path, "assert True\nassert False\n")
    assert len(manager.get_errors()) == 2
    assert {item["line"] for item in manager.get_errors()} == {1, 2}
    assert all(item["rule_id"] == "B101" for item in manager.get_errors())
    assert "Traceback" not in caplog.text
    assert len(caplog.records) == 1
    output = io.StringIO()
    json_formatter.report(manager, output, "LOW", "LOW")
    document = json.loads(output.getvalue())
    assert document["status"] == "partial"
    assert len(document["errors"]) == 2
    output = io.StringIO()
    sarif.report(manager, output, "LOW", "LOW")
    document = json.loads(output.getvalue())
    invocation = document["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert len(invocation["toolExecutionNotifications"]) == 2
