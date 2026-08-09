from __future__ import annotations

import sys

from tools.security_benchmark_runner.adapters import (
    AdapterContext,
    BanditAdapter,
    CodeQLAdapter,
    CommandAdapter,
    PysaAdapter,
    PyFlowAdapter,
    adapter_for,
)


def _context(tmp_path, engine, script, **config):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    run_dir = tmp_path / f"run-{engine}"
    run_dir.mkdir()
    return AdapterContext(
        engine=engine,
        sample_id="sample-one",
        target=target,
        run_dir=run_dir,
        timeout_seconds=5,
        config={"command": [sys.executable, str(script)], **config},
    )


def test_bandit_adapter_accepts_findings_exit_code(tmp_path):
    script = tmp_path / "bandit.py"
    script.write_text(
        """
import json, pathlib, sys
if '--version' in sys.argv:
    print('bandit fake-1')
    raise SystemExit(0)
output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
output.write_text(json.dumps({'results': [{'test_id': 'B101'}]}))
raise SystemExit(1)
""",
        encoding="utf-8",
    )

    result = BanditAdapter().run(_context(tmp_path, "bandit", script))

    assert result.status == "complete"
    assert result.finding_count == 1


def test_codeql_adapter_creates_database_and_parses_sarif(tmp_path):
    script = tmp_path / "codeql.py"
    script.write_text(
        """
import json, pathlib, sys
if len(sys.argv) > 1 and sys.argv[1] == 'version':
    print('codeql fake-1')
elif sys.argv[1:3] == ['database', 'create']:
    pathlib.Path(sys.argv[3]).mkdir(parents=True)
elif sys.argv[1:3] == ['database', 'analyze']:
    output_index = sys.argv.index('--output') + 1
    pathlib.Path(sys.argv[output_index]).write_text(
        json.dumps({'runs': [{'results': [{'ruleId': 'fake'}]}]})
    )
else:
    raise SystemExit(2)
""",
        encoding="utf-8",
    )

    result = CodeQLAdapter().run(_context(tmp_path, "codeql", script))

    assert result.status == "complete"
    assert result.finding_count == 1
    assert len(result.commands) == 2


def test_pysa_adapter_uses_isolated_configuration_and_counts_issues(tmp_path):
    script = tmp_path / "pyre.py"
    script.write_text(
        """
import pathlib, sys
if '--version' in sys.argv:
    print('pyre fake-1')
    raise SystemExit(0)
output = pathlib.Path(sys.argv[sys.argv.index('--save-results-to') + 1])
output.mkdir(parents=True)
(output / 'taint-output.json').write_text(
    '{"kind":"issue","data":{"code":5005}}\\n'
    '{"kind":"model","data":{}}\\n'
)
""",
        encoding="utf-8",
    )
    context = _context(
        tmp_path,
        "pysa",
        script,
        taint_models_path="/models",
    )

    result = PysaAdapter().run(context)

    assert result.status == "complete"
    assert result.finding_count == 1
    configuration = (context.run_dir / ".pyre_configuration").read_text()
    assert str(context.target) in configuration
    assert "/models" in configuration
    assert "--no-verify" not in result.commands[0].argv


def test_pyflow_adapter_uses_report_policy_for_findings_and_partial_status(tmp_path):
    script = tmp_path / "pyflow.py"
    script.write_text(
        """
import json, pathlib, sys
if '--version' in sys.argv:
    print('PyFlow fake-1')
    raise SystemExit(0)
output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
engine = sys.argv[sys.argv.index('--engine') + 1]
assert sys.argv[sys.argv.index('--exit-code-policy') + 1] == 'report'
if engine == 'cpg':
    output.write_text(json.dumps({'status': 'partial', 'findings': []}))
    raise SystemExit(0)
output.write_text(json.dumps({'status': 'complete', 'results': [{'test_id': 'B602'}]}))
raise SystemExit(0)
""",
        encoding="utf-8",
    )

    findings = PyFlowAdapter("pyflow-ast-scanner", "ast-scanner").run(
        _context(tmp_path, "pyflow-ast-scanner", script)
    )
    partial = PyFlowAdapter("pyflow-cpg", "cpg").run(_context(tmp_path, "pyflow-cpg", script))

    assert findings.status == "complete"
    assert findings.finding_count == 1
    assert partial.status == "partial"


def test_declarative_command_adapter_runs_steps_and_parses_report(tmp_path):
    script = tmp_path / "analyzer.py"
    script.write_text(
        """
import json, os, pathlib, sys
if '--version' in sys.argv:
    print('custom ' + os.environ['CUSTOM_VERSION'])
else:
    output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
    output.write_text(json.dumps({'status': 'complete', 'issues': [{}, {}]}))
""",
        encoding="utf-8",
    )
    target = tmp_path / "target"
    target.mkdir()
    run_dir = tmp_path / "run-custom"
    run_dir.mkdir()
    config = {
        "adapter": "command",
        "version_argv": [sys.executable, str(script), "--version"],
        "version_env": {"CUSTOM_VERSION": "1.2.3"},
        "steps": [
            {
                "name": "scan",
                "argv": [
                    sys.executable,
                    str(script),
                    "--target",
                    "{target}",
                    "--output",
                    "{report}",
                    "{sample_args}",
                ],
            }
        ],
        "report": {
            "path": "report.json",
            "format": "json",
            "findings_pointer": "/issues",
            "analysis_status_pointer": "/status",
        },
    }
    context = AdapterContext(
        engine="custom",
        sample_id="sample-one",
        target=target,
        run_dir=run_dir,
        timeout_seconds=5,
        sample_args=("--extra",),
        config=config,
    )

    result = CommandAdapter("custom").run(context)

    assert result.status == "complete"
    assert result.finding_count == 2
    assert result.tool_version == "custom 1.2.3"
    assert result.commands[0].argv[-1] == "--extra"
    assert isinstance(adapter_for("custom", config), CommandAdapter)
