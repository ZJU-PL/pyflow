"""Keep the beginner example and its documented pass wrapper executable."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def plugin():
    path = ROOT / "examples" / "ifds_plugin.py"
    spec = importlib.util.spec_from_file_location("ifds_plugin_example", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


def test_plugin_visits_called_procedure_but_not_dead_code(tmp_path, plugin):
    source = tmp_path / "demo.py"
    source.write_text("def helper():\n    return 1\ndef unused():\n    return 2\nhelper()\n")
    session, result = plugin.analyze_file(source)
    assert result.is_complete
    assert session.diagnostics == ()
    graph = session.adapter.supergraph
    names = {fact for node in graph.ordered_nodes() for fact in result.facts_at(node)}
    assert "helper" in names
    assert "unused" not in names
    module = next(
        proc for proc in graph.ordered_procedures() if proc.code.codeName().endswith(".<module>")
    )
    exit_facts = set().union(*(result.facts_at(node) for node in graph.ordered_exits_of(module)))
    assert "helper" in exit_facts
    assert plugin.ZERO in exit_facts


def test_default_demo_runs_without_arguments():
    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "ifds_plugin.py")],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "Analyzed: ifds_demo.py\nReachable functions: helper\n"
    assert result.stderr == ""


def test_documented_pass_wrapper(plugin):
    session, _ = plugin.analyze_file(ROOT / "tests/fixtures/analysis_inputs/ifds_demo.py")
    tutorial = (ROOT / "docs/source/how-to/ifds-plugin.rst").read_text()
    block = tutorial.split(".. code-block:: python\n\n", 1)[1].split("\nHere ", 1)[0]
    namespace = {"session": session, "VisitedFunctions": plugin.VisitedFunctions}
    exec(textwrap.dedent(block), namespace)
    pass_result = namespace["passes"]["visited_functions"]
    assert pass_result.success
    assert not pass_result.changed
    result = pass_result.data
    assert any(
        "helper" in result.facts_at(node) for node in session.adapter.supergraph.ordered_nodes()
    )
