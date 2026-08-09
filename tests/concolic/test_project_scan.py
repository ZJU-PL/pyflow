"""Static target discovery, input synthesis, and project scanning tests."""

from __future__ import annotations

from pyflow.concolic.project import (
    InputSynthesizer,
    ScanStatus,
    discover_targets,
    scan_project,
)


def test_catalog_discovers_functions_without_importing_module(tmp_path):
    marker = tmp_path / "imported.txt"
    source = tmp_path / "sample.py"
    source.write_text(
        f"open({str(marker)!r}, 'w').write('bad')\n"
        "def public(value: int, label: str = 'x') -> bool:\n"
        "    return value > 0\n"
        "def _private():\n"
        "    return 1\n"
        "class Example:\n"
        "    @staticmethod\n"
        "    def method(value: int):\n"
        "        return value\n",
        encoding="utf-8",
    )

    targets = discover_targets(tmp_path)

    assert not marker.exists()
    assert [target.qualname for target in targets] == ["public", "Example.method"]
    public, method = targets
    assert public.eligible
    assert public.parameters[0].annotation == "int"
    assert public.parameters[0].required
    assert not public.parameters[1].required
    assert public.hazards == ("module_filesystem",)
    assert not method.eligible
    assert method.descriptor_kind == "staticmethod"
    assert "method_entry_not_supported" in method.eligibility_reasons


def test_input_synthesizer_uses_annotations_tiers_and_overrides(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "from typing import Literal\n"
        "def target(count: int, text: str, values: list[int], "
        "mode: Literal['a', 'b']):\n"
        "    return count\n",
        encoding="utf-8",
    )
    target = discover_targets(source)[0]
    synthesizer = InputSynthesizer(
        {f"{target.identifier}.text": lambda _t, _p, tier: f"tier-{tier}"}
    )

    assert synthesizer.synthesize(target, 0).inputs == (0, "tier-0", [], "a")
    assert synthesizer.synthesize(target, 2).inputs == (-1, "tier-2", [1, 1], "a")


def test_project_scan_classifies_supported_and_hazardous_functions(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "def classify(value: int):\n"
        "    if value > 0:\n"
        "        return 'positive'\n"
        "    return 'other'\n"
        "def dangerous(path: str):\n"
        "    with open(path, 'w') as stream:\n"
        "        stream.write('x')\n",
        encoding="utf-8",
    )

    result = scan_project(
        tmp_path,
        input_complexity=1,
        function_timeout=10,
        exploration_options={"max_iterations": 10},
    )

    functions = {item.target.qualname: item for item in result.functions}
    assert functions["classify"].status is ScanStatus.SUPPORTED
    assert len(functions["classify"].attempts) == 2
    assert all(attempt.status is ScanStatus.SUPPORTED for attempt in functions["classify"].attempts)
    assert functions["dangerous"].status is ScanStatus.SIDE_EFFECT_HAZARD
    payload = result.to_dict()
    assert payload["summary"]["discovered"] == 2
    assert payload["summary"]["statuses"]["supported"] == 1
    assert payload["summary"]["statuses"]["side_effect_hazard"] == 1


def test_project_scan_replay_preserves_package_relative_imports(tmp_path):
    package = tmp_path / "example"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helper.py").write_text(
        "def adjust(value):\n" "    return value + 1\n",
        encoding="utf-8",
    )
    (package / "target.py").write_text(
        "from .helper import adjust\n" "def calculate(value: int):\n" "    return adjust(value)\n",
        encoding="utf-8",
    )

    result = scan_project(
        package / "target.py",
        input_complexity=0,
        exploration_options={"max_iterations": 5},
    )

    assert result.functions[0].status is ScanStatus.SUPPORTED
