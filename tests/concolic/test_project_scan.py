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
    assert method.eligible
    assert method.descriptor_kind == "staticmethod"
    assert method.entry == "Example.method"
    assert [parameter.name for parameter in method.parameters] == ["value"]


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


def test_input_synthesizer_supports_optional_annotated_tuple_and_bytes(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "from typing import Annotated, Optional\n"
        "def target(maybe: Optional[int], pair: tuple[int, str], "
        "payload: Annotated[bytes, 'wire']):\n"
        "    return maybe\n",
        encoding="utf-8",
    )
    target = discover_targets(source)[0]
    synthesizer = InputSynthesizer()

    assert synthesizer.synthesize(target, 0).inputs == (None, (0, ""), b"")
    assert synthesizer.synthesize(target, 1).inputs == (1, (0, ""), b"a")


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
        exploration_options={
            "max_iterations": 10,
            "total_timeout": 5,
            "per_run_timeout": 1,
            "solver_timeout": 0.5,
        },
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
        exploration_options={
            "max_iterations": 5,
            "total_timeout": 5,
            "per_run_timeout": 1,
            "solver_timeout": 0.5,
        },
    )

    assert result.functions[0].status is ScanStatus.SUPPORTED


def test_project_scan_times_out_worker_that_hangs_during_replay(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "while True:\n" "    pass\n" "def target(value: int):\n" "    return value\n",
        encoding="utf-8",
    )

    result = scan_project(
        source,
        input_complexity=0,
        function_timeout=0.5,
        exploration_options={
            "max_iterations": 2,
            "total_timeout": 0.25,
            "per_run_timeout": 0.1,
            "solver_timeout": 0.05,
        },
    )

    assert result.functions[0].status is ScanStatus.TIMEOUT
    assert result.functions[0].attempts[0].reason == "worker exceeded 0.5s"


def test_project_scan_runtime_audit_wall_blocks_indirect_file_writes(tmp_path):
    marker = tmp_path / "written.txt"
    source = tmp_path / "sample.py"
    source.write_text(
        "writer = open\n"
        f"writer({str(marker)!r}, 'w').write('unsafe')\n"
        "def target():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_project(source, input_complexity=0, function_timeout=2)

    assert result.functions[0].status is ScanStatus.SIDE_EFFECT_HAZARD
    assert not marker.exists()


def test_input_synthesizer_supports_set_annotations(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        "def target(values: set[int], frozen: frozenset[str]):\n"
        "    return len(values) + len(frozen)\n",
        encoding="utf-8",
    )
    target = discover_targets(source)[0]
    synthesizer = InputSynthesizer()

    assert synthesizer.synthesize(target, 0).inputs == (set(), frozenset())
    assert synthesizer.synthesize(target, 1).inputs == ({0}, frozenset({""}))
